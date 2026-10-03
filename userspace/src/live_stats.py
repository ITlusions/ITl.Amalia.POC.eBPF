#!/usr/bin/env python3
"""
Live inbound-connection dashboard.

Reads JSON-line events directly from stdin (piped straight from loader's
ring-buffer callbacks, no intermediate file) and renders a real-time table
of unique peers: IP, protocol, local port, connection count, and
first/last-seen timestamps. On exit (Ctrl+C) it writes a forensic summary
JSON capturing the full metadata needed for later investigation.

Usage:
    sudo build/loader --obj kernel/programs/sensor.bpf.o --duration 0 \\
        --enable network --direction inbound | python3 userspace/src/live_stats.py
"""

import argparse
import json
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

CLEAR_SCREEN = "\x1b[2J\x1b[H"

TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
    5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
    9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING",
}


class ConnectionLedger:
    """Aggregates raw loader events into per-peer forensic records"""

    def __init__(self):
        self.entries: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.total_events = 0
        self.lock = threading.Lock()

    def record(self, event: Dict[str, Any]) -> None:
        if event.get("type") != "network":
            return

        # For inbound events (see sensor.bpf.c) the connecting peer is
        # "daddr"/"dport" (remote address) while "saddr"/"sport" is the
        # local side that accepted the connection.
        peer_ip = event.get("daddr", "unknown")
        protocol = event.get("protocol", "unknown")
        key = (peer_ip, protocol)
        ts = event.get("timestamp", 0) / 1e9
        ts_iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        with self.lock:
            entry = self.entries.get(key)
            if entry is None:
                entry = {
                    "peer_ip": peer_ip,
                    "protocol": protocol,
                    "first_seen": ts_iso,
                    "first_seen_epoch": ts,
                    "last_seen": ts_iso,
                    "last_seen_epoch": ts,
                    "count": 0,
                    "local_ports": set(),
                    "peer_ports": set(),
                    "processes": set(),
                    "uids": set(),
                    "tcp_states": set(),
                    "dns_hits": 0,
                }
                self.entries[key] = entry

            entry["count"] += 1
            entry["last_seen"] = ts_iso
            entry["last_seen_epoch"] = ts
            entry["local_ports"].add(event.get("sport", 0))
            entry["peer_ports"].add(event.get("dport", 0))
            entry["processes"].add(f"{event.get('comm', '?')}({event.get('pid', 0)})")
            entry["uids"].add(event.get("uid", 0))
            state = event.get("tcp_state")
            if state is not None:
                entry["tcp_states"].add(TCP_STATES.get(state, str(state)))
            if event.get("is_dns"):
                entry["dns_hits"] += 1

            self.total_events += 1

    def render_rows(self):
        with self.lock:
            rows = sorted(self.entries.values(), key=lambda e: e["last_seen_epoch"], reverse=True)
            # Deep-copy the mutable set fields so the renderer can safely read
            # them after releasing the lock while the reader thread keeps mutating.
            return [
                {
                    **e,
                    "local_ports": set(e["local_ports"]),
                    "peer_ports": set(e["peer_ports"]),
                    "processes": set(e["processes"]),
                    "uids": set(e["uids"]),
                    "tcp_states": set(e["tcp_states"]),
                }
                for e in rows
            ]

    def export_forensic_summary(self, path: Path) -> None:
        """Write the full per-peer metadata (ports, processes, uids, state
        history, first/last seen) needed to reconstruct who connected,
        from where, using what, and when."""
        records = []
        for entry in self.render_rows():
            records.append({
                "peer_ip": entry["peer_ip"],
                "protocol": entry["protocol"],
                "connection_count": entry["count"],
                "first_seen": entry["first_seen"],
                "last_seen": entry["last_seen"],
                "local_ports": sorted(entry["local_ports"]),
                "peer_ports": sorted(entry["peer_ports"]),
                "processes": sorted(entry["processes"]),
                "uids": sorted(entry["uids"]),
                "tcp_states_observed": sorted(entry["tcp_states"]),
                "dns_hits": entry["dns_hits"],
            })

        summary = {
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "total_events": self.total_events,
            "unique_peers": len(records),
            "connections": records,
        }

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(summary, f, indent=2)


class JsonlTailer:
    """Follows a growing JSONL file, tolerating truncation/restart (legacy/offline mode)"""

    def __init__(self, path: Path):
        self.path = path
        self._pos = 0

    def read_new_lines(self):
        if not self.path.exists():
            return []

        size = self.path.stat().st_size
        if size < self._pos:
            self._pos = 0  # file was truncated/restarted

        lines = []
        with open(self.path, "r") as f:
            f.seek(self._pos)
            for line in f:
                line = line.strip()
                if line:
                    lines.append(line)
            self._pos = f.tell()
        return lines


class StdinReader(threading.Thread):
    """Continuously reads JSON-line events from stdin (piped from loader) into the ledger"""

    def __init__(self, ledger: ConnectionLedger):
        super().__init__(daemon=True)
        self.ledger = ledger

    def run(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            self.ledger.record(event)


def render_table(ledger: ConnectionLedger, source: str) -> None:
    rows = ledger.render_rows()
    now = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")

    out = [CLEAR_SCREEN]
    out.append(f"Live inbound connections — source: {source}")
    out.append(f"Refreshed: {now}    Unique peers: {len(rows)}    Total events: {ledger.total_events}")
    out.append("")
    out.append(f"{'PEER IP':<22}{'PROTO':<7}{'LOCAL PORTS':<16}{'COUNT':<8}{'LAST SEEN (UTC)':<22}{'STATE':<14}{'PROCESS'}")
    out.append("-" * 120)

    for entry in rows[:40]:
        ports = ",".join(str(p) for p in sorted(entry["local_ports"])[:4])
        state = ",".join(sorted(entry["tcp_states"])[:2]) or "-"
        proc = ",".join(sorted(entry["processes"])[:2]) or "-"
        out.append(
            f"{entry['peer_ip']:<22}{entry['protocol']:<7}{ports:<16}"
            f"{entry['count']:<8}{entry['last_seen']:<22}{state:<14}{proc}"
        )

    if len(rows) > 40:
        out.append(f"... ({len(rows) - 40} more peers, see forensic summary on exit)")

    out.append("")
    out.append("Press Ctrl+C to stop and write the forensic summary JSON.")
    sys.stdout.write("\n".join(out) + "\n")
    sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="Live inbound-connection dashboard")
    parser.add_argument("--jsonl", default=None,
                         help="Legacy/offline mode: tail a JSONL file instead of reading stdin")
    parser.add_argument("--refresh", type=float, default=1.0, help="Redraw interval in seconds")
    parser.add_argument("--summary-out", default="/tmp/ebpf-telemetry/connection-summary.json",
                         help="Forensic summary output path")
    args = parser.parse_args()

    summary_path = Path(args.summary_out)
    ledger = ConnectionLedger()

    stop = {"flag": False}

    def on_signal(sig, frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    if args.jsonl:
        # Legacy mode: poll a file for new lines (no live stream available)
        source = args.jsonl
        tailer = JsonlTailer(Path(args.jsonl))
        while not stop["flag"]:
            for line in tailer.read_new_lines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ledger.record(event)
            render_table(ledger, source)
            time.sleep(args.refresh)
    else:
        # Default mode: read events live from stdin (piped from loader), no file involved
        source = "stdin (live pipe from loader)"
        reader = StdinReader(ledger)
        reader.start()
        while not stop["flag"] and reader.is_alive():
            render_table(ledger, source)
            time.sleep(args.refresh)
        render_table(ledger, source)

    ledger.export_forensic_summary(summary_path)
    print(f"\n[+] Forensic summary written to {summary_path}")


if __name__ == "__main__":
    main()
