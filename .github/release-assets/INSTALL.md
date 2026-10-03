# Installing from a prebuilt release bundle

This bundle contains a precompiled CO-RE eBPF object, the native libbpf
loader, and the Python agent/dashboard — no build toolchain required on the
target.

## Requirements

- Linux kernel 5.8+ with BTF support (check: `ls /sys/kernel/btf/vmlinux`)
- Matching architecture: `linux-x86_64` or `linux-arm64` (Raspberry Pi 4/5 64-bit OS)
- `libbpf` runtime library installed (`sudo apt install libbpf1` on Debian/Ubuntu,
  or `sudo dnf install libbpf` on Fedora/RHEL)
- `python3` (no extra pip packages required for the core loader/dashboard)
- Root access to load eBPF programs

## Contents

| File | Purpose |
|---|---|
| `sensor.bpf.o` | Precompiled CO-RE eBPF object (process/network/file hooks) |
| `vmlinux.h` | Kernel type definitions used at compile time (reference only, not needed at runtime) |
| `loader` | Native libbpf binary: loads `sensor.bpf.o`, attaches hooks, streams events |
| `loader.c` | Source for `loader`, in case you need to rebuild for a different kernel/arch |
| `implant_agent.py` | Full pipeline: load, collect for N seconds, export JSON, detection modules |
| `live_stats.py` | Real-time inbound-connection dashboard, reads events via pipe (no file needed) |
| `config.json` | Default profile (network events, both directions) |
| `config-inbound.json` | Inbound-only profile (only accept-side kprobes attached) |

> `sensor.bpf.o` is CO-RE (Compile Once – Run Everywhere): field offsets are
> resolved against the *target* kernel's BTF at load time, so it is portable
> across kernel versions of the same architecture. If `loader` fails to load
> it on your kernel, rebuild from `loader.c` + a fresh `vmlinux.h` generated
> on the target with `bpftool btf dump file /sys/kernel/btf/vmlinux format c`.

## Install

```bash
tar xzf ebpf-implant-linux-<arch>.tar.gz
sudo mkdir -p /opt/ebpf-implant
sudo cp -r ebpf-implant-linux-<arch>/* /opt/ebpf-implant/
sudo chmod 711 /opt/ebpf-implant                 # traverse-only
sudo chmod 644 /opt/ebpf-implant/live_stats.py   # must run without sudo
```

## Run

**One-shot collection + JSON export:**

```bash
sudo python3 /opt/ebpf-implant/implant_agent.py \
  --bpf /opt/ebpf-implant/sensor.bpf.c \
  --load --collect 60 --export
```

(Use `--config /opt/ebpf-implant/config-inbound.json` to only capture inbound connections.)

**Live inbound-connection dashboard (no file, direct pipe):**

```bash
sudo /opt/ebpf-implant/loader \
  --obj /opt/ebpf-implant/sensor.bpf.o \
  --duration 0 --enable network --direction inbound \
| python3 /opt/ebpf-implant/live_stats.py
```

Press `Ctrl+C` to stop; writes a forensic summary JSON to
`/tmp/ebpf-telemetry/connection-summary.json` (peer IPs, ports, processes,
UIDs, TCP state history, first/last seen).

## Troubleshooting

- **`sudo: a password is required`** — enter the password when prompted; it
  can't be automated from a script/CI pipeline.
- **`Permission denied` opening `live_stats.py`** — re-run the `chmod` commands above.
- **Loader fails to attach/load** — confirm the bundle's architecture matches
  your host (`uname -m`) and that `/sys/kernel/btf/vmlinux` exists.
