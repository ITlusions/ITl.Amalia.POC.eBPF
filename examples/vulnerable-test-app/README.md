# Intentionally Vulnerable Test Fixture

`vulnerable_app.c` is a Vulnserver-style UDP server: one listener, several
distinct and deliberately buggy command handlers, each hidden inside an
innocuous-looking "legitimate" function — the same pattern real bugs are
found in. `exploit.py` uses Scapy to craft and send the `COMMAND:data`
packet that triggers each one.

**This exists only to validate this repo's blue-team telemetry pipeline**
(does the eBPF sensor see the inbound packet + process exec, does the
server crash/misbehave predictably, does crash telemetry reach
`detection/crash_detection`). It is not a general-purpose exploit tool.

**Binds to `127.0.0.1` only, by design — never bind this to `0.0.0.0` or
run it on anything but an isolated lab machine.** Every command below is a
remotely triggerable bug on purpose.

## Commands / bug classes

| `--command` | Wire format | Bug class | Looks like... | Trigger notes |
|---|---|---|---|---|
| `overflow` | `OVERFLOW:<data>` | Stack buffer overflow | "log the username" | `--size 200` crashes it |
| `banner` | `BANNER:<data>` | Format string | "customizable welcome banner" | `printf(user_input)` instead of `printf("%s", ...)` — leaks stack memory or crashes |
| `nick` | `NICK:<data>` | Heap off-by-one | "store a nickname" | `malloc(strlen)` missing `+1` for the NUL `strcpy()` writes. **May not crash immediately** — a 1-byte heap overflow often only corrupts adjacent metadata silently; run under AddressSanitizer/valgrind for deterministic detection |
| `records` | `RECORDS:<count>` | Integer overflow -> undersized heap alloc | "pre-allocate N records" | `--size 1073741825` wraps the 32-bit size calculation to 4 bytes, then overflows writing past it |
| `session-open` | `SESSION_OPEN:<data>` | setup for UAF | "open a session" | run before `session-close`/`session-touch` |
| `session-close` | `SESSION_CLOSE` | frees session, forgets to NULL it | "close a session" | — |
| `session-touch` | `SESSION_TOUCH` | Use-after-free | "keepalive ping" | run *after* `session-close`. **May not crash immediately** — freed heap memory is often still mapped/unmodified right after `free()`; run under valgrind (`--tool=memcheck`) for deterministic detection |
| `bio-set` | `BIO_SET:<data>` | — | "set profile bio" | optional setup |
| `bio-reset` | `BIO_RESET` | — | "reset profile" | leaves the profile pointer NULL |
| `bio-print` | `BIO_PRINT` | NULL pointer dereference | "show profile" | crashes if bio was never set or was reset first |

## Build

```bash
gcc -g -O0 -fno-stack-protector -z execstack -o vulnerable_app vulnerable_app.c
pip install scapy   # exploit.py dependency
```

`-fno-stack-protector -z execstack` disable stack canaries/NX so the overflow
and off-by-one bugs are actually exploitable rather than just caught by
glibc's `__stack_chk_fail` — useful for a clean crash demo. Omit those flags
to instead see how modern mitigations turn the same bugs into a
detected/aborted process.

## Run it

```bash
# Terminal 1: start the vulnerable listener
./vulnerable_app

# Terminal 2: send a harmless packet first (works fine)
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'OVERFLOW:short_name', ('127.0.0.1', 31337))
"

# Terminal 2: now trigger a bug (needs root/CAP_NET_RAW for Scapy to send)
sudo python3 exploit.py --target 127.0.0.1 --command overflow --size 200

# Other bugs:
sudo python3 exploit.py --command banner --size 40         # format string
sudo python3 exploit.py --command nick --size 64            # heap off-by-one
sudo python3 exploit.py --command records --size 1073741825 # integer overflow (32-bit wrap)
sudo python3 exploit.py --command session-open --size 10
sudo python3 exploit.py --command session-close
sudo python3 exploit.py --command session-touch             # use-after-free
sudo python3 exploit.py --command bio-print                 # NULL deref (bio never set)
```

Terminal 1 will print the received (sometimes truncated/garbled) payload
and then crash (`Segmentation fault (core dumped)`) or misbehave, depending
on the bug.

> **WSL2 caveat (verified):** Scapy's raw packet injection does not reach
> the loopback interface under WSL2's virtualized network stack — even a
> 10-byte test packet never arrives at the listener (confirmed with
> `tcpdump -i lo`), despite `send()` reporting success. This is the same
> underlying limitation as the loopback kprobe quirk in
> `docs/WSL2-TESTING.md`. On WSL2, either run `exploit.py` against a
> second machine/VM on a real network, or use the plain-`socket.sendto()`
> snippet above for local testing — the overflow bug is confirmed to work
> end-to-end that way (verified: oversized payload delivered via a normal
> UDP socket reliably crashes the server with SIGSEGV). On bare-metal
> Linux, `exploit.py` against `127.0.0.1` works as expected.

## Observing it with the eBPF sensor

```bash
sudo python3 /opt/ebpf-implant/implant_agent.py \
  --config-set collection.network_events.enabled true \
  --config-set collection.process_events.enabled true \
  --bpf /opt/ebpf-implant/sensor.bpf.c --load --collect 30 --export
# in another terminal, while collecting:
./vulnerable_app &
sudo python3 exploit.py --command overflow --size 200
```

The `kprobe/__udp4_lib_rcv` hook captures the inbound UDP packet and the
`tp/sched/sched_process_exec` hook captures `vulnerable_app`'s exec. The
crash itself (SIGSEGV) is **not** currently captured — `sensor.bpf.c` has no
signal-delivery hook. Wiring up a `kprobe/do_coredump` or tracepoint on
`signal_deliver` is a separate, larger feature if you want end-to-end crash
telemetry through `detection/crash_detection/detector.py`.
