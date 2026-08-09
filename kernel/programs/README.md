# eBPF Kernel Programs

This directory contains the eBPF kernel programs that run in kernel space.

## Structure

Each program should:
- Be compiled to bytecode (BPF object files)
- Have a corresponding header defining its interface
- Include documentation about its behavior

## Example Program Template

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Your eBPF program here
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read(struct trace_event_raw_sys_enter *ctx)
{
    // Implementation
    return 0;
}

char _license[] SEC("license") = "GPL";
```

## Building

Programs are built using clang with the BPF backend:
```bash
clang -O2 -target bpf -c program.c -o program.o
```
