# Userspace Applications

This directory contains the user-space applications that interact with eBPF programs.

## Structure

- **main.c** - Main loader application
- **loader.c** - eBPF program loader and manager
- **utils.c** - Utility functions

## Responsibilities

The userspace application typically:
1. Loads compiled eBPF programs into the kernel
2. Attaches them to hooks (tracepoints, kprobes, etc.)
3. Reads data from kernel-space buffers (perf buffers, ring buffers, maps)
4. Processes and displays collected data

## Building

Applications are built using standard C compilers with libbpf:
```bash
gcc -o app main.c loader.c utils.c -lbpf
```
