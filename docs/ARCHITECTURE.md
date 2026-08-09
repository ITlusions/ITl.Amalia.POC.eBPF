# Architecture

## System Overview

This eBPF project follows a two-tier architecture:

```
┌─────────────────────────────────────┐
│     User-Space Application          │
│  (Loader, Event Processing)         │
└────────────────┬────────────────────┘
                 │
         libbpf (syscalls)
                 │
┌────────────────▼────────────────────┐
│    Linux Kernel                     │
│  - eBPF VM                          │
│  - Map Storage                      │
│  - Hooks (tracepoints, kprobes)     │
└─────────────────────────────────────┘
```

## Components

### Kernel Space (eBPF Programs)
- Lightweight, fast execution
- Limited API access (to maintain security)
- Direct access to kernel data structures
- Compiled to BPF bytecode

### User Space (Loader & App)
- Rich environment for data processing
- Can use standard C libraries
- Responsible for program lifecycle management
- Displays results and handles logging

## Data Flow

1. **Loading Phase**
   - User app reads compiled eBPF object file
   - libbpf validates and loads into kernel
   - Programs attached to specified hooks

2. **Execution Phase**
   - Kernel events trigger eBPF programs
   - Programs collect/filter data
   - Data written to maps or ring buffers

3. **Reading Phase**
   - User app polls maps/buffers
   - Processes collected events
   - Outputs results (logs, metrics, etc.)

## Key Interfaces

### Maps
Key-value storage accessible from both kernel and user space.

### Ring Buffer / Perf Buffer
Efficient data transfer from kernel to userspace.

### Hooks
- **Tracepoints**: Stable kernel tracing points
- **Kprobes**: Dynamic function tracing
- **Uprobes**: User-space function tracing
