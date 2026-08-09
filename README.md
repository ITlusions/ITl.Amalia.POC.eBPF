# ITL.Amalia.Poc.eBpf

Proof of Concept for eBPF applications - Amalia project at ITL

## Overview

This is a C/C++ eBPF monorepo containing kernel-space eBPF programs and corresponding user-space applications for system monitoring, networking, or performance analysis.

## Project Structure

```
ITL.Amalia.Poc.eBpf/
├── kernel/          # eBPF kernel programs
│   ├── programs/    # Individual eBPF programs
│   └── headers/     # Shared kernel headers
├── userspace/       # User-space applications
│   ├── src/         # Application source code
│   ├── include/     # Application headers
│   └── tools/       # Utility tools
├── docs/            # Documentation
├── build/           # Build output and artifacts
├── .github/         # GitHub workflows and templates
├── CMakeLists.txt   # Build configuration
├── Makefile         # Alternative build system
└── .gitignore       # Git ignore rules
```

## Building

### Prerequisites

- Linux kernel with eBPF support (5.8+)
- clang/LLVM (for compiling eBPF)
- libbpf library
- cmake or make
- Standard C development tools

### Build Instructions

```bash
# Using CMake
mkdir -p build
cd build
cmake ..
make

# Or using Make directly
make -f Makefile
```

## Project Status

- [ ] Initial kernel program templates
- [ ] User-space harness
- [ ] Build system setup
- [ ] Documentation

## Contributing

Follow the project coding standards and include tests for new features.

## License

[To be determined]

## Contact

ITL Amalia Project Team
