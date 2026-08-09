# ITL.Amalia.Poc.eBpf Project Instructions

## Project Overview

**Type:** eBPF Proof of Concept  
**Language:** C/C++  
**Structure:** Monorepo (kernel + userspace)  

## Directory Layout

- **kernel/** - eBPF kernel programs
  - programs/ - Individual eBPF program implementations
  - headers/ - Shared kernel headers and defines
  
- **userspace/** - User-space applications
  - src/ - Main application code
  - include/ - Header files
  - tools/ - Utility programs for testing/debugging

- **docs/** - Project documentation
- **build/** - Build outputs and artifacts
- **.github/** - GitHub workflows and CI/CD

## Key Files

- `CMakeLists.txt` - Primary build configuration
- `Makefile` - Alternative build system for quick builds
- `.gitignore` - Git exclusion rules

## Development Guidelines

### Code Style
- C code should follow Linux kernel coding standards
- Use 8-space tabs (or 4-space indents if preferred)
- Comment complex logic and algorithm decisions

### Building
```bash
cmake -B build && cmake --build build
# or
make build
```

### Testing
- Add tests to the userspace/tests directory
- Use assertions for kernel program validation
- Test on multiple kernel versions when possible

### Commits
- Use clear, descriptive commit messages
- Reference issues when applicable
- Keep commits focused and atomic

## Dependencies

- libbpf (user-space library for eBPF)
- LLVM/Clang (for eBPF compilation)
- Linux kernel headers
- CMake 3.12+

## Status & TODOs

- [ ] Initial skeleton created
- [ ] Add first kernel program example
- [ ] Add user-space loader example
- [ ] CI/CD workflows
- [ ] Documentation structure
