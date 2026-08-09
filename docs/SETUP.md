# Development Setup

## Prerequisites

### System Requirements
- Linux kernel 5.8 or later (with eBPF support)
- Root access (for loading eBPF programs)
- 2GB+ available disk space

### Required Tools

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    libz-dev \
    pkg-config \
    cmake \
    build-essential \
    git
```

#### RHEL/CentOS/Fedora
```bash
sudo dnf install -y \
    clang \
    llvm-devel \
    elfutils-libelf-devel \
    zlib-devel \
    pkg-config \
    cmake \
    gcc \
    git
```

### Build Dependencies

#### libbpf
```bash
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
make install
```

#### Kernel Headers
```bash
sudo apt-get install -y linux-headers-$(uname -r)
```

## Building the Project

### Using CMake (Recommended)
```bash
mkdir -p build
cd build
cmake ..
make
```

### Using Make
```bash
make build
```

## Running

After building, run with elevated privileges:
```bash
sudo ./build/app
```

## Verification

Check eBPF program status:
```bash
sudo bpftool prog list
sudo bpftool map list
```

## Troubleshooting

### "Cannot open object file: No such file or directory"
- Ensure eBPF programs are compiled
- Check file paths in loader

### "Permission denied" when loading programs
- Run with sudo
- Check your user's capabilities

### Missing kernel headers
- Install linux-headers package
- Verify `/usr/include/linux/` exists
