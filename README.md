# Unreal Engine Linux kernel tools.
Contains eBPF probes to instrument internals of Linux kernel.
Contact dmytro.ivanov@epicgames.com for questions.

## Requirements:
Linux kernel >= 5.8
libbpf >= 0.8

## Building:
cmake -B build/debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug

cmake -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release

## Cross-compiling for ARM64:
Install an aarch64 cross-compiler and build libbpf from source targeting aarch64. Then configure
with the toolchain file, pointing PKG_CONFIG_LIBDIR at your libbpf install:

export PKG_CONFIG_LIBDIR=/path/to/libbpf/lib64/pkgconfig:/usr/lib/aarch64-linux-gnu/pkgconfig
cmake -B build/release-arm64 -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=ToolchainArm64.cmake
cmake --build build/release-arm64

## Usage:
Must be run as root. Specify the parent process name to monitor:

sudo ./LinuxUEKernelTools -ParentProcessName <name> [-SocketBasePath <path>]

-ParentProcessName: name of the process to monitor (and its children)
-SocketBasePath:    base path for Unix domain sockets (default: /tmp/LinuxUEKernelTools)