# Unreal Engine Linux kernel tools.
Contains eBPF probes to instrument internals of Linux kernel.
Contact dmytro.ivanov@epicgames.com for questions.

## Requirements:
Linux kernel >= 5.8
libbpf >= 0.8

## Environment setup:
cmake -B build/debug -DCMAKE_BUILD_TYPE=Debug

cmake -B build/release -DCMAKE_BUILD_TYPE=Release

cmake --build build/debug

cmake --build build/release