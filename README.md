# eBPF Learning

Welcome to my repository for learning eBPF!
This project contains my personal notes and code samples to learn eBPF.
Feel free to collaborate by opening an issue or creating a pull request!

## Notes

eBPF technology allows to run arbitrary code in the linux kernel. 
It is a powerful technology that allows extending kernel functionality or solve cross-cutting 
use-cases like monitoring and security.

eBPF is a program written in restricted C (compiled with clang) into eBPF bytecode.
eBPF code/bytecode is verified to make sure it does not crash/block kernel.
The eBPF bytecode is loaded from the user space into the kernel via `bpf` system call.

The userspace application can share data with eBPF code via eBPF maps.

## References
