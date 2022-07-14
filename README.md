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
The eBPF code is executed when an event in the kernel happens (kprobe, uprobe, e.g. new process is cloned)

The userspace application can share data with eBPF code via eBPF maps.

## Linux utilities

```bash
readelf --section-details --headers .output/opensnoop.bpf.o
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           Linux BPF
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          11304 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         20
  Section header string table index: 19

Section Headers:
  [Nr] Name
       Type              Address          Offset            Link
       Size              EntSize          Info              Align
       Flags
  [ 0] 
       NULL             0000000000000000  0000000000000000  0
       0000000000000000 0000000000000000  0                 0
       [0000000000000000]: 
  [ 1] .text
       PROGBITS         0000000000000000  0000000000000040  0
       0000000000000000 0000000000000000  0                 4
       [0000000000000006]: ALLOC, EXEC
  [ 2] tracepoint/syscalls/sys_enter_open
       PROGBITS         0000000000000000  0000000000000040  0
       0000000000000178 0000000000000000  0                 8
       [0000000000000006]: ALLOC, EXEC
  [ 3] tracepoint/syscalls/sys_enter_openat
       PROGBITS         0000000000000000  00000000000001b8  0
       0000000000000178 0000000000000000  0                 8
       [0000000000000006]: ALLOC, EXEC
  [ 4] tracepoint/syscalls/sys_exit_open
       PROGBITS         0000000000000000  0000000000000330  0
       00000000000002d0 0000000000000000  0                 8
       [0000000000000006]: ALLOC, EXEC
  [ 5] tracepoint/syscalls/sys_exit_openat
       PROGBITS         0000000000000000  0000000000000600  0
       00000000000002d0 0000000000000000  0                 8
       [0000000000000006]: ALLOC, EXEC
  [ 6] .rodata
       PROGBITS         0000000000000000  00000000000008d0  0
       000000000000000d 0000000000000000  0                 4
       [0000000000000002]: ALLOC
  [ 7] .maps
       PROGBITS         0000000000000000  00000000000008e0  0
       0000000000000038 0000000000000000  0                 8
       [0000000000000003]: WRITE, ALLOC
  [ 8] license
       PROGBITS         0000000000000000  0000000000000918  0
       0000000000000004 0000000000000000  0                 1
       [0000000000000003]: WRITE, ALLOC
  [ 9] .BTF
       PROGBITS         0000000000000000  000000000000091c  0
       0000000000000d2b 0000000000000000  0                 1
       [0000000000000000]: 
  [10] .BTF.ext
       PROGBITS         0000000000000000  0000000000001647  0
       00000000000007ec 0000000000000000  0                 1
       [0000000000000000]: 
  [11] .symtab
       SYMTAB           0000000000000000  0000000000001e38  19
       00000000000002d0 0000000000000018  19                8
       [0000000000000000]: 
  [12] .reltracepoint/syscalls/sys_enter_open
       REL              0000000000000000  0000000000002108  11
       0000000000000040 0000000000000010  2                 8
       [0000000000000000]: 
  [13] .reltracepoint/syscalls/sys_enter_openat
       REL              0000000000000000  0000000000002148  11
       0000000000000040 0000000000000010  3                 8
       [0000000000000000]: 
  [14] .reltracepoint/syscalls/sys_exit_open
       REL              0000000000000000  0000000000002188  11
       0000000000000040 0000000000000010  4                 8
       [0000000000000000]: 
  [15] .reltracepoint/syscalls/sys_exit_openat
       REL              0000000000000000  00000000000021c8  11
       0000000000000040 0000000000000010  5                 8
       [0000000000000000]: 
  [16] .rel.BTF
       REL              0000000000000000  0000000000002208  11
       0000000000000070 0000000000000010  9                 8
       [0000000000000000]: 
  [17] .rel.BTF.ext
       REL              0000000000000000  0000000000002278  11
       0000000000000780 0000000000000010  10                8
       [0000000000000000]: 
  [18] .llvm_addrsig
       LOOS+0xfff4c03   0000000000000000  00000000000029f8  0
       000000000000000b 0000000000000000  0                 1
       [0000000080000000]: EXCLUDE
  [19] .strtab
       STRTAB           0000000000000000  0000000000002a03  0
       0000000000000224 0000000000000000  0                 1
       [0000000000000000]: 
```

* Machine is "Linux BPF"

### List running eBPF programs

```bash
sudo bpftool prog list
174: tracepoint  name tracepoint__sys  tag 9f196d70d0c1964b  gpl
        loaded_at 2022-07-14T13:21:29+0000  uid 0
        xlated 248B  jited 140B  memlock 4096B  map_ids 11,8
        btf_id 40
176: tracepoint  name tracepoint__sys  tag 47b06acd3f9a5527  gpl
        loaded_at 2022-07-14T13:21:29+0000  uid 0
        xlated 248B  jited 140B  memlock 4096B  map_ids 11,8
        btf_id 40
177: tracepoint  name tracepoint__sys  tag 387291c2fb839ac6  gpl
        loaded_at 2022-07-14T13:21:29+0000  uid 0
        xlated 696B  jited 475B  memlock 4096B  map_ids 8,11,9
        btf_id 40
178: tracepoint  name tracepoint__sys  tag 387291c2fb839ac6  gpl
        loaded_at 2022-07-14T13:21:29+0000  uid 0
        xlated 696B  jited 475B  memlock 4096B  map_ids 8,11,9
        btf_id 40
194: cgroup_device  tag c8b47a902f1cc68b  gpl
        loaded_at 2022-07-14T13:21:31+0000  uid 0
        xlated 464B  jited 288B  memlock 4096B
```

### List created eBPF maps

```bash
sudo bpftool map list
8: hash  name start  flags 0x0
        key 4B  value 16B  max_entries 10240  memlock 245760B
        btf_id 40
9: perf_event_array  name events  flags 0x0
        key 4B  value 4B  max_entries 1  memlock 4096B
11: array  name opensnoo.rodata  flags 0x480
        key 4B  value 13B  max_entries 1  memlock 4096B
        btf_id 40  frozen
```

### Show source code of running eBPF program

```bash
bpftool prog dump xlated id 174 linum
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter * ctx):
; int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx) [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:50 line_col:0]
   0: (bf) r6 = r1
; u64 id = bpf_get_current_pid_tgid(); [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:52 line_col:11]
   1: (85) call bpf_get_current_pid_tgid#139360
; u32 pid = id; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:55 line_col:6]
   2: (63) *(u32 *)(r10 -4) = r0
; if (targ_tgid && targ_tgid != tgid) [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:36 line_col:6]
   3: (18) r1 = map[id:11][0]+4
   5: (61) r2 = *(u32 *)(r1 +0)
; if (targ_pid && targ_pid != pid) [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:38 line_col:6]
   6: (18) r1 = map[id:11][0]+0
   8: (61) r2 = *(u32 *)(r1 +0)
; if (valid_uid(targ_uid)) { [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:40 line_col:16]
   9: (18) r7 = map[id:11][0]+8
  11: (61) r1 = *(u32 *)(r7 +0)
  12: (18) r2 = 0xffffffff
; if (targ_uid != uid) { [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:42 line_col:7]
  14: (b7) r1 = 0
; struct args_t args = {}; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:59 line_col:17]
  15: (7b) *(u64 *)(r10 -16) = r1
  16: (7b) *(u64 *)(r10 -24) = r1
; args.fname = (const char *)ctx->args[0]; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:60 line_col:30]
  17: (79) r1 = *(u64 *)(r6 +16)
; args.fname = (const char *)ctx->args[0]; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:60 line_col:14]
  18: (7b) *(u64 *)(r10 -24) = r1
; args.flags = (int)ctx->args[1]; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:61 line_col:21]
  19: (79) r1 = *(u64 *)(r6 +24)
; args.flags = (int)ctx->args[1]; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:61 line_col:14]
  20: (63) *(u32 *)(r10 -16) = r1
  21: (bf) r2 = r10
; struct args_t args = {}; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:59 line_col:17]
  22: (07) r2 += -4
  23: (bf) r3 = r10
  24: (07) r3 += -24
; bpf_map_update_elem(&start, &pid, &args, 0); [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:62 line_col:3]
  25: (18) r1 = map[id:8]
  27: (b7) r4 = 0
  28: (85) call htab_map_update_elem#158512
; return 0; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:64 line_col:2]
  29: (b7) r0 = 0
  30: (95) exit
```


## References
