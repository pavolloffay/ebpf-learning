## Kprobe example

## Build 

```bash
go generate ./...
go build -o kprobe ./kprobe
sudo ./kprobe
```

```bash
go run -exec  sudo ./kprobe
```

The output is in `/sys/kernel/debug/tracing/trace_pipe`


## Strace - system calls

```bash
sudo strace -e bpf ./kprobe/kprobe                                                                                                                                                      ploffay@fedora
--- SIGURG {si_signo=SIGURG, si_code=SI_TKILL, si_pid=182361, si_uid=0} ---
--- SIGURG {si_signo=SIGURG, si_code=SI_TKILL, si_pid=182361, si_uid=0} ---
--- SIGURG {si_signo=SIGURG, si_code=SI_TKILL, si_pid=182361, si_uid=0} ---
bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_ARRAY, key_size=4, value_size=4, max_entries=1, map_flags=0, inner_map_fd=0, map_name="", map_ifindex=0, btf_fd=0, btf_key_type_id=0, btf_value_type_id=0, btf_vmlinux_value_type_id=0, map_extra=0}, 72) = 3
bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_ARRAY, key_size=4, value_size=4, max_entries=1, map_flags=0, inner_map_fd=0, map_name="feature_test", map_ifindex=0, btf_fd=0, btf_key_type_id=0, btf_value_type_id=0, btf_vmlinux_value_type_id=0, map_extra=0}, 72) = 3
bpf(BPF_BTF_LOAD, {btf="\237\353\1\0\30\0\0\0\0\0\0\0\34\0\0\0\34\0\0\0\3\0\0\0\0\0\0\0\0\0\0\2"..., btf_log_buf=NULL, btf_size=55, btf_log_size=0, btf_log_level=0}, 32) = 3
bpf(BPF_BTF_LOAD, {btf="\237\353\1\0\30\0\0\0\0\0\0\0\30\0\0\0\30\0\0\0\3\0\0\0\0\0\0\0\0\0\0\r"..., btf_log_buf=NULL, btf_size=51, btf_log_size=0, btf_log_level=0}, 32) = 3
bpf(BPF_BTF_LOAD, {btf="\237\353\1\0\30\0\0\0\0\0\0\0\234\0\0\0\234\0\0\0\370\0\0\0\0\0\0\0\0\0\0\2"..., btf_log_buf=NULL, btf_size=428, btf_log_size=0, btf_log_level=0}, 32) = 3
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_KPROBE, insn_cnt=6, insns=0xc0000d6120, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(0, 0, 0), prog_flags=0, prog_name="", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=0, func_info_rec_size=0, func_info=NULL, func_info_cnt=0, line_info_rec_size=0, line_info=NULL, line_info_cnt=0, attach_btf_id=0, attach_prog_fd=0, fd_array=NULL}, 144) = 7
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_KPROBE, insn_cnt=22, insns=0xc000100000, license="Dual MIT/GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(5, 17, 12), prog_flags=0, prog_name="hellow_world", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=3, func_info_rec_size=8, func_info=0xc0000d9940, func_info_cnt=1, line_info_rec_size=16, line_info=0xc0000f6090, line_info_cnt=5, attach_btf_id=0, attach_prog_fd=0, fd_array=NULL}, 144) = 7
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_KPROBE, insn_cnt=2, insns=0xc00018e010, license="MIT", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(5, 17, 12), prog_flags=0, prog_name="probe_bpf_perf_", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=0, func_info_rec_size=0, func_info=NULL, func_info_cnt=0, line_info_rec_size=0, line_info=NULL, line_info_cnt=0, attach_btf_id=0, attach_prog_fd=0, fd_array=NULL}, 144) = 8
bpf(BPF_LINK_CREATE, {link_create={prog_fd=8, target_fd=0, attach_type=BPF_PERF_EVENT, flags=0}}, 32) = -1 EBADF (Bad file descriptor)
bpf(BPF_LINK_CREATE, {link_create={prog_fd=7, target_fd=3, attach_type=BPF_PERF_EVENT, flags=0}}, 32) = 8
2022/07/15 12:10:34 Waiting for events..
^Cstrace: Process 182361 detached
```
