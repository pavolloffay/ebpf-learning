// +build ignore

#include "common.h"

// fixes cannot call GPL-restricted function from non-GPL compatible program
char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
  .type        = BPF_MAP_TYPE_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u64),
  .max_entries = 1,
};


SEC("kprobe/sys_execve")
int hellow_world(void *ctx) {
  const u32 key     = 0;
  u64 initval = 1, *valp;

  valp = bpf_map_lookup_elem(&kprobe_map, &key);
  if (!valp) {
    bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
    return 0;
  }
  __sync_fetch_and_add(valp, 1);

  u64 uid;
  uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  const char fmt_str[] = "Hello, world, from BPF! My PID is %d\n";
  // read the output via
  // sudo cat /sys/kernel/debug/tracing/trace_pipe
  bpf_trace_printk(fmt_str, sizeof(fmt_str), uid);

  return 0;
}
