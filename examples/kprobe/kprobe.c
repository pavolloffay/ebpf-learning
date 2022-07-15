// +build ignore

#include "common.h"

// fixes cannot call GPL-restricted function from non-GPL compatible program
char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/sys_execve")
int hellow_world(void *ctx) {
  const char fmt_str[] = "Hello, world, from BPF! My PID is\n";
  // read the output via
  // sudo cat /sys/kernel/debug/tracing/trace_pipe
  bpf_trace_printk(fmt_str, sizeof(fmt_str));
  return 0;
}
