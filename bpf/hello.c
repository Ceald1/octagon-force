/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_core_read.h> // <-- CRUCIAL: Required for BPF_CORE_READ macro
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fmod_ret/__x64_sys_openat")
int BPF_PROG(modify_openat, const struct pt_regs *regs) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  char comm[TASK_COMM_LEN];

  // 1. Get the current task structure safely
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // 2. Safely chain dereference task->real_parent->pid using CO-RE macros
  pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);

  bpf_get_current_comm(&comm, sizeof(comm));
  bpf_printk("magic performed! Parent PID: %d\n", parent_pid);

  return 0;
}
