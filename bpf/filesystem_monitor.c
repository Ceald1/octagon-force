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

struct file_system_enforcer_map {
  char FileAccessed[256];
  pid_t SourcePID;
  __u64 ContainerID;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, pid_t);
  __type(value, struct file_system_enforcer_map);
  __uint(max_entries, 32);
} file_system_enforcer_map_pin SEC(".maps");

SEC("fmod_ret/__x64_sys_openat")
int BPF_PROG(file_system_enforcer, const struct pt_regs *regs) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  char comm[TASK_COMM_LEN];

  // 1. Get the current task structure safely
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // 2. Safely chain dereference task->real_parent->pid using CO-RE macros
  pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);

  bpf_get_current_comm(&comm, sizeof(comm));
  __u64 cgid = bpf_get_current_cgroup_id();
  struct file_system_enforcer_map event;
  const char *user_filename = (const char *)regs->si;

  if (bpf_probe_read_user_str(event.FileAccessed, sizeof(event.FileAccessed),
                              user_filename) < 0)
    return 0;

  event.ContainerID = cgid;
  event.SourcePID = parent_pid;
  bpf_map_update_elem(&file_system_enforcer_map_pin, &parent_pid, &event,
                      BPF_ANY);

  return 0;
}
