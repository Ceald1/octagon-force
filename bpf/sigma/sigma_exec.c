#include "sigma.h"

SEC("tracepoint/sched/sched_process_exec")
int sigma_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // Filter host processes (PID NS level 0)
  struct pid *thread_pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(thread_pid, level);

  if (level == 0) {
    return 0;
  }

  u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  u64 start_time = BPF_CORE_READ(task, start_time);
  pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);
  __u64 cgid = bpf_get_current_cgroup_id();

  struct sigma_event event = {};

  // Extract filename using kernel dynamic array offset bitmask
  // __data_loc_filename contains: (length << 16) | offset
  unsigned int filename_offset = ctx->__data_loc_filename & 0xFFFF;
  const char *filename_ptr = (const char *)ctx + filename_offset;

  // Read filename from kernel space
  long ret =
      bpf_probe_read_kernel_str(event.data, sizeof(event.data), filename_ptr);
  if (ret < 0) {
    bpf_printk("[SIGMA ERR] Failed to read filename: %ld", ret);
    return 0;
  }

  bpf_probe_read_kernel_str(event.hooked, sizeof(event.hooked),
                            "sched_process_exec");

  event.ContainerID = cgid;
  event.SourcePID = parent_pid;

  struct proc_key key = {
      .pid = pid,
      .start_time = start_time,
  };

  bpf_map_update_elem(&octagon_force_sigma_event_map_pin, &key, &event,
                      BPF_ANY);

  return 0;
}

// SEC("tracepoint/syscalls/sys_enter_execve")
// int sigma_sched_process_exec(struct bpf_raw_tracepoint_args *ctx1) {
//
//   struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//
//   struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
//   struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
//   __u32 pid_ns_level = BPF_CORE_READ(pid_ns, level);
//
//   if (pid_ns_level == 0) {
//     return 0;
//   } // ignore if not in container
//
//   u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
//   u64 start_time = BPF_CORE_READ(task, start_time);
//   pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);
//   __u64 cgid = bpf_get_current_cgroup_id();
//
//   struct sigma_event event;
//   __builtin_memset(event.data, 0, sizeof(event.data));
//
//   const char *filename = (const char *)ctx1->args[0];
//   bpf_probe_read_user_str(event.data, 128, filename);
//
//   bpf_probe_read_kernel_str(event.hooked, sizeof(event.hooked),
//                             "sys_enter_execve");
//
//   event.ContainerID = cgid;
//   event.SourcePID = parent_pid;
//   struct proc_key key = {
//       .pid = pid,
//       .start_time = start_time,
//   };
//   bpf_probe_read_kernel_str(event.hooked, sizeof(event.hooked),
//                             "sys_enter_execve");
//   bpf_map_update_elem(&octagon_force_sigma_event_map_pin, &key, &event,
//                       BPF_ANY);
//   // #ifdef DEBUG_YES
//   bpf_printk("%s\n", event.data);
//   // #endif
//   return 0;
// }
