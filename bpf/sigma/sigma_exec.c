#include "sigma.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int BPF_PROG(sigma_sched_process_exec, struct trace_event_raw_sys_enter *ctx1) {

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
  struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
  __u32 pid_ns_level = BPF_CORE_READ(pid_ns, level);

  if (pid_ns_level == 0) {
    return 0;
  } // ignore if not in container

  u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  u64 start_time = BPF_CORE_READ(task, start_time);
  pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);
  __u64 cgid = bpf_get_current_cgroup_id();

  struct sigma_event event;
  __builtin_memset(event.data, 0, sizeof(event.data));
  const char *filename = (const char *)ctx1->args[0];
  bpf_probe_read_user_str(event.data, 128, filename);

  bpf_probe_read_kernel_str(event.hooked, sizeof(event.hooked),
                            "sys_enter_execve");

  event.ContainerID = cgid;
  event.SourcePID = pid;
  struct proc_key key = {
      .pid = pid,
      .start_time = start_time,
  };
  bpf_probe_read_kernel_str(event.hooked, sizeof(event.hooked),
                            "sys_enter_execve");
  bpf_map_update_elem(&octagon_force_sigma_event_map_pin, &key, &event,
                      BPF_ANY);
#ifdef DEBUG_YES
  bpf_printk("%s\n", event.data);
#endif
  return 0;
}
