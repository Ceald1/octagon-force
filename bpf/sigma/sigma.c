#define BPF_NO_GLOBAL_DATA
#include "sigma.h"

SEC("tp/syscalls/sys_enter_write")
int sigma_enter_write(struct trace_event_raw_sys_enter *ctx) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
  struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
  __u32 pid_ns_level = BPF_CORE_READ(pid_ns, level);

  if (pid_ns_level == 0) {
    return 0;
  } // ignore if not in container

  u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  u64 start_time = bpf_ktime_get_ns();
  pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);
  __u64 cgid = bpf_get_current_cgroup_id(); // container ID
  struct sigma_event event;

  char *user_buf = (char *)ctx->args[1];
  size_t count = ctx->args[2];

  if (count > sizeof(event.data))
    count = sizeof(event.data);

  bpf_probe_read_user(event.data, count, user_buf);
  event.ContainerID = cgid;
  event.SourcePID = parent_pid;
  struct proc_key key = {
      .pid = pid,
      .start_time = start_time,
  };
  bpf_map_update_elem(&octagon_force_sigma_event_map_pin, &key, &event,
                      BPF_ANY);

  return 0;
};
