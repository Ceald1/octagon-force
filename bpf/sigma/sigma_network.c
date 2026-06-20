#include "sigma.h"

SEC("kprobe/__sys_sendto")
int BPF_KPROBE(sigma_tc, int fd, const char *buf, size_t len) {

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
  bpf_probe_read_kernel_str(event.hooked, sizeof(event.hooked), "network");
  event.ContainerID = cgid;
  event.SourcePID = parent_pid;
  struct proc_key key = {
      .pid = pid,
      .start_time = start_time,
  };

  bpf_probe_read_kernel_str(event.data, sizeof(event.data), buf);

  bpf_map_update_elem(&octagon_force_sigma_event_map_pin, &key, &event,
                      BPF_ANY);
#ifdef DEBUG_YES
  bpf_printk("called send to");
#endif
  return 0;
}
