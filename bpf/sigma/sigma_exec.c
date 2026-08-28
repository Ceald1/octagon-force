#include "sigma.h"

SEC("lsm/bprm_check_security")
int BPF_PROG(sigma_sched_process_exec, struct linux_binprm *bprm) {

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
  struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
  __u32 pid_ns_level = BPF_CORE_READ(pid_ns, level);

  if (pid_ns_level == 0) {
    return 0;
  } // ignore if not in container

  u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  u64 start_time = BPF_CORE_READ(task, start_time);
  struct pid *thread_pid = BPF_CORE_READ(task, group_leader, thread_pid);
  unsigned int level = BPF_CORE_READ(thread_pid, level);

  pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);

  u32 host_pid = BPF_CORE_READ(thread_pid, numbers[0].nr);

  // 3. Extract Container NS PID (the PID seen inside the container)
  u32 container_pid = BPF_CORE_READ(thread_pid, numbers[level].nr);
  __u64 cgid = bpf_get_current_cgroup_id();

  struct sigma_event event;
  __builtin_memset(event.data, 0, sizeof(event.data));
  const char *filename = bprm->filename;
  bpf_probe_read_kernel_str(event.data, 128, filename);

  bpf_probe_read_kernel_str(event.hooked, sizeof(event.hooked),
                            "check_security");
  //  void *arg_start = (void *)BPF_CORE_READ(bprm, mm, arg_start);
  //  void *arg_end = (void *)BPF_CORE_READ(bprm, mm, arg_end);
  //  unsigned long arg_length = arg_end - arg_start;
  //  if (arg_length > 0) {
  //    arg_length = arg_length < 128 ? arg_length : 128;
  //    bpf_probe_read_kernel(event.data + 128, arg_length, arg_start);
  //  }
  event.ContainerID = cgid;
  event.SourcePID = container_pid;
  struct proc_key key = {
      .pid = pid,
      .start_time = start_time,
  };
  bpf_map_update_elem(&octagon_force_sigma_event_map_pin, &key, &event,
                      BPF_ANY);
#ifdef DEBUG_YES
  bpf_printk("%s\n", event.data);
#endif
  return 0;
}
