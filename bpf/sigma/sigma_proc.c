#include "sigma.h"

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sigma_clone, struct task_struct *parent,
             struct task_struct *child) {
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

  // Safely read mm struct off the child
  struct mm_struct *mm = BPF_CORE_READ(child, mm);
  if (!mm) {
    return 0;
  }

  // 1. Extract Executable File Name (Kernel space read)
  struct file *exe_file = BPF_CORE_READ(mm, exe_file);
  if (exe_file) {
    const unsigned char *name_ptr =
        BPF_CORE_READ(exe_file, f_path.dentry, d_name.name);
    if (name_ptr) {
      // Read binary name directly into event.data buffer
      bpf_probe_read_kernel_str(event.data, sizeof(event.data), name_ptr);
    }
  }

  // 2. Extract Command Line Arguments (User space read)
  unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
  unsigned long arg_end = BPF_CORE_READ(mm, arg_end);

  if (arg_start && arg_end > arg_start) {
    char cmdline[128];
    // Must use user_str helper since arg_start points to user virtual memory
    bpf_probe_read_user_str(event.data, sizeof(cmdline), (void *)arg_start);

    bpf_probe_read_kernel_str(event.hooked, sizeof(event.hooked), "fork");

    event.ContainerID = cgid;
    event.SourcePID = pid;
    struct proc_key key = {
        .pid = pid,
        .start_time = start_time,
    };
    bpf_map_update_elem(&octagon_force_sigma_event_map_pin, &key, &event,
                        BPF_ANY);
  }

  return 0;
}
