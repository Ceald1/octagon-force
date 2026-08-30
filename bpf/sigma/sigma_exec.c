#include "sigma.h"

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sigma_event);
} scratchpad_map SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int sigma_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // Filter host processes (PID NS level 0)
  struct pid *thread_pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(thread_pid, level);

  if (level == 0) {
    return 0;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 user_pid = (u32)(pid_tgid >> 32);

  // 3. Fetch True Parent PID
  // Use group_leader->real_parent to handle multi-threaded exec transitions
  // safely
  struct task_struct *leader = BPF_CORE_READ(task, group_leader);
  struct task_struct *parent_task = BPF_CORE_READ(leader, real_parent);
  u32 parent_pid = BPF_CORE_READ(parent_task, tgid);

  u64 start_time = BPF_CORE_READ(task, start_time);
  // u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  // u64 start_time = BPF_CORE_READ(task, start_time);
  // pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);
  __u64 cgid = bpf_get_current_cgroup_id();

  struct sigma_event event = {};

  // Extract filename using kernel dynamic array offset bitmask
  // __data_loc_filename contains: (length << 16) | offset
  unsigned int filename_offset = ctx->__data_loc_filename & 0xFFFF;
  const char *filename_ptr = (const char *)ctx + filename_offset;

  // Read filename from kernel space
  // long ret =
  //    bpf_probe_read_kernel_str(event.data, sizeof(event.data), filename_ptr);
  // if (ret < 0) {
  //  bpf_printk("[SIGMA ERR] Failed to read filename: %ld", ret);
  //  return 0;
  //}
  struct mm_struct *mm = BPF_CORE_READ(task, mm);
  if (!mm) {
    return 0;
  }

  unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
  unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
  unsigned long len = arg_end - arg_start;

  if (len == 0) {
    return 0;
  }
  if (len >= MAX_CMDLINE_LEN) {
    len = MAX_CMDLINE_LEN - 1;
  }

  // 2. Read raw string memory block (arguments separated by \0)
  long ret = bpf_probe_read_user(event.data, len, (void *)arg_start);
  if (ret < 0) {
    // Fallback: Read binary name from tracepoint if reading mm memory fails
    unsigned int filename_offset = ctx->__data_loc_filename & 0xFFFF;
    const char *filename_ptr = (const char *)ctx + filename_offset;
    bpf_probe_read_kernel_str(event.data, sizeof(event.data), filename_ptr);
  } else {
// 3. Replace intermediate null terminators with spaces
#pragma unroll
    for (int i = 0; i < MAX_CMDLINE_LEN - 1; i++) {
      if ((unsigned long)i >= len) {
        break;
      }
      if (event.data[i] == '\0' && (unsigned long)(i + 1) < len) {
        event.data[i] = ' ';
      }
    }
  }

  bpf_probe_read_kernel_str(event.hooked, sizeof(event.hooked), "execve");

  event.ContainerID = cgid;
  event.SourcePID = parent_pid;

  struct proc_key key = {
      .pid = user_pid,
      .start_time = start_time,
  };

  bpf_map_update_elem(&octagon_force_sigma_event_map_pin, &key, &event,
                      BPF_ANY);

  return 0;
}
