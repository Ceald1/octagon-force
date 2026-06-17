#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#if defined(bpf_strstr)
#else
extern int bpf_strstr(const char *str, const char *substr) __ksym;
#endif

#ifdef DEBUG
#define DEBUG_YES = 1
#endif

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct file_system_enforcer_map {
  char FileAccessed[32];
  pid_t SourcePID;
  __u64 ContainerID;
  bool action;
  char RuleName[32];
};

struct proc_key {
  __u32 pid;
  __u64 start_time;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct proc_key);
  __type(value, struct file_system_enforcer_map);
  __uint(max_entries, 1048576);
} octagon_force_filesystem_monitor_enforcer_map_pin SEC(".maps");

struct file_system_enforcer_rules {
  char Name[32]; // all good rules need names!
  // filename
  char FileName[32];
  // action, boolean for either deny or alert
  bool action;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, struct file_system_enforcer_rules);
  __uint(max_entries, 100);
} octagon_force_filesystem_monitor_enforcer_rules_pin SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(file_system_enforcer, struct file *file) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
  struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
  __u32 pid_ns_level = BPF_CORE_READ(pid_ns, level);

  if (pid_ns_level == 0)
    return 0;

  u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  u64 start_time = bpf_ktime_get_ns();
  pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);
  __u64 cgid = bpf_get_current_cgroup_id();

  struct file_system_enforcer_map event = {};

  int ret =
      bpf_d_path(&file->f_path, event.FileAccessed, sizeof(event.FileAccessed));
  if (ret < 0)
    return 0;

  // early exit if no rules loaded
  u32 zero = 0;
  struct file_system_enforcer_rules *first = bpf_map_lookup_elem(
      &octagon_force_filesystem_monitor_enforcer_rules_pin, &zero);
  if (!first || first->FileName[0] == '\0') {
#ifdef DEBUG_YES
    bpf_printk("no rules loaded!\n");
#endif
    return 0;
  }

  for (int i = 0; i < 100; i++) {
    struct file_system_enforcer_rules *rule = bpf_map_lookup_elem(
        &octagon_force_filesystem_monitor_enforcer_rules_pin, &i);
    if (!rule)
      continue;

    if (rule->FileName[0] == '\0')
      continue;

    int result = bpf_strstr(event.FileAccessed, rule->FileName);
#ifdef DEBUG_YES
    bpf_printk("checking: %s against %s = %d\n", event.FileAccessed,
               rule->FileName, result);
#endif

    if (result < 0)
      continue;

    __builtin_memset(&event, 0, sizeof(event));

    bpf_probe_read_kernel_str(event.FileAccessed, sizeof(event.FileAccessed),
                              rule->FileName);

    bpf_probe_read_kernel_str(event.RuleName, sizeof(event.RuleName),
                              rule->Name);
    event.ContainerID = cgid;
    event.SourcePID = parent_pid;
    event.action = rule->action;

    struct proc_key key = {
        .pid = pid,
        .start_time = start_time,
    };

    bpf_map_update_elem(&octagon_force_filesystem_monitor_enforcer_map_pin,
                        &key, &event, BPF_ANY);

    if (!rule->action) {
#ifdef DEBUG_YES
      bpf_printk(
          "denied access to: %s from %d on container: %llu\n with rule: %s \n",
          event.FileAccessed, event.SourcePID, event.ContainerID,
          event.RuleName);
#endif
      return -EACCES;
    }

    return 0;
  }

  return 0;
}
