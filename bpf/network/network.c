#include "network.h"

#define AF_INET 2
#define AF_INET6 10

// 1. Define a CPU-isolated scratchpad to offload your massive buffers from the
// stack
struct scratchpad_t {
  char Host[256];
  struct sockaddr_in addr4;
  struct sockaddr_in6 addr6;
  struct network_event event;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct scratchpad_t);
} octagon_scratchpad SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(octagon_network_rules, struct socket *sock,
             struct sockaddr *address,
             int addrlen) { // FIXED: Removed illegal trailing 'int ret'

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
  struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);

  if (!pid_ns)
    return 0;
  __u32 pid_ns_level = BPF_CORE_READ(pid_ns, level);

  if (pid_ns_level == 0) {
    return 0; // ignore if not in container
  }

  // 2. Fetch your 0-stack scratchpad reference from the map
  __u32 zero = 0;
  struct scratchpad_t *scratch =
      bpf_map_lookup_elem(&octagon_scratchpad, &zero);
  if (!scratch)
    return 0; // Guard clause required by the BPF verifier

  // Completely wipe the buffers clean before each execution
  __builtin_memset(scratch->Host, 0, sizeof(scratch->Host));

  unsigned short family = 0;
  bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

  if (family == AF_INET) {
    // Copy safely into our scratchpad allocation
    if (bpf_probe_read_kernel(&scratch->addr4, sizeof(scratch->addr4),
                              address) == 0) {
      __u64 ip_args[1] = {(__u64)&scratch->addr4.sin_addr.s_addr};
      bpf_snprintf(scratch->Host, sizeof(scratch->Host), "%pI4", ip_args,
                   sizeof(ip_args));
    }
  } else if (family == AF_INET6) {
    if (bpf_probe_read_kernel(&scratch->addr6, sizeof(scratch->addr6),
                              address) == 0) {
      __u64 ip_args[1] = {(__u64)&scratch->addr6.sin6_addr};
      bpf_snprintf(scratch->Host, sizeof(scratch->Host), "%pI6", ip_args,
                   sizeof(ip_args));
    }
  } else {
    return 0; // Safely ignore unsupported protocols (like AF_UNIX)
  }

  bpf_printk("host captured: %s", scratch->Host);

  // 3. Perform lookup using the safe, zeroed scratchpad string buffer
  struct network_enforcer_rules *rule = bpf_map_lookup_elem(
      &octagon_force_network_enforcer_rules_pin, scratch->Host);

  if (rule) {
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    u64 start_time = bpf_ktime_get_ns();
    pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);
    __u64 cgid = bpf_get_current_cgroup_id();

    // Zero out the event storage allocation inside the scratchpad map
    __builtin_memset(&scratch->event, 0, sizeof(scratch->event));

    // Fill event fields safely
    bpf_probe_read_kernel_str(scratch->event.Host, sizeof(scratch->event.Host),
                              rule->Host);
    scratch->event.ContainerID = cgid;
    scratch->event.SourcePID = parent_pid;
    // FIXED: Removed invalid event.action compilation breaker

    struct proc_key key = {
        .pid = pid,
        .start_time = start_time,
    };

    bpf_map_update_elem(&octagon_force_network_event_map_pin, &key,
                        &scratch->event, BPF_ANY);

    // rule->action == true means ALLOW / ALERT ONLY.
    // rule->action == false means DENY connection.
    if (!rule->action) {

      // (Permission Denied)
      return -EACCES;
    }
  }

  return 0; // Clear connection path
}
