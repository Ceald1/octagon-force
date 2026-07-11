#include "network.h"

static __always_inline __u32 get_pid_ns_level(struct task_struct *task) {
  struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
  if (!nsproxy)
    return 0;
  struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
  if (!pid_ns)
    return 0;
  return BPF_CORE_READ(pid_ns, level);
}

SEC("kprobe/__sys_connect")
int BPF_KPROBE(octagon_force_connect, int fd, struct sockaddr *uservaddr,
               int addrlen) {

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  __u32 pid_ns_level = get_pid_ns_level(task);

  if (pid_ns_level == 0)
    return 0;

  u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  u64 start_time = bpf_ktime_get_ns();
  pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);
  __u64 cgid = bpf_get_current_cgroup_id();
  struct network_event e = {};
  // #ifdef DEBUG_YES
  //   bpf_printk("network enter event!");
  // #endif
  struct proc_key key;
  key.pid = pid;
  key.start_time = start_time;
  e.ContainerID = cgid;
  e.SourcePID = parent_pid;
  char name[20] = "opened";
  bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName), name);

  bpf_map_update_elem(&octagon_force_network_event_map_pin, &key, &e, BPF_ANY);
  return 0;
}

SEC("fentry/tcp_set_state")
int BPF_PROG(octagon_force_tcp_state, struct sock *sk, int newstate) {
  if (!sk) {
    return 0;
  }
  if (BPF_CORE_READ(sk, sk_protocol) != 6) {
    return 0;
  }
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  __u32 pid_ns_level = get_pid_ns_level(task);

  if (pid_ns_level == 0) {
    return 0;
  }

  u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  u64 start_time = bpf_ktime_get_ns();
  pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);
  __u64 cgid = bpf_get_current_cgroup_id();
  struct network_event e = {};

  struct proc_key key;
  key.pid = pid;
  key.start_time = start_time;
  e.ContainerID = cgid;
  e.SourcePID = parent_pid;
  switch (newstate) {
  case TCP_ESTABLISHED:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName), "established");
    // char name[20] = "established";
  case TCP_SYN_SENT:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName), "syn sent");
  case TCP_SYN_RECV:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName), "syn received");
  case TCP_FIN_WAIT1:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName),
                              "waiting goodbye");
  case TCP_FIN_WAIT2:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName),
                              "wait remote fin");
  case TCP_TIME_WAIT:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName), "wandering");
  case TCP_CLOSE:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName), "closed");
  case TCP_CLOSE_WAIT:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName),
                              "remote closed");
  case TCP_LAST_ACK:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName),
                              "waiting last ack");
  case TCP_LISTEN:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName), "listening");
  case TCP_CLOSING:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName), "both closed");
  case TCP_NEW_SYN_RECV:
    bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName),
                              "new syn received");
  }
#ifdef DEBUG_YES
  bpf_printk("tcp event: %s", e.eventName);
#endif

  bpf_map_update_elem(&octagon_force_network_event_map_pin, &key, &e, BPF_ANY);
  return 0;
}

SEC("kprobe/__dev_queue_xmit")
int BPF_KPROBE(octagon_force_packets_sent, struct sk_buff *sk) {
  if (!sk) {
    return 0;
  }
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  __u32 pid_ns_level = get_pid_ns_level(task);

  if (pid_ns_level == 0)
    return 0;

  u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  u64 start_time = bpf_ktime_get_ns();
  pid_t parent_pid = BPF_CORE_READ(task, real_parent, pid);
  __u64 cgid = bpf_get_current_cgroup_id();
  struct network_event e = {};
  // #ifdef DEBUG_YES
  //   bpf_printk("network sent packet!");
  // #endif
  struct proc_key key;
  key.pid = pid;
  key.start_time = start_time;
  e.ContainerID = cgid;
  e.SourcePID = parent_pid;
  char name[20] = "sent packet";
  bpf_probe_read_kernel_str(e.eventName, sizeof(e.eventName), name);

  bpf_map_update_elem(&octagon_force_network_event_map_pin, &key, &e, BPF_ANY);
  return 0;
}
