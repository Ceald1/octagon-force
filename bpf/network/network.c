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
  e.family = BPF_CORE_READ(sk, __sk_common.skc_family);
  e.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

  if (e.family == 2) { // AF_INET (IPv4)
    e.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  } else if (e.family == 10) { // AF_INET6 (IPv6)
    BPF_CORE_READ_INTO(&e.daddr_v6, sk,
                       __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&e.saddr_v6, sk,
                       __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
  }
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

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

SEC("kprobe/__dev_queue_xmit")
int BPF_KPROBE(octagon_force_packets_sent, struct sk_buff *skb) {
  if (!skb) {
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
  unsigned char *head = BPF_CORE_READ(skb, head);
  u16 network_header = BPF_CORE_READ(skb, network_header);
  u16 protocol =
      BPF_CORE_READ(skb, protocol); // Ethernet protocol (in network byte order)

  // Check layer 3 protocol (bpf_ntohs handles network byte order)
  if (protocol == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = (struct iphdr *)(head + network_header);
    e.family = 2; // AF_INET
    e.daddr_v4 = BPF_CORE_READ(iph, daddr);
    e.saddr_v4 = BPF_CORE_READ(iph, saddr);
  } else if (protocol == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(head + network_header);
    e.family = 10; // AF_INET6
    BPF_CORE_READ_INTO(&e.daddr_v6, ip6h, daddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&e.saddr_v6, ip6h, saddr.in6_u.u6_addr8);
  }
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
