#define BPF_NO_GLOBAL_DATA
#include "../vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#if defined(bpf_strstr)
#else
extern int bpf_strstr(const char *str, const char *substr) __ksym;
#endif
#define ARGV_LEN 154
#ifdef DEBUG
#define DEBUG_YES = 1
#endif

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// send events to app
struct network_event {
  __u64 ContainerID; /*  8 bytes (offset 0)  */
  pid_t SourcePID;   /*  4 bytes (offset 8)  */
  __u16 family;      /*  2 bytes (offset 12) */
  __be16 dport;      /*  2 bytes (offset 14) */
  __be32 saddr_v4;
  __be32 daddr_v4;            /*  4 bytes (offset 16) */
  unsigned char daddr_v6[16]; /* 16 bytes (offset 20) */
  unsigned char saddr_v6[16];
  char eventName[24]; /* 24 bytes (offset 36) - Extended to 24 to pad naturally
                       */
}; /* Total C size = 60 bytes */

struct proc_key {
  __u32 pid;
  __u64 start_time;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct proc_key);
  __type(value, struct network_event);
  __uint(max_entries, 2097152); // 1048576);
} octagon_force_network_event_map_pin SEC(".maps");

struct network_enforcer_rules {
  char Name[32]; // all good rules need names!
  // hostname/ip
  char Host[256];
  // action, boolean for either deny or alert
  bool action;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, char[256]);
  __type(value, struct network_enforcer_rules);
  __uint(max_entries, 1048576);
} octagon_force_network_enforcer_rules_pin SEC(".maps");
