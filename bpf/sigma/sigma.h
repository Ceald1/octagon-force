#define BPF_NO_GLOBAL_DATA
#include "../vmlinux.h"

#include <bpf/bpf_core_read.h>
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
struct sigma_event {
  pid_t SourcePID;
  __u64 ContainerID;
  char data[256];
  char hooked[16];
};

struct proc_key {
  __u32 pid;
  __u64 start_time;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct proc_key);
  __type(value, struct sigma_event);
  __uint(max_entries, 2097152); // 1048576);
} octagon_force_sigma_event_map_pin SEC(".maps");
