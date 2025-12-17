//#include <linux/bpf.h>          // BPF constants (OK)
#include "vmlinux.h"            // CO-RE types (OK)
//#include <linux/fcntl.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "file_monitor.h"
#define O_WRONLY  00000001
#define O_RDWR    00000002


char LICENSE[] SEC("license") = "GPL";

/* perf event map */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

/* user-initiated processes (spawned from shell) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(int));   // pid
    __uint(value_size, sizeof(int)); // dummy value
} user_pids SEC(".maps");

/* get the directory inoutted by the user */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[256]);
} watch_dir SEC(".maps");

static __always_inline int starts_with_full(const char *s, const char *p)
{
#pragma unroll
    for (int i = 0; i < 64; i++) {
        if (p[i] == '\0')
            return 1;
        if (s[i] != p[i])
            return 0;
    }
    return 0;
}

static __always_inline int starts_with(const char *s, const char *p)
{
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (p[i] == '\0')
            return 1;   
        if (s[i] != p[i])
            return 0;
    }
    return 0;
}

static __always_inline int allow_event(char *filename)
{
    int pid;

    if (filename[0] == '\0')
        return 0;

    if (filename[0] != '/')
        return 0;
        
    char *dir;
    __u32 key = 0;

    dir = bpf_map_lookup_elem(&watch_dir, &key);
    if (!dir)
        return 0;

    if (!starts_with_full(filename, dir))
        return 0;

    if (filename[0]=='/' &&
        (filename[1]=='p' || filename[1]=='s' || filename[1]=='d'))
        return 0;

    if (filename[0]=='/' &&
        (filename[1]=='l' ||
         (filename[1]=='u' && filename[2]=='s')))
        return 0;

#pragma unroll
    for (int i = 0; i < 252; i++) {
        if (filename[i]=='.' &&
            filename[i+1]=='s' &&
            filename[i+2]=='o')
            return 0;
        if (filename[i]=='\0')
            break;
    }

    pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&user_pids, &pid))
        return 0;

    return 1;
}


static __always_inline int contains_so(const char *s)
{
#pragma unroll
    for (int i = 0; i < 252; i++) {
        if (s[i] == '.' &&
            s[i+1] == 's' &&
            s[i+2] == 'o')
            return 1;
        if (s[i] == '\0')
            return 0;
    }
    return 0;
}

static __always_inline void fill_common(struct event *e)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];

    bpf_get_current_comm(comm, sizeof(comm));

    /* mark EVERY exec, not just shell */
    u8 one = 1;
    bpf_map_update_elem(&user_pids, &pid, &one, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event e = {};
    int flags;

    /* Common fields */
    fill_common(&e);

    /* Read filename */
    bpf_probe_read_user_str(
        e.filename,
        sizeof(e.filename),
        (void *)ctx->args[1]
    );

    /* Scope + noise filtering FIRST */
    if (!allow_event(e.filename))
        return 0;

    /* Read open flags */
    flags = (int)ctx->args[2];

    /* SECURITY SEMANTICS */
    if (flags & O_WRONLY || flags & O_RDWR) {
        e.event_type = EVT_WRITE;
        e.evt_severity   = SEV_WARN;
    } else {
        e.event_type = EVT_READ;
        e.evt_severity   = SEV_INFO;
    }

    /* Optional syscall metadata (debug only) */
    __builtin_memcpy(e.syscall, "openat", 7);

    /* Emit event */
    bpf_perf_event_output(
        ctx,
        &events,
        BPF_F_CURRENT_CPU,
        &e,
        sizeof(e)
    );

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct event e = {};
    fill_common(&e);

    bpf_probe_read_user_str(e.filename, sizeof(e.filename), (void *)ctx->args[1]);

    if (!allow_event(e.filename))
        return 0;

    e.event_type   = EVT_DELETE;
    e.evt_severity = SEV_ALERT;

    __builtin_memcpy(e.syscall, "unlinkat", 7);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tp_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    struct event e = {};
    fill_common(&e);
    char msg[] = "MKDIR HIT\n";
    bpf_trace_printk(msg, sizeof(msg));

    bpf_probe_read_user_str(e.filename, sizeof(e.filename), (void *)ctx->args[1]);

    if (!allow_event(e.filename))
        return 0;

    e.event_type = EVT_RENAME;
    e.evt_severity = SEV_ALERT;

    __builtin_memcpy(e.syscall, "renameat2", 7);
    bpf_perf_event_output(ctx, &events,
                          BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

//rm -f file_monitor
// clang -g -O2 -target bpf   -D__TARGET_ARCH_x86   -I.   -I/usr/include/bpf   -I/usr/include/x86_64-linux-gnu   -c file_monitor.bpf.c   -o file_monitor.bpf.o
//clang -g -O2   -I.   file_monitor.c   -lbpf   -o file_monitor
//sudo ./file_monitor