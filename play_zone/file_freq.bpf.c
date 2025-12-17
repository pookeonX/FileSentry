#include <linux/bpf.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#define WATCH_DIR "/home/purva-s/Projects/"
#include "file_freq.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");


static __always_inline void submit(
    struct trace_event_raw_sys_enter *ctx,
    const char *syscall,
    const char *filename)
{
    struct freq_event e = {};

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid = pid_tgid >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.filename, sizeof(e.filename), filename);
    __builtin_memcpy(e.syscall, syscall, sizeof(e.syscall));

    bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
}

/* -------- Tracepoints -------- */

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    submit(ctx, "openat", (void *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_openat2(struct trace_event_raw_sys_enter *ctx)
{
    submit(ctx, "openat2", (void *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int tp_creat(struct trace_event_raw_sys_enter *ctx)
{
    submit(ctx, "creat", (void *)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int tp_unlink(struct trace_event_raw_sys_enter *ctx)
{
    submit(ctx, "unlink", (void *)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    submit(ctx, "unlinkat", (void *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    submit(ctx, "execve", (void *)ctx->args[0]);
    return 0;
}
