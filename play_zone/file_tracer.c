#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "file_tracer.h"

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
    exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct tracer_event *e = data;

    printf("%-8s | %-10s | %-6d | %s\n",
           e->syscall,
           e->comm,
           e->pid,
           e->filename);
}

int main(void)
{
    struct bpf_object *obj;
    struct bpf_map *map;
    struct perf_buffer *pb;
    struct bpf_program *prog;
    struct bpf_link *link;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    obj = bpf_object__open_file("file_tracer.bpf.o", NULL);
    if (!obj) return 1;

    if (bpf_object__load(obj)) return 1;

    /* attach all tracepoints */
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__attach(prog)) {
            fprintf(stderr, "Failed to attach program\n");
            return 1;
        }
    }

    map = bpf_object__find_map_by_name(obj, "events");
    if (!map) return 1;

    pb = perf_buffer__new(
        bpf_map__fd(map),
        128,
        handle_event,
        NULL,
        NULL,
        NULL
    );
    if (!pb) return 1;

    printf("TIMELESS FILE SYSCALL TRACE\n");
    printf("SYSCALL  | PROCESS    | PID    | FILE\n");
    printf("-------------------------------------------\n");

    while (!exiting)
        perf_buffer__poll(pb, 100);

    perf_buffer__free(pb);
    bpf_object__close(obj);
    return 0;
}
