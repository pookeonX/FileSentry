#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "file_freq.h"

static volatile int running = 1;

/* syscall counters */
struct counter {
    char name[16];
    unsigned long count;
};

static struct counter counters[16];
static int counter_count = 0;

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct freq_event *e = data;

    for (int i = 0; i < counter_count; i++) {
        if (strcmp(counters[i].name, e->syscall) == 0) {
            counters[i].count++;
            return;
        }
    }

    strcpy(counters[counter_count].name, e->syscall);
    counters[counter_count].count = 1;
    counter_count++;
}

static void sigint_handler(int signo)
{
    running = 0;
}

int main()
{
    struct bpf_object *obj;
    struct bpf_map *events;
    struct perf_buffer *pb;

    signal(SIGINT, sigint_handler);

    obj = bpf_object__open_file("file_freq.bpf.o", NULL);
    bpf_object__load(obj);

    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj)
        bpf_program__attach(prog);

    events = bpf_object__find_map_by_name(obj, "events");

    pb = perf_buffer__new(
        bpf_map__fd(events), 128,
        handle_event, NULL, NULL, NULL);

    while (running) {
        perf_buffer__poll(pb, 100);

        printf("\033[2J\033[H"); // clear screen
        printf("Syscall Frequency:\n\n");

        for (int i = 0; i < counter_count; i++) {
            printf("%-10s %lu\n",
                   counters[i].name,
                   counters[i].count);
        }

        usleep(500000);
    }

    return 0;
}
