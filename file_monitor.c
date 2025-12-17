#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "file_monitor.h"
#include <time.h>
#include <sys/stat.h>

#define CSV_FILE "file_events.csv"
#define C_RESET   "\033[0m"
#define C_GRAY    "\033[90m"
#define C_YELLOW  "\033[33m"
#define C_RED     "\033[31;1m"


const char *severity_color(__u8 s)
{
    switch (s) {
        case SEV_INFO:  return C_GRAY;
        case SEV_WARN:  return C_YELLOW;
        case SEV_ALERT: return C_RED;
        default:        return C_RESET;
    }
}


const char *event_type_str(__u8 t) {
    switch (t) {
        case EVT_READ:   return "READ";
        case EVT_WRITE:  return "WRITE";
        case EVT_DELETE: return "DELETE";
        case EVT_RENAME: return "RENAME";
        default:         return "UNKNOWN";
    }
}

const char *severity_str(__u8 s) {
    switch (s) {
        case SEV_INFO:  return "INFO";
        case SEV_WARN:  return "WARN";
        case SEV_ALERT: return "ALERT";
        default:        return "UNKNOWN";
    }
}


static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct event *e = data;
    FILE *f;
    char ts[32];
    time_t now;
    struct tm *tm;

    /* Timestamp */
    time(&now);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
    if (e->evt_severity == SEV_INFO)
        return;
    /* Terminal output (human-facing) */
    // printf(
    //     "%s[%s] %-6s | %s(%d) | %s%s\n",
    //     severity_color(e->evt_severity),
    //     severity_str(e->evt_severity),
    //     event_type_str(e->event_type),
    //     e->comm,
    //     e->pid,
    //     e->filename,
    //     C_RESET
    // );

    /* CSV logging (audit-facing) */
    f = fopen(CSV_FILE, "a");
    if (!f)
        return;

    fprintf(
        f,
        "%s,%d,%s,%s,%s,%s\n",
        ts,
        e->pid,
        e->comm,
        event_type_str(e->event_type),
        severity_str(e->evt_severity),
        e->filename
    );

    fclose(f);
}


static void init_csv(void)
{
    struct stat st;
    FILE *f;

    // /* If file already exists, do nothing */
    // if (stat(CSV_FILE, &st) == 0)
    //     return;

    f = fopen(CSV_FILE, "w");
    if (!f)
        return;

    fprintf(f, "timestamp,pid,process,event,severity,path\n");
    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory_to_watch>\n", argv[0]);
        return 1;
    }

    char watch_path[256] = {};
    if (!realpath(argv[1], watch_path)) {
        perror("realpath");
        return 1;
    }

    /* ensure trailing slash */
    int len = strlen(watch_path);
    if (watch_path[len - 1] != '/')
        strcat(watch_path, "/");

    struct bpf_object *obj;
    struct bpf_map *events_map;
    struct perf_buffer *pb;

    obj = bpf_object__open_file("file_monitor.bpf.o", NULL);
    if (!obj) return 1;

    if (bpf_object__load(obj)) return 1;

    /* pass watch directory to BPF */
    struct bpf_map *watch_map;
    int watch_fd;
    __u32 key = 0;

    watch_map = bpf_object__find_map_by_name(obj, "watch_dir");
    if (!watch_map) {
        fprintf(stderr, "Failed to find watch_dir map\n");
        return 1;
    }

    watch_fd = bpf_map__fd(watch_map);

    if (bpf_map_update_elem(watch_fd, &key, watch_path, BPF_ANY) < 0) {
        perror("bpf_map_update_elem");
        return 1;
    }

    struct bpf_program *prog_open, *prog_exec, *prog_unlinkat, *prog_renameat2;
    struct bpf_link *link_open, *link_exec, *link_unlinkat, *link_renameat2;

    /* attach sched_process_exec */
    prog_exec = bpf_object__find_program_by_name(obj, "tp_exec");
    if (!prog_exec) {
        fprintf(stderr, "Failed to find tp_execve\n");
        return 1;
    }

    link_exec = bpf_program__attach_tracepoint(
        prog_exec,
        "sched",
        "sched_process_exec"
    );
    if (!link_exec) {
        fprintf(stderr, "Failed to attach sched_process_exec\n");
        return 1;
    }

    /* attach sys_enter_openat */
    prog_open = bpf_object__find_program_by_name(obj, "tp_openat");
    if (!prog_open) {
        fprintf(stderr, "Failed to find tp_openat\n");
        return 1;
    }

    link_open = bpf_program__attach_tracepoint(
        prog_open,
        "syscalls",
        "sys_enter_openat"
    );
    if (!link_open) {
        fprintf(stderr, "Failed to attach sys_enter_openat\n");
        return 1;
    }
    
    prog_unlinkat = bpf_object__find_program_by_name(obj, "tp_unlinkat");
    if(!prog_unlinkat){
        fprintf(stderr, "Failed to find tp_unlinkat\n");
        return 1;
    }
    link_unlinkat = bpf_program__attach_tracepoint(
        prog_unlinkat,
        "syscalls",
        "sys_enter_unlinkat"
    );  
    if(!link_unlinkat){
        fprintf(stderr, "Failed to attach sys_enter_unlinkat\n");
        return 1;
    }
    prog_renameat2 = bpf_object__find_program_by_name(obj, "tp_renameat2");
    if(!prog_renameat2){
        fprintf(stderr, "Failed to find tp_renameat2");
        return 1;
    }
    link_renameat2 = bpf_program__attach_tracepoint(
        prog_renameat2,
        "syscalls",
        "sys_enter_renameat2"
    );
    if(!link_renameat2){
        fprintf(stderr, "Failed to attach sys_enter_renameat2");
        return 1;
    }

    events_map = bpf_object__find_map_by_name(obj, "events");
    if (!events_map) return 1;

    pb = perf_buffer__new(
        bpf_map__fd(events_map),
        128,
        handle_event,
        NULL,
        NULL,
        NULL
    );
    init_csv();
    while (1) {
        perf_buffer__poll(pb, 100);
    }

    return 0;
}