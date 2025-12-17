#ifndef __FILE_MONITOR_H__
#define __FILE_MONITOR_H__

#define TASK_COMM_LEN 16

enum event_type {
    EVT_READ = 0,
    EVT_WRITE = 1,
    EVT_DELETE = 2,
    EVT_RENAME = 3,
};

enum evt_severity {
    SEV_INFO = 0,
    SEV_WARN = 1,
    SEV_ALERT = 2,
};
struct event {
    unsigned int pid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char syscall[32];
    __u8 event_type;
    __u8 evt_severity;
};

#endif
