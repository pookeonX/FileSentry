#ifndef __FILE_TRACER_H__
#define __FILE_TRACER_H__

#define TASK_COMM_LEN 16

struct tracer_event {
    unsigned int pid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char syscall[16];
};

#endif