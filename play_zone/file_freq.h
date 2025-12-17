#ifndef __FILE_FREQ_H__
#define __FILE_FREQ_H__

#define TASK_COMM_LEN 16

struct freq_event {
    unsigned int pid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char syscall[16];
};

#endif