// network_monitor.h
// Shared between kernel and userspace

#ifndef __NETWORK_MONITOR_H
#define __NETWORK_MONITOR_H

#define TASK_COMM_LEN 16

struct event {
    __u32 pid;
    __u32 uid;
    __u64 ts;
    char comm[TASK_COMM_LEN];
    __u32 syscall_id;
};

#endif /* __NETWORK_MONITOR_H */