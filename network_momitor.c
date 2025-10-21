// network_monitor.c
// User-space loader and event processor

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "network_monitor.h"

static volatile bool exiting = false;

// Syscall name mapping
static const char *syscall_name(__u32 id)
{
    switch (id) {
        case 1: return "connect";
        case 2: return "accept";
        case 3: return "sendto";
        default: return "unknown";
    }
}

// Signal handler for graceful shutdown
static void sig_handler(int sig)
{
    exiting = true;
}

// Callback for ring buffer events
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;
    
    // Convert timestamp (nanoseconds since boot to wall time)
    // Note: For simplicity, using current time. In production, 
    // you'd calculate based on boot time offset
    t = time(NULL);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    
    printf("%-8s %-7d %-7d %-16s %s\n",
           ts, e->pid, e->uid, e->comm, syscall_name(e->syscall_id));
    
    return 0;
}

// libbpf error/debug callback
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    struct bpf_link *links[4] = {};
    int err, map_fd;
    
    // Set up libbpf errors and debug output
    libbpf_set_print(libbpf_print_fn);
    
    // Open BPF object file
    obj = bpf_object__open_file("network_monitor.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }
    
    // Load BPF object into kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    // Attach tracepoints
    links[0] = bpf_program__attach(bpf_object__find_program_by_name(obj, "handle_connect"));
    links[1] = bpf_program__attach(bpf_object__find_program_by_name(obj, "handle_accept"));
    links[2] = bpf_program__attach(bpf_object__find_program_by_name(obj, "handle_accept4"));
    links[3] = bpf_program__attach(bpf_object__find_program_by_name(obj, "handle_sendto"));
    
    for (int i = 0; i < 4; i++) {
        if (!links[i]) {
            fprintf(stderr, "Failed to attach BPF program %d\n", i);
            goto cleanup;
        }
    }
    
    // Get ring buffer map file descriptor
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find events map\n");
        goto cleanup;
    }
    
    // Create ring buffer
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    // Set up signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("Successfully loaded and attached BPF programs!\n");
    printf("Monitoring network syscalls... Press Ctrl+C to stop\n\n");
    printf("%-8s %-7s %-7s %-16s %s\n", 
           "TIME", "PID", "UID", "COMMAND", "SYSCALL");
    printf("------------------------------------------------------------\n");
    
    // Poll for events
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
cleanup:
    printf("\nCleaning up...\n");
    ring_buffer__free(rb);
    for (int i = 0; i < 4; i++) {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);
    
    return err != 0;
}