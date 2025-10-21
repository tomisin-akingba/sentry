/ network_monitor.bpf.c
// Kernel-side eBPF program (libbpf style)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "network_monitor.h"

// Define the ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} events SEC(".maps");

// Helper function to submit events
static __always_inline int submit_event(__u32 syscall_id)
{
    struct event *e;
    
    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    // Fill event data
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->ts = bpf_ktime_get_ns();
    e->syscall_id = syscall_id;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Submit to userspace
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint for connect syscall
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    return submit_event(1);
}

// Tracepoint for accept syscall
SEC("tracepoint/syscalls/sys_enter_accept")
int handle_accept(struct trace_event_raw_sys_enter *ctx)
{
    return submit_event(2);
}

// Tracepoint for accept4 syscall
SEC("tracepoint/syscalls/sys_enter_accept4")
int handle_accept4(struct trace_event_raw_sys_enter *ctx)
{
    return submit_event(2);
}

// Tracepoint for sendto syscall
SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx)
{
    return submit_event(3);
}

char LICENSE[] SEC("license") = "GPL";