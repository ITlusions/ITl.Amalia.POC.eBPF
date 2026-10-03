#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Event structures matching JSON output format */

struct process_event {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[16];
    char filename[256];
    char argv[512];
};

struct network_event {
    u64 timestamp;
    u32 pid;
    u32 uid;
    char comm[16];
    u8 protocol;           /* TCP=1, UDP=2 */
    u8 family;             /* AF_INET=2, AF_INET6=10 */
    u16 sport;
    u16 dport;
    u32 saddr;             /* IPv4 source */
    u32 daddr;             /* IPv4 destination */
    u8 saddr6[16];         /* IPv6 source */
    u8 daddr6[16];         /* IPv6 destination */
    u8 direction;          /* inbound=1, outbound=2 */
    u32 bytes_sent;        /* For TCP */
    u32 bytes_received;    /* For TCP */
    u8 tcp_state;          /* TCP connection state */
    u8 retransmits;        /* Retransmit count */
    u32 payload_size;      /* Captured payload length */
    char payload[96];      /* First 96 bytes of payload */
    u8 is_dns;             /* DNS query detected (1=yes) */
};

struct file_event {
    u64 timestamp;
    u32 pid;
    u32 uid;
    char comm[16];
    char path[256];
    u32 flags;
    u32 mode;
    u8 op_type;       /* open=1, close=2, read=3, write=4 */
};

/* Ring buffers for kernel -> userspace data transfer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} process_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} network_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

/* Helper function to read user string safely */
static __always_inline int read_user_str(char *dst, size_t sz, const void *unsafe_ptr)
{
    return bpf_probe_read_user_str(dst, sz, unsafe_ptr);
}

/* Helper function to read kernel string safely */
static __always_inline int read_kernel_str(char *dst, size_t sz, const void *unsafe_ptr)
{
    return bpf_probe_read_kernel_str(dst, sz, unsafe_ptr);
}

/* Helper to copy IPv6 address */
static __always_inline void copy_ipv6_addr(u8 *dst, const struct in6_addr *src)
{
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        bpf_probe_read_kernel(dst + i*4, 4, &src->in6_u.u6_addr32[i]);
    }
}

/* Helper to detect DNS queries (port 53) */
static __always_inline int is_dns_query(u16 sport, u16 dport)
{
    return (sport == 53 || dport == 53) ? 1 : 0;
}

/* Helper to read socket payload safely */
static __always_inline int read_socket_payload(char *dst, size_t sz, struct sock *sk)
{
    /* Try to read from sk_receive_queue if available */
    return 0; /* Simplified - payload capture handled via skb inspection */
}

/* =====================================================
   PROCESS EXECUTION HOOKS
   ===================================================== */

/* Capture execve() syscalls */
SEC("tp/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_event *e;

    e = bpf_ringbuf_reserve(&process_events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid = bpf_get_current_uid_gid() >> 32;

    /* sched_process_exec has no ppid/comm/argv fields; derive from task_struct */
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* filename is a __data_loc string, resolve its offset within ctx */
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
                               (void *)ctx + (ctx->__data_loc_filename & 0xFFFF));

    /* argv is not available from this tracepoint */
    e->argv[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Capture fork() syscalls */
SEC("tp/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct process_event *e;

    e = bpf_ringbuf_reserve(&process_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = ctx->child_pid;
    e->ppid = ctx->parent_pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid = bpf_get_current_uid_gid() >> 32;

    /* child_comm is a __data_loc string, resolve its offset within ctx */
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm),
                              (void *)ctx + (ctx->__data_loc_child_comm & 0xFFFF));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* =====================================================
   NETWORK HOOKS (TCP connections)
   ===================================================== */

/* Hook into tcp_v4_connect for outbound IPv4 connections */
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct network_event *e;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport;
    u32 saddr, daddr;
    u16 dport;
    u8 tcp_state;

    e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->protocol = 1;      /* TCP */
    e->family = 2;        /* AF_INET */
    e->direction = 2;     /* Outbound */

    /* Read socket addresses */
    bpf_probe_read_kernel(&saddr, 4, &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, 4, &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, 2, &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, 2, &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&tcp_state, 1, &sk->__sk_common.skc_state);

    e->saddr = saddr;
    e->daddr = daddr;
    e->sport = sport;
    e->dport = __builtin_bswap16(dport);
    e->tcp_state = tcp_state;
    e->is_dns = is_dns_query(sport, __builtin_bswap16(dport));

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Hook into tcp_v4_syn_recv_sock for inbound IPv4 connections */
SEC("kprobe/tcp_v4_syn_recv_sock")
int trace_tcp_accept(struct pt_regs *ctx)
{
    struct network_event *e;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport;
    u32 saddr, daddr;
    u16 dport;
    u8 tcp_state;

    e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->protocol = 1;      /* TCP */
    e->family = 2;        /* AF_INET */
    e->direction = 1;     /* Inbound */

    /* Read socket addresses */
    bpf_probe_read_kernel(&saddr, 4, &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, 4, &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, 2, &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, 2, &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&tcp_state, 1, &sk->__sk_common.skc_state);

    e->saddr = saddr;
    e->daddr = daddr;
    e->sport = sport;
    e->dport = __builtin_bswap16(dport);
    e->tcp_state = tcp_state;
    e->is_dns = is_dns_query(sport, __builtin_bswap16(dport));

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Hook into tcp_v6_connect for outbound IPv6 connections */
SEC("kprobe/tcp_v6_connect")
int trace_tcp_v6_connect(struct pt_regs *ctx)
{
    struct network_event *e;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport, dport;
    u8 tcp_state;

    e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->protocol = 1;      /* TCP */
    e->family = 10;       /* AF_INET6 */
    e->direction = 2;     /* Outbound */

    /* Read IPv6 addresses */
    copy_ipv6_addr(e->saddr6, &sk->__sk_common.skc_v6_rcv_saddr);
    copy_ipv6_addr(e->daddr6, &sk->__sk_common.skc_v6_daddr);

    bpf_probe_read_kernel(&sport, 2, &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, 2, &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&tcp_state, 1, &sk->__sk_common.skc_state);

    e->sport = sport;
    e->dport = __builtin_bswap16(dport);
    e->tcp_state = tcp_state;
    e->is_dns = is_dns_query(sport, __builtin_bswap16(dport));

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Hook into tcp_v6_syn_recv_sock for inbound IPv6 connections */
SEC("kprobe/tcp_v6_syn_recv_sock")
int trace_tcp_v6_accept(struct pt_regs *ctx)
{
    struct network_event *e;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport, dport;
    u8 tcp_state;

    e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->protocol = 1;      /* TCP */
    e->family = 10;       /* AF_INET6 */
    e->direction = 1;     /* Inbound */

    /* Read IPv6 addresses */
    copy_ipv6_addr(e->saddr6, &sk->__sk_common.skc_v6_rcv_saddr);
    copy_ipv6_addr(e->daddr6, &sk->__sk_common.skc_v6_daddr);

    bpf_probe_read_kernel(&sport, 2, &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, 2, &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&tcp_state, 1, &sk->__sk_common.skc_state);

    e->sport = sport;
    e->dport = __builtin_bswap16(dport);
    e->tcp_state = tcp_state;
    e->is_dns = is_dns_query(sport, __builtin_bswap16(dport));

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Hook into udp_sendmsg for outbound UDP packets */
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx)
{
    struct network_event *e;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport, dport;
    u32 saddr, daddr;
    u16 family;

    e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->protocol = 2;      /* UDP */
    e->direction = 2;     /* Outbound */

    bpf_probe_read_kernel(&family, 2, &sk->__sk_common.skc_family);
    e->family = family;

    if (family == 2) {     /* AF_INET */
        bpf_probe_read_kernel(&saddr, 4, &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&daddr, 4, &sk->__sk_common.skc_daddr);
        e->saddr = saddr;
        e->daddr = daddr;
    } else if (family == 10) { /* AF_INET6 */
        copy_ipv6_addr(e->saddr6, &sk->__sk_common.skc_v6_rcv_saddr);
        copy_ipv6_addr(e->daddr6, &sk->__sk_common.skc_v6_daddr);
    }

    bpf_probe_read_kernel(&sport, 2, &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, 2, &sk->__sk_common.skc_dport);

    e->sport = sport;
    e->dport = __builtin_bswap16(dport);
    e->is_dns = is_dns_query(sport, __builtin_bswap16(dport));

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Hook into __udp4_lib_rcv for inbound UDP packets (IPv4) */
SEC("kprobe/__udp4_lib_rcv")
int trace_udp_rcv(struct pt_regs *ctx)
{
    struct network_event *e;
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;
    u32 saddr, daddr;
    u16 sport, dport;
    void *data_ptr;

    e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->protocol = 2;      /* UDP */
    e->family = 2;        /* AF_INET */
    e->direction = 1;     /* Inbound */

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Hook into tcp_v4_destroy_sock for connection close events */
SEC("kprobe/tcp_v4_destroy_sock")
int trace_tcp_close(struct pt_regs *ctx)
{
    struct network_event *e;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport, dport;
    u32 saddr, daddr;

    e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->protocol = 1;      /* TCP */
    e->family = 2;        /* AF_INET */
    e->direction = 3;     /* Connection close */

    bpf_probe_read_kernel(&saddr, 4, &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, 4, &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, 2, &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, 2, &sk->__sk_common.skc_dport);

    e->saddr = saddr;
    e->daddr = daddr;
    e->sport = sport;
    e->dport = __builtin_bswap16(dport);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* =====================================================
   FILE ACCESS HOOKS
   ===================================================== */

/* Capture open() syscalls */
SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *e;
    char *filename_ptr;

    e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->op_type = 1;  /* open */
    e->flags = ctx->args[2];
    e->mode = ctx->args[3];

    /* Get filename from userspace */
    filename_ptr = (char *)ctx->args[1];
    bpf_probe_read_user_str(&e->path, sizeof(e->path), filename_ptr);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Capture read() syscalls */
SEC("tp/syscalls/sys_enter_read")
int trace_read(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *e;

    e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->op_type = 3;  /* read */

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Capture write() syscalls */
SEC("tp/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *e;

    e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->op_type = 4;  /* write */

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
