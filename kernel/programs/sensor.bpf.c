#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/in6.h>

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
    u8 protocol;      /* TCP=1, UDP=2 */
    u16 sport;
    u16 dport;
    u32 saddr;
    u32 daddr;
    u8 direction;     /* inbound=1, outbound=2 */
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

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid = bpf_get_current_uid_gid() >> 32;
    e->ppid = ctx->ppid;

    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), &ctx->comm);
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), &ctx->filename);

    /* Capture first 512 bytes of argv if available */
    bpf_probe_read_user_str(&e->argv, sizeof(e->argv), (void *)ctx->argv);

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

    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), &ctx->child_comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* =====================================================
   NETWORK HOOKS (TCP connections)
   ===================================================== */

/* Hook into tcp_v4_connect for outbound connections */
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct network_event *e;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport;
    u32 saddr, daddr;
    u16 dport;

    e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->protocol = 1;  /* TCP */
    e->direction = 2;  /* Outbound */

    /* Read socket addresses */
    bpf_probe_read_kernel(&saddr, 4, &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, 4, &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, 2, &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, 2, &sk->__sk_common.skc_dport);

    e->saddr = saddr;
    e->daddr = daddr;
    e->sport = sport;
    e->dport = __builtin_bswap16(dport);  /* Network byte order -> host order */

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Hook into tcp_v4_receive_established for inbound connections */
SEC("kprobe/tcp_v4_syn_recv_sock")
int trace_tcp_accept(struct pt_regs *ctx)
{
    struct network_event *e;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport;
    u32 saddr, daddr;
    u16 dport;

    e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->protocol = 1;  /* TCP */
    e->direction = 1;  /* Inbound */

    /* Read socket addresses */
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
