/*
 * Minimal libbpf CO-RE loader for sensor.bpf.c.
 *
 * BCC cannot load a pre-compiled CO-RE object (no raw object-load API in
 * this BCC version) and its own compat headers conflict with a full
 * vmlinux.h, so this loader uses libbpf directly: open the object, load
 * it into the kernel, auto-attach every program by its SEC() name, then
 * poll the enabled ring buffers and append each event as one JSON line.
 */

#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

/* Must stay binary-compatible with the structs in kernel/programs/sensor.bpf.c */

struct process_event {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    char comm[16];
    char filename[256];
    char argv[512];
};

struct network_event {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t uid;
    char comm[16];
    uint8_t protocol;
    uint8_t family;
    uint16_t sport;
    uint16_t dport;
    uint32_t saddr;
    uint32_t daddr;
    uint8_t saddr6[16];
    uint8_t daddr6[16];
    uint8_t direction;
    uint32_t bytes_sent;
    uint32_t bytes_received;
    uint8_t tcp_state;
    uint8_t retransmits;
    uint32_t payload_size;
    char payload[96];
    uint8_t is_dns;
};

struct file_event {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t uid;
    char comm[16];
    char path[256];
    uint32_t flags;
    uint32_t mode;
    uint8_t op_type;
};

static volatile sig_atomic_t g_stop;
static FILE *g_out;
static long g_process_count, g_network_count, g_file_count;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* Writes a bounded, possibly non-terminated char array as an escaped JSON string */
static void write_json_string(FILE *f, const char *s, size_t maxlen)
{
    fputc('"', f);
    for (size_t i = 0; i < maxlen && s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            fputc('\\', f);
            fputc(c, f);
        } else if (c == '\n') {
            fputs("\\n", f);
        } else if (c < 0x20 || c > 0x7e) {
            fputc('.', f);
        } else {
            fputc(c, f);
        }
    }
    fputc('"', f);
}

/* Writes one finished JSON line to stdout (for live piping) and, if an
 * --out file was given, to that file too. */
static void emit_line(const char *line)
{
    fputs(line, stdout);
    fflush(stdout);
    if (g_out) {
        fputs(line, g_out);
        fflush(g_out);
    }
}

static int handle_process_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct process_event))
        return 0;
    const struct process_event *e = data;

    char *buf;
    size_t len;
    FILE *mem = open_memstream(&buf, &len);

    fprintf(mem, "{\"type\":\"process\",\"timestamp\":%llu,\"pid\":%u,\"ppid\":%u,"
                 "\"uid\":%u,\"gid\":%u,\"comm\":", (unsigned long long)e->timestamp,
            e->pid, e->ppid, e->uid, e->gid);
    write_json_string(mem, e->comm, sizeof(e->comm));
    fprintf(mem, ",\"filename\":");
    write_json_string(mem, e->filename, sizeof(e->filename));
    fprintf(mem, "}\n");
    fclose(mem);
    emit_line(buf);
    free(buf);
    g_process_count++;
    return 0;
}

static int handle_network_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct network_event))
        return 0;
    const struct network_event *e = data;
    char saddr[INET6_ADDRSTRLEN] = {0};
    char daddr[INET6_ADDRSTRLEN] = {0};

    if (e->family == 10) {
        inet_ntop(AF_INET6, e->saddr6, saddr, sizeof(saddr));
        inet_ntop(AF_INET6, e->daddr6, daddr, sizeof(daddr));
    } else {
        inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
        inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));
    }

    char *buf;
    size_t len;
    FILE *mem = open_memstream(&buf, &len);

    fprintf(mem,
            "{\"type\":\"network\",\"timestamp\":%llu,\"pid\":%u,\"uid\":%u,\"comm\":",
            (unsigned long long)e->timestamp, e->pid, e->uid);
    write_json_string(mem, e->comm, sizeof(e->comm));
    fprintf(mem,
            ",\"protocol\":\"%s\",\"saddr\":\"%s\",\"daddr\":\"%s\",\"sport\":%u,"
            "\"dport\":%u,\"direction\":\"%s\",\"tcp_state\":%u,\"is_dns\":%s}\n",
            e->protocol == 1 ? "TCP" : "UDP", saddr, daddr, e->sport, e->dport,
            e->direction == 1 ? "inbound" : e->direction == 2 ? "outbound" : "close",
            e->tcp_state, e->is_dns ? "true" : "false");
    fclose(mem);
    emit_line(buf);
    free(buf);
    g_network_count++;
    return 0;
}

static int handle_file_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct file_event))
        return 0;
    const struct file_event *e = data;

    char *buf;
    size_t len;
    FILE *mem = open_memstream(&buf, &len);

    fprintf(mem, "{\"type\":\"file\",\"timestamp\":%llu,\"pid\":%u,\"uid\":%u,\"comm\":",
            (unsigned long long)e->timestamp, e->pid, e->uid);
    write_json_string(mem, e->comm, sizeof(e->comm));
    fprintf(mem, ",\"path\":");
    write_json_string(mem, e->path, sizeof(e->path));
    fprintf(mem, ",\"flags\":%u,\"mode\":%u,\"op_type\":%u}\n", e->flags, e->mode,
            e->op_type);
    fclose(mem);
    emit_line(buf);
    free(buf);
    g_file_count++;
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --obj <sensor.o> [--duration SEC] [--enable process,network,file] "
            "[--direction inbound|outbound|all] [--out PATH]\n"
            "Events are always streamed as JSON lines on stdout (for live piping); "
            "--out additionally archives them to a file.\n",
            prog);
}

/* Programs whose SEC() direction doesn't match the requested filter are
 * skipped at attach time (not just filtered post-hoc) to cut overhead. */
static bool program_matches_direction(const char *name, const char *direction)
{
    static const char *outbound_only[] = {
        "trace_tcp_connect", "trace_tcp_v6_connect", "trace_udp_sendmsg", NULL
    };
    static const char *inbound_only[] = {
        "trace_tcp_accept", "trace_tcp_v6_accept", "trace_udp_rcv", NULL
    };

    if (!strcmp(direction, "all"))
        return true;

    const char **exclude = !strcmp(direction, "inbound") ? outbound_only : inbound_only;
    for (int i = 0; exclude[i]; i++) {
        if (!strcmp(name, exclude[i]))
            return false;
    }
    /* trace_tcp_close and process/file programs are direction-agnostic */
    return true;
}

int main(int argc, char **argv)
{
    const char *obj_path = NULL;
    const char *out_path = NULL;
    const char *enable = "network";
    const char *direction = "all";
    int duration = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--obj") && i + 1 < argc)
            obj_path = argv[++i];
        else if (!strcmp(argv[i], "--duration") && i + 1 < argc)
            duration = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--enable") && i + 1 < argc)
            enable = argv[++i];
        else if (!strcmp(argv[i], "--direction") && i + 1 < argc)
            direction = argv[++i];
        else if (!strcmp(argv[i], "--out") && i + 1 < argc)
            out_path = argv[++i];
        else {
            usage(argv[0]);
            return 1;
        }
    }
    if (!obj_path) {
        usage(argv[0]);
        return 1;
    }
    if (strcmp(direction, "all") && strcmp(direction, "inbound") && strcmp(direction, "outbound")) {
        usage(argv[0]);
        return 1;
    }

    bool want_process = strstr(enable, "process") != NULL;
    bool want_network = strstr(enable, "network") != NULL;
    bool want_file = strstr(enable, "file") != NULL;

    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rlim); /* best-effort, ignored on cgroup-accounted kernels */

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "[!] Failed to open BPF object: %s\n", obj_path);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "[!] Failed to load BPF object into kernel\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog;
    int attached = 0, failed = 0, skipped = 0;
    bpf_object__for_each_program(prog, obj) {
        const char *name = bpf_program__name(prog);
        if (!program_matches_direction(name, direction)) {
            skipped++;
            continue;
        }
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "[!] Failed to attach %s (kernel symbol may be missing)\n", name);
            failed++;
            continue;
        }
        attached++;
    }
    fprintf(stderr, "[+] Attached %d program(s), %d failed, %d skipped (direction=%s)\n",
            attached, failed, skipped, direction);

    g_out = NULL;
    if (out_path) {
        g_out = fopen(out_path, "w");
        if (!g_out) {
            fprintf(stderr, "[!] Failed to open output file: %s\n", out_path);
            bpf_object__close(obj);
            return 1;
        }
    }

    struct ring_buffer *rb = NULL;
    if (want_process) {
        struct bpf_map *m = bpf_object__find_map_by_name(obj, "process_events");
        if (m)
            rb = ring_buffer__new(bpf_map__fd(m), handle_process_event, NULL, NULL);
    }
    if (want_network) {
        struct bpf_map *m = bpf_object__find_map_by_name(obj, "network_events");
        if (m) {
            if (!rb)
                rb = ring_buffer__new(bpf_map__fd(m), handle_network_event, NULL, NULL);
            else
                ring_buffer__add(rb, bpf_map__fd(m), handle_network_event, NULL);
        }
    }
    if (want_file) {
        struct bpf_map *m = bpf_object__find_map_by_name(obj, "file_events");
        if (m) {
            if (!rb)
                rb = ring_buffer__new(bpf_map__fd(m), handle_file_event, NULL, NULL);
            else
                ring_buffer__add(rb, bpf_map__fd(m), handle_file_event, NULL);
        }
    }
    if (!rb) {
        fprintf(stderr, "[!] No ring buffers enabled/found\n");
        if (g_out)
            fclose(g_out);
        bpf_object__close(obj);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    fprintf(stderr, "[*] Collecting events (duration=%ds, enabled=%s)%s%s\n", duration,
            enable, out_path ? " -> " : " (stdout only)", out_path ? out_path : "");

    time_t start = time(NULL);
    while (!g_stop) {
        ring_buffer__poll(rb, 100 /* ms */);
        if (duration > 0 && time(NULL) - start >= duration)
            break;
    }

    fprintf(stderr, "[+] Collected process=%ld network=%ld file=%ld\n", g_process_count,
            g_network_count, g_file_count);

    ring_buffer__free(rb);
    if (g_out)
        fclose(g_out);
    bpf_object__close(obj);
    return 0;
}
