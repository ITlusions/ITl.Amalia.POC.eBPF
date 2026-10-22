/*
 * INTENTIONALLY VULNERABLE TEST FIXTURE — NOT PRODUCTION CODE.
 *
 * Vulnserver-style: a single UDP listener dispatching to several distinct,
 * deliberately buggy "legitimate looking" command handlers, used to
 * validate the blue-team telemetry/crash-detection pipeline in this repo
 * (run the eBPF sensor while triggering each bug via exploit.py and confirm
 * the inbound packet + crash are visible in captured telemetry).
 *
 * Binds to 127.0.0.1 ONLY. Never bind this to 0.0.0.0 or expose it beyond
 * an isolated lab — every command below is a remotely-triggerable bug by
 * design.
 *
 * Commands (see exploit.py --command):
 *   OVERFLOW:<data>       stack buffer overflow (strcpy into fixed buffer)
 *   BANNER:<data>         format string bug (printf(user_input))
 *   NICK:<data>           heap off-by-one (malloc missing +1 for NUL)
 *   RECORDS:<count>       integer overflow -> undersized heap allocation
 *   SESSION_OPEN:<data>   allocate + populate a "session" (setup for UAF)
 *   SESSION_CLOSE         free the session (forgets to NULL the pointer)
 *   SESSION_TOUCH         use-after-free (read + write freed memory)
 *   BIO_SET:<data>        set profile bio (lazily allocates profile)
 *   BIO_RESET             reset profile to NULL
 *   BIO_PRINT             NULL pointer dereference if bio was reset/unset
 *   HELP                  list commands (not a bug, mirrors Vulnserver)
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LISTEN_PORT 31337

/* ===================================================================
 * OVERFLOW: stack buffer overflow
 * Looks like an ordinary "log the username" helper — the kind of
 * innocuous-looking function real overflow bugs hide in: no obviously
 * dangerous call, just a fixed-size local buffer and an unchecked copy.
 * =================================================================== */
static void log_username(const char *username)
{
    char record[32];              /* fixed-size stack buffer */

    strcpy(record, username);     /* VULNERABLE: no length check, no bound */

    printf("[log] user connected: %s\n", record);
}

/* ===================================================================
 * BANNER: format string vulnerability
 * Looks like a customizable welcome banner feature. The bug is passing
 * attacker data directly as the format string instead of as an argument.
 * =================================================================== */
static void print_welcome_banner(const char *custom_greeting)
{
    printf("[banner] ");
    printf(custom_greeting);      /* VULNERABLE: should be printf("%s", ...) */
    printf("\n");
}

/* ===================================================================
 * NICK: heap off-by-one
 * Looks like it stores a nickname sized exactly to fit the input. The
 * bug: the allocation forgets the extra byte for the NUL terminator that
 * strcpy() always writes, corrupting one byte of heap metadata/adjacent data.
 * =================================================================== */
static void store_nickname(const char *nickname)
{
    size_t len = strlen(nickname);
    char *buf = malloc(len);      /* VULNERABLE: missing +1 for '\0' */
    if (!buf) {
        printf("[nick] allocation failed\n");
        return;
    }
    strcpy(buf, nickname);        /* writes len+1 bytes into a len-byte buffer */
    printf("[nick] stored: %s\n", buf);
    free(buf);
}

/* ===================================================================
 * RECORDS: integer overflow leading to an undersized heap allocation
 * Looks like a normal "pre-allocate N records" capacity-planning helper.
 * The bug: the size calculation can wrap around before malloc() sees it,
 * so the subsequent fill loop writes far past the real allocation.
 * =================================================================== */
static void allocate_records(const char *count_str)
{
    int count = atoi(count_str);                     /* attacker-controlled */
    unsigned int wrapped_size =                       /* VULNERABLE: 32-bit multiply wraps */
        (unsigned int)count * (unsigned int)sizeof(int);

    int *records = malloc(wrapped_size);
    if (!records) {
        printf("[records] allocation failed\n");
        return;
    }
    for (int i = 0; i < count; i++)
        records[i] = i;           /* writes past the wrapped-small allocation */

    printf("[records] allocated %d records (alloc size %u bytes)\n", count, wrapped_size);
    free(records);
}

/* ===================================================================
 * SESSION_*: use-after-free
 * Looks like ordinary session lifecycle management (open/close/keepalive).
 * The bug: close_session() frees the session but forgets to NULL the
 * pointer, so a later "keepalive" touch reads and writes freed memory.
 * =================================================================== */
static char *g_session = NULL;

static void open_session(const char *data)
{
    g_session = malloc(64);
    if (!g_session) {
        printf("[session] allocation failed\n");
        return;
    }
    strncpy(g_session, data, 63);
    g_session[63] = '\0';
    printf("[session] opened: %s\n", g_session);
}

static void close_session(void)
{
    printf("[session] closing: %s\n", g_session ? g_session : "(none)");
    free(g_session);              /* VULNERABLE: g_session is not reset to NULL */
}

static void touch_session(void)
{
    /* looks like a harmless keepalive ping */
    printf("[session] touch: %s\n", g_session);  /* UAF read */
    strcpy(g_session, "touched");                 /* UAF write */
}

/* ===================================================================
 * BIO_*: NULL pointer dereference
 * Looks like ordinary user-profile management. The bug: BIO_PRINT never
 * checks whether the profile was ever set (or was reset), so printing an
 * absent profile dereferences NULL.
 * =================================================================== */
static char *g_bio = NULL;

static void set_bio(const char *bio)
{
    free(g_bio);
    g_bio = strdup(bio);
    printf("[profile] bio set: %s\n", g_bio);
}

static void reset_bio(void)
{
    free(g_bio);
    g_bio = NULL;
    printf("[profile] bio reset\n");
}

static void print_bio(void)
{
    /* VULNERABLE: no NULL check. strlen() genuinely dereferences the
     * pointer (unlike printf("%s", NULL), which glibc prints as "(null)"
     * without crashing). */
    printf("[profile] bio (%zu bytes): %s\n", strlen(g_bio), g_bio);
}

static void print_help(void)
{
    printf("[help] commands: OVERFLOW BANNER NICK RECORDS "
           "SESSION_OPEN SESSION_CLOSE SESSION_TOUCH BIO_SET BIO_RESET BIO_PRINT HELP\n");
}

/* Splits "COMMAND:data" into command and data (data may be empty) */
static void dispatch(char *packet)
{
    char *colon = strchr(packet, ':');
    char *data = "";
    if (colon) {
        *colon = '\0';
        data = colon + 1;
    }

    if (!strcmp(packet, "OVERFLOW"))
        log_username(data);
    else if (!strcmp(packet, "BANNER"))
        print_welcome_banner(data);
    else if (!strcmp(packet, "NICK"))
        store_nickname(data);
    else if (!strcmp(packet, "RECORDS"))
        allocate_records(data);
    else if (!strcmp(packet, "SESSION_OPEN"))
        open_session(data);
    else if (!strcmp(packet, "SESSION_CLOSE"))
        close_session();
    else if (!strcmp(packet, "SESSION_TOUCH"))
        touch_session();
    else if (!strcmp(packet, "BIO_SET"))
        set_bio(data);
    else if (!strcmp(packet, "BIO_RESET"))
        reset_bio();
    else if (!strcmp(packet, "BIO_PRINT"))
        print_bio();
    else if (!strcmp(packet, "HELP"))
        print_help();
    else
        printf("[!] Unknown command: %s (try HELP)\n", packet);
}

int main(void)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1"); /* loopback only, never 0.0.0.0 */

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    printf("[*] Listening on 127.0.0.1:%d (UDP) - lab use only\n", LISTEN_PORT);
    print_help();

    char packet[1024];
    for (;;) {
        ssize_t n = recvfrom(sock, packet, sizeof(packet) - 1, 0, NULL, NULL);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }
        packet[n] = '\0';
        dispatch(packet);       /* attacker-controlled payload reaches the bug */
    }
}

