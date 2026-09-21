/* Unit tests for the read-only JSONL data socket. UNIX-domain only —
 * keeps tests hermetic (no port collisions in CI). The TCP path uses
 * the same accept / write loop, so a UNIX-domain roundtrip exercises
 * the broadcast / non-blocking-write / disconnect code with equal
 * weight. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "runner.h"
#include "data_socket.h"
#include "sloth.h"
#include "jsonl.h"
#include "formatter.h"

static void ds_seed_pnl(sloth_state_t *s);

static const char *sock_path(void) {
    static char path[64];
    snprintf(path, sizeof(path), "/tmp/sloth-test-ds-%d.sock", (int)getpid());
    return path;
}

static int connect_client(const char *path) {
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    if (c < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (connect(c, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(c);
        return -1;
    }
    return c;
}

static void test_unconfigured_emit_is_noop(void) {
    /* Must not crash, must not block, must return immediately. */
    data_socket_emit("{\"type\":\"test\"}");
    ASSERT_EQ(data_socket_has_clients(), 0);
}

static void test_init_bad_spec(void) {
    ASSERT(data_socket_init(NULL)         != 0);
    ASSERT(data_socket_init("")           != 0);
    ASSERT(data_socket_init("garbage")    != 0);
    ASSERT(data_socket_init("tcp:nohost") != 0);
    ASSERT(data_socket_init("tcp:127.0.0.1:0")     != 0);
    ASSERT(data_socket_init("tcp:127.0.0.1:99999") != 0);
}

static void test_unix_roundtrip_single_client(void) {
    const char *path = sock_path();
    char spec[80];
    snprintf(spec, sizeof(spec), "unix:%s", path);

    ASSERT_EQ(data_socket_init(spec), 0);

    int c = connect_client(path);
    ASSERT(c >= 0);

    data_socket_tick();
    ASSERT_EQ(data_socket_has_clients(), 1);

    data_socket_emit("{\"type\":\"dns\",\"qname\":\"example.com\"}");

    char buf[128];
    ssize_t n = read(c, buf, sizeof(buf) - 1);
    ASSERT(n > 0);
    buf[n] = '\0';
    /* The emitter must append a trailing '\n' so consumers can frame. */
    ASSERT_STR(buf, "{\"type\":\"dns\",\"qname\":\"example.com\"}\n");

    close(c);
    data_socket_cleanup();
    /* Cleanup must unlink the socket path. */
    ASSERT(access(path, F_OK) != 0);
}

static void test_unix_broadcast_to_multiple_clients(void) {
    const char *path = sock_path();
    char spec[80];
    snprintf(spec, sizeof(spec), "unix:%s", path);
    ASSERT_EQ(data_socket_init(spec), 0);

    int a = connect_client(path);
    int b = connect_client(path);
    ASSERT(a >= 0 && b >= 0);

    data_socket_tick();
    ASSERT_EQ(data_socket_has_clients(), 1);   /* "any clients?" — yes */

    data_socket_emit("hello");

    char buf_a[16] = {0}, buf_b[16] = {0};
    ASSERT_EQ(read(a, buf_a, sizeof(buf_a) - 1), 6);   /* "hello\n" */
    ASSERT_EQ(read(b, buf_b, sizeof(buf_b) - 1), 6);
    ASSERT_STR(buf_a, "hello\n");
    ASSERT_STR(buf_b, "hello\n");

    close(a); close(b);
    data_socket_cleanup();
}

static void test_disconnected_client_is_harvested(void) {
    const char *path = sock_path();
    char spec[80];
    snprintf(spec, sizeof(spec), "unix:%s", path);
    ASSERT_EQ(data_socket_init(spec), 0);

    int c = connect_client(path);
    ASSERT(c >= 0);
    data_socket_tick();
    ASSERT_EQ(data_socket_has_clients(), 1);

    /* Client disconnects abruptly. The next emit must reap the fd
     * (EPIPE on send) so subsequent has_clients() reports 0. */
    close(c);
    /* Two emits: first triggers EPIPE and reap; second confirms
     * nobody is left. */
    data_socket_emit("first");
    data_socket_emit("second");
    ASSERT_EQ(data_socket_has_clients(), 0);

    data_socket_cleanup();
}

/* Empty payload must be a no-op (line 175 `if (len == 0) return;`).
 * Mutating the `0` constant or the comparison would either short-
 * circuit a real send, or send a bare newline that downstream
 * consumers would treat as a corrupt frame. We verify by emitting
 * "" then a real line and checking only the real line arrives. */
static void test_emit_empty_payload_is_skipped(void) {
    const char *path = sock_path();
    char spec[80];
    snprintf(spec, sizeof(spec), "unix:%s", path);
    ASSERT_EQ(data_socket_init(spec), 0);

    int c = connect_client(path);
    ASSERT(c >= 0);
    data_socket_tick();

    data_socket_emit("");      /* must NOT send anything */
    data_socket_emit("hello"); /* must send "hello\n" */

    char buf[16] = {0};
    ssize_t n = read(c, buf, sizeof(buf) - 1);
    ASSERT(n > 0);
    buf[n] = '\0';
    /* If the empty emit had leaked a "\n", buf would start with "\n";
     * the explicit string compare catches that. */
    ASSERT_STR(buf, "hello\n");

    close(c);
    data_socket_cleanup();
}

/* ── Fault-injection (via data_socket_test_set_*_fn hooks) ─────── */

/* Toggleable fakes used by the fault-injection tests below.
 * Each test sets `g_fake_*_mode` to choose its behaviour, then
 * installs the fake via the hook. `errno` is set so the production
 * code path's EAGAIN / EPIPE classification fires correctly. */
static int g_fake_send_mode  = 0;    /* 0=passthrough, 1=EAGAIN, 2=partial, 3=zero */
static int g_fake_send_calls = 0;
static int g_fake_partial_n  = 3;

static ssize_t fake_send(int fd, const void *buf, size_t len, int flags) {
    g_fake_send_calls++;
    switch (g_fake_send_mode) {
    case 1:                          /* EAGAIN — slow client */
        errno = EAGAIN;
        return -1;
    case 2:                          /* partial write (truncated) */
        return g_fake_partial_n < (ssize_t)len ? g_fake_partial_n : (ssize_t)len;
    case 3:                          /* zero — pretend connection went away */
        errno = ECONNRESET;
        return 0;
    default:
        return send(fd, buf, len, flags);
    }
}

/* Drain everything sloth will write to `c`, ticking between reads so
 * queued bytes get flushed as the socket buffer empties. Stops after a
 * few rounds with no new bytes. Returns bytes read; buf is NUL-ended. */
static size_t drain_client(int c, char *buf, size_t cap) {
    int fl = fcntl(c, F_GETFL, 0);
    fcntl(c, F_SETFL, fl | O_NONBLOCK);
    size_t got = 0;
    int idle = 0;
    while (idle < 3 && got + 1 < cap) {
        ssize_t n = read(c, buf + got, cap - 1 - got);
        if (n > 0) { got += (size_t)n; idle = 0; continue; }
        if (n == 0) break;                       /* EOF — sloth closed us */
        data_socket_tick();
        idle++;
    }
    buf[got] = '\0';
    fcntl(c, F_SETFL, fl);
    return got;
}

static int count_prefix_lines(const char *buf, const char *prefix) {
    int n = 0;
    size_t pl = strlen(prefix);
    for (const char *p = buf; *p; ) {
        if (strncmp(p, prefix, pl) == 0) n++;
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return n;
}

/* ── #93: framing under backpressure ──────────────────────────
 *
 * A pass-through fake that really writes to the client socket but lets
 * the test cap how much gets through: a byte budget (then `io_block`
 * errno), a per-call chunk size, and an errno value planted on every
 * *successful* return so a writer that reads errno after a positive
 * short write sees a stale value. */
static long io_budget     = -1;        /* bytes still allowed; -1 = no cap */
static size_t io_chunk    = 0;         /* max bytes per call; 0 = no cap */
static int  io_block      = EAGAIN;    /* errno once the budget is spent */
static int  io_stale      = 0;         /* errno planted on success */
static int  io_calls      = 0;
static int  io_eintr      = 0;         /* next N calls fail with EINTR */

static void io_reset(void) {
    io_budget = -1; io_chunk = 0; io_block = EAGAIN; io_stale = 0; io_calls = 0;
    io_eintr = 0;
}

static ssize_t io_send(int fd, const void *buf, size_t len, int flags) {
    io_calls++;
    if (io_eintr > 0) { io_eintr--; errno = EINTR; return -1; }
    size_t n = len;
    if (io_chunk && n > io_chunk) n = io_chunk;
    if (io_budget >= 0) {
        if (io_budget == 0) { errno = io_block; return -1; }
        if ((long)n > io_budget) n = (size_t)io_budget;
    }
    ssize_t r = send(fd, buf, n, flags);
    if (r > 0) {
        if (io_budget >= 0) io_budget -= r;
        errno = io_stale;
    }
    return r;
}

static time_t io_now = 1000;
static time_t io_clock(void) { return io_now; }

static int ds_open_one(void) {
    const char *path = sock_path();
    char spec[80]; snprintf(spec, sizeof(spec), "unix:%s", path);
    if (data_socket_init(spec) != 0) return -1;
    int c = connect_client(path);
    data_socket_tick();
    return c;
}

static void ds_close_one(int c) {
    data_socket_test_set_send_fn(NULL);
    data_socket_test_set_clock_fn(NULL);
    io_reset();
    if (c >= 0) close(c);
    data_socket_cleanup();
}

/* The issue's exact sequence: record A's payload is accepted, its
 * delimiter hits EAGAIN, record B arrives. The old writer sent "\n" as
 * its own send() and forgot it, so the consumer saw `AB\n`. */
static void test_delimiter_eagain_then_next_record(void) {
    io_reset();
    int c = ds_open_one();
    ASSERT(c >= 0);
    data_socket_test_set_send_fn(io_send);

    io_budget = (long)strlen("{\"a\":1}");     /* payload fits, '\n' blocks */
    data_socket_emit("{\"a\":1}");
    ASSERT_EQ(data_socket_has_clients(), 1);

    io_budget = -1;                            /* client drains again */
    data_socket_emit("{\"b\":2}");

    char buf[64];
    drain_client(c, buf, sizeof(buf));
    ASSERT_STR(buf, "{\"a\":1}\n{\"b\":2}\n");
    ds_close_one(c);
}

/* A positive short write leaves errno untouched. A writer that tests
 * errno without checking for a negative return sees whatever was there
 * — here a planted EAGAIN — and abandons a half-written record. */
static void test_short_write_with_stale_errno(void) {
    io_reset();
    int c = ds_open_one();
    ASSERT(c >= 0);
    data_socket_test_set_send_fn(io_send);

    io_chunk = 3;
    io_stale = EAGAIN;
    data_socket_emit("long-payload");
    ASSERT_EQ(data_socket_has_clients(), 1);
    data_socket_emit("next");

    char buf[64];
    drain_client(c, buf, sizeof(buf));
    ASSERT_STR(buf, "long-payload\nnext\n");
    ds_close_one(c);
}

/* EINTR is a signal landing mid-call, not a verdict on the peer:
 * retry at once, keep the client, deliver the record intact. */
static void test_eintr_is_retried(void) {
    io_reset();
    int c = ds_open_one();
    ASSERT(c >= 0);
    data_socket_test_set_send_fn(io_send);

    io_eintr = 2;
    data_socket_emit("{\"sig\":1}");
    ASSERT_EQ(data_socket_has_clients(), 1);
    ASSERT_EQ(io_calls, 3);

    char buf[32];
    drain_client(c, buf, sizeof(buf));
    ASSERT_STR(buf, "{\"sig\":1}\n");
    ds_close_one(c);
}

/* A record that has started and then hits a terminal error cannot be
 * completed: the client is closed, and nothing else is written after
 * the prefix — the consumer sees an unterminated tail, then EOF. */
static void test_terminal_error_mid_record_disconnects(void) {
    io_reset();
    int c = ds_open_one();
    ASSERT(c >= 0);
    data_socket_test_set_send_fn(io_send);

    io_budget = 4;
    io_block  = EPIPE;
    data_socket_emit("abcdefgh");
    ASSERT_EQ(data_socket_has_clients(), 0);
    data_socket_emit("never");

    char buf[64];
    drain_client(c, buf, sizeof(buf));
    ASSERT_STR(buf, "abcd");
    ds_close_one(c);
}

/* A client that drops mid-record leaves nothing behind: the next client
 * starts on a record boundary, and (#47) gets the baseline again. */
static void test_reconnect_gets_clean_baseline(void) {
    io_reset();
    int a = ds_open_one();
    ASSERT(a >= 0);
    sloth_state_t s; ds_seed_pnl(&s);
    jsonl_emit_pnl_clients(&s);                /* A sees it; cache primed */
    char buf[4096];
    drain_client(a, buf, sizeof(buf));
    ASSERT_EQ(count_prefix_lines(buf, "{\"type\":\"pnl_client\""), 1);

    data_socket_test_set_send_fn(io_send);
    io_budget = 5;
    data_socket_emit("{\"half\":\"record\"}");  /* A stuck mid-record */
    close(a);                                  /* ...and gives up */
    io_budget = -1;
    data_socket_emit("{\"reap\":1}");          /* EPIPE reaps A */
    ASSERT_EQ(data_socket_has_clients(), 0);

    int b = connect_client(sock_path());
    ASSERT(b >= 0);
    data_socket_tick();                        /* accept → cache reset */
    jsonl_emit_pnl_clients(&s);                /* unchanged, but new sink */
    drain_client(b, buf, sizeof(buf));
    ASSERT(strncmp(buf, "{\"type\":\"pnl_client\"", 20) == 0);
    ASSERT_EQ(count_prefix_lines(buf, "{\"type\":\"pnl_client\""), 1);
    ASSERT(strstr(buf, "half") == NULL);
    ASSERT(strstr(buf, "socket_gap") == NULL);
    ASSERT(buf[strlen(buf) - 1] == '\n');
    ds_close_one(b);
}

/* Queue full: only whole, not-yet-started records are dropped, the
 * drop is counted, and the next delivered record is preceded by a
 * socket_gap marker whose `seq` reconciles received + dropped. */
#define OVF_REC   1000u                         /* payload bytes */
#define OVF_N     600
static char *overflow_then_drain(int c, unsigned long long *dropped) {
    static char rec[OVF_REC + 1];
    unsigned long long before = data_socket_dropped_total();
    data_socket_test_set_send_fn(io_send);
    io_budget = 0;                             /* peer never drains */
    for (int i = 0; i < OVF_N; i++) {
        int k = snprintf(rec, sizeof(rec), "{\"n\":%d,\"pad\":\"", i);
        memset(rec + k, 'x', OVF_REC - (size_t)k - 2);
        memcpy(rec + OVF_REC - 2, "\"}", 3);
        data_socket_emit(rec);
    }
    *dropped = data_socket_dropped_total() - before;
    ASSERT_EQ(data_socket_has_clients(), 1);

    io_budget = -1;                            /* peer drains again */
    data_socket_emit("{\"tail\":1}");
    size_t cap = 2u * DATA_SOCKET_QUEUE_MAX;
    char *buf = malloc(cap);
    if (buf) drain_client(c, buf, cap);
    return buf;
}

static void test_queue_overflow_counts_drops(void) {
    io_reset();
    int c = ds_open_one();
    ASSERT(c >= 0);
    unsigned long long dropped = 0;
    char *buf = overflow_then_drain(c, &dropped);
    ASSERT(buf != NULL);
    if (!buf) { ds_close_one(c); return; }

    int fit = (int)(DATA_SOCKET_QUEUE_MAX / (OVF_REC + 1));
    ASSERT_EQ((long long)dropped, (long long)(OVF_N - fit));
    ASSERT_EQ(count_prefix_lines(buf, "{\"n\":"), fit);
    ASSERT_EQ(count_prefix_lines(buf, "{\"type\":\"socket_gap\""), 1);

    /* Every line is a whole record: no line holds two, none is cut. */
    int bad = 0;
    for (char *p = buf; *p; ) {
        char *nl = strchr(p, '\n');
        if (!nl) { bad++; break; }
        if (*p != '{' || nl[-1] != '}') bad++;
        if (strstr(p, "}{") && strstr(p, "}{") < nl) bad++;
        p = nl + 1;
    }
    ASSERT_EQ(bad, 0);

    char want[128];
    snprintf(want, sizeof(want), "\"seq\":%d,\"dropped\":%d,\"dropped_total\":%d}",
             OVF_N, OVF_N - fit, OVF_N - fit);
    char *gap = strstr(buf, "{\"type\":\"socket_gap\"");
    ASSERT(gap != NULL);
    ASSERT(gap && strstr(gap, want) != NULL);
    /* Marker comes after the last delivered record, before the tail. */
    ASSERT(gap && strstr(gap, "{\"tail\":1}\n") != NULL);
    ASSERT(gap && strstr(gap, "{\"n\":") == NULL);
    free(buf);
    ds_close_one(c);
}

/* The marker is a record like any other: in --out-format cef it is
 * CEF too, so a CEF consumer never sees a stray JSON line. */
static void test_gap_marker_follows_out_format(void) {
    io_reset();
    int c = ds_open_one();
    ASSERT(c >= 0);
    formatter_set(OUT_FMT_CEF);
    unsigned long long dropped = 0;
    char *buf = overflow_then_drain(c, &dropped);
    formatter_set(OUT_FMT_JSONL);
    ASSERT(buf != NULL);
    if (!buf) { ds_close_one(c); return; }
    ASSERT(dropped > 0);
    ASSERT_EQ(count_prefix_lines(buf, "CEF:0|sloth-net|sloth|1|socket_gap|"), 1);
    ASSERT(strstr(buf, "{\"type\":\"socket_gap\"") == NULL);
    free(buf);
    ds_close_one(c);
}

/* A peer that stops reading is not guaranteed to ever EPIPE. Once it
 * has accepted nothing for DATA_SOCKET_STALL_SECS it is closed. */
static void test_stalled_client_is_disconnected(void) {
    io_reset();
    int c = ds_open_one();
    ASSERT(c >= 0);
    data_socket_test_set_clock_fn(io_clock);
    data_socket_test_set_send_fn(io_send);

    io_now = 1000;
    data_socket_tick();
    io_now = 1000 + 10 * DATA_SOCKET_STALL_SECS;   /* idle, nothing queued */
    data_socket_tick();
    ASSERT_EQ(data_socket_has_clients(), 1);

    io_budget = 0;
    data_socket_emit("{\"stuck\":1}");           /* queued at t0 */
    time_t t0 = io_now;
    io_now = t0 + DATA_SOCKET_STALL_SECS - 1;
    data_socket_tick();
    ASSERT_EQ(data_socket_has_clients(), 1);
    io_now = t0 + DATA_SOCKET_STALL_SECS;
    data_socket_tick();
    ASSERT_EQ(data_socket_has_clients(), 0);
    ds_close_one(c);
}

/* A slow client that is still making progress keeps its connection:
 * the stall clock restarts on every byte the kernel accepts. */
static void test_slow_client_progress_resets_stall(void) {
    io_reset();
    int c = ds_open_one();
    ASSERT(c >= 0);
    data_socket_test_set_clock_fn(io_clock);
    data_socket_test_set_send_fn(io_send);

    io_now = 5000;
    io_budget = 0;
    data_socket_emit("{\"slow\":1}");
    io_now = 5000 + DATA_SOCKET_STALL_SECS - 5;
    io_budget = 2;                                /* two bytes get through */
    data_socket_tick();
    io_now = 5000 + DATA_SOCKET_STALL_SECS + 5;   /* 30+ since queued ... */
    data_socket_tick();
    ASSERT_EQ(data_socket_has_clients(), 1);      /* ... but not since progress */
    io_now = 5000 + 2 * DATA_SOCKET_STALL_SECS - 5;
    data_socket_tick();
    ASSERT_EQ(data_socket_has_clients(), 0);
    ds_close_one(c);
}

/* An EAGAIN on an untouched record keeps the client and queues the
 * record whole. Only one send() for payload + delimiter together. */
static void test_send_eagain_keeps_client(void) {
    const char *path = sock_path();
    char spec[80]; snprintf(spec, sizeof(spec), "unix:%s", path);
    ASSERT_EQ(data_socket_init(spec), 0);
    int c = connect_client(path);
    ASSERT(c >= 0);
    data_socket_tick();
    ASSERT_EQ(data_socket_has_clients(), 1);

    g_fake_send_mode  = 1;            /* EAGAIN */
    g_fake_send_calls = 0;
    data_socket_test_set_send_fn(fake_send);

    data_socket_emit("queued");       /* fake send fails with EAGAIN */

    /* Slow-client branch: client kept, no close, no compact. */
    ASSERT_EQ(data_socket_has_clients(), 1);
    /* One send() for payload and delimiter together: a second call for
     * the '\n' is exactly the split #93 removed. */
    ASSERT_EQ(g_fake_send_calls, 1);

    /* Restore: the queued record goes out first, whole, then the new
     * one — nothing lost, nothing glued together. */
    data_socket_test_set_send_fn(NULL);
    data_socket_emit("ok");
    char buf[32];
    drain_client(c, buf, sizeof(buf));
    ASSERT_STR(buf, "queued\nok\n");

    close(c);
    data_socket_cleanup();
}

/* A positive short send() is progress, not failure: the writer loops
 * from the new offset until the record is out. 13 bytes ("long-payload"
 * + '\n') at 3 per call is exactly 5 calls; fewer means a tail was
 * abandoned, more means bytes were re-sent. */
static void test_send_partial_is_resumed(void) {
    const char *path = sock_path();
    char spec[80]; snprintf(spec, sizeof(spec), "unix:%s", path);
    ASSERT_EQ(data_socket_init(spec), 0);
    int c = connect_client(path);
    ASSERT(c >= 0);
    data_socket_tick();
    ASSERT_EQ(data_socket_has_clients(), 1);

    g_fake_send_mode  = 2;          /* return 3 bytes for any size */
    g_fake_partial_n  = 3;
    g_fake_send_calls = 0;
    data_socket_test_set_send_fn(fake_send);

    data_socket_emit("long-payload");
    ASSERT_EQ(data_socket_has_clients(), 1);
    ASSERT_EQ(g_fake_send_calls, 5);

    /* send() returning 0 for a non-empty buffer is not progress and
     * would spin forever: terminal, client closed. */
    g_fake_send_mode = 3;
    data_socket_emit("gone");
    ASSERT_EQ(data_socket_has_clients(), 0);

    data_socket_test_set_send_fn(NULL);
    g_fake_send_mode = 0;
    close(c);
    data_socket_cleanup();
}

/* Kills the `accept` overflow-guard mutations on line 158
 * (`while (g_client_n < MAX_CLIENTS)`): with the guard intact,
 * a fake accept that always returns a fresh fd should be drained
 * exactly MAX_CLIENTS times — not less, not more. */
static int  g_fake_accept_calls   = 0;
static int  g_fake_accept_max     = 0;   /* return at most this many fds */

static int fake_accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)addr; (void)addrlen;
    g_fake_accept_calls++;
    if (g_fake_accept_calls > g_fake_accept_max) {
        errno = EAGAIN;
        return -1;
    }
    /* Return an arbitrary "valid" fd by duplicating stderr — the test
     * never actually reads/writes through these, only the bookkeeping
     * matters. We close them in cleanup. */
    return dup(fd);
}

static void test_tick_caps_at_max_clients(void) {
    const char *path = sock_path();
    char spec[80]; snprintf(spec, sizeof(spec), "unix:%s", path);
    ASSERT_EQ(data_socket_init(spec), 0);

    g_fake_accept_calls = 0;
    g_fake_accept_max   = 100;        /* fake will "accept" forever */
    data_socket_test_set_accept_fn(fake_accept);

    data_socket_tick();

    /* The while-loop stops drainage at MAX_CLIENTS (= 16). The fake
     * was called exactly 16 times (each returning a fresh fd), then
     * the guard exits the loop. Not 15, not 17. */
    ASSERT_EQ(g_fake_accept_calls, 16);
    ASSERT_EQ(data_socket_has_clients(), 1);

    data_socket_test_set_accept_fn(NULL);
    data_socket_cleanup();
}

/* When a client in the MIDDLE of the array disconnects, the emit
 * loop must compact via swap-with-last (drop_client():
 * `g_clients[i] = g_clients[--g_client_n]`) so the surviving
 * client at the end keeps receiving. Without compaction, either
 * (a) the disconnected fd stays in the array and breaks all
 * subsequent sends, or (b) the array shifts and we double-skip
 * the swapped-in fd. Either way a subsequent emit fails to reach
 * the still-connected client. */
static void test_middle_client_disconnect_compacts(void) {
    const char *path = sock_path();
    char spec[80];
    snprintf(spec, sizeof(spec), "unix:%s", path);
    ASSERT_EQ(data_socket_init(spec), 0);

    int a = connect_client(path);
    int b = connect_client(path);
    int c = connect_client(path);
    ASSERT(a >= 0 && b >= 0 && c >= 0);
    data_socket_tick();

    /* B disconnects; A and C remain. */
    close(b);

    /* First emit triggers EPIPE on B's slot and compacts. */
    data_socket_emit("post-drop");

    /* Drain A and C — both must have received "post-drop\n".
     * (The order of accept is arbitrary; we just need both alive
     * fds to see the bytes.) */
    char buf_a[32] = {0}, buf_c[32] = {0};
    ssize_t na = read(a, buf_a, sizeof(buf_a) - 1);
    ssize_t nc = read(c, buf_c, sizeof(buf_c) - 1);
    ASSERT(na > 0);
    ASSERT(nc > 0);
    buf_a[na] = '\0'; buf_c[nc] = '\0';
    ASSERT(strcmp(buf_a, "post-drop\n") == 0);
    ASSERT(strcmp(buf_c, "post-drop\n") == 0);

    /* A second emit confirms both fds are still healthy after the
     * compaction step (i.e. neither was accidentally closed). */
    data_socket_emit("alive");
    char buf2_a[16] = {0}, buf2_c[16] = {0};
    ASSERT(read(a, buf2_a, sizeof(buf2_a) - 1) == 6);
    ASSERT(read(c, buf2_c, sizeof(buf2_c) - 1) == 6);
    ASSERT_STR(buf2_a, "alive\n");
    ASSERT_STR(buf2_c, "alive\n");

    close(a); close(c);
    data_socket_cleanup();
}

/* ── accept → change-cache baseline (issue #47) ──────────────
 *
 * A client that connects mid-run is a fresh sink: it never saw the rows
 * the change-only cache (#42) is suppressing. These use the file sink to
 * count what a snapshot pass actually emits — the socket client is a
 * dup'd fd nothing reads, only its acceptance matters. */

static char ds_jsonl_path[] = "/tmp/sloth_ds_jsonl_XXXXXX";

static void ds_open_jsonl(void) {
    int fd = mkstemp(ds_jsonl_path);
    if (fd >= 0) close(fd);
    jsonl_close();
    FILE *fp = fopen(ds_jsonl_path, "w"); if (fp) fclose(fp);
    ASSERT(jsonl_open(ds_jsonl_path));
}

static int ds_jsonl_lines(void) {
    FILE *fp = fopen(ds_jsonl_path, "r");
    if (!fp) return -1;
    int n = 0, c, last = '\n';
    while ((c = fgetc(fp)) != EOF) { if (c == '\n') n++; last = c; }
    if (last != '\n') n++;      /* unterminated trailing line still counts */
    fclose(fp);
    return n;
}

static void ds_seed_pnl(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    s->pnl_clients[0].mac[0]      = 0x02;
    s->pnl_clients[0].mac[5]      = 0x47;
    snprintf(s->pnl_clients[0].ssids[0],
             sizeof(s->pnl_clients[0].ssids[0]), "HomeNet");
    s->pnl_clients[0].ssid_count  = 1;
    s->pnl_clients[0].probe_count = 3;
    s->pnl_clients[0].last_seen   = 1700000000;
    s->pnl_count = 1;
}

/* The regression: without the reset the third pass stays suppressed and
 * the just-connected client never learns this device exists. */
static void test_accept_reemits_baseline(void) {
    const char *path = sock_path();
    char spec[80]; snprintf(spec, sizeof(spec), "unix:%s", path);
    ASSERT_EQ(data_socket_init(spec), 0);

    sloth_state_t s; ds_seed_pnl(&s);
    ds_open_jsonl();
    jsonl_emit_pnl_clients(&s);      /* new → 1 line */
    jsonl_emit_pnl_clients(&s);      /* unchanged → suppressed */
    ASSERT_EQ(ds_jsonl_lines(), 1);

    g_fake_accept_calls = 0;
    g_fake_accept_max   = 1;         /* exactly one client connects */
    data_socket_test_set_accept_fn(fake_accept);
    data_socket_tick();
    data_socket_test_set_accept_fn(NULL);

    jsonl_emit_pnl_clients(&s);      /* still unchanged — but new sink */
    ASSERT_EQ(ds_jsonl_lines(), 2);

    jsonl_close();
    unlink(ds_jsonl_path);
    data_socket_cleanup();
}

/* The control that keeps the fix honest: a tick that accepts nobody must
 * leave the cache alone. Resetting unconditionally would also pass the
 * test above while re-emitting the entire baseline every poll cycle —
 * exactly the volume #42 removed. */
static void test_tick_without_accept_keeps_cache(void) {
    const char *path = sock_path();
    char spec[80]; snprintf(spec, sizeof(spec), "unix:%s", path);
    ASSERT_EQ(data_socket_init(spec), 0);

    sloth_state_t s; ds_seed_pnl(&s);
    ds_open_jsonl();
    jsonl_emit_pnl_clients(&s);      /* new → 1 line */

    g_fake_accept_calls = 0;
    g_fake_accept_max   = 0;         /* fake immediately returns EAGAIN */
    data_socket_test_set_accept_fn(fake_accept);
    data_socket_tick();
    data_socket_tick();
    data_socket_test_set_accept_fn(NULL);

    jsonl_emit_pnl_clients(&s);      /* unchanged, no new sink → silent */
    ASSERT_EQ(ds_jsonl_lines(), 1);

    jsonl_close();
    unlink(ds_jsonl_path);
    data_socket_cleanup();
}

/* Every accept is a fresh sink, including the second and later ones —
 * a tailer that reconnects after a crash must get its baseline even
 * though other clients are already attached. */
static void test_second_client_also_reemits(void) {
    const char *path = sock_path();
    char spec[80]; snprintf(spec, sizeof(spec), "unix:%s", path);
    ASSERT_EQ(data_socket_init(spec), 0);

    sloth_state_t s; ds_seed_pnl(&s);
    ds_open_jsonl();

    g_fake_accept_calls = 0;
    g_fake_accept_max   = 1;
    data_socket_test_set_accept_fn(fake_accept);
    data_socket_tick();                  /* client A */
    jsonl_emit_pnl_clients(&s);          /* new → 1 line */
    jsonl_emit_pnl_clients(&s);          /* unchanged → suppressed */
    ASSERT_EQ(ds_jsonl_lines(), 1);

    g_fake_accept_calls = 0;
    g_fake_accept_max   = 1;
    data_socket_tick();                  /* client B joins */
    data_socket_test_set_accept_fn(NULL);

    jsonl_emit_pnl_clients(&s);
    ASSERT_EQ(ds_jsonl_lines(), 2);

    jsonl_close();
    unlink(ds_jsonl_path);
    data_socket_cleanup();
}

void run_data_socket_tests(void) {
    TEST_SUITE("data socket (read-only JSONL stream)");
    RUN_TEST(test_unconfigured_emit_is_noop);
    RUN_TEST(test_init_bad_spec);
    RUN_TEST(test_unix_roundtrip_single_client);
    RUN_TEST(test_unix_broadcast_to_multiple_clients);
    RUN_TEST(test_disconnected_client_is_harvested);
    RUN_TEST(test_emit_empty_payload_is_skipped);
    RUN_TEST(test_middle_client_disconnect_compacts);

    TEST_SUITE("data socket (fault injection)");
    RUN_TEST(test_send_eagain_keeps_client);
    RUN_TEST(test_send_partial_is_resumed);
    RUN_TEST(test_tick_caps_at_max_clients);

    TEST_SUITE("data socket (record framing under backpressure, #93)");
    RUN_TEST(test_delimiter_eagain_then_next_record);
    RUN_TEST(test_short_write_with_stale_errno);
    RUN_TEST(test_eintr_is_retried);
    RUN_TEST(test_terminal_error_mid_record_disconnects);
    RUN_TEST(test_reconnect_gets_clean_baseline);
    RUN_TEST(test_queue_overflow_counts_drops);
    RUN_TEST(test_gap_marker_follows_out_format);
    RUN_TEST(test_stalled_client_is_disconnected);
    RUN_TEST(test_slow_client_progress_resets_stall);

    TEST_SUITE("data socket (accept → baseline re-emit, #47)");
    RUN_TEST(test_accept_reemits_baseline);
    RUN_TEST(test_tick_without_accept_keeps_cache);
    RUN_TEST(test_second_client_also_reemits);
}
