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
#include <sys/socket.h>
#include <sys/un.h>

#include "runner.h"
#include "data_socket.h"

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

/* Kills the EAGAIN/EWOULDBLOCK slow-client branch (line 190):
 * `if (errno == EAGAIN || errno == EWOULDBLOCK) { i++; continue; }`.
 * If the `||` mutated to `&&`, EAGAIN (without EWOULDBLOCK) would
 * fall through to the close-and-compact path; client_n would drop. */
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

    data_socket_emit("dropped");      /* fake send fails with EAGAIN */

    /* Slow-client branch: client kept, no close, no compact. */
    ASSERT_EQ(data_socket_has_clients(), 1);
    /* Just one send call (the first `n1`); the second `\n` send is
     * gated by the success of the first. */
    ASSERT_EQ(g_fake_send_calls, 1);

    /* Restore and confirm the client is still usable. */
    data_socket_test_set_send_fn(NULL);
    data_socket_emit("ok");
    char buf[16] = {0};
    ssize_t n = read(c, buf, sizeof(buf) - 1);
    ASSERT(n > 0);
    buf[n] = '\0';
    ASSERT_STR(buf, "ok\n");

    close(c);
    data_socket_cleanup();
}

/* Kills the partial-send check (line 184: `int ok = (n1 == len);`):
 * a fake that returns fewer bytes than asked must trigger the
 * close-and-compact branch — the client is broken from our side. */
static void test_send_partial_harvests_client(void) {
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
    errno = 0;                       /* not EAGAIN — force the harvest path */
    data_socket_test_set_send_fn(fake_send);

    data_socket_emit("long-payload"); /* len=12, fake returns 3 */

    /* Partial send → ok=false → not EAGAIN → close + compact. */
    ASSERT_EQ(data_socket_has_clients(), 0);

    data_socket_test_set_send_fn(NULL);
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
 * loop must compact via swap-with-last (line 200:
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
    RUN_TEST(test_send_partial_harvests_client);
    RUN_TEST(test_tick_caps_at_max_clients);
}
