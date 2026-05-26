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

void run_data_socket_tests(void) {
    TEST_SUITE("data socket (read-only JSONL stream)");
    RUN_TEST(test_unconfigured_emit_is_noop);
    RUN_TEST(test_init_bad_spec);
    RUN_TEST(test_unix_roundtrip_single_client);
    RUN_TEST(test_unix_broadcast_to_multiple_clients);
    RUN_TEST(test_disconnected_client_is_harvested);
}
