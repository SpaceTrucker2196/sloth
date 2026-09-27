#include "runner.h"
#include "discovery.h"
#include "observe.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* ── Routable-port classification ────────────────────────── */

static void test_routable_tcp_port(void) {
    ASSERT_EQ(discovery_routable_tcp_port("tcp:192.168.1.50:8765"), 8765);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:100.64.0.2:9000"),   9000);
}

static void test_loopback_not_routable(void) {
    ASSERT_EQ(discovery_routable_tcp_port("tcp:127.0.0.1:8765"), -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:localhost:8765"), -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:::1:8765"),       -1);
}

static void test_unix_and_malformed_not_routable(void) {
    ASSERT_EQ(discovery_routable_tcp_port("unix:/var/run/sloth.sock"), -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:192.168.1.5"), -1);   /* no port */
    ASSERT_EQ(discovery_routable_tcp_port("tcp:192.168.1.5:0"), -1); /* bad port */
    ASSERT_EQ(discovery_routable_tcp_port("garbage"), -1);
    ASSERT_EQ(discovery_routable_tcp_port(NULL), -1);
}

/* #86: the whole 127.0.0.0/8 is loopback, not just 127.0.0.1. The
 * data-socket guard binds 127.0.0.2 without --data-socket-allow-remote
 * because nothing off-host can reach it; advertising it over mDNS would
 * announce a service no client can connect to. */
static void test_whole_loopback_net_not_routable(void) {
    ASSERT_EQ(discovery_routable_tcp_port("tcp:127.0.0.2:8765"),       -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:127.1.2.3:8765"),       -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:127.255.255.254:8765"), -1);
    /* One past the /8 on either side is routable. */
    ASSERT_EQ(discovery_routable_tcp_port("tcp:126.255.255.255:8765"), 8765);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:128.0.0.1:8765"),       8765);
}

/* The wildcard binds every interface, so it is the most reachable bind
 * there is — the guard classifies it remote and discovery must agree. */
static void test_wildcard_is_routable(void) {
    ASSERT_EQ(discovery_routable_tcp_port("tcp:0.0.0.0:8765"), 8765);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:0.0.0.0:1"),    1);
}

/* #86: atoi accepted a numeric prefix, so "8765x" advertised 8765 even
 * though the binder rejects the spec outright. Every port shape the
 * binder refuses must also be refused here. */
static void test_port_parse_is_full_string(void) {
    ASSERT_EQ(discovery_routable_tcp_port("tcp:192.168.1.5:8765x"),  -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:192.168.1.5:8765 "),  -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:192.168.1.5:"),       -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:192.168.1.5:65536"),  -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:192.168.1.5:-1"),     -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:192.168.1.5:99999999999999999999"), -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:192.168.1.5:65535"),  65535);
}

/* A filesystem socket has no address to advertise, whatever its path —
 * including one whose text happens to look like host:port. */
static void test_unix_specs_never_routable(void) {
    ASSERT_EQ(discovery_routable_tcp_port("unix:/run/sloth.sock"),      -1);
    ASSERT_EQ(discovery_routable_tcp_port("unix:/tmp/10.0.0.1:8765"),   -1);
    ASSERT_EQ(discovery_routable_tcp_port("unix:"),                     -1);
    ASSERT_EQ(discovery_routable_tcp_port(""),                          -1);
}

/* Discovery must never advertise a spec the binder would not bind: a
 * hostname is not a literal the binder accepts (inet_pton only). */
static void test_non_literal_host_not_routable(void) {
    ASSERT_EQ(discovery_routable_tcp_port("tcp:sensor.lan:8765"), -1);
    ASSERT_EQ(discovery_routable_tcp_port("tcp:999.1.1.1:8765"),  -1);
}

/* ── Service XML ─────────────────────────────────────────── */

static void test_xml_contains_service_and_port(void) {
    char buf[1024];
    int n = discovery_service_xml(buf, sizeof(buf), "living-room", 8765);
    ASSERT(n > 0);
    ASSERT(strstr(buf, "<type>_sloth._tcp</type>") != NULL);
    ASSERT(strstr(buf, "<port>8765</port>") != NULL);
    ASSERT(strstr(buf, "<name>living-room</name>") != NULL);
    ASSERT(strstr(buf, "<service-group>") != NULL);
}

static void test_xml_escapes_instance(void) {
    char buf[1024];
    ASSERT(discovery_service_xml(buf, sizeof(buf), "a&b<c>", 1) > 0);
    ASSERT(strstr(buf, "a&amp;b&lt;c&gt;") != NULL);
}

static void test_xml_rejects_bad_args(void) {
    char buf[1024];
    ASSERT_EQ(discovery_service_xml(buf, sizeof(buf), "x", 0), -1);
    ASSERT_EQ(discovery_service_xml(buf, sizeof(buf), "x", 70000), -1);
    ASSERT_EQ(discovery_service_xml(NULL, 0, "x", 1), -1);
    /* Truncation: a tiny buffer can't hold the document. */
    char small[16];
    ASSERT_EQ(discovery_service_xml(small, sizeof(small), "x", 1), -1);
}

/* ── Publish / unpublish round-trip (to a temp path) ─────── */

static void test_publish_writes_and_unpublish_removes(void) {
    char path[] = "/tmp/sloth_disc_test_XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0);
    close(fd);

    /* Routable spec → file written with the advertised port. */
    ASSERT_EQ(discovery_publish("tcp:192.168.1.50:8765", path), 0);
    FILE *f = fopen(path, "r");
    ASSERT(f != NULL);
    char content[2048]; size_t got = fread(content, 1, sizeof(content) - 1, f);
    content[got] = '\0';
    fclose(f);
    ASSERT(strstr(content, "<port>8765</port>") != NULL);
    ASSERT(strstr(content, "_sloth._tcp") != NULL);

    /* Unpublish removes exactly that file. */
    discovery_unpublish();
    ASSERT(access(path, F_OK) != 0);
}

static void test_publish_skips_loopback(void) {
    char path[] = "/tmp/sloth_disc_lo_XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0);
    close(fd);
    unlink(path);   /* start absent */

    /* Loopback bind → nothing published, file stays absent. */
    ASSERT_EQ(discovery_publish("tcp:127.0.0.1:8765", path), -1);
    ASSERT(access(path, F_OK) != 0);
    discovery_unpublish();   /* safe no-op */
}

/* ── Strict observation suppresses the carve-out (#84) ───── */

static void test_strict_suppresses_publish(void) {
    char path[] = "/tmp/sloth_disc_strict_XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0);
    close(fd);
    unlink(path);   /* start absent */

    observe_reset_policy();
    observe_lock_strict();

    /* A routable bind that would otherwise publish: under --strict no
     * service file is written, so avahi-daemon never announces on
     * sloth's behalf. */
    ASSERT_EQ(discovery_publish("tcp:192.168.1.50:8765", path), -1);
    ASSERT(access(path, F_OK) != 0);

    /* Same spec, same path, lock cleared → it does publish, so the -1
     * above is the lock and not some unrelated failure. */
    observe_reset_policy();
    ASSERT_EQ(discovery_publish("tcp:192.168.1.50:8765", path), 0);
    ASSERT_EQ(access(path, F_OK), 0);

    discovery_unpublish();
    ASSERT(access(path, F_OK) != 0);
}

void run_discovery_tests(void) {
    TEST_SUITE("mDNS discovery advertisement (#29)");
    RUN_TEST(test_routable_tcp_port);
    RUN_TEST(test_loopback_not_routable);
    RUN_TEST(test_unix_and_malformed_not_routable);
    RUN_TEST(test_whole_loopback_net_not_routable);
    RUN_TEST(test_wildcard_is_routable);
    RUN_TEST(test_port_parse_is_full_string);
    RUN_TEST(test_unix_specs_never_routable);
    RUN_TEST(test_non_literal_host_not_routable);
    RUN_TEST(test_xml_contains_service_and_port);
    RUN_TEST(test_xml_escapes_instance);
    RUN_TEST(test_xml_rejects_bad_args);
    RUN_TEST(test_publish_writes_and_unpublish_removes);
    RUN_TEST(test_publish_skips_loopback);
    RUN_TEST(test_strict_suppresses_publish);
}
