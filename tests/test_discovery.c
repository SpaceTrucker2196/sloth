#include "runner.h"
#include "discovery.h"
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

void run_discovery_tests(void) {
    TEST_SUITE("mDNS discovery advertisement (#29)");
    RUN_TEST(test_routable_tcp_port);
    RUN_TEST(test_loopback_not_routable);
    RUN_TEST(test_unix_and_malformed_not_routable);
    RUN_TEST(test_xml_contains_service_and_port);
    RUN_TEST(test_xml_escapes_instance);
    RUN_TEST(test_xml_rejects_bad_args);
    RUN_TEST(test_publish_writes_and_unpublish_removes);
    RUN_TEST(test_publish_skips_loopback);
}
