#include "runner.h"
#include "discovery.h"
#include "observe.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "tmp_dir.h"

/* The service file lands in a directory sloth does not own, as root,
 * so publish goes through secure_file (#134). A fresh mkdtemp (0700,
 * euid-owned) stands in for /etc/avahi/services: it passes
 * sfile_system_dir()'s owner/mode rule, and a bare mkstemp path in a
 * 1777 /tmp — which the older tests used — is exactly what that rule
 * refuses. */
static char g_dir[TEST_TMP_MAX];
static char g_path[128];

static void fresh_dir(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/sloth_disc_XXXXXX", test_tmpdir());
    ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_path, sizeof(g_path), "%s/sloth.service", g_dir);
}

static void remove_dir(void) {
    const char *names[] = { "sloth.service", ".sloth.service.tmp",
                            "sentinel", "sentinel2", NULL };
    char p[160];
    for (int i = 0; names[i]; i++) {
        snprintf(p, sizeof(p), "%s/%s", g_dir, names[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

static int read_file(const char *path, char *buf, size_t sz) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t got = fread(buf, 1, sz - 1, f);
    buf[got] = '\0';
    fclose(f);
    return (int)got;
}

static void write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL);
    fputs(text, f);
    fclose(f);
}

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
    fresh_dir();
    /* An existing regular file at the name is replaced: re-running
     * sloth must not be refused by its own previous advertisement. */
    write_file(g_path, "stale");

    /* Routable spec → file written with the advertised port. */
    ASSERT_EQ(discovery_publish("tcp:192.168.1.50:8765", g_path), 0);
    char content[2048];
    ASSERT(read_file(g_path, content, sizeof(content)) > 0);
    ASSERT(strstr(content, "<port>8765</port>") != NULL);
    ASSERT(strstr(content, "_sloth._tcp") != NULL);

    /* 0644 on purpose: avahi-daemon runs as `avahi` and must read it.
     * A regular file, one link, no temp left behind. */
    struct stat st;
    ASSERT_EQ(lstat(g_path, &st), 0);
    ASSERT(S_ISREG(st.st_mode));
    ASSERT_EQ((int)(st.st_mode & 07777), 0644);
    ASSERT_EQ((int)st.st_nlink, 1);
    char tmp[160];
    snprintf(tmp, sizeof(tmp), "%s/.sloth.service.tmp", g_dir);
    ASSERT(access(tmp, F_OK) != 0);

    /* Unpublish removes exactly that file. */
    discovery_unpublish();
    ASSERT(access(g_path, F_OK) != 0);
    remove_dir();
}

static void test_publish_skips_loopback(void) {
    fresh_dir();
    /* Loopback bind → nothing published, file stays absent. */
    ASSERT_EQ(discovery_publish("tcp:127.0.0.1:8765", g_path), -1);
    ASSERT(access(g_path, F_OK) != 0);
    discovery_unpublish();   /* safe no-op */
    remove_dir();
}

/* ── The write is symlink-safe (#134) ─────────────────────── */

/* The bypass the issue found: fopen(out, "w") as root followed a
 * symlink planted at sloth.service and truncated its target (CWE-59).
 * Plant one pointing at a sentinel; publish must leave the sentinel
 * byte-for-byte intact and replace the LINK with a regular file.
 * Mutation-proved: with the fopen writer restored the sentinel reads
 * as the service XML and this goes red. */
static void test_publish_does_not_follow_a_planted_symlink(void) {
    fresh_dir();
    char sentinel[160];
    snprintf(sentinel, sizeof(sentinel), "%s/sentinel", g_dir);
    write_file(sentinel, "SENTINEL: must survive publish\n");
    ASSERT_EQ(symlink(sentinel, g_path), 0);

    ASSERT_EQ(discovery_publish("tcp:192.168.1.50:8765", g_path), 0);

    char content[2048];
    ASSERT(read_file(sentinel, content, sizeof(content)) > 0);
    ASSERT_STR(content, "SENTINEL: must survive publish\n");

    struct stat st;
    ASSERT_EQ(lstat(g_path, &st), 0);
    ASSERT(S_ISREG(st.st_mode));          /* the link itself is gone */
    ASSERT_EQ((int)(st.st_mode & 07777), 0644);
    ASSERT(read_file(g_path, content, sizeof(content)) > 0);
    ASSERT(strstr(content, "<port>8765</port>") != NULL);

    /* Unpublish removes the file sloth wrote and nothing else. */
    discovery_unpublish();
    ASSERT(access(g_path, F_OK) != 0);
    ASSERT_EQ(access(sentinel, F_OK), 0);
    remove_dir();
}

/* The temp name is sloth's own, so a stale one is removed before the
 * O_EXCL create — removed by name, never written through. A link
 * planted there must not reach its target either. */
static void test_publish_replaces_a_stale_tmp_without_following_it(void) {
    fresh_dir();
    char sentinel[160], tmp[160];
    snprintf(sentinel, sizeof(sentinel), "%s/sentinel2", g_dir);
    snprintf(tmp, sizeof(tmp), "%s/.sloth.service.tmp", g_dir);
    write_file(sentinel, "SENTINEL2\n");
    ASSERT_EQ(symlink(sentinel, tmp), 0);

    ASSERT_EQ(discovery_publish("tcp:192.168.1.50:8765", g_path), 0);

    char content[64];
    ASSERT(read_file(sentinel, content, sizeof(content)) > 0);
    ASSERT_STR(content, "SENTINEL2\n");
    ASSERT(access(tmp, F_OK) != 0);       /* consumed by the rename */
    struct stat st;
    ASSERT_EQ(lstat(g_path, &st), 0);
    ASSERT(S_ISREG(st.st_mode));

    discovery_unpublish();
    remove_dir();
}

/* A directory anyone can write into is refused outright, because the
 * name sloth renames onto could be replanted between its checks and
 * the rename. /tmp is the canonical case; the test makes its own 01777
 * directory with /tmp's mode rather than writing into the host's /tmp,
 * so the run directory (tests/tmp_dir.h) holds everything it touches. */
static void test_publish_refuses_a_shared_directory(void) {
    char dir[TEST_TMP_MAX], path[TEST_TMP_MAX + 32];
    test_tmp_path(dir, sizeof(dir), "sloth_disc_shared_XXXXXX");
    ASSERT(mkdtemp(dir) != NULL);
    ASSERT_EQ(chmod(dir, 01777), 0);
    snprintf(path, sizeof(path), "%s/sloth.service", dir);

    ASSERT_EQ(discovery_publish("tcp:192.168.1.50:8765", path), -1);
    ASSERT(access(path, F_OK) != 0);
    discovery_unpublish();   /* nothing to remove */
    ASSERT_EQ(rmdir(dir), 0);
}

/* ── Strict observation suppresses the carve-out (#84) ───── */

static void test_strict_suppresses_publish(void) {
    fresh_dir();
    observe_reset_policy();
    observe_lock_strict();

    /* A routable bind that would otherwise publish: under --strict no
     * service file is written, so avahi-daemon never announces on
     * sloth's behalf. */
    ASSERT_EQ(discovery_publish("tcp:192.168.1.50:8765", g_path), -1);
    ASSERT(access(g_path, F_OK) != 0);

    /* Same spec, same path, lock cleared → it does publish, so the -1
     * above is the lock and not some unrelated failure. */
    observe_reset_policy();
    ASSERT_EQ(discovery_publish("tcp:192.168.1.50:8765", g_path), 0);
    ASSERT_EQ(access(g_path, F_OK), 0);

    discovery_unpublish();
    ASSERT(access(g_path, F_OK) != 0);
    remove_dir();
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
    RUN_TEST(test_publish_does_not_follow_a_planted_symlink);
    RUN_TEST(test_publish_replaces_a_stale_tmp_without_following_it);
    RUN_TEST(test_publish_refuses_a_shared_directory);
    RUN_TEST(test_strict_suppresses_publish);
}
