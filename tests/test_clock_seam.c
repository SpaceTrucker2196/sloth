#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth_clock.h"
#include "flood_window.h"

/* The clock seam (#109) and the migration off direct libc clock calls.
 *
 * A module that reads time(NULL) or clock_gettime() itself is one a
 * test cannot drive: its TTLs and windows age only in real time, and a
 * value stamped through the seam compared against one read from libc
 * is the exact bug the taint TTL had. The list below names the files
 * that have moved; it grows one commit at a time and the test fails
 * naming the file that regressed. Same shape as the Makefile and
 * main.c scrapers in test_docs_consistency.c: read the source, count,
 * assert. */

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

/* Occurrences of needle in hay, comments included: a comment quoting
 * the call reads as a call, and the file's own prose can say "libc
 * clock" instead. Strict beats clever here. */
static int cs_count(const char *hay, const char *needle) {
    int n = 0;
    size_t len = strlen(needle);
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += len) n++;
    return n;
}

/* Files that read only sloth_wall() / sloth_mono_ms(). src/sloth_clock.c
 * is the one place the libc calls belong and is deliberately absent. */
static const char *const cs_migrated[] = {
    "src/alerts/engine.c",
    "src/alerts/rules_mle.c",
    "src/alerts/rules_enterprise.c",
    "src/alerts/rules_wired.c",
    "src/alerts/rules_wifi_mgmt.c",
    "src/alerts/rules_twin.c",
    "src/flood_window.c",
    "src/alert_pcap.c",
    "src/dns.c",
    "src/cleartext_creds.c",
    "src/top_hosts.c",
    "src/seqnum_track.c",
    "src/assoc_track.c",
    "src/poll.c",
    "src/smtp_snoop.c",
    "src/smb_snoop.c",
    "src/kerb_snoop.c",
    "src/rdp_snoop.c",
    "src/ldap_snoop.c",
    "src/karma_detect.c",
    "src/dhcp_snoop.c",
    "src/nbns_snoop.c",
    "src/bgp_snoop.c",
    "src/probe_pnl.c",
    "src/ndp_snoop.c",
    "src/quic_log.c",
    "src/mqtt_snoop.c",
    "src/mdns_snoop.c",
    "src/posture.c",
    "src/devices.c",
    "src/tls_log.c",
    "src/formatter.c",
    "src/pcap_write.c",
    "src/snmp_snoop.c",
    "src/ssh_snoop.c",
    "src/ssdp_snoop.c",
    "src/scan.c",
    "src/http_log.c",
    "src/icmp_log.c",
    "src/twins.c",
    "src/ntp_log.c",
    "src/dns_log.c",
    "src/onvif_discovery.c",
    "src/tui.c",
    "src/platform/linux_wifi.c",
    "src/platform/linux.c",
    "src/platform/bsd.c",
    "src/data_socket.c",
    "src/bandwidth.c",
};

/* The counter must see calls before its zero means anything. */
static void test_counter_sees_direct_clock_calls(void) {
    static const char src[] =
        "    time_t now = time(NULL);\n"
        "    /* was time(NULL) */\n"
        "    clock_gettime(CLOCK_MONOTONIC, &ts);\n";
    ASSERT_EQ(cs_count(src, "time(NULL)"), 2);
    ASSERT_EQ(cs_count(src, "clock_gettime("), 1);
    ASSERT_EQ(cs_count("    time_t now = sloth_wall();\n", "time(NULL)"), 0);
    ASSERT_EQ(cs_count("", "time(NULL)"), 0);
}

static void test_migrated_files_have_no_direct_clock_calls(void) {
    int n = (int)(sizeof(cs_migrated) / sizeof(cs_migrated[0]));
    for (int i = 0; i < n; i++) {
        char *src = slurp(cs_migrated[i]);
        ASSERT(src != NULL);
        if (!src) {
            fprintf(stderr, "    cannot read %s (run from the repo root)\n",
                    cs_migrated[i]);
            continue;
        }
        int wall = cs_count(src, "time(NULL)");
        int mono = cs_count(src, "clock_gettime(");
        if (wall || mono)
            fprintf(stderr, "    %s reads libc directly: %d time(NULL), "
                            "%d clock_gettime(); use sloth_wall() / "
                            "sloth_mono_ms()\n", cs_migrated[i], wall, mono);
        ASSERT_EQ(wall, 0);
        ASSERT_EQ(mono, 0);
        free(src);
    }
}

/* ── The seam itself ─────────────────────────────────────── */

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t fake_mono(void) { return g_mono; }
static time_t   fake_wall(void) { return g_wall; }

#define WALL0 ((time_t)1500000000)

static void test_real_clocks_by_default(void) {
    sloth_clock_test_set(NULL, NULL);
    time_t libc = time(NULL);
    time_t wall = sloth_wall();
    ASSERT(wall - libc >= -1 && wall - libc <= 1);
    uint64_t a = sloth_mono_ms();
    uint64_t b = sloth_mono_ms();
    ASSERT(b >= a);
}

/* A fake monotonic value no real clock can produce: CLOCK_MONOTONIC in
 * milliseconds since boot would need ~290 million years to get here, so
 * "the value is not the sentinel" proves the real clock is back without
 * assuming anything about how long the host has been up. The first
 * version of this test asserted real > 123456 ms, i.e. uptime over two
 * minutes, and a fresh CI runner failed it under TSan on 2026-10-15. */
#define MONO_SENTINEL (UINT64_MAX - 1)

static void test_test_set_swaps_and_null_restores(void) {
    g_mono = MONO_SENTINEL; g_wall = WALL0;
    sloth_clock_test_set(fake_mono, fake_wall);
    ASSERT_EQ(sloth_mono_ms(), MONO_SENTINEL);
    ASSERT_EQ((long)sloth_wall(), (long)WALL0);
    g_wall = WALL0 + 7;
    ASSERT_EQ((long)sloth_wall(), (long)(WALL0 + 7));
    /* Each clock restores independently: mono is real again (not the
     * sentinel, plausible magnitude, non-decreasing) while wall is still
     * the fake. */
    sloth_clock_test_set(NULL, fake_wall);
    uint64_t m1 = sloth_mono_ms();
    uint64_t m2 = sloth_mono_ms();
    ASSERT(m1 != MONO_SENTINEL);
    ASSERT(m1 < UINT64_MAX / 2);
    ASSERT(m2 >= m1);
    ASSERT_EQ((long)sloth_wall(), (long)(WALL0 + 7));
    sloth_clock_test_set(NULL, NULL);
    time_t libc = time(NULL);
    time_t wall = sloth_wall();
    ASSERT(wall - libc >= -1 && wall - libc <= 1);
}

/* The #88 names and the #109 names are one seam, not two: a module
 * still on flood_wall() and one already on sloth_wall() must agree
 * under an injected clock, or the taint fix would re-create the bug it
 * closed across the forward boundary. */
static void test_flood_forwards_share_the_seam(void) {
    g_mono = 99; g_wall = WALL0;
    flood_test_set_clock(fake_mono, fake_wall);
    ASSERT_EQ((long)sloth_wall(), (long)WALL0);
    ASSERT_EQ(sloth_mono_ms(), (uint64_t)99);
    sloth_clock_test_set(NULL, NULL);
    g_wall = WALL0 + 1;
    sloth_clock_test_set(fake_mono, fake_wall);
    ASSERT_EQ((long)flood_wall(), (long)(WALL0 + 1));
    ASSERT_EQ(flood_mono_ms(), (uint64_t)99);
    flood_test_set_clock(NULL, NULL);
    ASSERT((long)sloth_wall() > (long)WALL0);
}

void run_clock_seam_tests(void) {
    TEST_SUITE("clock seam (#109)");
    RUN_TEST(test_counter_sees_direct_clock_calls);
    RUN_TEST(test_migrated_files_have_no_direct_clock_calls);
    RUN_TEST(test_real_clocks_by_default);
    RUN_TEST(test_test_set_swaps_and_null_restores);
    RUN_TEST(test_flood_forwards_share_the_seam);
    sloth_clock_test_set(NULL, NULL);
}
