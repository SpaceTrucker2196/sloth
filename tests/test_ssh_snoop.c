#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "ssh_snoop.h"

/* SSH banners (RFC 4253 §4.2):
 *   SSH-protoversion-softwareversion SP comments CR LF
 * protoversion is "1.99" or "2.0". The banners below are
 * hand-rolled byte arrays — never fed back through an encoder
 * the parser owns. */

static const uint8_t BANNER_OPENSSH[] =
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
static const uint8_t BANNER_DROPBEAR[] =
    "SSH-2.0-dropbear_2022.83\r\n";
static const uint8_t BANNER_LEGACY[] =
    "SSH-1.99-OpenSSH_6.6.1p1\r\n";

/* ── Server-side banner observation ─────────────────────── */

static void test_detects_openssh_banner(void) {
    ssh_snoop_clear();
    /* src_port=22 → server side. */
    ASSERT_EQ(ssh_snoop_observe("10.0.0.10", 22, "10.0.0.5", 49152,
                                BANNER_OPENSSH,
                                (int)sizeof(BANNER_OPENSSH) - 1), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ssh_snoop_snapshot(&s);
    ASSERT_EQ(s.ssh_flow_count, 1);
    ASSERT_STR(s.ssh_flows[0].src_ip, "10.0.0.5");   /* client */
    ASSERT_STR(s.ssh_flows[0].dst_ip, "10.0.0.10");  /* server */
    ASSERT_EQ(s.ssh_flows[0].banner_count, 1);
    ASSERT(strstr(s.ssh_flows[0].server_banner, "OpenSSH") != NULL);
}

static void test_detects_dropbear_banner(void) {
    ssh_snoop_clear();
    ssh_snoop_observe("10.0.0.10", 22, "10.0.0.5", 49152,
                      BANNER_DROPBEAR, (int)sizeof(BANNER_DROPBEAR) - 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ssh_snoop_snapshot(&s);
    ASSERT(strstr(s.ssh_flows[0].server_banner, "dropbear") != NULL);
}

static void test_detects_legacy_1_99_banner(void) {
    ssh_snoop_clear();
    ASSERT_EQ(ssh_snoop_observe("10.0.0.10", 22, "10.0.0.5", 49152,
                                BANNER_LEGACY,
                                (int)sizeof(BANNER_LEGACY) - 1), 1);
}

/* Client banner — payload reaches port 22, banner content is fine,
 * but we deliberately don't count it (counting would double every
 * connection because both sides emit a banner). */
static void test_client_banner_not_counted(void) {
    ssh_snoop_clear();
    ASSERT_EQ(ssh_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 22,
                                BANNER_OPENSSH,
                                (int)sizeof(BANNER_OPENSSH) - 1), 0);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ssh_snoop_snapshot(&s);
    ASSERT_EQ(s.ssh_flow_count, 0);
}

/* ── Aggregation ────────────────────────────────────────── */

static void test_repeated_banners_accumulate(void) {
    ssh_snoop_clear();
    for (int i = 0; i < 12; i++) {
        ssh_snoop_observe("10.0.0.10", 22, "10.0.0.5", 49152,
                          BANNER_OPENSSH,
                          (int)sizeof(BANNER_OPENSSH) - 1);
    }
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ssh_snoop_snapshot(&s);
    ASSERT_EQ(s.ssh_flow_count, 1);
    ASSERT_EQ(s.ssh_flows[0].banner_count, 12);
}

static void test_two_clients_tracked_separately(void) {
    ssh_snoop_clear();
    ssh_snoop_observe("10.0.0.10", 22, "10.0.0.5", 49152,
                      BANNER_OPENSSH,
                      (int)sizeof(BANNER_OPENSSH) - 1);
    ssh_snoop_observe("10.0.0.10", 22, "10.0.0.6", 49152,
                      BANNER_OPENSSH,
                      (int)sizeof(BANNER_OPENSSH) - 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ssh_snoop_snapshot(&s);
    ASSERT_EQ(s.ssh_flow_count, 2);
}

/* Same client probing two SSH servers — two distinct flows. */
static void test_two_servers_tracked_separately(void) {
    ssh_snoop_clear();
    ssh_snoop_observe("10.0.0.10", 22, "10.0.0.5", 49152,
                      BANNER_OPENSSH,
                      (int)sizeof(BANNER_OPENSSH) - 1);
    ssh_snoop_observe("10.0.0.11", 22, "10.0.0.5", 49152,
                      BANNER_OPENSSH,
                      (int)sizeof(BANNER_OPENSSH) - 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ssh_snoop_snapshot(&s);
    ASSERT_EQ(s.ssh_flow_count, 2);
}

/* ── Port gating ───────────────────────────────────────── */

static void test_non_ssh_port_rejected(void) {
    ssh_snoop_clear();
    ASSERT_EQ(ssh_snoop_observe("10.0.0.10", 8022, "10.0.0.5", 49152,
                                BANNER_OPENSSH,
                                (int)sizeof(BANNER_OPENSSH) - 1), 0);
}

/* ── Negative cases ─────────────────────────────────────── */

/* HTTP banner on port 22 — port matches, payload doesn't. The
 * "SSH-" prefix check must reject this. */
static void test_non_ssh_payload_rejected(void) {
    ssh_snoop_clear();
    static const uint8_t HTTP[] = "HTTP/1.1 200 OK\r\n";
    ASSERT_EQ(ssh_snoop_observe("10.0.0.10", 22, "10.0.0.5", 49152,
                                HTTP, (int)sizeof(HTTP) - 1), 0);
}

/* "SSH-" prefix with no second hyphen — not a valid banner. */
static void test_prefix_without_dash_rejected(void) {
    ssh_snoop_clear();
    static const uint8_t BAD[] = "SSH-evil!data\r\n";
    /* No hyphen in the first 12 bytes after the prefix — rejected. */
    ASSERT_EQ(ssh_snoop_observe("10.0.0.10", 22, "10.0.0.5", 49152,
                                BAD, (int)sizeof(BAD) - 1), 0);
}

/* Banner truncated below the minimum length. */
static void test_truncated_banner_rejected(void) {
    ssh_snoop_clear();
    static const uint8_t SHORT[] = "SSH";
    ASSERT_EQ(ssh_snoop_observe("10.0.0.10", 22, "10.0.0.5", 49152,
                                SHORT, (int)sizeof(SHORT) - 1), 0);
}

/* Banner storage truncates at the first CR/LF and at non-printable
 * bytes so a hostile server can't poison the log line. */
static void test_banner_truncates_at_crlf(void) {
    ssh_snoop_clear();
    static const uint8_t BANNER_WITH_TAIL[] =
        "SSH-2.0-OpenSSH_8.9\r\nGARBAGE";
    ssh_snoop_observe("10.0.0.10", 22, "10.0.0.5", 49152,
                      BANNER_WITH_TAIL,
                      (int)sizeof(BANNER_WITH_TAIL) - 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ssh_snoop_snapshot(&s);
    ASSERT(strstr(s.ssh_flows[0].server_banner, "GARBAGE") == NULL);
    ASSERT(strstr(s.ssh_flows[0].server_banner, "OpenSSH") != NULL);
}

/* ── Suite ──────────────────────────────────────────────── */

void run_ssh_snoop_tests(void) {
    TEST_SUITE("ssh_snoop: server-banner detection");
    RUN_TEST(test_detects_openssh_banner);
    RUN_TEST(test_detects_dropbear_banner);
    RUN_TEST(test_detects_legacy_1_99_banner);
    RUN_TEST(test_client_banner_not_counted);

    TEST_SUITE("ssh_snoop: aggregation");
    RUN_TEST(test_repeated_banners_accumulate);
    RUN_TEST(test_two_clients_tracked_separately);
    RUN_TEST(test_two_servers_tracked_separately);

    TEST_SUITE("ssh_snoop: port gating");
    RUN_TEST(test_non_ssh_port_rejected);

    TEST_SUITE("ssh_snoop: negative cases");
    RUN_TEST(test_non_ssh_payload_rejected);
    RUN_TEST(test_prefix_without_dash_rejected);
    RUN_TEST(test_truncated_banner_rejected);
    RUN_TEST(test_banner_truncates_at_crlf);
}
