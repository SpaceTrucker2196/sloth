#include <string.h>
#include "runner.h"
#include "tui.h"
#include "sloth.h"
#include "views/osi.h"

/* The OSI view is a pure synthesis layer — it reads sloth_state_t and
 * renders one row per OSI layer. Tests verify (a) empty-state renders
 * without crashing, (b) populated state produces the expected
 * per-layer counts inside the rendered text, read back from the
 * offscreen ncurses screen the suite draws into (#116). */

static void test_osi_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_osi_draw(&s);
    ASSERT_LINE_HAS(0, "conns:0 ifaces:0");
    ASSERT_SCREEN_HAS("L7 Application");
    ASSERT_SCREEN_HAS("DNS:0  HTTP:0  TLS:0  QUIC:0");
    ASSERT_SCREEN_HAS("(no iface");
}

static void test_osi_key_is_noop(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_osi_key(&s, 'q');
    view_osi_key(&s, 'k');
    /* no state changes — synthesis-only view */
    ASSERT_EQ(s.active_view, 0);
}

static void test_osi_draw_with_populated_state(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));

    /* L7 counters */
    s.dns_log_count  = 3;
    s.http_log_count = 2;
    s.tls_log_count  = 4;
    s.quic_log_count = 1;
    s.mdns_count     = 5;
    s.nbns_count     = 1;
    s.ntp_log_count  = 1;

    /* L6 — populate TLS versions to exercise the version-histogram
     * branches. */
    snprintf(s.tls_log[0].tls_ver, sizeof(s.tls_log[0].tls_ver), "TLS 1.3");
    snprintf(s.tls_log[1].tls_ver, sizeof(s.tls_log[1].tls_ver), "TLS 1.3");
    snprintf(s.tls_log[2].tls_ver, sizeof(s.tls_log[2].tls_ver), "TLS 1.2");
    snprintf(s.tls_log[3].tls_ver, sizeof(s.tls_log[3].tls_ver), "TLS 1.0");
    snprintf(s.tls_log[0].ja3, sizeof(s.tls_log[0].ja3), "abcd1234");
    snprintf(s.tls_log[1].ja3, sizeof(s.tls_log[1].ja3), "abcd1234");
    snprintf(s.tls_log[2].ja3, sizeof(s.tls_log[2].ja3), "deadbeef");

    /* L5 */
    s.eapol_count = 2;

    /* L4 — TCP est, listen, other; UDP. */
    s.conn_count = 4;
    s.conns[0].proto = PROTO_TCP;  s.conns[0].state = 1;
    snprintf(s.conns[0].remote_addr, sizeof(s.conns[0].remote_addr),
             "192.0.2.10");
    s.conns[1].proto = PROTO_TCP;  s.conns[1].state = 10;
    snprintf(s.conns[1].remote_addr, sizeof(s.conns[1].remote_addr),
             "192.0.2.20");
    s.conns[2].proto = PROTO_UDP;  s.conns[2].state = 0;
    snprintf(s.conns[2].remote_addr, sizeof(s.conns[2].remote_addr),
             "2001:db8::1");
    s.conns[3].proto = PROTO_TCP;  s.conns[3].state = 2;  /* SYN_SENT */
    snprintf(s.conns[3].remote_addr, sizeof(s.conns[3].remote_addr),
             "192.0.2.10");          /* dup IP — distinct-host = 3 */

    /* L3 */
    s.arp_count       = 7;
    s.icmp_log_count  = 2;

    /* L2 */
    s.iface_count    = 2;
    snprintf(s.ifaces[0].name, sizeof(s.ifaces[0].name), "eth0");
    snprintf(s.ifaces[1].name, sizeof(s.ifaces[1].name), "wlan0");
    s.ap_count        = 3;
    s.wifi_sta_count  = 4;
    s.device_count    = 5;
    s.beacon_count    = 6;

    /* L1 */
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan0mon");

    view_osi_draw(&s);
    /* One row per layer, each carrying the counts seeded for it. The
     * duplicate remote 192.0.2.10 makes three distinct hosts, two of
     * them IPv4. */
    ASSERT_LINE_HAS(0, "conns:4 ifaces:2");
    ASSERT_LINE_HAS(runner_screen_find("L7 Application"),
                    "DNS:3  HTTP:2  TLS:4  QUIC:1  mDNS:5  NBNS:1  NTP:1");
    ASSERT_LINE_HAS(runner_screen_find("L6 Presentation"),
                    "TLS 1.3:2  TLS 1.2:1  legacy:1  JA3:2 distinct");
    ASSERT_LINE_HAS(runner_screen_find("L5 Session"),
                    "TLS sessions:4  QUIC:1  EAPOL:2");
    ASSERT_LINE_HAS(runner_screen_find("L4 Transport"),
                    "TCP:3 (E:1 L:1 ?:1)  UDP:1  ICMP:2");
    ASSERT_LINE_HAS(runner_screen_find("L3 Network"),
                    "IPv4 hosts:2  IPv6 hosts:1  ARP mappings:7");
    ASSERT_LINE_HAS(runner_screen_find("L2 Data Link"),
                    "ifaces:2  APs:3  STAs:4  devices:5  beacons:6");
    ASSERT_LINE_HAS(runner_screen_find("L1 Physical"),
                    "probe iface: wlan0mon (monitor mode)");
}

void run_osi_tests(void) {
    TEST_SUITE("osi view");
    RUN_TEST(test_osi_draw_empty);
    RUN_TEST(test_osi_key_is_noop);
    RUN_TEST(test_osi_draw_with_populated_state);
}
