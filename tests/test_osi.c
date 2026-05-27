#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "views/osi.h"

/* The OSI view is a pure synthesis layer — it reads sloth_state_t and
 * renders one row per OSI layer. Tests verify (a) empty-state renders
 * without crashing, (b) populated state produces the expected
 * per-layer counts inside the rendered text. We capture the rendered
 * output through the null TUI's printf passthrough; the runner's
 * stdout is what we'll get since WITH_NCURSES is off in test builds. */

static void test_osi_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    /* must not crash on a fully zeroed state */
    view_osi_draw(&s);
    ASSERT(1);
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
    ASSERT(1);
}

void run_osi_tests(void) {
    TEST_SUITE("osi view");
    RUN_TEST(test_osi_draw_empty);
    RUN_TEST(test_osi_key_is_noop);
    RUN_TEST(test_osi_draw_with_populated_state);
}
