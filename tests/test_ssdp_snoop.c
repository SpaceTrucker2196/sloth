#include <string.h>
#include <stdio.h>
#include "runner.h"
#include "sloth.h"
#include "ssdp_snoop.h"
#include "views/ssdp.h"

/* ── Helpers ────────────────────────────────────────────── */

static const uint8_t *to_u8(const char *s) { return (const uint8_t *)s; }

static const char *notify_alive =
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "NTS: ssdp:alive\r\n"
    "USN: uuid:router-001::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "LOCATION: http://192.168.1.1:49152/rootDesc.xml\r\n"
    "\r\n";

static const char *notify_byebye =
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "NTS: ssdp:byebye\r\n"
    "USN: uuid:router-001::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n";

static const char *msearch =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n";

static const char *notify_rootdevice =
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "NT: upnp:rootdevice\r\n"
    "NTS: ssdp:alive\r\n"
    "USN: uuid:tv-001::upnp:rootdevice\r\n"
    "LOCATION: http://192.168.1.50:1234/desc.xml\r\n"
    "\r\n";

/* ── Detection tests ─────────────────────────────────────── */

static void test_notify_alive_detected(void) {
    ssdp_clear();
    char info[64] = "";
    int r = ssdp_snoop("192.168.1.1", to_u8(notify_alive),
                       (int)strlen(notify_alive), info, sizeof(info));
    ASSERT_EQ(r, 1);
}

static void test_notify_byebye_detected(void) {
    ssdp_clear();
    char info[64] = "";
    int r = ssdp_snoop("192.168.1.1", to_u8(notify_byebye),
                       (int)strlen(notify_byebye), info, sizeof(info));
    ASSERT_EQ(r, 1);
}

static void test_msearch_detected(void) {
    ssdp_clear();
    char info[64] = "";
    int r = ssdp_snoop("192.168.1.50", to_u8(msearch),
                       (int)strlen(msearch), info, sizeof(info));
    ASSERT_EQ(r, 1);
}

static void test_unknown_method_rejected(void) {
    ssdp_clear();
    const char *bad = "GET / HTTP/1.1\r\nHost: foo\r\n\r\n";
    char info[64] = "";
    int r = ssdp_snoop("10.0.0.1", to_u8(bad), (int)strlen(bad),
                       info, sizeof(info));
    ASSERT_EQ(r, 0);
}

static void test_too_short_rejected(void) {
    ssdp_clear();
    char info[64] = "";
    int r = ssdp_snoop("10.0.0.1", to_u8("HI"), 2, info, sizeof(info));
    ASSERT_EQ(r, 0);
}

/* ── Header extraction tests ─────────────────────────────── */

static void test_alive_nts_stored(void) {
    ssdp_clear();
    ssdp_snoop("192.168.1.1", to_u8(notify_alive),
               (int)strlen(notify_alive), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    ASSERT_EQ(s.ssdp_count, 1);
    ASSERT_STR(s.ssdp_devices[0].nts, "alive");
}

static void test_byebye_nts_stored(void) {
    ssdp_clear();
    ssdp_snoop("192.168.1.1", to_u8(notify_byebye),
               (int)strlen(notify_byebye), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    ASSERT_EQ(s.ssdp_count, 1);
    ASSERT_STR(s.ssdp_devices[0].nts, "byebye");
}

static void test_msearch_nts_is_search(void) {
    ssdp_clear();
    ssdp_snoop("192.168.1.50", to_u8(msearch),
               (int)strlen(msearch), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    ASSERT_EQ(s.ssdp_count, 1);
    ASSERT_STR(s.ssdp_devices[0].nts, "search");
}

static void test_ip_stored(void) {
    ssdp_clear();
    ssdp_snoop("10.20.30.40", to_u8(notify_alive),
               (int)strlen(notify_alive), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    ASSERT_STR(s.ssdp_devices[0].ip, "10.20.30.40");
}

static void test_location_stored(void) {
    ssdp_clear();
    ssdp_snoop("192.168.1.1", to_u8(notify_alive),
               (int)strlen(notify_alive), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    ASSERT(strstr(s.ssdp_devices[0].location, "192.168.1.1") != NULL);
}

static void test_usn_stored(void) {
    ssdp_clear();
    ssdp_snoop("192.168.1.1", to_u8(notify_alive),
               (int)strlen(notify_alive), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    ASSERT(strstr(s.ssdp_devices[0].usn, "router-001") != NULL);
}

/* ── Deduplication tests ─────────────────────────────────── */

static void test_dedup_by_usn(void) {
    ssdp_clear();
    /* same USN → same slot */
    ssdp_snoop("192.168.1.1", to_u8(notify_alive),
               (int)strlen(notify_alive), NULL, 0);
    ssdp_snoop("192.168.1.1", to_u8(notify_alive),
               (int)strlen(notify_alive), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    ASSERT_EQ(s.ssdp_count, 1);
}

static void test_different_usn_different_slot(void) {
    ssdp_clear();
    ssdp_snoop("192.168.1.1",  to_u8(notify_alive),
               (int)strlen(notify_alive), NULL, 0);
    ssdp_snoop("192.168.1.50", to_u8(notify_rootdevice),
               (int)strlen(notify_rootdevice), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    ASSERT_EQ(s.ssdp_count, 2);
}

static void test_dedup_msearch_by_ip_type(void) {
    ssdp_clear();
    /* M-SEARCH has no USN — dedup by ip+type */
    ssdp_snoop("192.168.1.50", to_u8(msearch), (int)strlen(msearch), NULL, 0);
    ssdp_snoop("192.168.1.50", to_u8(msearch), (int)strlen(msearch), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    ASSERT_EQ(s.ssdp_count, 1);
}

/* ── Info string test ────────────────────────────────────── */

static void test_info_string_alive(void) {
    ssdp_clear();
    char info[64] = "";
    ssdp_snoop("192.168.1.1", to_u8(notify_alive),
               (int)strlen(notify_alive), info, sizeof(info));
    ASSERT(strstr(info, "alive") != NULL);
    ASSERT(strstr(info, "SSDP") != NULL);
}

static void test_info_string_byebye(void) {
    ssdp_clear();
    char info[64] = "";
    ssdp_snoop("192.168.1.1", to_u8(notify_byebye),
               (int)strlen(notify_byebye), info, sizeof(info));
    ASSERT(strstr(info, "byebye") != NULL);
}

static void test_info_null_ok(void) {
    ssdp_clear();
    int r = ssdp_snoop("192.168.1.1", to_u8(notify_alive),
                       (int)strlen(notify_alive), NULL, 0);
    ASSERT_EQ(r, 1);
}

/* ── Clear test ──────────────────────────────────────────── */

static void test_clear_resets_count(void) {
    ssdp_clear();
    ssdp_snoop("192.168.1.1", to_u8(notify_alive),
               (int)strlen(notify_alive), NULL, 0);
    ssdp_clear();

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    ASSERT_EQ(s.ssdp_count, 0);
}

/* ── View draw/nav smoke tests ───────────────────────────── */

static void test_view_draw_empty(void) {
    ssdp_clear();
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    view_ssdp_draw(&s);
    ASSERT(1);
}

static void test_view_draw_with_entries(void) {
    ssdp_clear();
    ssdp_snoop("192.168.1.1",  to_u8(notify_alive),
               (int)strlen(notify_alive), NULL, 0);
    ssdp_snoop("192.168.1.50", to_u8(notify_rootdevice),
               (int)strlen(notify_rootdevice), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    view_ssdp_draw(&s);
    ASSERT_EQ(s.ssdp_count, 2);
}

static void test_view_nav_up_down(void) {
    ssdp_clear();
    ssdp_snoop("192.168.1.1",  to_u8(notify_alive),
               (int)strlen(notify_alive), NULL, 0);
    ssdp_snoop("192.168.1.50", to_u8(notify_rootdevice),
               (int)strlen(notify_rootdevice), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);

    ASSERT_EQ(s.ssdp_sel, 0);
    view_ssdp_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.ssdp_sel, 1);
    view_ssdp_key(&s, SLOTH_KEY_DOWN);   /* clamped */
    ASSERT_EQ(s.ssdp_sel, 1);
    view_ssdp_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.ssdp_sel, 0);
    view_ssdp_key(&s, SLOTH_KEY_UP);    /* clamped */
    ASSERT_EQ(s.ssdp_sel, 0);
}

static void test_view_clear_key(void) {
    ssdp_clear();
    ssdp_snoop("192.168.1.1", to_u8(notify_alive),
               (int)strlen(notify_alive), NULL, 0);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ssdp_snapshot(&s);
    ASSERT_EQ(s.ssdp_count, 1);

    view_ssdp_key(&s, 'c');
    ASSERT_EQ(s.ssdp_count, 0);
    ASSERT_EQ(s.ssdp_sel, 0);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_ssdp_snoop_tests(void) {
    TEST_SUITE("ssdp detection");
    RUN_TEST(test_notify_alive_detected);
    RUN_TEST(test_notify_byebye_detected);
    RUN_TEST(test_msearch_detected);
    RUN_TEST(test_unknown_method_rejected);
    RUN_TEST(test_too_short_rejected);

    TEST_SUITE("ssdp header extraction");
    RUN_TEST(test_alive_nts_stored);
    RUN_TEST(test_byebye_nts_stored);
    RUN_TEST(test_msearch_nts_is_search);
    RUN_TEST(test_ip_stored);
    RUN_TEST(test_location_stored);
    RUN_TEST(test_usn_stored);

    TEST_SUITE("ssdp deduplication");
    RUN_TEST(test_dedup_by_usn);
    RUN_TEST(test_different_usn_different_slot);
    RUN_TEST(test_dedup_msearch_by_ip_type);

    TEST_SUITE("ssdp info string");
    RUN_TEST(test_info_string_alive);
    RUN_TEST(test_info_string_byebye);
    RUN_TEST(test_info_null_ok);

    TEST_SUITE("ssdp clear");
    RUN_TEST(test_clear_resets_count);

    TEST_SUITE("ssdp view");
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_with_entries);
    RUN_TEST(test_view_nav_up_down);
    RUN_TEST(test_view_clear_key);
}
