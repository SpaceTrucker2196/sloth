#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "dhcp_snoop.h"
#include "dns.h"
#include "views/dhcp_snoop.h"

/* ── Packet builder ──────────────────────────────────────── */

/* DHCP header layout (RFC 2131):
 *   0     op       (1=request, 2=reply)
 *   1     htype    (1=Ethernet)
 *   2     hlen     (6)
 *   3     hops
 *   4-7   xid
 *   8-9   secs
 *   10-11 flags
 *   12-15 ciaddr
 *   16-19 yiaddr
 *   20-23 siaddr
 *   24-27 giaddr
 *   28-43 chaddr  (MAC in first 6 bytes)
 *   44-107 sname  (64 bytes)
 *   108-235 file  (128 bytes)
 *   236-239 magic cookie 0x63825363
 *   240+  options
 */

typedef struct {
    uint8_t  op;
    uint8_t  mac[6];
    uint32_t yiaddr;   /* offered IP, host order; 0 = unset */
    uint32_t ciaddr;   /* client IP, host order; 0 = unset */
    uint8_t  msg_type; /* DHCP option 53 */
    const char *hostname; /* option 12, or NULL */
} dhcp_args_t;

static int build_dhcp(dhcp_args_t *a, uint8_t *buf, int bufsz) {
    if (bufsz < 300) return 0;
    memset(buf, 0, (size_t)bufsz);
    buf[0] = a->op;
    buf[1] = 1;           /* htype Ethernet */
    buf[2] = 6;           /* hlen */
    memcpy(buf + 28, a->mac, 6);

    /* yiaddr (network order) */
    buf[16] = (a->yiaddr >> 24) & 0xFF;
    buf[17] = (a->yiaddr >> 16) & 0xFF;
    buf[18] = (a->yiaddr >>  8) & 0xFF;
    buf[19] =  a->yiaddr        & 0xFF;
    /* ciaddr */
    buf[12] = (a->ciaddr >> 24) & 0xFF;
    buf[13] = (a->ciaddr >> 16) & 0xFF;
    buf[14] = (a->ciaddr >>  8) & 0xFF;
    buf[15] =  a->ciaddr        & 0xFF;

    /* magic cookie */
    buf[236] = 0x63; buf[237] = 0x82;
    buf[238] = 0x53; buf[239] = 0x63;

    int off = 240;
    /* option 53: message type */
    buf[off++] = 53; buf[off++] = 1; buf[off++] = a->msg_type;

    /* option 12: hostname */
    if (a->hostname) {
        int hlen = (int)strlen(a->hostname);
        buf[off++] = 12; buf[off++] = (uint8_t)hlen;
        memcpy(buf + off, a->hostname, (size_t)hlen);
        off += hlen;
    }
    buf[off++] = 255; /* end */
    return off;
}

static uint8_t mac_a[6] = {0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33};
static uint8_t mac_b[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

static void reset(void) {
    dhcp_snoop_clear();
    dns_init();
}

/* ── Protocol tests ──────────────────────────────────────── */

static void test_ack_fills_ip_and_hostname(void) {
    reset();
    dhcp_args_t a = {
        .op = 2, .mac = {0xAA,0xBB,0xCC,0x11,0x22,0x33},
        .yiaddr = (192u<<24)|(168u<<16)|(1u<<8)|50u,
        .msg_type = 5, .hostname = "myhost"
    };
    uint8_t buf[300]; char info[64] = "";
    int len = build_dhcp(&a, buf, sizeof(buf));
    ASSERT_EQ(1, dhcp_snoop(buf, len, info, sizeof(info)));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dhcp_snoop_snapshot(&s);
    ASSERT_EQ(1, s.dhcp_event_count);
    ASSERT_STR("192.168.1.50", s.dhcp_events[0].ip);
    ASSERT_STR("myhost",       s.dhcp_events[0].hostname);
    ASSERT_EQ(5, s.dhcp_events[0].msg_type);
}

static void test_ack_populates_dns_cache(void) {
    reset();
    dhcp_args_t a = {
        .op = 2, .mac = {0xDE,0xAD,0xBE,0xEF,0x00,0x01},
        .yiaddr = (10u<<24)|(0u<<16)|(0u<<8)|5u,
        .msg_type = 5, .hostname = "devbox"
    };
    uint8_t buf[300]; char info[64];
    dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));

    const char *resolved = dns_lookup("10.0.0.5");
    ASSERT(resolved != NULL && strcmp(resolved, "devbox") == 0);
}

static void test_discover_no_ip(void) {
    reset();
    dhcp_args_t a = {
        .op = 1, .mac = {0x11,0x22,0x33,0x44,0x55,0x66},
        .yiaddr = 0, .msg_type = 1, .hostname = "laptop"
    };
    uint8_t buf[300]; char info[64] = "";
    int len = build_dhcp(&a, buf, sizeof(buf));
    ASSERT_EQ(1, dhcp_snoop(buf, len, info, sizeof(info)));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dhcp_snoop_snapshot(&s);
    ASSERT_EQ(1, s.dhcp_event_count);
    ASSERT_EQ(1, s.dhcp_events[0].msg_type);
    /* no IP yet */
    ASSERT(s.dhcp_events[0].ip[0] == '\0' ||
           strcmp(s.dhcp_events[0].ip, "0.0.0.0") == 0);
}

static void test_discover_no_dns_cache(void) {
    /* DNS cache should NOT be updated for DISCOVER (no IP confirmed) */
    reset();
    dhcp_args_t a = {
        .op = 1, .mac = {0x11,0x22,0x33,0x44,0x55,0x77},
        .yiaddr = 0, .msg_type = 1, .hostname = "phantom"
    };
    uint8_t buf[300]; char info[64];
    dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));
    /* no IP resolved for "phantom" */
    ASSERT(dns_lookup("0.0.0.0") == NULL ||
           strcmp(dns_lookup("0.0.0.0"), "phantom") != 0);
}

static void test_request_uses_ciaddr(void) {
    reset();
    dhcp_args_t a = {
        .op = 1,
        .mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF},
        .ciaddr = (172u<<24)|(16u<<16)|(0u<<8)|99u,
        .yiaddr = 0,
        .msg_type = 3, .hostname = "reqhost"
    };
    uint8_t buf[300]; char info[64];
    dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dhcp_snoop_snapshot(&s);
    ASSERT_EQ(1, s.dhcp_event_count);
    ASSERT_STR("172.16.0.99", s.dhcp_events[0].ip);
}

static void test_dedup_same_mac(void) {
    reset();
    dhcp_args_t a = {
        .op = 2, .mac = {0xAA,0xBB,0xCC,0x11,0x22,0x33},
        .yiaddr = (192u<<24)|(168u<<16)|(1u<<8)|10u,
        .msg_type = 5, .hostname = "first"
    };
    uint8_t buf[300]; char info[64];
    dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));

    /* Same MAC, new IP/hostname */
    a.yiaddr = (192u<<24)|(168u<<16)|(1u<<8)|20u;
    a.hostname = "second";
    dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dhcp_snoop_snapshot(&s);
    ASSERT_EQ(1, s.dhcp_event_count);   /* still one entry */
    ASSERT_STR("192.168.1.20", s.dhcp_events[0].ip);
    ASSERT_STR("second",       s.dhcp_events[0].hostname);
}

static void test_different_mac_separate_entries(void) {
    reset();
    dhcp_args_t a = {
        .op = 2, .yiaddr = (10u<<24)|(0u<<16)|(0u<<8)|1u,
        .msg_type = 5, .hostname = "hostA"
    };
    memcpy(a.mac, mac_a, 6);
    uint8_t buf[300]; char info[64];
    dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));

    a.yiaddr = (10u<<24)|(0u<<16)|(0u<<8)|2u;
    a.hostname = "hostB";
    memcpy(a.mac, mac_b, 6);
    dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dhcp_snoop_snapshot(&s);
    ASSERT_EQ(2, s.dhcp_event_count);
}

static void test_too_short_rejected(void) {
    reset();
    uint8_t buf[239] = {0};
    char info[64] = "";
    ASSERT_EQ(0, dhcp_snoop(buf, 239, info, sizeof(info)));
}

static void test_wrong_op_rejected(void) {
    reset();
    dhcp_args_t a = {
        .op = 3, .mac = {1,2,3,4,5,6},
        .msg_type = 5, .hostname = "x"
    };
    uint8_t buf[300]; char info[64] = "";
    int len = build_dhcp(&a, buf, sizeof(buf));
    ASSERT_EQ(0, dhcp_snoop(buf, len, info, sizeof(info)));
}

static void test_wrong_htype_rejected(void) {
    reset();
    dhcp_args_t a = {
        .op = 2, .mac = {1,2,3,4,5,6},
        .msg_type = 5, .hostname = "x"
    };
    uint8_t buf[300]; char info[64] = "";
    int len = build_dhcp(&a, buf, sizeof(buf));
    buf[1] = 6;  /* token ring, not Ethernet */
    ASSERT_EQ(0, dhcp_snoop(buf, len, info, sizeof(info)));
}

static void test_bad_magic_rejected(void) {
    reset();
    dhcp_args_t a = {
        .op = 2, .mac = {1,2,3,4,5,6},
        .msg_type = 5, .hostname = "x"
    };
    uint8_t buf[300]; char info[64] = "";
    int len = build_dhcp(&a, buf, sizeof(buf));
    buf[236] = 0xDE; /* corrupt magic cookie */
    ASSERT_EQ(0, dhcp_snoop(buf, len, info, sizeof(info)));
}

static void test_no_message_type_rejected(void) {
    /* Packet with valid header but no option 53 = unrecognised */
    reset();
    uint8_t buf[300]; memset(buf, 0, sizeof(buf));
    buf[0] = 2; buf[1] = 1; buf[2] = 6;
    buf[236]=0x63; buf[237]=0x82; buf[238]=0x53; buf[239]=0x63;
    buf[240] = 255; /* end immediately, no option 53 */
    char info[64] = "";
    ASSERT_EQ(0, dhcp_snoop(buf, 241, info, sizeof(info)));
}

static void test_info_contains_hostname_and_ip(void) {
    reset();
    dhcp_args_t a = {
        .op = 2, .mac = {0xAA,0xBB,0xCC,0x11,0x22,0x44},
        .yiaddr = (192u<<24)|(168u<<16)|(5u<<8)|1u,
        .msg_type = 5, .hostname = "infohost"
    };
    uint8_t buf[300]; char info[64] = "";
    dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));
    ASSERT(strstr(info, "infohost")    != NULL);
    ASSERT(strstr(info, "192.168.5.1") != NULL);
}

static void test_info_no_hostname(void) {
    reset();
    dhcp_args_t a = {
        .op = 2, .mac = {0xAA,0xBB,0xCC,0x11,0x22,0x55},
        .yiaddr = (10u<<24)|(1u<<16)|(1u<<8)|9u,
        .msg_type = 5, .hostname = NULL
    };
    uint8_t buf[300]; char info[64] = "";
    int r = dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));
    ASSERT_EQ(1, r);
    ASSERT(strstr(info, "ACK") != NULL || strstr(info, "DHCP") != NULL);
}

static void test_last_seen_set(void) {
    reset();
    dhcp_args_t a = {
        .op = 2, .mac = {0x01,0x02,0x03,0x04,0x05,0x06},
        .yiaddr = (1u<<24)|(2u<<16)|(3u<<8)|4u,
        .msg_type = 5, .hostname = "ts"
    };
    uint8_t buf[300]; char info[64];
    dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dhcp_snoop_snapshot(&s);
    ASSERT(s.dhcp_events[0].last_seen > 0);
}

static void test_clear_empties_table(void) {
    reset();
    dhcp_args_t a = {
        .op = 2, .mac = {0xAA,0xBB,0xCC,0x11,0x22,0x66},
        .yiaddr = (1u<<24)|(1u<<16)|(1u<<8)|1u,
        .msg_type = 5, .hostname = "clearme"
    };
    uint8_t buf[300]; char info[64];
    dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));
    dhcp_snoop_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dhcp_snoop_snapshot(&s);
    ASSERT_EQ(0, s.dhcp_event_count);
}

/* ── View draw / nav tests ───────────────────────────────── */

static void test_draw_empty_state(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_dhcp_snoop_draw(&s);   /* must not crash */
}

static void test_draw_with_entries(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.dhcp_event_count = 2;
    snprintf(s.dhcp_events[0].mac,      18, "aa:bb:cc:11:22:33");
    snprintf(s.dhcp_events[0].ip,       46, "192.168.1.50");
    snprintf(s.dhcp_events[0].hostname, 64, "pc1");
    s.dhcp_events[0].msg_type  = 5;
    s.dhcp_events[0].last_seen = 1000000;
    snprintf(s.dhcp_events[1].mac,      18, "de:ad:be:ef:00:01");
    snprintf(s.dhcp_events[1].ip,       46, "192.168.1.51");
    s.dhcp_events[1].msg_type  = 3;
    s.dhcp_events[1].last_seen = 1000000;
    view_dhcp_snoop_draw(&s);   /* must not crash */
}

static void test_nav_down_up(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.dhcp_event_count = 3;
    ASSERT_EQ(0, s.dhcp_event_sel);
    view_dhcp_snoop_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(1, s.dhcp_event_sel);
    view_dhcp_snoop_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(2, s.dhcp_event_sel);
    view_dhcp_snoop_key(&s, SLOTH_KEY_DOWN);   /* clamp */
    ASSERT_EQ(2, s.dhcp_event_sel);
    view_dhcp_snoop_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(1, s.dhcp_event_sel);
    view_dhcp_snoop_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(0, s.dhcp_event_sel);
    view_dhcp_snoop_key(&s, SLOTH_KEY_UP);   /* clamp */
    ASSERT_EQ(0, s.dhcp_event_sel);
}

static void test_clear_key_resets_state(void) {
    dhcp_args_t a = {
        .op = 2, .mac = {0xAA,0xBB,0xCC,0x11,0x22,0x77},
        .yiaddr = (1u<<24), .msg_type = 5, .hostname = "x"
    };
    uint8_t buf[300]; char info[64];
    dhcp_snoop(buf, build_dhcp(&a, buf, sizeof(buf)), info, sizeof(info));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dhcp_snoop_snapshot(&s);
    s.dhcp_event_sel = 1;
    ASSERT_GT(s.dhcp_event_count, 0);

    view_dhcp_snoop_key(&s, 'c');
    ASSERT_EQ(0, s.dhcp_event_count);
    ASSERT_EQ(0, s.dhcp_event_sel);
}

/* ── Entry point ────────────────────────────────────────── */

void run_dhcp_snoop_tests(void) {
    TEST_SUITE("dhcp_snoop protocol");
    RUN_TEST(test_ack_fills_ip_and_hostname);
    RUN_TEST(test_ack_populates_dns_cache);
    RUN_TEST(test_discover_no_ip);
    RUN_TEST(test_discover_no_dns_cache);
    RUN_TEST(test_request_uses_ciaddr);
    RUN_TEST(test_dedup_same_mac);
    RUN_TEST(test_different_mac_separate_entries);
    RUN_TEST(test_too_short_rejected);
    RUN_TEST(test_wrong_op_rejected);
    RUN_TEST(test_wrong_htype_rejected);
    RUN_TEST(test_bad_magic_rejected);
    RUN_TEST(test_no_message_type_rejected);
    RUN_TEST(test_info_contains_hostname_and_ip);
    RUN_TEST(test_info_no_hostname);
    RUN_TEST(test_last_seen_set);
    RUN_TEST(test_clear_empties_table);

    TEST_SUITE("dhcp_snoop view");
    RUN_TEST(test_draw_empty_state);
    RUN_TEST(test_draw_with_entries);
    RUN_TEST(test_nav_down_up);
    RUN_TEST(test_clear_key_resets_state);
}
