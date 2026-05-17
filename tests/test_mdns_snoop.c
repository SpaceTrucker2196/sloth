/* tests/test_mdns_snoop.c — mDNS snooping unit tests */

#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "mdns_snoop.h"
#include "views/mdns.h"
#include "dns.h"

/* ── Hand-crafted mDNS packets ───────────────────────────── */

/*
 * pkt_ptr: PTR response
 *   _http._tcp.local  →  mydevice._http._tcp.local
 *
 * Header (12 bytes): ANCOUNT=1
 * Answer owner: _http._tcp.local inline at offset 12 (18 bytes)
 * TYPE=PTR(0x0C), CLASS=IN, TTL=4500
 * RDLENGTH=11: \x08mydevice + \xC0\x0C (ptr to offset 12)
 */
static const uint8_t pkt_ptr[] = {
    0x00,0x00, 0x84,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00,
    0x05,'_','h','t','t','p',
    0x04,'_','t','c','p',
    0x05,'l','o','c','a','l', 0x00,
    0x00,0x0C, 0x00,0x01, 0x00,0x00,0x11,0x94,
    0x00,0x0B,
    0x08,'m','y','d','e','v','i','c','e', 0xC0,0x0C
};

/*
 * pkt_srv: SRV response
 *   mydevice._http._tcp.local  →  port 80, target mydevice.local
 */
static const uint8_t pkt_srv[] = {
    0x00,0x00, 0x84,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00,
    /* owner: mydevice._http._tcp.local (27 bytes) */
    0x08,'m','y','d','e','v','i','c','e',
    0x05,'_','h','t','t','p',
    0x04,'_','t','c','p',
    0x05,'l','o','c','a','l', 0x00,
    0x00,0x21, 0x00,0x01, 0x00,0x00,0x11,0x94,
    0x00,0x16,   /* RDLENGTH=22 */
    0x00,0x00, 0x00,0x00, 0x00,0x50,  /* priority=0, weight=0, port=80 */
    0x08,'m','y','d','e','v','i','c','e',
    0x05,'l','o','c','a','l', 0x00
};

/*
 * pkt_a: A response
 *   mydevice.local  →  192.168.1.100
 */
static const uint8_t pkt_a[] = {
    0x00,0x00, 0x84,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00,
    0x08,'m','y','d','e','v','i','c','e',
    0x05,'l','o','c','a','l', 0x00,
    0x00,0x01, 0x00,0x01, 0x00,0x00,0x00,0xF0,
    0x00,0x04,
    0xC0,0xA8,0x01,0x64   /* 192.168.1.100 */
};

/*
 * pkt_a_cacheflush: same as pkt_a but CLASS field has cache-flush bit set (0x8001).
 *   mydevice.local  →  192.168.1.101
 */
static const uint8_t pkt_a_cacheflush[] = {
    0x00,0x00, 0x84,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00,
    0x08,'m','y','d','e','v','i','c','e',
    0x05,'l','o','c','a','l', 0x00,
    0x00,0x01, 0x80,0x01, 0x00,0x00,0x00,0xF0,  /* CLASS=0x8001 */
    0x00,0x04,
    0xC0,0xA8,0x01,0x65   /* 192.168.1.101 */
};

/*
 * pkt_aaaa: AAAA response
 *   mydevice.local  →  fe80::1
 */
static const uint8_t pkt_aaaa[] = {
    0x00,0x00, 0x84,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00,
    0x08,'m','y','d','e','v','i','c','e',
    0x05,'l','o','c','a','l', 0x00,
    0x00,0x1C, 0x00,0x01, 0x00,0x00,0x00,0xF0,
    0x00,0x10,
    0xFE,0x80, 0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00, 0x00,0x00, 0x00,0x00,0x00,0x01   /* fe80::1 */
};

/*
 * pkt_combined: PTR (ANCOUNT=1) + SRV + A (ARCOUNT=2)
 *   _ssh._tcp.local → pi._ssh._tcp.local
 *   pi._ssh._tcp.local → port 22, host pi.local
 *   pi.local → 192.168.1.42
 */
static const uint8_t pkt_combined[] = {
    0x00,0x00, 0x84,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x02,
    /* RR1 PTR: _ssh._tcp.local (17 bytes) */
    0x04,'_','s','s','h',
    0x04,'_','t','c','p',
    0x05,'l','o','c','a','l', 0x00,
    0x00,0x0C, 0x00,0x01, 0x00,0x00,0x11,0x94,
    0x00,0x14,  /* RDLENGTH=20 */
    0x02,'p','i',
    0x04,'_','s','s','h',
    0x04,'_','t','c','p',
    0x05,'l','o','c','a','l', 0x00,
    /* RR2 SRV: pi._ssh._tcp.local → port 22, pi.local (20 byte owner) */
    0x02,'p','i',
    0x04,'_','s','s','h',
    0x04,'_','t','c','p',
    0x05,'l','o','c','a','l', 0x00,
    0x00,0x21, 0x00,0x01, 0x00,0x00,0x11,0x94,
    0x00,0x10,  /* RDLENGTH=16 */
    0x00,0x00, 0x00,0x00, 0x00,0x16,  /* port=22 */
    0x02,'p','i',
    0x05,'l','o','c','a','l', 0x00,
    /* RR3 A: pi.local → 192.168.1.42 */
    0x02,'p','i',
    0x05,'l','o','c','a','l', 0x00,
    0x00,0x01, 0x00,0x01, 0x00,0x00,0x00,0xF0,
    0x00,0x04,
    0xC0,0xA8,0x01,0x2A   /* 192.168.1.42 */
};

/*
 * pkt_arcount: PTR in ARCOUNT (additional) section only.
 *   _http._tcp.local → mydevice._http._tcp.local
 */
static const uint8_t pkt_arcount[] = {
    0x00,0x00, 0x84,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x01,
    0x05,'_','h','t','t','p',
    0x04,'_','t','c','p',
    0x05,'l','o','c','a','l', 0x00,
    0x00,0x0C, 0x00,0x01, 0x00,0x00,0x11,0x94,
    0x00,0x0B,
    0x08,'m','y','d','e','v','i','c','e', 0xC0,0x0C
};

/*
 * pkt_with_question: QDCOUNT=1, ANCOUNT=1
 *   Question: _http._tcp.local PTR
 *   Answer: ptr to mydevice._http._tcp.local (using compression)
 */
static const uint8_t pkt_with_question[] = {
    0x00,0x00, 0x84,0x00, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00,
    /* question: _http._tcp.local (18 bytes, offset 12) */
    0x05,'_','h','t','t','p',
    0x04,'_','t','c','p',
    0x05,'l','o','c','a','l', 0x00,
    /* QTYPE=PTR, QCLASS=IN */
    0x00,0x0C, 0x00,0x01,
    /* answer owner: pointer to offset 12 */
    0xC0,0x0C,
    0x00,0x0C, 0x00,0x01, 0x00,0x00,0x11,0x94,
    0x00,0x0B,
    0x08,'m','y','d','e','v','i','c','e', 0xC0,0x0C
};

/* ── Helpers ─────────────────────────────────────────────── */

static sloth_state_t g_st;

static void setup(void) {
    mdns_clear();
    dns_reset();
    memset(&g_st, 0, sizeof(g_st));
}

/* ── Tests ───────────────────────────────────────────────── */

static void test_too_short(void) {
    setup();
    ASSERT(mdns_snoop(pkt_ptr, 11) == 0);
    ASSERT(mdns_snoop(pkt_ptr, 0)  == 0);
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 0);
}

static void test_empty_header(void) {
    setup();
    uint8_t hdr[12] = {0};
    ASSERT(mdns_snoop(hdr, 12) == 0);
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 0);
}

static void test_ptr_creates_service(void) {
    setup();
    int r = mdns_snoop(pkt_ptr, sizeof(pkt_ptr));
    ASSERT(r >= 1);
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
    ASSERT(strcmp(g_st.mdns_services[0].instance,
                 "mydevice._http._tcp.local") == 0);
}

static void test_ptr_service_type_extracted(void) {
    setup();
    mdns_snoop(pkt_ptr, sizeof(pkt_ptr));
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
    ASSERT(strcmp(g_st.mdns_services[0].service, "_http._tcp") == 0);
}

static void test_srv_host_and_port(void) {
    setup();
    mdns_snoop(pkt_srv, sizeof(pkt_srv));
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
    ASSERT(strcmp(g_st.mdns_services[0].instance,
                 "mydevice._http._tcp.local") == 0);
    ASSERT(g_st.mdns_services[0].port == 80);
    ASSERT(strcmp(g_st.mdns_services[0].host, "mydevice.local") == 0);
}

static void test_srv_service_type_from_instance(void) {
    setup();
    mdns_snoop(pkt_srv, sizeof(pkt_srv));
    mdns_snapshot(&g_st);
    ASSERT(strcmp(g_st.mdns_services[0].service, "_http._tcp") == 0);
}

static void test_a_injects_dns_cache(void) {
    setup();
    mdns_snoop(pkt_a, sizeof(pkt_a));
    /* DNS cache should have hostname for this IP */
    const char *h = dns_lookup("192.168.1.100");
    ASSERT(h != NULL);
    ASSERT(strstr(h, "mydevice") != NULL);
}

static void test_a_fills_service_ip(void) {
    setup();
    /* SRV first: creates entry with host=mydevice.local */
    mdns_snoop(pkt_srv, sizeof(pkt_srv));
    /* A record: should fill ip on the matching service */
    mdns_snoop(pkt_a, sizeof(pkt_a));
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
    ASSERT(strcmp(g_st.mdns_services[0].ip, "192.168.1.100") == 0);
}

static void test_aaaa_injects_dns_cache(void) {
    setup();
    mdns_snoop(pkt_aaaa, sizeof(pkt_aaaa));
    const char *h = dns_lookup("fe80::1");
    ASSERT(h != NULL);
    ASSERT(strstr(h, "mydevice") != NULL);
}

static void test_aaaa_fills_service_ip(void) {
    setup();
    mdns_snoop(pkt_srv, sizeof(pkt_srv));
    mdns_snoop(pkt_aaaa, sizeof(pkt_aaaa));
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
    /* ip field should contain the IPv6 address */
    ASSERT(strstr(g_st.mdns_services[0].ip, "fe80") != NULL);
}

static void test_dedup_same_instance(void) {
    setup();
    mdns_snoop(pkt_ptr, sizeof(pkt_ptr));
    mdns_snoop(pkt_ptr, sizeof(pkt_ptr));
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
}

static void test_multi_service(void) {
    setup();
    /* _http._tcp via pkt_ptr and _ssh._tcp via pkt_combined PTR */
    mdns_snoop(pkt_ptr, sizeof(pkt_ptr));
    mdns_snoop(pkt_combined, sizeof(pkt_combined));
    mdns_snapshot(&g_st);
    /* expect at least 2 distinct service entries */
    ASSERT(g_st.mdns_count >= 2);
}

static void test_combined_packet(void) {
    setup();
    int r = mdns_snoop(pkt_combined, sizeof(pkt_combined));
    ASSERT(r >= 1);
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count >= 1);

    /* find the pi service */
    int found = 0;
    for (int i = 0; i < g_st.mdns_count; i++) {
        if (strcmp(g_st.mdns_services[i].instance,
                   "pi._ssh._tcp.local") == 0) {
            ASSERT(g_st.mdns_services[i].port == 22);
            ASSERT(strcmp(g_st.mdns_services[i].host, "pi.local") == 0);
            ASSERT(strcmp(g_st.mdns_services[i].ip, "192.168.1.42") == 0);
            ASSERT(strcmp(g_st.mdns_services[i].service, "_ssh._tcp") == 0);
            found = 1;
        }
    }
    ASSERT(found == 1);
}

static void test_arcount_section(void) {
    setup();
    /* PTR is in the ARCOUNT section — must still be processed */
    int r = mdns_snoop(pkt_arcount, sizeof(pkt_arcount));
    ASSERT(r >= 1);
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
    ASSERT(strcmp(g_st.mdns_services[0].instance,
                 "mydevice._http._tcp.local") == 0);
}

static void test_question_section_skipped(void) {
    setup();
    int r = mdns_snoop(pkt_with_question, sizeof(pkt_with_question));
    ASSERT(r >= 1);
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
    ASSERT(strcmp(g_st.mdns_services[0].instance,
                 "mydevice._http._tcp.local") == 0);
}

static void test_cacheflush_class_bit(void) {
    setup();
    /* cache-flush bit in CLASS should not prevent A record from being processed */
    mdns_snoop(pkt_a_cacheflush, sizeof(pkt_a_cacheflush));
    const char *h = dns_lookup("192.168.1.101");
    ASSERT(h != NULL);
    ASSERT(strstr(h, "mydevice") != NULL);
}

static void test_snapshot_copies_to_state(void) {
    setup();
    mdns_snoop(pkt_ptr, sizeof(pkt_ptr));
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
    ASSERT(strcmp(g_st.mdns_services[0].instance,
                 "mydevice._http._tcp.local") == 0);
}

static void test_clear_resets(void) {
    setup();
    mdns_snoop(pkt_ptr, sizeof(pkt_ptr));
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
    mdns_clear();
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 0);
}

static void test_truncated_rdlen(void) {
    setup();
    /* Packet with RDLENGTH pointing beyond end — should return 0 cleanly */
    uint8_t bad[44];
    memcpy(bad, pkt_a, sizeof(pkt_a));
    bad[36] = 0x00;
    bad[37] = 0x20;  /* RDLENGTH=32, but only 4 bytes remain */
    ASSERT(mdns_snoop(bad, (int)sizeof(pkt_a)) == 0);
}

static void test_sanity_count_overflow(void) {
    setup();
    /* ANCOUNT=200 is > 64 — must be rejected */
    uint8_t bad[12] = {0x00,0x00, 0x84,0x00, 0x00,0x00, 0x00,0xC8,
                       0x00,0x00, 0x00,0x00};
    ASSERT(mdns_snoop(bad, 12) == 0);
}

static void test_ptr_last_seen_set(void) {
    setup();
    mdns_snoop(pkt_ptr, sizeof(pkt_ptr));
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
    ASSERT(g_st.mdns_services[0].last_seen != 0);
}

static void test_srv_last_seen_set(void) {
    setup();
    mdns_snoop(pkt_srv, sizeof(pkt_srv));
    mdns_snapshot(&g_st);
    ASSERT(g_st.mdns_count == 1);
    ASSERT(g_st.mdns_services[0].last_seen != 0);
}

static void test_ptr_then_srv_merge(void) {
    setup();
    /* PTR first (creates entry with service type, no port/host) */
    mdns_snoop(pkt_ptr, sizeof(pkt_ptr));
    /* SRV next (fills port + host on same entry) */
    mdns_snoop(pkt_srv, sizeof(pkt_srv));
    mdns_snapshot(&g_st);
    /* still only one entry */
    ASSERT(g_st.mdns_count == 1);
    ASSERT(strcmp(g_st.mdns_services[0].service, "_http._tcp") == 0);
    ASSERT(g_st.mdns_services[0].port == 80);
    ASSERT(strcmp(g_st.mdns_services[0].host, "mydevice.local") == 0);
}

/* ── View draw smoke tests ───────────────────────────────── */

static void draw_to_null(const sloth_state_t *s) {
    FILE *devnull = fopen("/dev/null", "w");
    if (!devnull) return;
    FILE *saved = stdout;
    stdout = devnull;
    view_mdns_draw(s);
    stdout = saved;
    fclose(devnull);
}

static void test_draw_empty_state(void) {
    setup();
    /* zero-service state: should render the "(no mDNS ...)" line, no crash */
    draw_to_null(&g_st);
    ASSERT(g_st.mdns_count == 0);
}

static void test_draw_populated_state(void) {
    setup();
    /* inject a service directly into state */
    strncpy(g_st.mdns_services[0].instance,
            "My Printer._ipp._tcp.local", 63);
    strncpy(g_st.mdns_services[0].service, "_ipp._tcp", 31);
    strncpy(g_st.mdns_services[0].host, "printer.local", 63);
    strncpy(g_st.mdns_services[0].ip, "192.168.1.5", 45);
    g_st.mdns_services[0].port = 631;
    g_st.mdns_services[0].last_seen = 1;
    g_st.mdns_count = 1;
    draw_to_null(&g_st);
    ASSERT(g_st.mdns_count == 1);
}

static void test_draw_selected_row(void) {
    setup();
    /* populate 3 services, select the middle one */
    for (int i = 0; i < 3; i++) {
        snprintf(g_st.mdns_services[i].instance, 64,
                 "dev%d._http._tcp.local", i);
        strncpy(g_st.mdns_services[i].service, "_http._tcp", 31);
        snprintf(g_st.mdns_services[i].ip, 46, "192.168.1.%d", i + 1);
        g_st.mdns_services[i].port = (uint16_t)(8000 + i);
        g_st.mdns_services[i].last_seen = 1;
    }
    g_st.mdns_count = 3;
    g_st.mdns_sel = 1;
    draw_to_null(&g_st);
    ASSERT(g_st.mdns_sel == 1);
}

static void test_nav_down_up(void) {
    setup();
    g_st.mdns_count = 3;
    g_st.mdns_sel   = 0;
    view_mdns_key(&g_st, SLOTH_KEY_DOWN); ASSERT(g_st.mdns_sel == 1);
    view_mdns_key(&g_st, SLOTH_KEY_DOWN); ASSERT(g_st.mdns_sel == 2);
    view_mdns_key(&g_st, SLOTH_KEY_DOWN); ASSERT(g_st.mdns_sel == 2); /* clamped */
    view_mdns_key(&g_st, SLOTH_KEY_UP);   ASSERT(g_st.mdns_sel == 1);
    view_mdns_key(&g_st, SLOTH_KEY_UP);   ASSERT(g_st.mdns_sel == 0);
    view_mdns_key(&g_st, SLOTH_KEY_UP);   ASSERT(g_st.mdns_sel == 0); /* clamped */
}

static void test_draw_no_host_or_ip(void) {
    setup();
    /* service with only PTR info (no SRV/A yet): host="" ip="" port=0 */
    strncpy(g_st.mdns_services[0].instance,
            "Unknown._ssh._tcp.local", 63);
    strncpy(g_st.mdns_services[0].service, "_ssh._tcp", 31);
    g_st.mdns_services[0].last_seen = 1;
    g_st.mdns_count = 1;
    draw_to_null(&g_st);
    ASSERT(g_st.mdns_count == 1);
}

static void test_sel_clamp_after_clear(void) {
    setup();
    g_st.mdns_sel = 5;
    mdns_clear();
    view_mdns_key(&g_st, 'c');  /* clear via key also resets sel */
    ASSERT(g_st.mdns_sel == 0);
    ASSERT(g_st.mdns_count == 0);
}

/* ── Runner ──────────────────────────────────────────────── */

void run_mdns_snoop_tests(void) {
    printf("\n--- mDNS snoop ---\n");
    RUN_TEST(test_too_short);
    RUN_TEST(test_empty_header);
    RUN_TEST(test_ptr_creates_service);
    RUN_TEST(test_ptr_service_type_extracted);
    RUN_TEST(test_srv_host_and_port);
    RUN_TEST(test_srv_service_type_from_instance);
    RUN_TEST(test_a_injects_dns_cache);
    RUN_TEST(test_a_fills_service_ip);
    RUN_TEST(test_aaaa_injects_dns_cache);
    RUN_TEST(test_aaaa_fills_service_ip);
    RUN_TEST(test_dedup_same_instance);
    RUN_TEST(test_multi_service);
    RUN_TEST(test_combined_packet);
    RUN_TEST(test_arcount_section);
    RUN_TEST(test_question_section_skipped);
    RUN_TEST(test_cacheflush_class_bit);
    RUN_TEST(test_snapshot_copies_to_state);
    RUN_TEST(test_clear_resets);
    RUN_TEST(test_truncated_rdlen);
    RUN_TEST(test_sanity_count_overflow);
    RUN_TEST(test_ptr_last_seen_set);
    RUN_TEST(test_srv_last_seen_set);
    RUN_TEST(test_ptr_then_srv_merge);
    RUN_TEST(test_sel_clamp_after_clear);
    RUN_TEST(test_draw_empty_state);
    RUN_TEST(test_draw_populated_state);
    RUN_TEST(test_draw_selected_row);
    RUN_TEST(test_nav_down_up);
    RUN_TEST(test_draw_no_host_or_ip);
}
