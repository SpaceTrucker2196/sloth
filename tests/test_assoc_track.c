#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "assoc_track.h"
#include "beacon_snoop.h"

static void m(uint8_t out[6], uint8_t a, uint8_t b, uint8_t c,
                              uint8_t d, uint8_t e, uint8_t f) {
    out[0]=a; out[1]=b; out[2]=c; out[3]=d; out[4]=e; out[5]=f;
}

static void test_empty(void) {
    assoc_clear();
    ASSERT_EQ(assoc_count(), 0);
}

static void test_observe_creates_entry(void) {
    assoc_clear();
    uint8_t b[6], s[6];
    m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    m(s, 0x00,0x11,0x22,0x33,0x44,0x55);
    assoc_observe(b, s, "HomeWiFi", ASSOC_SRC_ASSOC, -50, 6);
    ASSERT_EQ(assoc_count(), 1);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    assoc_snapshot(&st);
    ASSERT_EQ(st.assoc_count, 1);
    ASSERT_EQ(memcmp(st.assocs[0].bssid,   b, 6), 0);
    ASSERT_EQ(memcmp(st.assocs[0].sta_mac, s, 6), 0);
    ASSERT_STR(st.assocs[0].ssid, "HomeWiFi");
    ASSERT_EQ(st.assocs[0].source, ASSOC_SRC_ASSOC);
}

static void test_eapol_promotes_source_over_assoc(void) {
    assoc_clear();
    uint8_t b[6], s[6];
    m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    m(s, 0x00,0x11,0x22,0x33,0x44,0x55);
    assoc_observe(b, s, NULL, ASSOC_SRC_ASSOC, -50, 6);
    assoc_observe(b, s, NULL, ASSOC_SRC_EAPOL, -50, 6);  /* stronger */
    sloth_state_t st; memset(&st, 0, sizeof(st));
    assoc_snapshot(&st);
    ASSERT_EQ(st.assocs[0].source, ASSOC_SRC_EAPOL);

    /* Weaker source after EAPOL must not downgrade. */
    assoc_observe(b, s, NULL, ASSOC_SRC_ASSOC, -50, 6);
    assoc_snapshot(&st);
    ASSERT_EQ(st.assocs[0].source, ASSOC_SRC_EAPOL);
}

static void test_forget_removes_entry(void) {
    assoc_clear();
    uint8_t b[6], s[6];
    m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    m(s, 0x00,0x11,0x22,0x33,0x44,0x55);
    assoc_observe(b, s, NULL, ASSOC_SRC_EAPOL, -50, 6);
    ASSERT_EQ(assoc_count(), 1);
    assoc_forget(b, s);
    ASSERT_EQ(assoc_count(), 0);
}

static void test_multicast_bssid_rejected(void) {
    assoc_clear();
    uint8_t b_mcast[6], s[6];
    m(b_mcast, 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01);   /* multicast bit */
    m(s,       0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    assoc_observe(b_mcast, s, NULL, ASSOC_SRC_ASSOC, -50, 6);
    ASSERT_EQ(assoc_count(), 0);
}

static void test_multiple_stas_per_bssid(void) {
    assoc_clear();
    uint8_t b[6]; m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    uint8_t s1[6]; m(s1, 0x00,0x11,0x22,0x33,0x44,0x55);
    uint8_t s2[6]; m(s2, 0x00,0x11,0x22,0x33,0x44,0x66);
    assoc_observe(b, s1, NULL, ASSOC_SRC_EAPOL, -50, 6);
    assoc_observe(b, s2, NULL, ASSOC_SRC_EAPOL, -55, 6);
    ASSERT_EQ(assoc_count(), 2);
}

static void test_sta_random_flag_set(void) {
    assoc_clear();
    uint8_t b[6]; m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    uint8_t rand[6]; m(rand, 0x02,0x11,0x22,0x33,0x44,0x55);
    assoc_observe(b, rand, NULL, ASSOC_SRC_ASSOC, -50, 6);
    sloth_state_t st; memset(&st, 0, sizeof(st));
    assoc_snapshot(&st);
    ASSERT_EQ(st.assocs[0].sta_random, 1);
}

static void test_ssid_backfilled_from_beacon_table(void) {
    /* No SSID in observe() → snapshot should pull it from beacon_snoop. */
    assoc_clear();
    beacon_clear();
    uint8_t b[6]; m(b, 0xaa,0xbb,0xcc,0xdd,0xee,0xff);
    uint8_t s[6]; m(s, 0x00,0x11,0x22,0x33,0x44,0x55);
    assoc_observe(b, s, NULL, ASSOC_SRC_EAPOL, -50, 6);
    /* After-the-fact beacon observation. */
    beacon_record(b, "Lab-WiFi", -50, 6, "WPA2", 102, NULL);
    sloth_state_t st; memset(&st, 0, sizeof(st));
    assoc_snapshot(&st);
    ASSERT_STR(st.assocs[0].ssid, "Lab-WiFi");
}

/* ── Association / reassociation REQUEST parse (#60) ──────── */

/*
 * AssocReq   (subtype 0, FC0 0x00): hdr(24) caps(2) listen(2) + IEs
 * ReassocReq (subtype 2, FC0 0x20): hdr(24) caps(2) listen(2)
 *                                    current-AP(6) + IEs
 *
 * A request travels STA -> AP, so addr2 is the client and addr3 the
 * BSSID — the mirror of the response case. Frames are built from
 * IEEE 802.11-2020 §9.3.3.6 / §9.3.3.8 rather than replayed from a
 * capture, per AGENTS.md.
 */

#define RQ_HDR 24

/* Note the 0x12 first octet: the I/G bit is the LSB of octet 0, so a
 * MAC starting 0x11 is group-addressed and the unicast guard in
 * assoc_request_observe() rejects it — correctly. Locally-administered
 * unicast (0x12) is what a real client uses. */
static const uint8_t RQ_STA[6]   = {0x12,0x22,0x33,0x44,0x55,0x66};
static const uint8_t RQ_BSSID[6] = {0xaa,0xbb,0xcc,0x11,0x22,0x33};

/* Build a request frame. Returns total length. */
static int build_req(uint8_t *f, int is_reassoc, uint16_t caps,
                     uint16_t listen, const uint8_t *ies, int ie_len) {
    memset(f, 0, RQ_HDR);
    f[0] = is_reassoc ? 0x20 : 0x00;
    memcpy(f + 4,  RQ_BSSID, 6);   /* addr1 = DA = the AP  */
    memcpy(f + 10, RQ_STA,   6);   /* addr2 = SA = client  */
    memcpy(f + 16, RQ_BSSID, 6);   /* addr3 = BSSID        */
    int off = RQ_HDR;
    f[off++] = (uint8_t)(caps & 0xff);   f[off++] = (uint8_t)(caps >> 8);
    f[off++] = (uint8_t)(listen & 0xff); f[off++] = (uint8_t)(listen >> 8);
    if (is_reassoc) { memset(f + off, 0xCC, 6); off += 6; }  /* current AP */
    if (ie_len > 0) { memcpy(f + off, ies, (size_t)ie_len); off += ie_len; }
    return off;
}

/* SSID IE + Supported Rates IE + an RSN IE offering SAE with MFP
 * required — a WPA3 client asking for the strong configuration. */
static const uint8_t IES_WPA3_SAE[] = {
    0x00, 0x04, 'h','o','m','e',                 /* SSID */
    0x01, 0x04, 0x82, 0x84, 0x8b, 0x96,          /* rates 1,2,5.5,11 (basic) */
    0x32, 0x04, 0x0c, 0x12, 0x18, 0x24,          /* ext rates 6,9,12,18 */
    0x30, 0x14,                                   /* RSN */
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,                       /* group CCMP */
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,           /* pairwise CCMP */
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x08,           /* AKM SAE */
    0xc0, 0x00                                    /* caps: MFPR|MFPC */
};

static void test_req_parses_assoc(void) {
    uint8_t f[256];
    int n = build_req(f, 0, 0x0431, 10, IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    assoc_req_t r;
    ASSERT_EQ(assoc_request_parse(f, n, &r), 1);
    ASSERT_EQ(r.is_reassoc, 0);
    ASSERT_EQ(memcmp(r.sta,   RQ_STA,   6), 0);
    ASSERT_EQ(memcmp(r.bssid, RQ_BSSID, 6), 0);
    ASSERT_EQ(r.capability_info, 0x0431);
    ASSERT_EQ(r.listen_interval, 10);
    ASSERT_STR(r.requested_ssid, "home");
}

static void test_req_parses_reassoc_with_current_ap(void) {
    /* The 6-byte Current AP Address shifts the IE list. Miscounting it
     * makes every IE unreadable, so the SSID coming back intact is the
     * assertion that matters. */
    uint8_t f[256];
    int n = build_req(f, 1, 0x0431, 5, IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    assoc_req_t r;
    ASSERT_EQ(assoc_request_parse(f, n, &r), 1);
    ASSERT_EQ(r.is_reassoc, 1);
    ASSERT_STR(r.requested_ssid, "home");
    ASSERT_EQ(r.listen_interval, 5);
    ASSERT(r.akm_bits & RSN_AKM_SAE);
}

static void test_req_extracts_rsn_ask(void) {
    /* The downgrade delta's input: what the client asked for. */
    uint8_t f[256];
    int n = build_req(f, 0, 0, 1, IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    assoc_req_t r;
    ASSERT_EQ(assoc_request_parse(f, n, &r), 1);
    ASSERT(r.akm_bits & RSN_AKM_SAE);
    ASSERT(r.akm_bits & RSN_AKM_SAE_FAMILY);
    ASSERT_EQ(r.akm_bits & RSN_AKM_PSK_FAMILY, 0u);
    ASSERT(r.pairwise_bits & RSN_CIPHER_CCMP);
    ASSERT_EQ(r.requested_mfp, 2);            /* MFP required */
}

static void test_req_extracts_rates(void) {
    uint8_t f[256];
    int n = build_req(f, 0, 0, 1, IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    assoc_req_t r;
    ASSERT_EQ(assoc_request_parse(f, n, &r), 1);
    /* Basic-rate flag (0x80) must be masked off, else 0x82 reads as
     * an unknown rate and 1M goes missing. */
    ASSERT(r.supported_rates & ASSOC_RATE_1M);
    ASSERT(r.supported_rates & ASSOC_RATE_11M);
    /* Extended Supported Rates (tag 50) must be walked too. */
    ASSERT(r.supported_rates & ASSOC_RATE_6M);
    ASSERT(r.supported_rates & ASSOC_RATE_18M);
    ASSERT_EQ(r.supported_rates & ASSOC_RATE_54M, 0u);
}

static void test_req_legacy_11b_client(void) {
    static const uint8_t ies[] = {
        0x00, 0x03, 'o','l','d',
        0x01, 0x04, 0x82, 0x84, 0x8b, 0x96      /* 1, 2, 5.5, 11 only */
    };
    uint8_t f[128];
    int n = build_req(f, 0, 0, 1, ies, (int)sizeof(ies));
    assoc_req_t r;
    ASSERT_EQ(assoc_request_parse(f, n, &r), 1);
    ASSERT_EQ(r.supported_rates, (uint32_t)ASSOC_RATES_11B_ONLY);
    ASSERT_EQ(r.akm_bits, 0u);                /* open — no RSN IE */
    ASSERT_EQ(r.requested_mfp, 0);
}

static void test_req_rejects_other_subtypes(void) {
    uint8_t f[128];
    assoc_req_t r;
    int n = build_req(f, 0, 0, 1, IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    f[0] = 0x10;   /* AssocRsp */
    ASSERT_EQ(assoc_request_parse(f, n, &r), 0);
    f[0] = 0x30;   /* ReassocRsp */
    ASSERT_EQ(assoc_request_parse(f, n, &r), 0);
    f[0] = 0x40;   /* ProbeReq */
    ASSERT_EQ(assoc_request_parse(f, n, &r), 0);
    f[0] = 0x80;   /* Beacon */
    ASSERT_EQ(assoc_request_parse(f, n, &r), 0);
}

static void test_req_rejects_truncated(void) {
    uint8_t f[128];
    assoc_req_t r;
    build_req(f, 0, 0, 1, NULL, 0);
    ASSERT_EQ(assoc_request_parse(f, RQ_HDR, &r), 0);        /* no fixed body */
    ASSERT_EQ(assoc_request_parse(f, RQ_HDR + 3, &r), 0);    /* partial */
    /* A reassoc frame only long enough for an assoc body is truncated:
     * its Current AP Address is missing. */
    build_req(f, 1, 0, 1, NULL, 0);
    ASSERT_EQ(assoc_request_parse(f, RQ_HDR + 4, &r), 0);
}

static void test_req_zeroed_on_reject(void) {
    uint8_t f[256];
    assoc_req_t r;
    int n = build_req(f, 0, 0, 1, IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    ASSERT_EQ(assoc_request_parse(f, n, &r), 1);
    ASSERT(r.akm_bits != 0u);
    f[0] = 0x80;
    ASSERT_EQ(assoc_request_parse(f, n, &r), 0);
    ASSERT_EQ(r.akm_bits, 0u);
    ASSERT_EQ(r.requested_ssid[0], '\0');
}

/* ── request table ───────────────────────────────────────── */

static void test_req_table_stores_and_finds(void) {
    assoc_request_clear();
    uint8_t f[256];
    int n = build_req(f, 0, 0, 7, IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    assoc_req_t r;
    ASSERT_EQ(assoc_request_parse(f, n, &r), 1);
    assoc_request_observe(&r, -50, 6);
    ASSERT_EQ(assoc_request_count(), 1);

    assoc_req_t got;
    ASSERT_EQ(assoc_request_find(RQ_BSSID, RQ_STA, &got), 1);
    ASSERT_EQ(got.listen_interval, 7);
    ASSERT(got.akm_bits & RSN_AKM_SAE);

    uint8_t other[6] = {0x99,0x99,0x99,0x99,0x99,0x99};
    ASSERT_EQ(assoc_request_find(RQ_BSSID, other, &got), 0);
    assoc_request_clear();
}

static void test_req_table_latest_ask_wins(void) {
    /* A client that re-requests with weaker parameters has changed its
     * mind; the delta must be measured against the new ask, not the
     * first one ever seen. */
    assoc_request_clear();
    uint8_t f[256];
    assoc_req_t r;
    int n = build_req(f, 0, 0, 1, IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    ASSERT_EQ(assoc_request_parse(f, n, &r), 1);
    assoc_request_observe(&r, -50, 6);

    static const uint8_t ies_open[] = { 0x00, 0x04, 'h','o','m','e' };
    n = build_req(f, 0, 0, 99, ies_open, (int)sizeof(ies_open));
    ASSERT_EQ(assoc_request_parse(f, n, &r), 1);
    assoc_request_observe(&r, -50, 6);

    ASSERT_EQ(assoc_request_count(), 1);      /* same pair, not a new row */
    assoc_req_t got;
    ASSERT_EQ(assoc_request_find(RQ_BSSID, RQ_STA, &got), 1);
    ASSERT_EQ(got.listen_interval, 99);
    ASSERT_EQ(got.akm_bits, 0u);              /* the weaker ask replaced it */
    assoc_request_clear();
}

static void test_req_table_rejects_multicast(void) {
    /* Same unicast-only guard the grant path applies — a broadcast
     * addr2 is not a client. */
    assoc_request_clear();
    assoc_req_t r;
    memset(&r, 0, sizeof(r));
    memcpy(r.bssid, RQ_BSSID, 6);
    memset(r.sta, 0xff, 6);                   /* broadcast */
    assoc_request_observe(&r, -50, 6);
    ASSERT_EQ(assoc_request_count(), 0);

    memcpy(r.sta, RQ_STA, 6);
    memset(r.bssid, 0, 6);                    /* all-zero BSSID */
    assoc_request_observe(&r, -50, 6);
    ASSERT_EQ(assoc_request_count(), 0);
    assoc_request_clear();
}

void run_assoc_track_tests(void) {
    TEST_SUITE("assoc_track");
    RUN_TEST(test_empty);
    RUN_TEST(test_observe_creates_entry);
    RUN_TEST(test_eapol_promotes_source_over_assoc);
    RUN_TEST(test_forget_removes_entry);
    RUN_TEST(test_multicast_bssid_rejected);
    RUN_TEST(test_multiple_stas_per_bssid);
    RUN_TEST(test_sta_random_flag_set);
    RUN_TEST(test_ssid_backfilled_from_beacon_table);

    TEST_SUITE("assoc request parse (#60)");
    RUN_TEST(test_req_parses_assoc);
    RUN_TEST(test_req_parses_reassoc_with_current_ap);
    RUN_TEST(test_req_extracts_rsn_ask);
    RUN_TEST(test_req_extracts_rates);
    RUN_TEST(test_req_legacy_11b_client);
    RUN_TEST(test_req_rejects_other_subtypes);
    RUN_TEST(test_req_rejects_truncated);
    RUN_TEST(test_req_zeroed_on_reject);

    TEST_SUITE("assoc request table (#60)");
    RUN_TEST(test_req_table_stores_and_finds);
    RUN_TEST(test_req_table_latest_ask_wins);
    RUN_TEST(test_req_table_rejects_multicast);
}
