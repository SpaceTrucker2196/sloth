#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "assoc_track.h"
#include "beacon_snoop.h"
#include "probe_pnl.h"
#include "tui.h"
#include "views/assoc.h"
#include "views/pnl.h"

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

/* ── downgrade delta across successive requests (#60) ─────── */

/* Build + parse + observe one request carrying the given IEs. */
static void observe_ies(const uint8_t *ies, int ie_len) {
    uint8_t f[256];
    int n = build_req(f, 0, 0, 1, ies, ie_len);
    assoc_req_t r;
    ASSERT_EQ(assoc_request_parse(f, n, &r), 1);
    assoc_request_observe(&r, -50, 6);
}

/* RSN offering PSK with MFP off — the WPA2 fallback lane. */
static const uint8_t IES_WPA2_PSK[] = {
    0x00, 0x04, 'h','o','m','e',
    0x30, 0x14,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,          /* AKM PSK */
    0x00, 0x00                                    /* no MFP */
};

static void test_downgrade_sae_to_psk(void) {
    /* The signature: a client that asked for SAE comes back asking for
     * PSK. That retry is the downgrade, and it is the one place it is
     * actually visible on the air. */
    assoc_request_clear();
    observe_ies(IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    ASSERT_EQ(assoc_request_downgrade_count(), 0);

    observe_ies(IES_WPA2_PSK, (int)sizeof(IES_WPA2_PSK));
    ASSERT_EQ(assoc_request_downgrade_count(), 1);

    assoc_req_t got;
    ASSERT_EQ(assoc_request_find(RQ_BSSID, RQ_STA, &got), 1);
    ASSERT(got.downgrade_flags & ASSOC_DG_AKM);
    ASSERT(got.downgrade_flags & ASSOC_DG_MFP);   /* required -> off */
    ASSERT(got.prev_akm_bits & RSN_AKM_SAE);
    ASSERT_EQ(got.prev_mfp, 2);
    assoc_request_clear();
}

static void test_upgrade_is_not_a_downgrade(void) {
    /* PSK then SAE is a client getting stronger. Must not fire. */
    assoc_request_clear();
    observe_ies(IES_WPA2_PSK, (int)sizeof(IES_WPA2_PSK));
    observe_ies(IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    ASSERT_EQ(assoc_request_downgrade_count(), 0);
    assoc_request_clear();
}

static void test_repeat_same_ask_is_not_a_downgrade(void) {
    /* An ordinary retry with identical parameters is not a downgrade —
     * otherwise every roaming client trips this. */
    assoc_request_clear();
    observe_ies(IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    observe_ies(IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    ASSERT_EQ(assoc_request_downgrade_count(), 0);
    assoc_request_clear();
}

static void test_dropping_rsn_entirely_is_not_akm_downgrade(void) {
    /* A client that stops sending RSN altogether is roaming to an open
     * BSS, not being downgraded onto PSK. The AKM flag requires the PSK
     * arm precisely so this stays quiet. */
    static const uint8_t ies_open[] = { 0x00, 0x04, 'h','o','m','e' };
    assoc_request_clear();
    observe_ies(IES_WPA3_SAE, (int)sizeof(IES_WPA3_SAE));
    observe_ies(ies_open, (int)sizeof(ies_open));
    assoc_req_t got;
    ASSERT_EQ(assoc_request_find(RQ_BSSID, RQ_STA, &got), 1);
    ASSERT_EQ(got.downgrade_flags & ASSOC_DG_AKM, 0);
    /* MFP genuinely did drop, and that is worth recording on its own. */
    ASSERT(got.downgrade_flags & ASSOC_DG_MFP);
    assoc_request_clear();
}

static void test_downgrade_pairwise_tkip(void) {
    /* TKIP appearing where it was absent — deprecated cipher newly on
     * offer from the same client. */
    static const uint8_t ies_tkip[] = {
        0x00, 0x04, 'h','o','m','e',
        0x30, 0x18,
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x02,
        0x02, 0x00, 0x00, 0x0f, 0xac, 0x04,       /* pairwise CCMP ... */
                    0x00, 0x0f, 0xac, 0x02,       /* ... and TKIP      */
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
        0x00, 0x00
    };
    assoc_request_clear();
    observe_ies(IES_WPA2_PSK, (int)sizeof(IES_WPA2_PSK));
    observe_ies(ies_tkip, (int)sizeof(ies_tkip));
    assoc_req_t got;
    ASSERT_EQ(assoc_request_find(RQ_BSSID, RQ_STA, &got), 1);
    ASSERT(got.downgrade_flags & ASSOC_DG_PAIRWISE);
    assoc_request_clear();
}

static void test_first_request_never_flags(void) {
    /* Nothing to compare against — a lone request cannot be a
     * downgrade, however weak it is. */
    assoc_request_clear();
    observe_ies(IES_WPA2_PSK, (int)sizeof(IES_WPA2_PSK));
    assoc_req_t got;
    ASSERT_EQ(assoc_request_find(RQ_BSSID, RQ_STA, &got), 1);
    ASSERT_EQ(got.downgrade_flags, 0);
    ASSERT_EQ(got.prev_akm_bits, 0u);
    assoc_request_clear();
}


/* ── assoc-request flood window (#60) ────────────────────── */

/* Feed n requests to one BSSID from `stas` distinct source MACs,
 * round-robin, all stamped now. */
static void flood_n(int n, int stas) {
    for (int i = 0; i < n; i++) {
        assoc_req_t r;
        memset(&r, 0, sizeof(r));
        memcpy(r.bssid, RQ_BSSID, 6);
        r.sta[0] = 0x12; r.sta[1] = 0x22; r.sta[2] = 0x33;
        r.sta[3] = 0x44; r.sta[4] = 0x55;
        r.sta[5] = (uint8_t)(i % stas);
        assoc_request_observe(&r, -50, 6);
    }
}

static void test_flood_below_threshold_silent(void) {
    assoc_flood_clear(); assoc_request_clear();
    flood_n(ASSOC_FLOOD_THRESH - 1, 4);
    uint8_t b[6]; int distinct = 0;
    ASSERT_EQ(assoc_flood_bssid(time(NULL), ASSOC_FLOOD_WIN_SECS,
                                ASSOC_FLOOD_THRESH, b, &distinct), 0);
    assoc_flood_clear(); assoc_request_clear();
}

static void test_flood_at_threshold_reports(void) {
    assoc_flood_clear(); assoc_request_clear();
    flood_n(ASSOC_FLOOD_THRESH, 4);
    uint8_t b[6]; int distinct = 0;
    int n = assoc_flood_bssid(time(NULL), ASSOC_FLOOD_WIN_SECS,
                              ASSOC_FLOOD_THRESH, b, &distinct);
    ASSERT_EQ(n, ASSOC_FLOOD_THRESH);
    ASSERT_EQ(memcmp(b, RQ_BSSID, 6), 0);
    ASSERT_EQ(distinct, 4);
    assoc_flood_clear(); assoc_request_clear();
}

static void test_flood_counts_distinct_stas(void) {
    /* Same rate, different shape: one talkative STA versus many
     * spoofed ones. The count must tell them apart, since that is what
     * separates a broken client from a MAC-spoofing flood. */
    assoc_flood_clear(); assoc_request_clear();
    flood_n(ASSOC_FLOOD_THRESH + 4, 1);
    uint8_t b[6]; int distinct = 0;
    assoc_flood_bssid(time(NULL), ASSOC_FLOOD_WIN_SECS,
                      ASSOC_FLOOD_THRESH, b, &distinct);
    ASSERT_EQ(distinct, 1);

    assoc_flood_clear(); assoc_request_clear();
    flood_n(ASSOC_FLOOD_THRESH + 4, 25);
    distinct = 0;
    assoc_flood_bssid(time(NULL), ASSOC_FLOOD_WIN_SECS,
                      ASSOC_FLOOD_THRESH, b, &distinct);
    ASSERT_EQ(distinct, 25);
    assoc_flood_clear(); assoc_request_clear();
}

static void test_flood_window_expiry(void) {
    /* Events older than the window must not count, or the alert never
     * clears once tripped. */
    assoc_flood_clear(); assoc_request_clear();
    flood_n(ASSOC_FLOOD_THRESH + 4, 4);
    uint8_t b[6];
    time_t future = time(NULL) + ASSOC_FLOOD_WIN_SECS + 10;
    ASSERT_EQ(assoc_flood_bssid(future, ASSOC_FLOOD_WIN_SECS,
                                ASSOC_FLOOD_THRESH, b, NULL), 0);
    assoc_flood_clear(); assoc_request_clear();
}

static void test_flood_is_per_bssid(void) {
    /* Requests spread over many APs are an ordinary busy environment,
     * not a flood at any one of them. */
    assoc_flood_clear(); assoc_request_clear();
    for (int i = 0; i < ASSOC_FLOOD_THRESH * 3; i++) {
        assoc_req_t r;
        memset(&r, 0, sizeof(r));
        memcpy(r.bssid, RQ_BSSID, 6);
        r.bssid[5] = (uint8_t)(i % 10);          /* 10 different APs */
        memcpy(r.sta, RQ_STA, 6);
        r.sta[5] = (uint8_t)(i % 7);
        assoc_request_observe(&r, -50, 6);
    }
    uint8_t b[6];
    ASSERT_EQ(assoc_flood_bssid(time(NULL), ASSOC_FLOOD_WIN_SECS,
                                ASSOC_FLOOD_THRESH, b, NULL), 0);
    assoc_flood_clear(); assoc_request_clear();
}


/* ── PNL PHY corroboration + view surfaces (#60 slice 5b) ─── */

/* TPRINT is printf in the test build, so both views can be captured
 * and asserted on. Same technique as test_help.c. */
static void capture_draw(void (*draw)(const sloth_state_t *),
                         const sloth_state_t *st, char *buf, int sz) {
    fflush(stdout);
    int saved = dup(fileno(stdout));
    FILE *tmp = tmpfile();
    dup2(fileno(tmp), fileno(stdout));
    draw(st);
    fflush(stdout);
    dup2(saved, fileno(stdout));
    close(saved);
    rewind(tmp);
    int n = (int)fread(buf, 1, sz - 1, tmp);
    buf[n < 0 ? 0 : n] = '\0';
    fclose(tmp);
}

static void test_pnl_phy_confirmed_by_assoc_request(void) {
    /* A probe said Wi-Fi 5; the association request says Wi-Fi 6. The
     * request is the stronger evidence and the tier moves. */
    probe_pnl_clear();
    uint8_t sta[6]; m(sta, 0x12,0x22,0x33,0x44,0x55,0x66);
    probe_pnl_observe(sta, "home", NULL, "Wi-Fi 5");
    ASSERT_EQ(probe_pnl_note_assoc_phy(sta, "Wi-Fi 6"), 1);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    probe_pnl_snapshot(&st);
    ASSERT_EQ(st.pnl_count, 1);
    ASSERT_STR(st.pnl_clients[0].phy, "Wi-Fi 6");
    ASSERT_EQ(st.pnl_clients[0].phy_confirmed, 1);
    /* An association request is not a probe. */
    ASSERT_EQ(st.pnl_clients[0].probe_count, 1);
    probe_pnl_clear();
}

static void test_pnl_phy_confirmation_without_upgrade(void) {
    /* The request agrees with the probe. The tier does not move, but it
     * is now corroborated — which is the distinction the marker shows. */
    probe_pnl_clear();
    uint8_t sta[6]; m(sta, 0x12,0x22,0x33,0x44,0x55,0x67);
    probe_pnl_observe(sta, "home", NULL, "Wi-Fi 6");
    ASSERT_EQ(probe_pnl_note_assoc_phy(sta, "Wi-Fi 6"), 1);
    sloth_state_t st; memset(&st, 0, sizeof(st));
    probe_pnl_snapshot(&st);
    ASSERT_STR(st.pnl_clients[0].phy, "Wi-Fi 6");
    ASSERT_EQ(st.pnl_clients[0].phy_confirmed, 1);
    probe_pnl_clear();
}

static void test_pnl_phy_never_downgrades(void) {
    probe_pnl_clear();
    uint8_t sta[6]; m(sta, 0x12,0x22,0x33,0x44,0x55,0x68);
    probe_pnl_observe(sta, "home", NULL, "Wi-Fi 7");
    ASSERT_EQ(probe_pnl_note_assoc_phy(sta, "Wi-Fi 4"), 1);
    sloth_state_t st; memset(&st, 0, sizeof(st));
    probe_pnl_snapshot(&st);
    ASSERT_STR(st.pnl_clients[0].phy, "Wi-Fi 7");
    probe_pnl_clear();
}

static void test_pnl_phy_does_not_create_a_row(void) {
    /* A client that associated but never sent a directed probe has no
     * preferred-network list. Creating an empty row would put a device
     * with no PNL into the PNL view. */
    probe_pnl_clear();
    uint8_t sta[6]; m(sta, 0x12,0x22,0x33,0x44,0x55,0x69);
    ASSERT_EQ(probe_pnl_note_assoc_phy(sta, "Wi-Fi 6"), 0);
    ASSERT_EQ(probe_pnl_count(), 0);
    probe_pnl_clear();
}

static void test_pnl_view_marks_confirmed_tier(void) {
    probe_pnl_clear();
    uint8_t sta[6]; m(sta, 0x12,0x22,0x33,0x44,0x55,0x6a);
    probe_pnl_observe(sta, "home", NULL, "Wi-Fi 6");
    probe_pnl_note_assoc_phy(sta, "Wi-Fi 6");
    sloth_state_t st; memset(&st, 0, sizeof(st));
    probe_pnl_snapshot(&st);
    char buf[8192];
    capture_draw(view_pnl_draw, &st, buf, sizeof(buf));
    ASSERT(strstr(buf, "Wi-Fi 6*") != NULL);
    probe_pnl_clear();
}

static void test_pnl_view_unconfirmed_tier_unmarked(void) {
    probe_pnl_clear();
    uint8_t sta[6]; m(sta, 0x12,0x22,0x33,0x44,0x55,0x6b);
    probe_pnl_observe(sta, "home", NULL, "Wi-Fi 6");
    sloth_state_t st; memset(&st, 0, sizeof(st));
    probe_pnl_snapshot(&st);
    char buf[8192];
    capture_draw(view_pnl_draw, &st, buf, sizeof(buf));
    ASSERT(strstr(buf, "Wi-Fi 6")  != NULL);
    ASSERT(strstr(buf, "Wi-Fi 6*") == NULL);
    probe_pnl_clear();
}

/* ── [w] Assoc view: the ask, and what it replaced ────────── */

static void seed_grant_and_ask(sloth_state_t *st, uint32_t akm,
                               uint32_t prev_akm, int dg) {
    memset(st, 0, sizeof(*st));
    assoc_t *a = &st->assocs[st->assoc_count++];
    m(a->bssid,   0xaa,0xbb,0xcc,0xdd,0xee,0x50);
    m(a->sta_mac, 0x12,0x22,0x33,0x44,0x55,0x70);
    snprintf(a->ssid, sizeof(a->ssid), "corp-wifi");
    a->source     = ASSOC_SRC_EAPOL;
    a->channel    = 6;
    a->signal_dbm = -50;
    a->last_seen  = time(NULL);

    assoc_req_t *r = &st->assoc_reqs[st->assoc_req_count++];
    memset(r, 0, sizeof(*r));
    m(r->bssid, 0xaa,0xbb,0xcc,0xdd,0xee,0x50);
    m(r->sta,   0x12,0x22,0x33,0x44,0x55,0x70);
    r->akm_bits        = akm;
    r->prev_akm_bits   = prev_akm;
    r->downgrade_flags = dg;
    r->requested_mfp   = dg & ASSOC_DG_MFP ? 0 : 2;
    r->prev_mfp        = 2;
}

static void test_assoc_view_shows_the_ask(void) {
    sloth_state_t st;
    seed_grant_and_ask(&st, RSN_AKM_SAE, 0, 0);
    char buf[8192];
    capture_draw(view_assoc_draw, &st, buf, sizeof(buf));
    ASSERT(strstr(buf, "asked") != NULL);      /* the column header */
    ASSERT(strstr(buf, "SAE")   != NULL);
    /* No downgrade, so no marker at all — asserted on the glyph rather
     * than on "->", because a marker block that runs with no flags set
     * still emits a bare delta and would slip past a text-only check. */
    ASSERT(strstr(buf, "\xe2\x88\x86") == NULL);
    ASSERT(strstr(buf, "->") == NULL);
    assoc_clear();
}

static void test_assoc_view_marks_akm_downgrade(void) {
    /* The row has to say what was given up, not merely that something
     * was — "SAE->PSK" is actionable, a bare glyph is not. */
    sloth_state_t st;
    seed_grant_and_ask(&st, RSN_AKM_PSK, RSN_AKM_SAE, ASSOC_DG_AKM);
    char buf[8192];
    capture_draw(view_assoc_draw, &st, buf, sizeof(buf));
    ASSERT(strstr(buf, "\xe2\x88\x86")  != NULL);
    ASSERT(strstr(buf, "SAE->PSK") != NULL);
    assoc_clear();
}

static void test_assoc_view_marks_mfp_downgrade(void) {
    sloth_state_t st;
    seed_grant_and_ask(&st, RSN_AKM_SAE, RSN_AKM_SAE, ASSOC_DG_MFP);
    char buf[8192];
    capture_draw(view_assoc_draw, &st, buf, sizeof(buf));
    ASSERT(strstr(buf, "MFP2->0") != NULL);
    assoc_clear();
}

static void test_assoc_view_no_request_shows_dash(void) {
    /* A grant we saw without ever catching the request — common when
     * sloth started mid-association. The column must not claim "open". */
    sloth_state_t st;
    seed_grant_and_ask(&st, RSN_AKM_SAE, 0, 0);
    st.assoc_req_count = 0;                    /* drop the ask */
    char buf[8192];
    capture_draw(view_assoc_draw, &st, buf, sizeof(buf));
    ASSERT(strstr(buf, "open") == NULL);
    assoc_clear();
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

    TEST_SUITE("assoc downgrade delta (#60)");
    RUN_TEST(test_downgrade_sae_to_psk);
    RUN_TEST(test_upgrade_is_not_a_downgrade);
    RUN_TEST(test_repeat_same_ask_is_not_a_downgrade);
    RUN_TEST(test_dropping_rsn_entirely_is_not_akm_downgrade);
    RUN_TEST(test_downgrade_pairwise_tkip);
    RUN_TEST(test_first_request_never_flags);

    TEST_SUITE("assoc flood window (#60)");
    RUN_TEST(test_flood_below_threshold_silent);
    RUN_TEST(test_flood_at_threshold_reports);
    RUN_TEST(test_flood_counts_distinct_stas);
    RUN_TEST(test_flood_window_expiry);
    RUN_TEST(test_flood_is_per_bssid);
    TEST_SUITE("PNL PHY corroboration (#60)");
    RUN_TEST(test_pnl_phy_confirmed_by_assoc_request);
    RUN_TEST(test_pnl_phy_confirmation_without_upgrade);
    RUN_TEST(test_pnl_phy_never_downgrades);
    RUN_TEST(test_pnl_phy_does_not_create_a_row);
    RUN_TEST(test_pnl_view_marks_confirmed_tier);
    RUN_TEST(test_pnl_view_unconfirmed_tier_unmarked);

    TEST_SUITE("[w] Assoc view — the ask (#60)");
    RUN_TEST(test_assoc_view_shows_the_ask);
    RUN_TEST(test_assoc_view_marks_akm_downgrade);
    RUN_TEST(test_assoc_view_marks_mfp_downgrade);
    RUN_TEST(test_assoc_view_no_request_shows_dash);
}
