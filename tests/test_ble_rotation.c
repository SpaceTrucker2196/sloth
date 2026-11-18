#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "ble_hci.h"
#include "ble_snoop.h"
#include "ble_flood.h"
#include "ble_detect.h"
#include "ble_rotation.h"
#include "ble_watchlist.h"
#include "jsonl.h"
#include "sensors.h"
#include "siphash.h"
#include "sloth_clock.h"
#include "tui.h"
#include "views/ble.h"
#include "tmp_dir.h"

/*
 * BLE address-rotation hints — #156 item 2 (src/ble_rotation.h,
 * research/bluetooth/ble-address-rotation.md).
 *
 * Every advertisement is a hand-built AD byte array, never a capture
 * (agents/AGENTS.md, "No pcap fixtures"):
 *
 *   MS-CDP beacon ([MS-CDP] 2.2.2.2.3): 0x1E 0xFF 06 00, then
 *     Scenario_Type 0x01, Version_and_Device_Type 0x29 (version 001,
 *     SKU 9 "Windows 10 Desktop"), Version_and_Flags 0x20 (001, 00000),
 *     Flags_and_Device_Status 0x00, Salt (4), Device_Hash (19).
 *   Fast Pair (Provider Advertising signal): Service Data 0xFE2C;
 *     discoverable = the 24-bit Model ID; not discoverable = version
 *     0x00, 0bLLLLTTTT (L 5, T 0b0000), a 5-octet Account Key Filter
 *     (n = 2 keys), 0b00100001, a 2-octet Salt.
 *   HCI LE Set Scan Enable (Vol 4 Part E §7.8.11, opcode 0x200C):
 *     LE_Scan_Enable, Filter_Duplicates. Every HCI-path test enables
 *     the scan with Filter_Duplicates 0 first (scan_on()), since a
 *     filtering or unknown controller proposes no link at all.
 *   Apple Handoff, UNVERIFIED: no vendor specification. Built from the
 *     papers' published layout (Celosia and Cunche, PoPETs 2020, Fig. 9;
 *     Martin et al., PoPETs 2019, Fig. 2): Continuity type 0x0C, length
 *     14, version/clipboard 1, IV 2, AES-GCM tag 1, payload 10.
 *
 * Addresses: Address[47:46] is the top two bits of the display-order
 * first octet (Core v5.4 Vol 6 Part B §1.3.2): 0x4x RPA, 0x1x NRPA,
 * 0xCx static random.
 */

TEST_STATE(g_s);

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }

static const char *const MON = BT_MONITOR_DEVICE;

/* LE Set Scan Enable on `adapter`, scanning, with Filter_Duplicates
 * `fd`, through the monitor decoder. */
static void scan_on(uint16_t adapter, uint8_t fd) {
    const uint8_t rec[] = { (uint8_t)(adapter >> 8), (uint8_t)adapter,
                            0, BT_MON_COMMAND_PKT, 0x0C, 0x20, 2, 0x01, fd };
    ASSERT_EQ((int)ble_mon_ingest(rec, sizeof(rec), sizeof(rec), g_wall, g_wall),
              (int)BLE_REC_COMMAND);
}

static void setup_scan(int hints_on, int scan) {
    g_mono = 5000000;
    g_wall = 1800000000;
    sloth_clock_test_set(pin_mono, pin_wall);
    memset(&g_s, 0, sizeof(g_s));
    ble_hci_rotation_enable(0);
    ble_clear();
    if (scan) scan_on(0, 0x00);
    if (hints_on) ASSERT_EQ(ble_hci_rotation_enable(1), 0);
}

static void setup(int hints_on) { setup_scan(hints_on, 1); }

static void teardown(void) {
    ble_hci_rotation_enable(0);
    ble_clear();
    sloth_clock_test_set(NULL, NULL);
}

static void obs_on(const uint8_t a[6], uint8_t atype, uint8_t evt,
                   const uint8_t *ad, size_t len, time_t ts,
                   const char *ifc, uint16_t adapter) {
    ble_adv_report_t r;
    memset(&r, 0, sizeof(r));
    r.event_type = evt;
    r.addr_type  = atype;
    for (int i = 0; i < 6; i++) r.addr[i] = a[5 - i];
    r.has_rssi = true;
    r.rssi = -60;
    ble_ad_parse(ad, len, &r);
    ble_obs_t o = { &r, SENSOR_BLE, ifc, adapter, -1, 0, ts };
    ble_dev_observe(&o);
}

static void obs(const uint8_t a[6], const uint8_t *ad, size_t len, time_t ts) {
    obs_on(a, 1, 0x03, ad, len, ts, MON, 0);
}

/* `a` heard every `step` seconds over [from, to]; returns how many
 * reports that was, for a caller that has to land on a count. */
static unsigned run_addr(const uint8_t a[6], const uint8_t *ad, size_t len,
                         time_t from, time_t to, time_t step) {
    unsigned n = 0;
    for (time_t t = from; t <= to; t += step, n++) obs(a, ad, len, t);
    return n;
}

static void rpa(uint8_t a[6], unsigned n) {
    a[0] = 0x45; a[1] = 0x11; a[2] = 0x22;
    a[3] = (uint8_t)(n >> 16); a[4] = (uint8_t)(n >> 8); a[5] = (uint8_t)n;
}

/* ── AD builders ──────────────────────────────────────────────────── */

#define CDP_LEN 31
static void ad_cdp(uint8_t b[CDP_LEN], uint8_t seed) {
    static const uint8_t head[] = { 0x1E, 0xFF, 0x06, 0x00, 0x01, 0x29, 0x20, 0x00 };
    memcpy(b, head, sizeof(head));
    b[8] = 0xA5; b[9] = 0x5A; b[10] = 0xC3; b[11] = (uint8_t)(0x3C ^ seed);  /* Salt */
    for (int i = 0; i < 19; i++) b[12 + i] = (uint8_t)(0x70 + i + seed);      /* Device_Hash */
}

#define HANDOFF_LEN 20
static void ad_handoff(uint8_t b[HANDOFF_LEN], uint8_t seed) {
    static const uint8_t head[] = { 0x13, 0xFF, 0x4C, 0x00, 0x0C, 0x0E, 0x00 };
    memcpy(b, head, sizeof(head));
    b[7] = 0xE1; b[8] = (uint8_t)(0x5A ^ seed);                  /* IV */
    b[9] = 0x9D;                                                  /* GCM tag */
    for (int i = 0; i < 10; i++) b[10 + i] = (uint8_t)(0xB0 + i); /* payload */
}

#define FP_ACCT_LEN 14
static void ad_fp_account(uint8_t b[FP_ACCT_LEN], uint8_t salt1) {
    const uint8_t v[] = { 0x0D, 0x16, 0x2C, 0xFE, 0x00, 0x50,
                          0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0x21, 0xE7, salt1 };
    memcpy(b, v, sizeof(v));
}

static const uint8_t AD_FP_DISC[] = { 0x06, 0x16, 0x2C, 0xFE, 0x12, 0x34, 0x56 };
/* Flags, then a HID appearance 0x03C1 (keyboard). */
static const uint8_t AD_KBD[] = { 0x02, 0x01, 0x05, 0x03, 0x19, 0xC1, 0x03 };

static ble_adv_report_t parsed(const uint8_t *ad, size_t len) {
    ble_adv_report_t r;
    memset(&r, 0, sizeof(r));
    ble_ad_parse(ad, len, &r);
    return r;
}

static void snap(void) { ble_snapshot(&g_s); }

static const ble_device_t *row(const uint8_t a[6]) {
    for (int i = 0; i < g_s.ble_device_count; i++)
        if (memcmp(g_s.ble_devices[i].addr, a, 6) == 0) return &g_s.ble_devices[i];
    return NULL;
}

/* ── SipHash-2-4 ──────────────────────────────────────────────────── */

static void test_siphash_vectors(void) {
    uint8_t k[16], m[16];
    for (int i = 0; i < 16; i++) { k[i] = (uint8_t)i; m[i] = (uint8_t)i; }
    /* Aumasson and Bernstein, INDOCRYPT 2012, Appendix A: key 00..0f,
     * the 15-byte message 00..0e. */
    ASSERT_EQ(siphash24(k, m, 15), 0xa129ca6149be45e5ULL);
    /* Reference implementation vectors.h, lengths 0 and 1 under the
     * same key. */
    ASSERT_EQ(siphash24(k, m, 0), 0x726fdb47dd0e0e31ULL);
    ASSERT_EQ(siphash24(k, m, 1), 0x74f839c593dc67fdULL);
}

/* ── Tokens and candidates ───────────────────────────────────────── */

static void test_cdp_token_is_salt_and_hash(void) {
    uint8_t ad[CDP_LEN];
    ad_cdp(ad, 0);
    ble_adv_report_t r = parsed(ad, sizeof(ad));
    ble_token_t t[3];
    memset(t, 0, sizeof(t));
    int disc = 9;
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, &disc), 1);
    ASSERT_EQ(disc, 0);
    ASSERT_EQ(t[0].kind, BLE_TOK_MS_CDP);
    ASSERT_EQ(t[0].len, 23);
    if (t[0].bytes) {
        ASSERT_EQ(t[0].bytes[0], 0xA5);      /* the Salt, not the fixed octets */
        ASSERT_EQ(t[0].bytes[22], 0x70 + 18);
    }

    /* Scenario_Type other than 1, and a beacon one octet short: no
     * token. Seen to fail, one mutation at a time: with the Scenario_Type
     * test made `1 &&`, and with the length test made `>= 26`. */
    ad[4] = 0x02;
    r = parsed(ad, sizeof(ad));
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, NULL), 0);
    ad_cdp(ad, 0);
    ad[0] = 0x1D;
    r = parsed(ad, sizeof(ad) - 1);
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, NULL), 0);
}

static void test_cdp_token_never_from_a_clipped_field(void) {
    /* An extended advertisement's manufacturer data longer than the 27
     * octets the decoder keeps: the first 27 look like a CDP beacon, but
     * the field is not one. Seen to fail: with `&& !r->mfr_data_clipped`
     * dropped from ble_rot_tokens(). */
    uint8_t ad[33];
    ad_cdp(ad, 0);
    ad[0] = 0x20;
    ad[31] = 0x01; ad[32] = 0x02;
    ble_adv_report_t r = parsed(ad, sizeof(ad));
    ASSERT(r.mfr_data_clipped);
    ble_token_t t[3];
    memset(t, 0, sizeof(t));
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, NULL), 0);
}

static void test_handoff_token_skips_its_first_octet(void) {
    uint8_t ad[HANDOFF_LEN];
    ad_handoff(ad, 0);
    ble_adv_report_t r = parsed(ad, sizeof(ad));
    ble_token_t t[3];
    memset(t, 0, sizeof(t));
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, NULL), 1);
    ASSERT_EQ(t[0].kind, BLE_TOK_APPLE_HANDOFF);
    ASSERT_EQ(t[0].len, 13);
    ASSERT(t[0].bytes && t[0].bytes[0] == 0xE1);

    /* After a Nearby Info TLV (0x10, length 5) in the same field. */
    uint8_t two[27] = { 0x1A, 0xFF, 0x4C, 0x00, 0x10, 0x05, 1, 2, 3, 4, 5 };
    memcpy(two + 11, ad + 4, 16);
    r = parsed(two, sizeof(two));
    memset(t, 0, sizeof(t));
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, NULL), 1);
    ASSERT(t[0].bytes && t[0].bytes[0] == 0xE1);

    /* Nearby alone (3-octet tag, under the 40-bit bound) and a Handoff
     * TLV of the wrong length: no token. Seen to fail: with apple_handoff()'s
     * `len == 14` made `len >= 5`. */
    const uint8_t nearby[] = { 0x0A, 0xFF, 0x4C, 0x00, 0x10, 0x05, 1, 2, 3, 4, 5 };
    r = parsed(nearby, sizeof(nearby));
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, NULL), 0);
    ad[0] = 0x12; ad[5] = 0x0D;
    r = parsed(ad, sizeof(ad) - 1);
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, NULL), 0);
}

static void test_fast_pair_forms(void) {
    uint8_t ad[FP_ACCT_LEN];
    ad_fp_account(ad, 0x01);
    ble_adv_report_t r = parsed(ad, sizeof(ad));
    ble_token_t t[3];
    memset(t, 0, sizeof(t));
    int disc = 9;
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, &disc), 1);
    ASSERT_EQ(disc, 0);
    ASSERT_EQ(t[0].kind, BLE_TOK_FAST_PAIR_ACCOUNT);
    /* Filter 5, then the salt 2 as its own run: the 0x21 header between
     * them is a constant and is left out. Seen to fail: with bytes2
     * pointed at the header (`salt_hdr` for `salt_hdr + 1`). */
    ASSERT_EQ(t[0].len, 5);
    ASSERT(t[0].bytes && t[0].bytes[0] == 0xD1 && t[0].bytes[4] == 0xD5);
    ASSERT_EQ(t[0].len2, 2);
    ASSERT(t[0].bytes2 && t[0].bytes2[0] == 0xE7 && t[0].bytes2[1] == 0x01);

    /* Discoverable: Model ID alone. Flagged, never a token. The
     * not-discoverable form above and the short filter below read
     * disc 0; seen to fail with the `len == 3` test made `len >= 3`. */
    r = parsed(AD_FP_DISC, sizeof(AD_FP_DISC));
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, &disc), 0);
    ASSERT_EQ(disc, 1);
    /* LE Audio Sharing form: version 0, then a Model ID field 0bLLLL0111. */
    const uint8_t audio[] = { 0x0A, 0x16, 0x2C, 0xFE, 0x00, 0x37, 0x12, 0x34, 0x56, 0x18, 0x00 };
    r = parsed(audio, sizeof(audio));
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, &disc), 0);
    ASSERT_EQ(disc, 1);
    /* A 3-octet filter is not this form, nor a 1-octet salt header.
     * Seen to fail, one mutation at a time: with `flen >= 4` made
     * `flen >= 3`, and with the 0x21 test made a low-nibble 0x1 test. */
    const uint8_t short_f[] = { 0x0B, 0x16, 0x2C, 0xFE, 0x00, 0x30, 1, 2, 3, 0x21, 7, 8 };
    r = parsed(short_f, sizeof(short_f));
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, &disc), 0);
    ASSERT_EQ(disc, 0);
    ad_fp_account(ad, 0x01);
    ad[11] = 0x11;
    r = parsed(ad, sizeof(ad));
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, NULL), 0);
    /* A 4-octet filter (one key) is the form, but filter + salt is at
     * most ~39.8 bits, under the 40-bit bound: no token, and not
     * discoverable either. Seen to fail: with BLE_ROT_FP_FILTER_MIN 4. */
    const uint8_t one_key[] = { 0x0C, 0x16, 0x2C, 0xFE, 0x00, 0x40,
                                0xD1, 0xD2, 0xD3, 0xD4, 0x21, 0xE7, 0x01 };
    r = parsed(one_key, sizeof(one_key));
    disc = 9;
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, &disc), 0);
    ASSERT_EQ(disc, 0);
}

static void test_only_private_addresses_are_candidates(void) {
    uint8_t a[6] = { 0x45, 1, 2, 3, 4, 5 };
    ASSERT_EQ(ble_rot_addr_candidate(1, a), 1);       /* RPA, 01 */
    a[0] = 0x15;
    ASSERT_EQ(ble_rot_addr_candidate(1, a), 1);       /* NRPA, 00 */
    a[0] = 0xC5;
    ASSERT_EQ(ble_rot_addr_candidate(1, a), 0);       /* static, 11 */
    a[0] = 0x85;
    ASSERT_EQ(ble_rot_addr_candidate(1, a), 0);       /* reserved, 10 */
    a[0] = 0x45;
    ASSERT_EQ(ble_rot_addr_candidate(0, a), 0);       /* public */
    ASSERT_EQ(ble_rot_addr_candidate(2, a), 0);       /* resolved identity */
    ASSERT_EQ(ble_rot_addr_candidate(3, a), 0);
    ASSERT_EQ(ble_rot_addr_candidate(0xFF, a), 0);    /* anonymous */
}

/* ── Linking ─────────────────────────────────────────────────────── */

static void cdp_rotation(time_t t0, uint8_t A[6], uint8_t B[6]) {
    uint8_t ad[CDP_LEN];
    ad_cdp(ad, 0);
    rpa(A, 1); rpa(B, 2);
    run_addr(A, ad, sizeof(ad), t0, t0 + 20, 2);
    run_addr(B, ad, sizeof(ad), t0 + 23, t0 + 60, 2);
}

static void test_cdp_carried_across_the_seam_is_a_payload_hint(void) {
    setup(1);
    uint8_t A[6], B[6];
    cdp_rotation(g_wall - 100, A, B);
    snap();
    const ble_device_t *a = row(A), *b = row(B);
    ASSERT(a && b);
    if (a && b) {
        ASSERT(a->hint.chain != 0);
        ASSERT_EQ(b->hint.chain, a->hint.chain);
        ASSERT_EQ(b->hint.basis, BLE_HINT_PAYLOAD);
        ASSERT_EQ(a->hint.basis, BLE_HINT_NONE);
        ASSERT_EQ(b->hint.hops, 1);
        ASSERT(b->hint.confidence > BLE_ROT_CONF_TIMING_MAX);
        ASSERT(b->hint.confidence <= BLE_ROT_CONF_PAYLOAD_MAX);
        ASSERT_EQ(b->hint.root_first, a->first_seen);
    }
    ASSERT_EQ(g_s.ble_rot.enabled, 1);
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    ASSERT_EQ(g_s.ble_rot.hints_timing, 0);
    ASSERT_EQ(ble_rot_distinct(&g_s), 1);
    teardown();
}

/* Pending until d_swap has passed with the old address silent. Seen to
 * fail: with the `< BLE_ROT_DSWAP_S` wait in tick() changed to `< 0`,
 * the link commits on the new address's first report. */
static void test_link_waits_d_swap_before_it_counts(void) {
    setup(1);
    uint8_t ad[CDP_LEN], A[6], B[6];
    ad_cdp(ad, 0);
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    run_addr(A, ad, sizeof(ad), t0, t0 + 20, 2);
    obs(B, ad, sizeof(ad), t0 + 23);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    ASSERT_EQ(row(B) ? row(B)->hint.chain : 1u, 0u);
    obs(B, ad, sizeof(ad), t0 + 33);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    teardown();
}

/* Exclusivity, at one-second resolution: the old address heard again,
 * in the same second, after the new one's first report. Seen to fail
 * twice, one mutation at a time: with the re-heard revocation in
 * ble_rot_observe() removed, and with the arrival-order test
 * (`F->last_ord >= E->first_ord`) removed from seam_ok() - the second
 * relinks on the new address's next report. */
static void test_interleaved_addresses_are_never_linked(void) {
    setup(1);
    uint8_t A[6], B[6];
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    obs(A, AD_KBD, sizeof(AD_KBD), t0);
    obs(B, AD_KBD, sizeof(AD_KBD), t0 + 1);
    obs(A, AD_KBD, sizeof(AD_KBD), t0 + 1);
    run_addr(B, AD_KBD, sizeof(AD_KBD), t0 + 2, t0 + 40, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, 0);
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    ASSERT_EQ(row(B) ? row(B)->hint.chain : 1u, 0u);
    teardown();
}

/* A payload link whose old address speaks again is revoked and its
 * token poisoned - here with an advertisement that carries no token, so
 * the re-heard path alone does it. Seen to fail: with that path in
 * ble_rot_observe() disabled. */
static void test_revoked_payload_link_poisons_its_token(void) {
    setup(1);
    uint8_t ad[CDP_LEN], A[6], B[6];
    ad_cdp(ad, 0);
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    run_addr(A, ad, sizeof(ad), t0, t0 + 20, 2);
    run_addr(B, ad, sizeof(ad), t0 + 22, t0 + 40, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    obs(A, AD_KBD, sizeof(AD_KBD), t0 + 41);
    snap();
    ASSERT_EQ(g_s.ble_rot.poisoned, 1);
    ASSERT_EQ(row(B) ? row(B)->hint.basis : 9, BLE_HINT_NONE);
    ASSERT_EQ(row(A) ? row(A)->hint.chain : 1u, 0u);
    teardown();
}

/* A replayed token: A and C carry it at once, so it is poisoned; B then
 * takes it over from A at a clean seam and still gets no payload link -
 * only the timing hint the shape allows. Seen to fail: with
 * is_poisoned() never true, B links on the payload. */
static void test_token_on_two_interleaving_addresses_is_poisoned(void) {
    setup(1);
    uint8_t ad[CDP_LEN], A[6], B[6], C[6];
    ad_cdp(ad, 0);
    rpa(A, 1); rpa(B, 2); rpa(C, 3);
    time_t t0 = g_wall - 100;
    obs(A, ad, sizeof(ad), t0);
    obs(C, ad, sizeof(ad), t0 + 1);
    obs(A, ad, sizeof(ad), t0 + 2);
    obs(C, ad, sizeof(ad), t0 + 3);
    run_addr(A, ad, sizeof(ad), t0 + 4, t0 + 10, 2);
    run_addr(B, ad, sizeof(ad), t0 + 14, t0 + 40, 2);
    snap();
    ASSERT(g_s.ble_rot.poisoned >= 1);
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    ASSERT_EQ(g_s.ble_rot.hints_timing, 1);
    ASSERT_EQ(row(B) ? row(B)->hint.basis : 9, BLE_HINT_TIMING);
    teardown();
}

/* BLE_ADV_FLOOD's fresh-address gate active on the payload key: a spam
 * tool can put a genuine CDP beacon on fresh addresses, so nothing on
 * the key links. Seen to fail: with ble_hci.c passing 0 for `flooded`. */
static void test_no_link_while_the_flood_gate_is_active(void) {
    setup(1);
    uint8_t ad[CDP_LEN], spam[CDP_LEN], A[6], B[6];
    ad_cdp(ad, 0);
    time_t t0 = g_wall - 100;
    for (unsigned i = 0; i < 25; i++) {
        uint8_t s[6] = { 0xC3, 0, 0, 0, (uint8_t)(i >> 8), (uint8_t)i };
        ad_cdp(spam, (uint8_t)(i + 1));
        obs_on(s, 1, 0x03, spam, sizeof(spam), t0, MON, 0);
    }
    rpa(A, 1); rpa(B, 2);
    run_addr(A, ad, sizeof(ad), t0 + 1, t0 + 5, 1);
    run_addr(B, ad, sizeof(ad), t0 + 7, t0 + 30, 1);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    ASSERT_EQ(g_s.ble_rot.hints_timing, 0);
    teardown();
}

/* Same token, clean seam, two HCI adapters: two seam tables. Seen to
 * fail: with the adapter left out of sensor_for()'s match. */
static void test_never_across_adapters(void) {
    setup(1);
    scan_on(1, 0x00);
    uint8_t ad[CDP_LEN], A[6], B[6];
    ad_cdp(ad, 0);
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    for (time_t t = t0; t <= t0 + 20; t += 2) obs_on(A, 1, 0x03, ad, sizeof(ad), t, MON, 0);
    for (time_t t = t0 + 22; t <= t0 + 50; t += 2) obs_on(B, 1, 0x03, ad, sizeof(ad), t, MON, 1);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    ASSERT_EQ(g_s.ble_rot.hints_timing, 0);
    teardown();
}

/* And across sensors: the host controller and an Ubertooth. Seen to
 * fail: with the iface left out of sensor_for()'s match. */
static void test_never_across_sensors(void) {
    setup(1);
    uint8_t ad[CDP_LEN], A[6], B[6];
    ad_cdp(ad, 0);
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    for (time_t t = t0; t <= t0 + 20; t += 2) obs_on(A, 1, 0x03, ad, sizeof(ad), t, MON, 0);
    for (time_t t = t0 + 22; t <= t0 + 50; t += 2) obs_on(B, 1, 0x03, ad, sizeof(ad), t, "ubertooth", 0);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    ASSERT_EQ(g_s.ble_rot.hints_timing, 0);
    teardown();
}

/* A Fast Pair discoverable advertisement: "the BLE address shall not be
 * rotated", so neither side is a candidate, though the shapes agree.
 * Seen to fail: with `fp_disc ||` removed from ble_rot_observe(). */
static void test_never_a_fast_pair_discoverable_advertisement(void) {
    setup(1);
    uint8_t A[6], B[6];
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    run_addr(A, AD_FP_DISC, sizeof(AD_FP_DISC), t0, t0 + 20, 2);
    run_addr(B, AD_FP_DISC, sizeof(AD_FP_DISC), t0 + 22, t0 + 50, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, 0);
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    teardown();
}

/* Fast Pair account data whose salt was regenerated with the RPA (the
 * spec's "should"): no payload link, only timing. Unchanged salt (the
 * vendor ignoring it): payload. Seen to fail: with the token cut to the
 * filter alone (`flen + 3` made `flen`). */
static void test_fast_pair_account_links_only_on_an_unchanged_salt(void) {
    setup(1);
    uint8_t a1[FP_ACCT_LEN], a2[FP_ACCT_LEN], A[6], B[6];
    ad_fp_account(a1, 0x01);
    ad_fp_account(a2, 0x02);
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    run_addr(A, a1, sizeof(a1), t0, t0 + 20, 2);
    run_addr(B, a2, sizeof(a2), t0 + 22, t0 + 50, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    ASSERT_EQ(g_s.ble_rot.hints_timing, 1);
    teardown();

    setup(1);
    rpa(A, 1); rpa(B, 2);
    run_addr(A, a1, sizeof(a1), t0, t0 + 20, 2);
    run_addr(B, a1, sizeof(a1), t0 + 22, t0 + 50, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    teardown();
}

static void test_handoff_carried_is_a_payload_hint(void) {
    setup(1);
    uint8_t ad[HANDOFF_LEN], A[6], B[6];
    ad_handoff(ad, 0);
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    run_addr(A, ad, sizeof(ad), t0, t0 + 20, 2);
    run_addr(B, ad, sizeof(ad), t0 + 22, t0 + 50, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    teardown();
}

/* Static random and resolved-identity addresses never rotate in the
 * privacy feature's sense: the same token at a perfect seam links
 * nothing. Seen to fail, one mutation at a time: with
 * ble_rot_addr_candidate()'s sub-type test replaced by `return 1`
 * (the static pair links), and with its Address_Type test dropped (the
 * resolved-identity pair links). */
static void test_static_and_identity_addresses_are_never_linked(void) {
    setup(1);
    uint8_t ad[CDP_LEN];
    ad_cdp(ad, 0);
    time_t t0 = g_wall - 100;
    uint8_t A[6] = { 0xC4, 1, 1, 1, 1, 1 }, B[6] = { 0xC4, 1, 1, 1, 1, 2 };
    for (time_t t = t0; t <= t0 + 20; t += 2) obs_on(A, 1, 0x03, ad, sizeof(ad), t, MON, 0);
    for (time_t t = t0 + 22; t <= t0 + 50; t += 2) obs_on(B, 1, 0x03, ad, sizeof(ad), t, MON, 0);
    uint8_t C[6] = { 0x45, 9, 9, 9, 9, 1 }, D[6] = { 0x45, 9, 9, 9, 9, 2 };
    for (time_t t = t0 + 60; t <= t0 + 80; t += 2) obs_on(C, 3, 0x03, ad, sizeof(ad), t, MON, 0);
    for (time_t t = t0 + 82; t <= t0 + 99; t += 2) obs_on(D, 3, 0x03, ad, sizeof(ad), t, MON, 0);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    ASSERT_EQ(g_s.ble_rot.hints_timing, 0);
    teardown();
}

/* ── Timing hints ────────────────────────────────────────────────── */

static void test_keyboard_rotating_is_a_timing_hint(void) {
    setup(1);
    uint8_t A[6], B[6];
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    run_addr(A, AD_KBD, sizeof(AD_KBD), t0, t0 + 20, 2);
    run_addr(B, AD_KBD, sizeof(AD_KBD), t0 + 22, t0 + 50, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, 1);
    const ble_device_t *b = row(B);
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(b->hint.basis, BLE_HINT_TIMING);
        ASSERT(b->hint.confidence <= BLE_ROT_CONF_TIMING_MAX);
    }
    teardown();
}

/* Two arrivals in one seam: timing cannot tell which. Seen to fail:
 * with timing_ambiguous() returning 0. */
static void test_two_arrivals_in_one_seam_are_ambiguous(void) {
    setup(1);
    uint8_t A[6], B[6], C[6];
    rpa(A, 1); rpa(B, 2); rpa(C, 3);
    time_t t0 = g_wall - 100;
    run_addr(A, AD_KBD, sizeof(AD_KBD), t0, t0 + 20, 2);
    obs(B, AD_KBD, sizeof(AD_KBD), t0 + 22);
    obs(C, AD_KBD, sizeof(AD_KBD), t0 + 24);
    run_addr(B, AD_KBD, sizeof(AD_KBD), t0 + 26, t0 + 50, 2);
    run_addr(C, AD_KBD, sizeof(AD_KBD), t0 + 27, t0 + 51, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, 0);
    teardown();
}

/* Different shapes at a clean seam: nothing to corroborate timing.
 * Seen to fail: with shape_eq()'s AD-structure comparison made `1`. */
static void test_timing_needs_the_same_shape(void) {
    setup(1);
    uint8_t A[6], B[6];
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    run_addr(A, AD_KBD, sizeof(AD_KBD), t0, t0 + 20, 2);
    const uint8_t battery[] = { 0x03, 0x03, 0x0F, 0x18 };    /* a UUID list only */
    run_addr(B, battery, sizeof(battery), t0 + 22, t0 + 50, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, 0);
    teardown();
}

/* Seen to fail: with the hop test removed from commit(), nine links. */
static void test_chain_is_capped_in_hops(void) {
    setup(1);
    time_t t = g_wall - 400;
    for (unsigned k = 0; k < 10; k++) {
        uint8_t a[6];
        rpa(a, 100 + k);
        run_addr(a, AD_KBD, sizeof(AD_KBD), t, t + 14, 2);
        t += 16;
    }
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, BLE_ROT_MAX_HOPS);
    teardown();
}

/* A chain older than the retention cap takes no further link. Seen to
 * fail: with the root-age test removed from commit(), two links. */
static void test_chain_is_capped_in_age(void) {
    setup(1);
    uint8_t A[6], B[6], C[6];
    rpa(A, 1); rpa(B, 2); rpa(C, 3);
    time_t t0 = g_wall - 8000;
    run_addr(A, AD_KBD, sizeof(AD_KBD), t0, t0 + 20, 2);
    run_addr(B, AD_KBD, sizeof(AD_KBD), t0 + 22, t0 + BLE_ROT_RETAIN_S + 30, 20);
    time_t last_b = t0 + 22 + ((BLE_ROT_RETAIN_S + 8) / 20) * 20;
    run_addr(C, AD_KBD, sizeof(AD_KBD), last_b + 2, last_b + 40, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, 1);
    teardown();
}

static void test_seam_table_evictions_are_counted(void) {
    setup(1);
    time_t t0 = g_wall - 200;
    for (unsigned i = 0; i < BLE_ROT_SEAM + 6; i++) {
        uint8_t a[6];
        rpa(a, 1000 + i);
        obs(a, AD_KBD, sizeof(AD_KBD), t0 + (time_t)i);
    }
    snap();
    ASSERT_EQ(g_s.ble_rot.seam_evictions, 6);
    teardown();
}

/* ── Review round: spray, filter, persistence, expiry ────────────── */

/* `a` once at `ts`, the monotonic clock moved with the frame clock so
 * BLE_ADV_FLOOD's windows roll as they would live. */
static time_t g_t0;
static void obs_live(const uint8_t a[6], uint8_t atype, const uint8_t *ad,
                     size_t len, time_t ts) {
    g_mono = 5000000 + (uint64_t)(ts - g_t0) * 1000u;
    obs_on(a, atype, 0x03, ad, len, ts, MON, 0);
}

static const uint8_t PUB[6] = { 0x00, 0x1B, 0xDC, 0, 0, 0x01 };

/* One captured CDP token sprayed on fresh addresses one after another,
 * one a second: never interleaving, and too slow for the flood gate
 * (ten fresh addresses a window against twenty). Three addresses first
 * heard inside one d_swap is not one advertiser. Seen to fail: with the
 * `fresh >= BLE_ROT_SPRAY_ADDRS` test in ble_rot_observe() made `0`
 * (payload links commit down the spray). */
static void test_sequential_token_spray_is_poisoned(void) {
    setup(1);
    uint8_t ad[CDP_LEN];
    ad_cdp(ad, 0);
    g_t0 = g_wall - 200;
    for (unsigned i = 0; i < 30; i++) {
        uint8_t a[6];
        rpa(a, 500 + i);
        obs_live(a, 1, ad, sizeof(ad), g_t0 + (time_t)i);
    }
    obs_live(PUB, 0, AD_KBD, sizeof(AD_KBD), g_t0 + 50);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    ASSERT(g_s.ble_rot.poisoned >= 1);
    teardown();
}

/* A genuine rotation A -> B, B heard once, then the flood gate trips on
 * the CDP key (25 static spam addresses, each its own token, in one
 * window) before B's link is due. B is never heard under the gate
 * itself, so only the sweep of every entry on the key stops the commit.
 * Seen to fail: with flood_sweep()'s `flags |= ENT_EXCLUDED` removed
 * (the link commits under the gate). */
static void test_link_pending_when_the_flood_gate_trips_is_refused(void) {
    setup(1);
    uint8_t ad[CDP_LEN], spam[CDP_LEN], A[6], B[6];
    ad_cdp(ad, 0);
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    run_addr(A, ad, sizeof(ad), t0, t0 + 10, 2);
    obs(B, ad, sizeof(ad), t0 + 12);
    for (unsigned i = 0; i < 25; i++) {
        uint8_t z[6] = { 0xC3, 0, 0, 1, (uint8_t)(i >> 8), (uint8_t)i };
        ad_cdp(spam, (uint8_t)(i + 1));
        obs_on(z, 1, 0x03, spam, sizeof(spam), t0 + 13, MON, 0);
    }
    obs_on(PUB, 0, 0x03, AD_KBD, sizeof(AD_KBD), t0 + 30, MON, 0);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    ASSERT_EQ(g_s.ble_rot.hints_timing, 0);
    teardown();
}

/* Filter_Duplicates on, and never seen: the controller may report each
 * address once, so the re-reports the guards need never come and
 * nothing links; off, the same rotation links. A link pending when the
 * filter goes on is revoked at commit. Seen to fail, one mutation at a
 * time: with ble_hci.c's `blind` forced to 0 (the unknown, 0x01, 0x02
 * and pending cases all link), with the Filter_Duplicates parse forced
 * to 0 (0x01, 0x02 and pending link), and with tick()'s `S->blind ||`
 * removed (the pending one commits). */
static void test_no_link_while_the_controller_may_filter_duplicates(void) {
    uint8_t A[6], B[6];
    setup_scan(1, 0);                         /* no scan enable seen */
    cdp_rotation(g_wall - 100, A, B);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    teardown();

    setup_scan(1, 0);
    scan_on(0, 0x01);                         /* filtering */
    cdp_rotation(g_wall - 100, A, B);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    teardown();

    setup_scan(1, 0);
    scan_on(0, 0x02);                         /* extended: filtering, reset per period */
    cdp_rotation(g_wall - 100, A, B);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    teardown();

    uint8_t ad[CDP_LEN];
    ad_cdp(ad, 0);
    time_t t0 = g_wall - 100;

    setup(1);                                 /* Filter_Duplicates 0 */
    run_addr(A, ad, sizeof(ad), t0, t0 + 20, 2);
    obs(B, ad, sizeof(ad), t0 + 22);          /* proposed, pending */
    scan_on(0, 0x01);
    obs(B, ad, sizeof(ad), t0 + 40);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    teardown();

    setup(1);
    cdp_rotation(g_wall - 100, A, B);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    teardown();
}

/* Links are window-scoped: 63 more private addresses evict the departed
 * one (the least recently heard), and the link goes with it, on both
 * rows, whether or not a snapshot ran since the commit. No link is left
 * that a later poison could not reach. Seen to fail, one mutation at a
 * time: with ent_free()'s two rot_revoke() calls removed (B keeps its
 * chain), and with ble_rot_update_row() returning on `e < 0` instead of
 * zeroing the hint (A's row keeps the chain its last snapshot copied).
 *
 * Eviction frees the OLDER side here, and only ever can: a live link
 * F -> E needs F's last report before E's first (seam_ok()), F heard
 * again revokes it, and ent_alloc() takes the least recently heard
 * entry, so E is never evicted while its link stands. This test reaches
 * the succ-side revoke only; the pred-side one is reached through
 * retention, by the test below. */
static void evict_after(int snap_between) {
    setup(1);
    uint8_t A[6], B[6];
    cdp_rotation(g_wall - 300, A, B);
    if (snap_between) {
        snap();
        ASSERT_EQ(ble_rot_distinct(&g_s), 1);
    }
    for (unsigned i = 0; i < BLE_ROT_SEAM - 1; i++) {
        uint8_t a[6];
        rpa(a, 2000 + i);
        obs(a, AD_KBD, sizeof(AD_KBD), g_wall - 200);   /* one instant: ambiguous */
    }
    snap();
    ASSERT_EQ(g_s.ble_rot.seam_evictions, 1);
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);            /* lifetime: it did commit */
    ASSERT_EQ(g_s.ble_device_count, BLE_ROT_SEAM + 1);
    ASSERT_EQ(ble_rot_distinct(&g_s), BLE_ROT_SEAM + 1);
    const ble_device_t *a = row(A), *b = row(B);
    ASSERT(a && b);
    if (a && b) {
        ASSERT_EQ(a->hint.chain, 0u);
        ASSERT_EQ(b->hint.chain, 0u);
        ASSERT_EQ(b->hint.basis, BLE_HINT_NONE);
    }
    teardown();
}

static void test_eviction_ends_the_link_on_both_rows(void) {
    evict_after(0);
    evict_after(1);
}

/* Retention frees on last_ts, not on arrival order, so it CAN free the
 * newer side of a live link first: a frame clock stepped back (an NTP
 * step under --bt-monitor, an out-of-order --bt-capture) leaves B's last
 * report stamped before A's. B expires alone, and A must lose the link
 * with it rather than keep a successor naming a wiped slot that the next
 * allocation reuses. Seen to fail: with ent_free()'s `if (X->pred >= 0)
 * rot_revoke(S, i);` removed (A's row keeps the chain). */
static void test_newer_entry_freed_first_ends_the_link(void) {
    setup(1);
    uint8_t A[6], B[6], ad[CDP_LEN];
    time_t t0 = g_wall - 100;
    cdp_rotation(t0, A, B);                  /* A to t0+20, B t0+23..t0+59 */
    ad_cdp(ad, 0);
    obs(B, ad, sizeof(ad), t0 + 1);          /* stamped before A's last */
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    ASSERT(row(A) && row(A)->hint.chain != 0);
    /* The frame clock (t0+59) carried BLE_ROT_RETAIN_S - 50 s on: B
     * (last t0+1) is past retention, A (last t0+20) is not. */
    g_mono += (uint64_t)(BLE_ROT_RETAIN_S - 50) * 1000u;
    snap();
    ASSERT_EQ(ble_rot_test_held(), 1);
    const ble_device_t *a = row(A), *b = row(B);
    ASSERT(a && b);
    if (a && b) {
        ASSERT_EQ(a->hint.chain, 0u);
        ASSERT_EQ(b->hint.chain, 0u);
    }
    ASSERT_EQ(ble_rot_distinct(&g_s), 2);
    teardown();
}

/* Expiry without frames: a quiet radio, or a --bt-capture file that
 * ended, still lets go. Twenty seconds of silence wipe the digests and
 * shapes of unlinked entries; two hours wipe the entries and the
 * expired poison slots, and the rows lose their chain with them. Seen
 * to fail, one mutation at a time: with sensor_now() returning S->now
 * (the frame clock alone: nothing is ever freed), and with tick()'s
 * expired-poison wipe made a no-op (the slot is still held). */
static void test_expiry_runs_without_frames(void) {
    setup(1);
    uint8_t A[6], B[6], C[6];
    rpa(A, 1); rpa(B, 2); rpa(C, 3);
    uint8_t ad[CDP_LEN];
    ad_cdp(ad, 0);
    time_t t0 = g_wall - 100;
    run_addr(A, ad, sizeof(ad), t0, t0 + 20, 2);
    obs(C, ad, sizeof(ad), t0 + 21);
    obs(A, ad, sizeof(ad), t0 + 22);         /* interleave: a poison slot */
    run_addr(B, AD_KBD, sizeof(AD_KBD), t0 + 30, t0 + 40, 2);
    snap();
    ASSERT(g_s.ble_rot.poisoned >= 1);
    ASSERT(ble_rot_test_digests() > 0);
    g_mono += (BLE_ROT_FORGET_S + 1) * 1000u;
    snap();
    ASSERT_EQ(ble_rot_test_digests(), 0);
    ASSERT(ble_rot_test_held() > 0);
    g_mono += (uint64_t)(BLE_ROT_RETAIN_S + 1) * 1000u;
    snap();
    ASSERT_EQ(ble_rot_test_held(), 0);
    teardown();

    setup(1);
    run_addr(A, AD_KBD, sizeof(AD_KBD), t0, t0 + 20, 2);
    run_addr(B, AD_KBD, sizeof(AD_KBD), t0 + 22, t0 + 40, 2);
    run_addr(C, AD_KBD, sizeof(AD_KBD), t0 + 42, t0 + 60, 2);
    snap();
    ASSERT_EQ(ble_rot_distinct(&g_s), 1);
    g_mono += 100000u * 1000u;
    g_wall += 100000;
    snap();
    ASSERT_EQ(ble_rot_test_held(), 0);
    ASSERT_EQ(g_s.ble_device_count, 3);
    ASSERT_EQ(ble_rot_distinct(&g_s), 3);
    teardown();
}

/* Seventeen tokens poisoned, thirty seconds apart (the flood gate stays
 * off), against sixteen slots: the seventeenth must not re-arm the
 * first. Token 0 then crosses a clean seam on fresh addresses and gets
 * no payload link. Seen to fail: with poison() overwriting slot 0 when
 * none is spare (token 0's slot, re-armed: a payload link). */
static void test_full_poison_list_fails_closed(void) {
    setup(1);
    g_t0 = g_wall - 2000;
    for (unsigned k = 0; k < BLE_ROT_POISON_MAX + 1; k++) {
        uint8_t ad[CDP_LEN], X[6], Y[6];
        ad_cdp(ad, (uint8_t)k);
        rpa(X, 600 + 2 * k); rpa(Y, 601 + 2 * k);
        time_t t = g_t0 + 30 * (time_t)k;
        obs_live(X, 1, ad, sizeof(ad), t);
        obs_live(Y, 1, ad, sizeof(ad), t + 1);
        obs_live(X, 1, ad, sizeof(ad), t + 2);
    }
    snap();
    ASSERT_EQ(g_s.ble_rot.poisoned, BLE_ROT_POISON_MAX + 1);
    uint8_t ad[CDP_LEN], P[6], Q[6];
    ad_cdp(ad, 0);
    rpa(P, 900); rpa(Q, 901);
    obs_live(P, 1, ad, sizeof(ad), g_t0 + 600);
    obs_live(Q, 1, ad, sizeof(ad), g_t0 + 601);
    obs_live(PUB, 0, AD_KBD, sizeof(AD_KBD), g_t0 + 620);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    teardown();
}

/* A token poisoned stays poisoned for its documented life, about an
 * hour, not an address interval: half an hour on, it crosses a clean
 * seam on fresh addresses and gets no payload link. Seen to fail: with
 * BLE_ROT_POISON_S at 900. */
static void test_poison_lasts_the_token_life(void) {
    setup(1);
    uint8_t ad[CDP_LEN], X[6], Y[6], P[6], Q[6];
    ad_cdp(ad, 0);
    rpa(X, 1); rpa(Y, 2); rpa(P, 3); rpa(Q, 4);
    g_t0 = g_wall - 2000;
    obs_live(X, 1, ad, sizeof(ad), g_t0);
    obs_live(Y, 1, ad, sizeof(ad), g_t0 + 1);
    obs_live(X, 1, ad, sizeof(ad), g_t0 + 2);
    obs_live(P, 1, ad, sizeof(ad), g_t0 + 1800);
    obs_live(Q, 1, ad, sizeof(ad), g_t0 + 1801);
    obs_live(PUB, 0, AD_KBD, sizeof(AD_KBD), g_t0 + 1820);
    snap();
    ASSERT_EQ(g_s.ble_rot.poisoned, 1);
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    teardown();
}

/* X -> A -> B on timing, then A heard again after B: the A -> B link
 * is wrong and goes, and A stays chained to X - its own link in is
 * committed. Seen to fail: with rot_revoke() judging A's chain by its
 * predecessor's link (`F->pred < 0 || S->e[F->pred].state !=
 * LINK_COMMITTED`) instead of A's own (X, the root, has none, so A
 * left its chain: three advertisers). */
static void test_revoking_a_link_keeps_the_older_half_chained(void) {
    setup(1);
    uint8_t X[6], A[6], B[6];
    rpa(X, 1); rpa(A, 2); rpa(B, 3);
    time_t t0 = g_wall - 200;
    run_addr(X, AD_KBD, sizeof(AD_KBD), t0, t0 + 20, 2);
    run_addr(A, AD_KBD, sizeof(AD_KBD), t0 + 22, t0 + 50, 2);
    run_addr(B, AD_KBD, sizeof(AD_KBD), t0 + 52, t0 + 80, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, 2);
    ASSERT_EQ(ble_rot_distinct(&g_s), 1);
    obs(A, AD_KBD, sizeof(AD_KBD), t0 + 81);
    snap();
    ASSERT_EQ(ble_rot_distinct(&g_s), 2);
    const ble_device_t *x = row(X), *a = row(A), *b = row(B);
    ASSERT(x && a && b);
    if (x && a && b) {
        ASSERT(x->hint.chain && x->hint.chain == a->hint.chain);
        ASSERT_EQ(b->hint.chain, 0u);
    }
    teardown();
}

/* ── Integration round: revocation, window, coverage ────────────── */

static void  jsonl_fresh(void);
static char *jsonl_slurp(void);

/* The older address back after its digests would have gone. A(T) for
 * 0-20 s, B(T) for 22-40 s (committed), the clock carried to 65 s with
 * nothing heard, then A(T) at 70 s: the link is revoked AND T poisoned,
 * so a later clean seam on T gets no payload link. Then a three-address
 * chain A -> B -> C on T with B silent past BLE_ROT_FORGET_S, poisoned
 * by C and X interleaving: every link resting on T goes, both hops.
 * Seen to fail: with ent_forget()'s early return for a linked entry
 * removed (the 20 s wipe takes the link's digest: no poison, P -> Q
 * commits, and A -> B survives the second poison). */
static void test_linked_entries_keep_the_digest_their_link_rests_on(void) {
    setup(1);
    uint8_t ad[CDP_LEN], A[6], B[6], C[6], X[6], P[6], Q[6];
    ad_cdp(ad, 0);
    rpa(A, 1); rpa(B, 2); rpa(C, 3); rpa(X, 4); rpa(P, 5); rpa(Q, 6);
    time_t t0 = g_wall - 200;
    run_addr(A, ad, sizeof(ad), t0, t0 + 20, 2);
    run_addr(B, ad, sizeof(ad), t0 + 22, t0 + 40, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    g_mono += 25 * 1000u;                    /* carried to t0 + 65 */
    snap();
    obs(A, ad, sizeof(ad), t0 + 70);
    snap();
    ASSERT_EQ(g_s.ble_rot.poisoned, 1);
    ASSERT_EQ(row(A) ? row(A)->hint.chain : 1u, 0u);
    ASSERT_EQ(row(B) ? row(B)->hint.chain : 1u, 0u);
    run_addr(P, ad, sizeof(ad), t0 + 100, t0 + 110, 2);
    run_addr(Q, ad, sizeof(ad), t0 + 112, t0 + 140, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    teardown();

    setup(1);
    run_addr(A, ad, sizeof(ad), t0, t0 + 20, 2);
    run_addr(B, ad, sizeof(ad), t0 + 22, t0 + 40, 2);
    run_addr(C, ad, sizeof(ad), t0 + 42, t0 + 80, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 2);
    ASSERT_EQ(ble_rot_distinct(&g_s), 1);
    obs(X, ad, sizeof(ad), t0 + 81);
    obs(C, ad, sizeof(ad), t0 + 82);
    snap();
    ASSERT_EQ(g_s.ble_rot.poisoned, 1);
    ASSERT_EQ(ble_rot_distinct(&g_s), 4);
    for (int i = 0; i < g_s.ble_device_count; i++)
        ASSERT_EQ(g_s.ble_devices[i].hint.chain, 0u);
    teardown();
}

/* A commit moves no change-only signature: on a quiet sensor, the line
 * written before B's link committed is the only one until the heartbeat,
 * though the band in it went from "0" to "1-9". Seen to fail: with
 * jsonl.c's `sig.ble_rot_on` taking `+ s->ble_rot.hints_payload` (a
 * second line, at the commit). */
static void test_a_commit_writes_no_sensor_health_line(void) {
    setup(1);
    uint8_t ad[CDP_LEN], A[6], B[6];
    ad_cdp(ad, 0);
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    jsonl_fresh();
    run_addr(A, ad, sizeof(ad), t0, t0 + 20, 2);
    obs(B, ad, sizeof(ad), t0 + 22);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    jsonl_emit_sensor_health(&g_s);
    run_addr(B, ad, sizeof(ad), t0 + 24, t0 + 40, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    g_wall += 1;
    jsonl_emit_sensor_health(&g_s);
    char *j = jsonl_slurp();
    int lines = 0;
    for (const char *q = j; (q = strstr(q, "\"type\":\"sensor_health\"")); q++) lines++;
    ASSERT_EQ(lines, 1);
    ASSERT(strstr(j, "\"ble_rot_hints\":\"0\"") != NULL);
    free(j);
    teardown();
}

/* Two pending links due in one tick, the newer one first: C sits in a
 * lower slot than B (the slot an expired entry left), so B -> C commits
 * before A -> B, and the commit of A -> B must carry its chain on to C.
 * Seen to fail: with commit()'s chain_relabel() call removed (C keeps
 * the id B had: three advertisers, C at one hop). */
static void test_an_out_of_order_commit_relabels_the_tail(void) {
    setup(1);
    uint8_t A[6], B[6], C[6], F[6];
    rpa(A, 1); rpa(B, 2); rpa(C, 3); rpa(F, 9);
    time_t t0 = g_wall - 200;
    obs(F, AD_KBD, sizeof(AD_KBD), t0 + 22 - BLE_ROT_RETAIN_S - 1);  /* slot 0, expires at B's first report */
    run_addr(A, AD_KBD, sizeof(AD_KBD), t0, t0 + 20, 2);              /* slot 1 */
    run_addr(B, AD_KBD, sizeof(AD_KBD), t0 + 22, t0 + 29, 1);         /* slot 2 */
    obs(C, AD_KBD, sizeof(AD_KBD), t0 + 31);                          /* slot 0 */
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, 0);
    g_mono += 20 * 1000u;
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, 2);
    ASSERT_EQ(ble_rot_distinct(&g_s), 2);       /* F, and A -> B -> C */
    const ble_device_t *a = row(A), *c = row(C);
    ASSERT(a && c);
    if (a && c) {
        ASSERT(a->hint.chain && c->hint.chain == a->hint.chain);
        ASSERT_EQ(c->hint.hops, 2);
    }
    teardown();
}

/* Proposed nothing while blind: a rotation heard under a filtering scan,
 * then the filter turned off before the link would fall due, still
 * commits nothing - the newer address was never proposed. Seen to
 * fail: with ble_rot_observe()'s `!S->blind &&` removed (B is proposed
 * under the filter, and the tick after the filter-off enable, no longer
 * blind, commits it). */
static void test_no_proposal_under_the_filter_survives_it_going_off(void) {
    setup_scan(1, 0);
    scan_on(0, 0x01);
    uint8_t ad[CDP_LEN], A[6], B[6];
    ad_cdp(ad, 0);
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    run_addr(A, ad, sizeof(ad), t0, t0 + 20, 2);
    obs(B, ad, sizeof(ad), t0 + 22);
    scan_on(0, 0x00);
    obs_on(PUB, 0, 0x03, AD_KBD, sizeof(AD_KBD), t0 + 40, MON, 0);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 0);
    ASSERT_EQ(row(B) ? row(B)->hint.chain : 1u, 0u);
    teardown();
}

/* Turning the flag off clears every row's hint by itself, with no
 * ble_clear() to mask it. Seen to fail: with ble_hci_rotation_enable()'s
 * row-hint memset removed (the rows keep a chain the off run never
 * refreshes). */
static void test_turning_the_flag_off_clears_the_rows(void) {
    setup(1);
    uint8_t A[6], B[6];
    cdp_rotation(g_wall - 100, A, B);
    snap();
    ASSERT(row(B) && row(B)->hint.chain != 0);
    ASSERT_EQ(ble_hci_rotation_enable(0), 0);
    snap();
    ASSERT_EQ(g_s.ble_device_count, 2);
    for (int i = 0; i < g_s.ble_device_count; i++)
        ASSERT_EQ(g_s.ble_devices[i].hint.chain, 0u);
    teardown();
}

/* ── Consumers ───────────────────────────────────────────────────── */

static void keyboard_rotating_four_times(void) {
    /* A session older than the rotation window, from a static address
     * (never a candidate), then one keyboard on four RPAs. */
    const uint8_t s[6] = { 0xC2, 0, 0, 0, 0, 0x99 };
    const uint8_t ad[] = { 0x02, 0x01, 0x06 };
    obs_on(s, 1, 0x00, ad, sizeof(ad), g_wall - 2000, MON, 0);
    time_t t = g_wall - 200;
    for (unsigned k = 0; k < 4; k++) {
        uint8_t a[6];
        rpa(a, 200 + k);
        run_addr(a, AD_KBD, sizeof(AD_KBD), t, t + 20, 4);
        t += 22;
    }
}

static int count_type(alert_type_t t) {
    int n = 0;
    for (int i = 0; i < g_s.alert_count; i++) if (g_s.alerts[i].type == t) n++;
    return n;
}

/* A HID appearance and Fast Pair account data with an unchanged salt:
 * a HID advertiser carrying a token across its rotations - which an
 * attacker cycling HID addresses can do on purpose. */
#define HID_FP_LEN (sizeof(AD_KBD) + FP_ACCT_LEN)
static void ad_hid_fp(uint8_t b[HID_FP_LEN]) {
    memcpy(b, AD_KBD, sizeof(AD_KBD));
    ad_fp_account(b + sizeof(AD_KBD), 0x01);
}

static void hid_fp_rotating_four_times(void) {
    const uint8_t s[6] = { 0xC2, 0, 0, 0, 0, 0x99 };
    const uint8_t ad[] = { 0x02, 0x01, 0x06 };
    obs_on(s, 1, 0x00, ad, sizeof(ad), g_wall - 2000, MON, 0);
    uint8_t hf[HID_FP_LEN];
    ad_hid_fp(hf);
    time_t t = g_wall - 200;
    for (unsigned k = 0; k < 4; k++) {
        uint8_t a[6];
        rpa(a, 300 + k);
        run_addr(a, hf, sizeof(hf), t, t + 20, 4);
        t += 22;
    }
}

/* What BLE_HID_UNEXPECTED wrote: count, key, title and detail of each. */
static void hid_outputs(char *out, size_t cap) {
    size_t off = 0;
    out[0] = '\0';
    for (int i = 0; i < g_s.alert_count; i++) {
        const alert_t *a = &g_s.alerts[i];
        if (a->type != ALERT_TYPE_BLE_HID_UNEXPECTED) continue;
        int w = snprintf(out + off, cap - off, "%s|%s|%s\n", a->key, a->title, a->detail);
        if (w > 0 && (size_t)w < cap - off) off += (size_t)w;
    }
}

/* Hints never weaken a detector: a token is attacker-supplied, so the
 * rotation form counts addresses with the flag on exactly as with it
 * off, both for a keyboard rotating on timing alone and for one whose
 * rotations carry a token and commit payload links. Same count, same
 * key, title and detail. Seen to fail: with hid_rotate_findings()
 * gating on `count - (int)s->ble_rot.hints_payload` (the payload
 * advertiser is suppressed with the flag on). */
static void test_hints_never_change_ble_hid_unexpected(void) {
    void (*scen[2])(void) = { keyboard_rotating_four_times, hid_fp_rotating_four_times };
    for (int k = 0; k < 2; k++) {
        static char off_out[4096], on_out[4096];
        setup(0);
        scen[k]();
        snap();
        alerts_update(&g_s);
        ASSERT_EQ(count_type(ALERT_TYPE_BLE_HID_UNEXPECTED), 1);
        hid_outputs(off_out, sizeof(off_out));
        teardown();
        alerts_clear();

        setup(1);
        scen[k]();
        snap();
        if (k == 0) ASSERT_EQ(g_s.ble_rot.hints_timing, 3);
        else        ASSERT_EQ(g_s.ble_rot.hints_payload, 3);
        ASSERT_EQ(ble_rot_distinct(&g_s), 2);   /* the estimate joins them */
        alerts_update(&g_s);
        ASSERT_EQ(count_type(ALERT_TYPE_BLE_HID_UNEXPECTED), 1);
        hid_outputs(on_out, sizeof(on_out));
        ASSERT_STR(on_out, off_out);
        teardown();
        alerts_clear();
    }
}

/* Any timing-only hint behind the estimate adds the research's timing
 * wording; a payload-only estimate does not carry it (the test below).
 * Seen to fail: with the `if (s->ble_rot.hints_timing)` line removed
 * from view_ble_draw() (and, for the absence below, made `if (1)`). */
static void test_view_states_the_timing_caveat(void) {
    setup(1);
    uint8_t A[6], B[6];
    rpa(A, 1); rpa(B, 2);
    time_t t0 = g_wall - 100;
    run_addr(A, AD_KBD, sizeof(AD_KBD), t0, t0 + 20, 2);
    run_addr(B, AD_KBD, sizeof(AD_KBD), t0 + 22, t0 + 50, 2);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, 1);
    tui_test_erase();
    view_ble_draw(&g_s);
    ASSERT_SCREEN_HAS("est. 1 advertiser for 2 addresses");
    ASSERT_SCREEN_HAS("Includes timing-only hints. Weak: another advertiser leaving and arriving reads the same.");
    teardown();
}

/* The estimate, its wording, and no link anywhere. Seen to fail, one
 * mutation at a time: with summary_cell() appending "may be the same as
 * chain N" for a chained row, and with draw_detail() adding a "chain"
 * line. */
static void test_view_states_the_estimate_and_never_a_link(void) {
    setup(1);
    uint8_t A[6], B[6];
    cdp_rotation(g_wall - 100, A, B);
    const uint8_t other[6] = { 0xC2, 0, 0, 0, 0, 0x42 };
    obs_on(other, 1, 0x00, AD_KBD, sizeof(AD_KBD), g_wall - 5, MON, 0);
    snap();
    tui_test_erase();
    view_ble_draw(&g_s);
    ASSERT_SCREEN_HAS("est. 2 advertisers for 3 addresses");
    ASSERT_SCREEN_HAS("possible address rotation");
    ASSERT_SCREEN_HAS("corroborates, does not confirm, and identifies no device or person");
    ASSERT_SCREEN_HAS("These records alone are not grounds for personnel action or physical identification.");
    ASSERT_SCREEN_HAS("Links cover the recent window only: an address out of it counts on its own.");
    /* The never-say words, and no row names another. */
    ASSERT_SCREEN_LACKS("same device");
    ASSERT_SCREEN_LACKS("tracked");
    ASSERT_SCREEN_LACKS("identified");
    ASSERT_SCREEN_LACKS("may be the same");
    ASSERT_SCREEN_LACKS("timing-only");
    /* Nor the detail of either linked row. */
    for (int i = 0; i < g_s.ble_device_count; i++) {
        g_s.ble_sel = i;
        view_ble_key(&g_s, '\n');
        tui_test_erase();
        view_ble_draw(&g_s);
        ASSERT_SCREEN_LACKS("rotation");
        ASSERT_SCREEN_LACKS("chain");
        view_ble_key(&g_s, 27);
    }
    teardown();
}

/* ── Off means off ───────────────────────────────────────────────── */

static char g_tmp[TEST_TMP_MAX];

static void jsonl_fresh(void) {
    snprintf(g_tmp, sizeof(g_tmp), "%s/sloth_blerot_XXXXXX", test_tmpdir());
    int fd = mkstemp(g_tmp);
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_tmp);
    ASSERT(jsonl_open(g_tmp));
}

static char *jsonl_slurp(void) {
    jsonl_close();
    FILE *fp = fopen(g_tmp, "r");
    char *buf = NULL;
    size_t n = 0;
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long sz = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        buf = malloc(sz > 0 ? (size_t)sz + 1 : 1);
        if (buf && sz > 0) n = fread(buf, 1, (size_t)sz, fp);
        fclose(fp);
    }
    if (!buf) buf = calloc(1, 1);
    else buf[n] = '\0';
    unlink(g_tmp);
    return buf;
}

/* Everything the BLE source writes in one tick: every JSONL record type
 * the snapshot emitter writes, the alerts, the view (list and every
 * detail), concatenated. */
static char *outputs(void) {
    jsonl_fresh();
    snap();
    alerts_update(&g_s);
    for (int i = 0; i < g_s.alert_count; i++) jsonl_emit_alert(&g_s.alerts[i]);
    jsonl_emit_state_snapshots(&g_s);
    char *j = jsonl_slurp();
    static char screen[1 << 16];
    size_t off = 0;
    tui_test_erase();
    view_ble_draw(&g_s);
    int w = tui_test_screen(screen, sizeof(screen) / 2);
    if (w > 0) off = (size_t)w;
    for (int i = 0; i < g_s.ble_device_count && off + 4096 < sizeof(screen); i++) {
        g_s.ble_sel = i;
        view_ble_key(&g_s, '\n');
        tui_test_erase();
        view_ble_draw(&g_s);
        w = tui_test_screen(screen + off, sizeof(screen) - off);
        if (w > 0) off += (size_t)w;
        view_ble_key(&g_s, 27);
    }
    screen[off] = '\0';
    size_t jl = strlen(j);
    char *all = malloc(jl + off + 2);
    if (!all) { free(j); return calloc(1, 1); }
    memcpy(all, j, jl);
    all[jl] = '\n';
    memcpy(all + jl + 1, screen, off + 1);
    free(j);
    return all;
}

/* The process's own size and descriptor gauges in sensor_health move
 * between any two runs in one process; they are blanked, nothing else. */
static void unprocess(char *t) {
    static const char *const keys[] = {
        "\"rss_kb\":", "\"rss_hwm_kb\":", "\"malloc_kb\":",
        "\"sqlite_mem_kb\":", "\"sqlite_mem_hwm_kb\":", "\"fd_count\":",
    };
    for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++)
        for (char *p = strstr(t, keys[k]); p; p = strstr(p + 1, keys[k]))
            for (char *v = p + strlen(keys[k]); *v >= '0' && *v <= '9'; v++)
                *v = '0';
}

/* Three payload links, one per token kind, laid out in frame-time
 * order. Replayed over the same seconds, only the first would link: the
 * frame clock would already stand past a later pair's older side, so
 * tick() forgets its digests before its newer address arrives. Each
 * newer address is heard for BLE_ROT_DSWAP_S past its first report, the
 * last one up to g_wall, so every link commits. */
static void rotation_scenario(void) {
    uint8_t A[6], B[6];
    cdp_rotation(g_wall - 100, A, B);
    uint8_t ho[HANDOFF_LEN], C[6], D[6];
    ad_handoff(ho, 0);
    rpa(C, 3); rpa(D, 4);
    run_addr(C, ho, sizeof(ho), g_wall - 38, g_wall - 30, 2);
    run_addr(D, ho, sizeof(ho), g_wall - 27, g_wall - 15, 2);
    uint8_t fp[FP_ACCT_LEN], E[6], F[6];
    ad_fp_account(fp, 0x01);
    rpa(E, 5); rpa(F, 6);
    run_addr(E, fp, sizeof(fp), g_wall - 14, g_wall - 12, 2);
    run_addr(F, fp, sizeof(fp), g_wall - 10, g_wall, 2);
}

/* With the flag absent: no seam table, no `ble_rot_` field, no estimate
 * line, every row's hint zero, and the bytes equal to a run made after
 * the feature was turned on and off again. That is determinism of the
 * off path plus absence, NOT byte identity with the build before #156:
 * both off runs come from this build, so an unconditional change to the
 * off path shows in both and passes here. The comparison with the
 * previous build is `make replay-check`, whose golden predates #156 and
 * replays a DLT 254 Bluetooth capture with the flag off (seen to fail:
 * with an unconditional `blerot_` field written into sensor_health).
 * Seen to fail here, one mutation at a time: with ble_hci.c's `if
 * (ble_rot_enabled())` gate removed (a table is allocated), with
 * jsonl.c's `if (s->ble_rot.enabled)` removed (three fields appear),
 * and with the view's removed (the estimate line appears). */
static void test_off_runs_match_and_carry_nothing(void) {
    setup(0);
    rotation_scenario();
    char *off1 = outputs();
    ASSERT_EQ(ble_rot_test_allocated(), 0);
    ASSERT(strstr(off1, "ble_rot_") == NULL);
    ASSERT(strstr(off1, "rotation hints") == NULL);
    ASSERT(strstr(off1, "\"type\":\"ble_device\"") != NULL);   /* the scan scanned something */
    for (int i = 0; i < g_s.ble_device_count; i++) {
        const ble_identity_hint_t *h = &g_s.ble_devices[i].hint;
        ASSERT(h->basis == 0 && h->chain == 0 && h->hops == 0 &&
               h->confidence == 0 && h->root_first == 0);
    }
    teardown();
    alerts_clear();

    /* On, then off: what an off run writes does not depend on whether
     * the feature ever ran. */
    setup(1);
    rotation_scenario();
    char *on = outputs();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 3);
    ASSERT(strstr(on, "\"ble_rot_hints\":\"1-9\"") != NULL);
    ASSERT(strstr(on, "rotation hints") != NULL);
    teardown();
    alerts_clear();
    setup(0);
    rotation_scenario();
    char *off2 = outputs();
    ASSERT_EQ(ble_rot_test_allocated(), 0);
    unprocess(off1);
    unprocess(off2);
    ASSERT_STR(off1, off2);
    free(off1); free(off2); free(on);
    teardown();
}

/* Every alert, in order: type, severity, key, title and detail. The
 * incident id is drawn per incident by the engine, so it is reduced to
 * whether one is set. */
static void alert_outputs(char *out, size_t cap) {
    size_t off = 0;
    out[0] = '\0';
    for (int i = 0; i < g_s.alert_count; i++) {
        const alert_t *a = &g_s.alerts[i];
        int w = snprintf(out + off, cap - off, "%d|%d|%s|%s|%s|%s\n",
                         (int)a->type, (int)a->sev, a->key, a->title, a->detail,
                         a->incident_id[0] ? "<id>" : "");
        if (w > 0 && (size_t)w < cap - off) off += (size_t)w;
    }
}

/* Swift Pair as the BLE Spam tool writes it (research/bluetooth/
 * ble-spam-flood.md): 0xFF, 06 00, beacon 03, sub-scenario 00, reserved
 * RSSI 80, then a name. A spam-listed key other than the CDP key the
 * rotation rides, so the flood gate never touches the rotation. */
static const uint8_t AD_SWIFT[] = { 0x08, 0xFF, 0x06, 0x00, 0x03, 0x00, 0x80, 'k', 'b' };

/* A Swift Pair flood exactly at BLE_ADV_FLOOD's gates, after a rotation
 * that commits one payload link: the key primed by one resident address,
 * one window boundary crossed, then BLE_FLOOD_DISTINCT_ADDRS fresh static
 * random addresses (never seam candidates) sending BLE_FLOOD_RATE *
 * BLE_FLOOD_WINDOW_S advertisements between them. On the edge, so a gate
 * moved by any hint counter stops it firing. No address on the flooded
 * key is hinted: that is flood_on_a_rotated_key(). */
static void flood_after_a_rotation(void) {
    uint8_t A[6], B[6];
    cdp_rotation(g_wall - 100, A, B);
    const uint8_t home[6] = { 0xC2, 0xFF, 0xFF, 0x00, 0x00, 0x01 };
    obs_on(home, 1, 0x03, AD_SWIFT, sizeof(AD_SWIFT), g_wall, MON, 0);
    g_mono += BLE_FLOOD_WINDOW_S * 1000u;
    const unsigned per = BLE_FLOOD_RATE * BLE_FLOOD_WINDOW_S / BLE_FLOOD_DISTINCT_ADDRS;
    for (unsigned k = 0; k < per; k++)
        for (unsigned i = 0; i < BLE_FLOOD_DISTINCT_ADDRS; i++) {
            const uint8_t z[6] = { 0xC3, 0, 0, 2, 0, (uint8_t)i };
            obs_on(z, 1, 0x03, AD_SWIFT, sizeof(AD_SWIFT), g_wall, MON, 0);
            g_mono += 2;
        }
}

/* A flood on the key a committed link rides, the hinted rows counted
 * inside it. Fast Pair's 0xFE2C is spam-listed and carries an account
 * token, so one key does both. The key primed by one resident address,
 * one window boundary crossed, then the rotation E -> F (both fresh in
 * the window, linked before the gate trips), then fresh static random
 * flooders up to exactly BLE_FLOOD_DISTINCT_ADDRS addresses and
 * BLE_FLOOD_RATE * BLE_FLOOD_WINDOW_S advertisements. The gate tripping
 * excludes E and F from further links (flood_sweep()) but leaves the
 * committed one standing, so a lane that counted a chain's addresses
 * once would lose one fresh address and go quiet. */
static void flood_on_a_rotated_key(uint8_t E[6], uint8_t F[6]) {
    uint8_t fp[FP_ACCT_LEN];
    ad_fp_account(fp, 0x01);
    const uint8_t home[6] = { 0xC2, 0xFF, 0xFF, 0x00, 0x00, 0x02 };
    obs_on(home, 1, 0x03, fp, sizeof(fp), g_wall - 101, MON, 0);
    g_mono += BLE_FLOOD_WINDOW_S * 1000u;
    rpa(E, 5); rpa(F, 6);
    /* Counted, not written down: a hard-coded count would let a change
     * to these runs move the flood off the edge with nothing going red. */
    const unsigned rotated = run_addr(E, fp, sizeof(fp), g_wall - 100, g_wall - 80, 2) +
                             run_addr(F, fp, sizeof(fp), g_wall - 77, g_wall - 40, 2);
    const unsigned total = BLE_FLOOD_RATE * BLE_FLOOD_WINDOW_S;
    const unsigned addrs = BLE_FLOOD_DISTINCT_ADDRS - 2;
    /* Room left for every flooder to be heard, or the edge is unreachable. */
    ASSERT(rotated + addrs <= total);
    if (rotated + addrs > total) return;
    for (unsigned k = 0; k < total - rotated; k++) {
        const uint8_t z[6] = { 0xC3, 0, 0, 3, 0, (uint8_t)(k % addrs) };
        obs_on(z, 1, 0x03, fp, sizeof(fp), g_wall, MON, 0);
        g_mono += 2;
    }
}

/* In-test watchlist rows, fixtures and not shipped rows (src/
 * ble_watchlist.h): the MS-CDP beacon's company ID and Scenario_Type,
 * and Fast Pair's Service Data UUID with version 0x00. */
static const ble_wl_row_t k_rot_rows[] = {
    { "cdp-fixture", BLE_WL_MFR, 0x0006, 0x01, -1, -1,
      "fixture: [MS-CDP] 2.2.2.2.3 beacon, Scenario_Type 1" },
    { "fp-fixture", BLE_WL_SVC_DATA, 0xFE2C, 0x00, -1, -1,
      "fixture: Fast Pair Provider Advertising signal, version 0" },
};

/* A CDP rotation, then a Fast Pair account rotation after it in frame
 * time (pairs replayed over the same seconds would not link; see
 * rotation_scenario()), then one CDP beacon with its own token on a
 * static random address that is never a candidate: both categories hold
 * linked rows, and the cdp category an unlinked one too. All inside
 * BLE_WATCH_RECENT_SECS. */
static void watched_rotations(void) {
    uint8_t A[6], B[6], E[6], F[6], fp[FP_ACCT_LEN], ad[CDP_LEN];
    cdp_rotation(g_wall - 100, A, B);
    ad_fp_account(fp, 0x01);
    rpa(E, 5); rpa(F, 6);
    run_addr(E, fp, sizeof(fp), g_wall - 38, g_wall - 24, 2);
    run_addr(F, fp, sizeof(fp), g_wall - 21, g_wall - 3, 2);
    ad_cdp(ad, 9);
    const uint8_t s[6] = { 0xC2, 0, 0, 0, 0, 0x77 };
    obs_on(s, 1, 0x03, ad, sizeof(ad), g_wall - 1, MON, 0);
}

/* The same for the other two BLE lanes: no rule reads a hint, so the
 * flag changes nothing BLE_ADV_FLOOD or BLE_WATCHLIST writes. The two
 * floods and the watchlist are separate runs, so no run's addresses
 * share the 256-row table with another's. Each is run with the flag
 * off, then on, the on run first shown to hold committed links on what
 * the rule reads. The first flood has its link on another key, so it
 * holds the lane's gates to every hint counter; the second has the
 * link's two rows inside the flood, so it holds the lane to every
 * per-address hint too. Seen to fail, one mutation at a time: with
 * flood_findings() skipping a window whose `fresh -
 * s->ble_rot.hints_payload` is under the gate (both edge floods are
 * silenced with the flag on); with flood_findings() taking from `fresh`
 * one per row on the flood's key with `hint.hops` set (the second flood
 * alone is silenced); and with watch_findings() skipping a row with
 * `d->hint.chain` set (the hinted rows drop out of the counts, and the
 * fp category out of the alerts, with the flag on). */
static void test_hints_never_change_ble_adv_flood_or_ble_watchlist(void) {
    static char off_out[8192], on_out[8192];

    setup(0);
    flood_after_a_rotation();
    snap();
    alerts_update(&g_s);
    ASSERT_EQ(count_type(ALERT_TYPE_BLE_ADV_FLOOD), 1);
    alert_outputs(off_out, sizeof(off_out));
    teardown();
    alerts_clear();

    setup(1);
    flood_after_a_rotation();
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    alerts_update(&g_s);
    ASSERT_EQ(count_type(ALERT_TYPE_BLE_ADV_FLOOD), 1);
    alert_outputs(on_out, sizeof(on_out));
    ASSERT_STR(on_out, off_out);
    teardown();
    alerts_clear();

    uint8_t E[6], F[6];
    setup(0);
    flood_on_a_rotated_key(E, F);
    snap();
    alerts_update(&g_s);
    ASSERT_EQ(count_type(ALERT_TYPE_BLE_ADV_FLOOD), 1);
    alert_outputs(off_out, sizeof(off_out));
    teardown();
    alerts_clear();

    setup(1);
    flood_on_a_rotated_key(E, F);
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 1);
    const ble_device_t *e = row(E), *f = row(F);
    ASSERT(e && f);
    if (e && f) {
        ASSERT(e->hint.chain != 0);
        ASSERT_EQ(f->hint.chain, e->hint.chain);
        ASSERT_EQ(f->hint.basis, BLE_HINT_PAYLOAD);
    }
    alerts_update(&g_s);
    ASSERT_EQ(count_type(ALERT_TYPE_BLE_ADV_FLOOD), 1);
    alert_outputs(on_out, sizeof(on_out));
    ASSERT_STR(on_out, off_out);
    teardown();
    alerts_clear();

    ASSERT_EQ(ble_watchlist_set_table(k_rot_rows, 2), 0);
    setup(0);
    watched_rotations();
    snap();
    alerts_update(&g_s);
    ASSERT_EQ(count_type(ALERT_TYPE_BLE_WATCHLIST), 2);
    alert_outputs(off_out, sizeof(off_out));
    ASSERT(strstr(off_out, "3 addresses matching watched category cdp-fixture") != NULL);
    ASSERT(strstr(off_out, "2 addresses matching watched category fp-fixture") != NULL);
    teardown();
    alerts_clear();

    setup(1);
    watched_rotations();
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 2);
    int hinted = 0;
    for (int i = 0; i < g_s.ble_device_count; i++)
        if (g_s.ble_devices[i].watch_cat[0] && g_s.ble_devices[i].hint.chain) hinted++;
    ASSERT_EQ(hinted, 4);
    alerts_update(&g_s);
    ASSERT_EQ(count_type(ALERT_TYPE_BLE_WATCHLIST), 2);
    alert_outputs(on_out, sizeof(on_out));
    ASSERT_STR(on_out, off_out);
    teardown();
    alerts_clear();
    ble_watchlist_reset();
}

static int has_ci(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < n && p[i] && (p[i] | 0x20) == (needle[i] | 0x20)) i++;
        if (i == n) return 1;
    }
    return 0;
}

/* No digest and no token byte reaches any output: every JSONL record,
 * the alerts, the view list and each detail. Each token is searched as
 * hex (plain, ':'- and ' '-separated, either case) over its first four
 * octets, and each digest as 16 hex digits and as decimal, signed and
 * unsigned. Seen to fail, one mutation at a time: with
 * ble_rot_update_row() writing a held digest as hex into the row's name
 * (exported in ble_device and shown in the list), and with ble_hci.c
 * writing manufacturer octets 4..7 as hex into the row's watch category
 * (exported in ble_device and shown in the detail). Not with a digest
 * copied into `poisoned`, as this said before: sensor_health writes
 * that count as a band, so the copy never reaches an output. */
static void test_no_digest_or_token_byte_reaches_any_output(void) {
    setup(1);
    rotation_scenario();
    char *all = outputs();
    ASSERT_EQ(g_s.ble_rot.hints_payload, 3);
    ASSERT(strstr(all, "\"ble_rot_hints\":\"1-9\"") != NULL);

    uint8_t cdp[CDP_LEN], ho[HANDOFF_LEN], fp[FP_ACCT_LEN];
    ad_cdp(cdp, 0); ad_handoff(ho, 0); ad_fp_account(fp, 0x01);
    struct { uint8_t kind; const uint8_t *b; uint8_t len;
             const uint8_t *b2; uint8_t len2; } tok[3] = {
        { BLE_TOK_MS_CDP,            cdp + 8,  23, NULL,    0 },
        { BLE_TOK_APPLE_HANDOFF,     ho + 7,   13, NULL,    0 },
        { BLE_TOK_FAST_PAIR_ACCOUNT, fp + 6,    5, fp + 12, 2 },
    };
    for (int k = 0; k < 3; k++) {
        char hx[3][16];
        const uint8_t *b = tok[k].b;
        snprintf(hx[0], sizeof(hx[0]), "%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
        snprintf(hx[1], sizeof(hx[1]), "%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3]);
        snprintf(hx[2], sizeof(hx[2]), "%02x %02x %02x %02x", b[0], b[1], b[2], b[3]);
        for (int f = 0; f < 3; f++) {
            if (has_ci(all, hx[f])) fprintf(stderr, "    token %d leaks as %s\n", k, hx[f]);
            ASSERT(!has_ci(all, hx[f]));
        }
        uint64_t d = ble_rot_test_digest(tok[k].kind, tok[k].b, tok[k].len,
                                         tok[k].b2, tok[k].len2);
        char dx[4][32];
        snprintf(dx[0], sizeof(dx[0]), "%016llx", (unsigned long long)d);
        snprintf(dx[1], sizeof(dx[1]), "%llu", (unsigned long long)d);
        snprintf(dx[2], sizeof(dx[2]), "%lld", (long long)d);
        snprintf(dx[3], sizeof(dx[3]), "%08llx", (unsigned long long)(d >> 32));
        for (int f = 0; f < 4; f++) {
            if (has_ci(all, dx[f])) fprintf(stderr, "    digest %d leaks as %s\n", k, dx[f]);
            ASSERT(!has_ci(all, dx[f]));
        }
    }
    /* And no field names a link or a token. */
    ASSERT(strstr(all, "digest") == NULL);
    ASSERT(strstr(all, "token") == NULL);
    ASSERT(strstr(all, "\"chain") == NULL);
    ASSERT(strstr(all, "root_first") == NULL);
    free(all);
    teardown();
}

/* A digest means nothing outside its run: re-enabling draws a new key.
 * Seen to fail: with the getrandom() draw replaced by a fixed key. */
static void test_key_is_drawn_per_run(void) {
    setup(1);
    const uint8_t t[7] = { 1, 2, 3, 4, 5, 6, 7 };
    uint64_t d1 = ble_rot_test_digest(BLE_TOK_FAST_PAIR_ACCOUNT, t, 5, t + 5, 2);
    ASSERT_EQ(ble_hci_rotation_enable(1), 0);
    uint64_t d2 = ble_rot_test_digest(BLE_TOK_FAST_PAIR_ACCOUNT, t, 5, t + 5, 2);
    ASSERT(d1 != d2);
    teardown();
}

void run_ble_rotation_tests(void) {
    TEST_SUITE("BLE address-rotation hints (#156 item 2)");
    RUN_TEST(test_siphash_vectors);
    RUN_TEST(test_cdp_token_is_salt_and_hash);
    RUN_TEST(test_cdp_token_never_from_a_clipped_field);
    RUN_TEST(test_handoff_token_skips_its_first_octet);
    RUN_TEST(test_fast_pair_forms);
    RUN_TEST(test_only_private_addresses_are_candidates);
    RUN_TEST(test_cdp_carried_across_the_seam_is_a_payload_hint);
    RUN_TEST(test_link_waits_d_swap_before_it_counts);
    RUN_TEST(test_interleaved_addresses_are_never_linked);
    RUN_TEST(test_revoked_payload_link_poisons_its_token);
    RUN_TEST(test_token_on_two_interleaving_addresses_is_poisoned);
    RUN_TEST(test_no_link_while_the_flood_gate_is_active);
    RUN_TEST(test_never_across_adapters);
    RUN_TEST(test_never_across_sensors);
    RUN_TEST(test_never_a_fast_pair_discoverable_advertisement);
    RUN_TEST(test_fast_pair_account_links_only_on_an_unchanged_salt);
    RUN_TEST(test_handoff_carried_is_a_payload_hint);
    RUN_TEST(test_static_and_identity_addresses_are_never_linked);
    RUN_TEST(test_keyboard_rotating_is_a_timing_hint);
    RUN_TEST(test_two_arrivals_in_one_seam_are_ambiguous);
    RUN_TEST(test_timing_needs_the_same_shape);
    RUN_TEST(test_chain_is_capped_in_hops);
    RUN_TEST(test_chain_is_capped_in_age);
    RUN_TEST(test_seam_table_evictions_are_counted);
    RUN_TEST(test_sequential_token_spray_is_poisoned);
    RUN_TEST(test_link_pending_when_the_flood_gate_trips_is_refused);
    RUN_TEST(test_no_link_while_the_controller_may_filter_duplicates);
    RUN_TEST(test_eviction_ends_the_link_on_both_rows);
    RUN_TEST(test_newer_entry_freed_first_ends_the_link);
    RUN_TEST(test_expiry_runs_without_frames);
    RUN_TEST(test_full_poison_list_fails_closed);
    RUN_TEST(test_poison_lasts_the_token_life);
    RUN_TEST(test_revoking_a_link_keeps_the_older_half_chained);
    RUN_TEST(test_linked_entries_keep_the_digest_their_link_rests_on);
    RUN_TEST(test_a_commit_writes_no_sensor_health_line);
    RUN_TEST(test_an_out_of_order_commit_relabels_the_tail);
    RUN_TEST(test_no_proposal_under_the_filter_survives_it_going_off);
    RUN_TEST(test_turning_the_flag_off_clears_the_rows);
    RUN_TEST(test_hints_never_change_ble_hid_unexpected);
    RUN_TEST(test_view_states_the_timing_caveat);
    RUN_TEST(test_view_states_the_estimate_and_never_a_link);
    RUN_TEST(test_off_runs_match_and_carry_nothing);
    RUN_TEST(test_hints_never_change_ble_adv_flood_or_ble_watchlist);
    RUN_TEST(test_no_digest_or_token_byte_reaches_any_output);
    RUN_TEST(test_key_is_drawn_per_run);
}
