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
#include "jsonl.h"
#include "sensors.h"
#include "siphash.h"
#include "sloth_clock.h"
#include "tui.h"
#include "views/ble.h"

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
 *     0x00, 0bLLLLTTTT (L 4, T 0b0000), a 4-octet Account Key Filter,
 *     0b00100001, a 2-octet Salt.
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

static void setup(int hints_on) {
    g_mono = 5000000;
    g_wall = 1800000000;
    sloth_clock_test_set(pin_mono, pin_wall);
    memset(&g_s, 0, sizeof(g_s));
    ble_hci_rotation_enable(0);
    ble_clear();
    if (hints_on) ASSERT_EQ(ble_hci_rotation_enable(1), 0);
}

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

/* `a` heard every `step` seconds over [from, to]. */
static void run_addr(const uint8_t a[6], const uint8_t *ad, size_t len,
                     time_t from, time_t to, time_t step) {
    for (time_t t = from; t <= to; t += step) obs(a, ad, len, t);
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

#define FP_ACCT_LEN 13
static void ad_fp_account(uint8_t b[FP_ACCT_LEN], uint8_t salt1) {
    const uint8_t v[] = { 0x0C, 0x16, 0x2C, 0xFE, 0x00, 0x40,
                          0xD1, 0xD2, 0xD3, 0xD4, 0x21, 0xE7, salt1 };
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
    ASSERT_EQ(t[0].len, 7);                  /* filter 4 + header + salt 2 */
    ASSERT(t[0].bytes && t[0].bytes[0] == 0xD1 && t[0].bytes[6] == 0x01);

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
    ad[10] = 0x11;
    r = parsed(ad, sizeof(ad));
    ASSERT_EQ(ble_rot_tokens(&r, t, 3, NULL), 0);
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
    ASSERT_EQ(ble_rot_distinct(&g_s, NULL, NULL), 1);
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

/* Without the hints, four addresses are four (the shipped behaviour);
 * with them, one advertiser. Seen to fail: with hid_rotate_findings()
 * gating on `count` instead of the de-duplicated `advertisers`. */
static void test_hid_rotation_counts_advertisers_with_hints(void) {
    setup(0);
    keyboard_rotating_four_times();
    snap();
    alerts_update(&g_s);
    ASSERT_EQ(count_type(ALERT_TYPE_BLE_HID_UNEXPECTED), 1);
    teardown();
    alerts_clear();

    setup(1);
    memset(&g_s, 0, sizeof(g_s));
    keyboard_rotating_four_times();
    snap();
    ASSERT_EQ(g_s.ble_rot.hints_timing, 3);
    alerts_update(&g_s);
    ASSERT_EQ(count_type(ALERT_TYPE_BLE_HID_UNEXPECTED), 0);
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
    /* The never-say words, and no row names another. */
    ASSERT_SCREEN_LACKS("same device");
    ASSERT_SCREEN_LACKS("tracked");
    ASSERT_SCREEN_LACKS("identified");
    ASSERT_SCREEN_LACKS("may be the same");
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

static char g_tmp[64];

static void jsonl_fresh(void) {
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/sloth_blerot_XXXXXX");
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

static void rotation_scenario(void) {
    uint8_t A[6], B[6];
    cdp_rotation(g_wall - 100, A, B);
    uint8_t ho[HANDOFF_LEN], C[6], D[6];
    ad_handoff(ho, 0);
    rpa(C, 3); rpa(D, 4);
    run_addr(C, ho, sizeof(ho), g_wall - 100, g_wall - 80, 2);
    run_addr(D, ho, sizeof(ho), g_wall - 78, g_wall - 40, 2);
    uint8_t fp[FP_ACCT_LEN], E[6], F[6];
    ad_fp_account(fp, 0x01);
    rpa(E, 5); rpa(F, 6);
    run_addr(E, fp, sizeof(fp), g_wall - 100, g_wall - 80, 2);
    run_addr(F, fp, sizeof(fp), g_wall - 78, g_wall - 40, 2);
}

/* With the flag absent: no seam table, no `ble_rot_` field, no estimate
 * line, every row's hint zero, and the bytes equal to a run made after
 * the feature was turned on and off again. Seen to fail, one mutation
 * at a time: with ble_hci.c's `if (ble_rot_enabled())` gate removed
 * (a table is allocated), with jsonl.c's `if (s->ble_rot.enabled)`
 * removed (four zero fields appear), and with the view's removed (the
 * estimate line appears). */
static void test_off_means_off_byte_identical(void) {
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
    ASSERT(strstr(on, "\"ble_rot_hints_payload\":3") != NULL);
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
 * ble_rot_snapshot() copying a held digest into `poisoned` (exported in
 * sensor_health), and with ble_hci.c writing manufacturer octets 4..7
 * as hex into the row's watch category (exported in ble_device and
 * shown in the detail). */
static void test_no_digest_or_token_byte_reaches_any_output(void) {
    setup(1);
    rotation_scenario();
    char *all = outputs();
    ASSERT(strstr(all, "\"ble_rot_hints_payload\":3") != NULL);

    uint8_t cdp[CDP_LEN], ho[HANDOFF_LEN], fp[FP_ACCT_LEN];
    ad_cdp(cdp, 0); ad_handoff(ho, 0); ad_fp_account(fp, 0x01);
    struct { uint8_t kind; const uint8_t *b; uint8_t len; } tok[3] = {
        { BLE_TOK_MS_CDP,            cdp + 8,  23 },
        { BLE_TOK_APPLE_HANDOFF,     ho + 7,   13 },
        { BLE_TOK_FAST_PAIR_ACCOUNT, fp + 6,    7 },
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
        uint64_t d = ble_rot_test_digest(tok[k].kind, tok[k].b, tok[k].len);
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
    uint64_t d1 = ble_rot_test_digest(BLE_TOK_FAST_PAIR_ACCOUNT, t, sizeof(t));
    ASSERT_EQ(ble_hci_rotation_enable(1), 0);
    uint64_t d2 = ble_rot_test_digest(BLE_TOK_FAST_PAIR_ACCOUNT, t, sizeof(t));
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
    RUN_TEST(test_hid_rotation_counts_advertisers_with_hints);
    RUN_TEST(test_view_states_the_estimate_and_never_a_link);
    RUN_TEST(test_off_means_off_byte_identical);
    RUN_TEST(test_no_digest_or_token_byte_reaches_any_output);
    RUN_TEST(test_key_is_drawn_per_run);
}
