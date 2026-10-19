#include <stdlib.h>
#include <string.h>
#include "runner.h"
#include "frame_build.h"
#include "rsn_ie.h"
#include "beacon_snoop.h"
#include "sensor_health.h"

/* RSN element parsed once (#128). Element bodies below are literal
 * bytes laid out per IEEE 802.11-2020 §9.4.2.24 (Figure 9-286):
 *
 *   Version(2 LE) | Group Data Cipher(4) | Pairwise Count(2 LE) |
 *   Pairwise(4N) | AKM Count(2 LE) | AKM(4M) | RSN Capabilities(2 LE) |
 *   PMKID Count(2 LE) | PMKID(16P) | Group Management Cipher(4)
 *
 * Suite selectors are OUI then type: 00-0F-AC-04 is CCMP-128 (Table
 * 9-149), 00-0F-AC-08 is SAE and 00-0F-AC-18 (decimal 24) SAE-EXT-KEY
 * (Table 9-151). Expected values are literals, never produced by the
 * code under test. */

#define IEEE 0x00, 0x0f, 0xac

/* Parse from a heap copy sized to the element exactly, so ASan sees any
 * read past `len` — a stack array with neighbours would hide one. */
static int parse_exact(const uint8_t *src, int len, rsn_ie_t *r) {
    uint8_t *h = (uint8_t *)malloc(len > 0 ? (size_t)len : 1u);
    if (!h) return -1;
    if (len > 0) memcpy(h, src, (size_t)len);
    int rc = rsn_ie_parse(h, len, r);
    /* Pointers into the copy must not outlive it. */
    r->pairwise = r->akm = r->pmkids = NULL;
    free(h);
    return rc;
}

/* ── the parser ───────────────────────────────────────────── */

static void test_every_field_is_decoded(void) {
    static const uint8_t b[] = {
        0x01, 0x00,                              /* version 1 */
        IEEE, 0x04,                              /* group CCMP-128 */
        0x02, 0x00, IEEE, 0x04, IEEE, 0x09,      /* CCMP, GCMP-256 */
        0x02, 0x00, IEEE, 0x02, IEEE, 0x08,      /* PSK, SAE */
        0xc0, 0x00,                              /* MFPR (b6) | MFPC (b7) */
        0x01, 0x00,                              /* 1 PMKID */
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22,
        IEEE, 0x06,                              /* BIP-CMAC-128 */
    };
    rsn_ie_t r;
    ASSERT_EQ(rsn_ie_parse(b, (int)sizeof b, &r), 1);
    ASSERT_EQ(r.version, 1);
    ASSERT_EQ(r.has_group, 1);
    ASSERT_EQ(r.group_sel, 0x000fac04u);
    ASSERT_EQ(r.pairwise_count, 2);
    ASSERT_EQ(r.pairwise_bits, (1u << 4) | (1u << 9));
    ASSERT_EQ(r.first_pairwise_sel, 0x000fac04u);
    ASSERT(r.pairwise == b + 8);
    ASSERT_EQ(r.akm_count, 2);
    ASSERT_EQ(r.akm_bits, (1u << 2) | (1u << 8));
    ASSERT_EQ(r.first_akm_sel, 0x000fac02u);
    ASSERT(r.akm == b + 18);
    ASSERT_EQ(r.has_caps, 1);
    ASSERT_EQ(r.caps, 0x00c0);
    ASSERT_EQ(r.mfpr, 1);
    ASSERT_EQ(r.mfpc, 1);
    ASSERT_EQ(r.has_pmkids, 1);
    ASSERT_EQ(r.pmkid_count, 1);
    ASSERT(r.pmkids == b + 30);
    ASSERT_EQ(r.pmkids[15], 0x22);
    ASSERT_EQ(r.has_group_mgmt, 1);
    ASSERT_EQ(r.group_mgmt_sel, 0x000fac06u);
    ASSERT_EQ(r.truncated, 0);
}

/* Every field after Version may be omitted, but only from the end
 * (§9.4.2.24). Stopping on a field boundary is therefore not a fault,
 * whichever boundary it is. */
static void test_any_field_boundary_is_a_clean_end(void) {
    static const uint8_t b[] = {
        0x01, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x02,
        0x80, 0x00,                              /* MFPC only */
        0x00, 0x00,                              /* 0 PMKIDs */
        IEEE, 0x06,
    };
    static const int cut[] = { 2, 6, 12, 18, 20, 22, 26 };
    rsn_ie_t r;
    for (size_t i = 0; i < sizeof cut / sizeof cut[0]; i++) {
        ASSERT_EQ(parse_exact(b, cut[i], &r), 1);
        ASSERT_EQ(r.truncated, 0);
    }
    parse_exact(b, 2, &r);
    ASSERT_EQ(r.has_group, 0);
    parse_exact(b, 6, &r);
    ASSERT_EQ(r.has_group, 1);
    ASSERT_EQ(r.pairwise_count, 0);
    parse_exact(b, 18, &r);
    ASSERT_EQ(r.akm_bits, 1u << 2);
    ASSERT_EQ(r.has_caps, 0);
    ASSERT_EQ(r.mfpc, 0);
    parse_exact(b, 20, &r);
    ASSERT_EQ(r.has_caps, 1);
    ASSERT_EQ(r.mfpc, 1);
    ASSERT_EQ(r.mfpr, 0);
    ASSERT_EQ(r.has_pmkids, 0);
    parse_exact(b, 22, &r);
    ASSERT_EQ(r.has_pmkids, 1);
    ASSERT_EQ(r.pmkid_count, 0);
    ASSERT_EQ(r.has_group_mgmt, 0);
    parse_exact(b, 26, &r);
    ASSERT_EQ(r.has_group_mgmt, 1);
}

/* The issue's case: a Pairwise Count of 200 in a 12-octet body. One
 * suite fits — exactly, its last octet is the element's last — and is
 * taken; the rest of the claim is a truncation and nothing after it is
 * read. Run on an exact-size heap copy so the sanitiser would see a
 * read of suite two.
 *
 * Mutation-proved: `off + 4 <= len` → `off + 4 < len` in suite_list()
 * drops the exact-fit suite, and pairwise_count/pairwise_bits go red. */
static void test_overstated_pairwise_count_keeps_what_fits(void) {
    static const uint8_t b[] = {
        0x01, 0x00, IEEE, 0x04,
        0xc8, 0x00,                              /* 200 pairwise */
        IEEE, 0x04,
    };
    rsn_ie_t r;
    ASSERT_EQ((int)sizeof b, 12);
    ASSERT_EQ(parse_exact(b, (int)sizeof b, &r), 1);
    ASSERT_EQ(r.pairwise_count, 1);
    ASSERT_EQ(r.pairwise_bits, 1u << 4);
    ASSERT_EQ(r.truncated, 1);
    ASSERT_EQ(r.akm_count, 0);
    ASSERT_EQ(r.akm_bits, 0u);
    ASSERT_EQ(r.has_caps, 0);
}

/* The same rule on the AKM list, and the suites before the cut are
 * still reported — a transition-mode BSS with a lying count keeps
 * both lanes it did transmit. */
static void test_overstated_akm_count_keeps_what_fits(void) {
    static const uint8_t b[] = {
        0x01, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x04,
        0x03, 0x00, IEEE, 0x02, IEEE, 0x08,      /* claims 3, carries 2 */
    };
    rsn_ie_t r;
    ASSERT_EQ(parse_exact(b, (int)sizeof b, &r), 1);
    ASSERT_EQ(r.akm_count, 2);
    ASSERT_EQ(r.akm_bits, (1u << 2) | (1u << 8));
    ASSERT_EQ(r.truncated, 1);
    ASSERT_EQ(r.has_caps, 0);
}

static void test_overstated_pmkid_count(void) {
    uint8_t b[22 + 16];
    static const uint8_t head[] = {
        0x01, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x08,
        0xc0, 0x00,
        0x02, 0x00,                              /* 2 PMKIDs, 1 present */
    };
    memcpy(b, head, sizeof head);
    memset(b + sizeof head, 0x33, sizeof b - sizeof head);
    rsn_ie_t r;
    ASSERT_EQ(parse_exact(b, (int)(sizeof head + 16), &r), 1);
    ASSERT_EQ(r.has_pmkids, 1);
    ASSERT_EQ(r.pmkid_count, 1);
    ASSERT_EQ(r.truncated, 1);
    ASSERT_EQ(r.has_group_mgmt, 0);
    ASSERT_EQ(r.has_caps, 1);
}

/* An element ending inside a fixed field is cut, not finished. */
static void test_partial_fixed_field_is_truncated(void) {
    static const uint8_t b[] = {
        0x01, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x02,
        0xc0, 0x00,
    };
    rsn_ie_t r;
    ASSERT_EQ(parse_exact(b, 5, &r), 1);         /* 3 of 4 group octets */
    ASSERT_EQ(r.truncated, 1);
    ASSERT_EQ(r.has_group, 0);
    ASSERT_EQ(parse_exact(b, 7, &r), 1);         /* 1 of 2 count octets */
    ASSERT_EQ(r.truncated, 1);
    ASSERT_EQ(r.has_group, 1);
    ASSERT_EQ(r.pairwise_count, 0);
    ASSERT_EQ(parse_exact(b, 19, &r), 1);        /* 1 of 2 caps octets */
    ASSERT_EQ(r.truncated, 1);
    ASSERT_EQ(r.akm_count, 1);
    ASSERT_EQ(r.has_caps, 0);
}

/* Version is mandatory, and 1 is the only defined value. */
static void test_version_absent_or_undefined(void) {
    static const uint8_t v1[] = { 0x01 };
    rsn_ie_t r;
    ASSERT_EQ(parse_exact(v1, 1, &r), 0);
    ASSERT_EQ(r.truncated, 1);
    ASSERT_EQ(r.version, 0);
    ASSERT_EQ(rsn_ie_parse(NULL, 0, &r), 0);
    ASSERT_EQ(r.truncated, 1);
    ASSERT_EQ(rsn_ie_parse(v1, 1, NULL), 0);

    /* Version 2 followed by bytes that would read as an SAE AKM under
     * the version-1 layout. Nothing is decoded from an undefined
     * layout. Mutation-proved: dropping the `version != 1` return in
     * rsn_ie_parse() reddens the akm_bits and has_group lines. */
    static const uint8_t v2[] = {
        0x02, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x08,
        0x00, 0x00,
    };
    ASSERT_EQ(parse_exact(v2, (int)sizeof v2, &r), 0);
    ASSERT_EQ(r.version, 2);
    ASSERT_EQ(r.has_group, 0);
    ASSERT_EQ(r.akm_bits, 0u);
    ASSERT_EQ(r.truncated, 0);
}

/* A vendor suite with type 4 is not CCMP. It is counted and kept whole,
 * but stays out of the IEEE bitmaps; so does an IEEE type too large to
 * have a bit. */
static void test_non_ieee_and_high_types_stay_out_of_the_bitmaps(void) {
    static const uint8_t b[] = {
        0x01, 0x00, 0x00, 0x50, 0xf2, 0x04,      /* group: 00-50-F2 type 4 */
        0x01, 0x00, 0x00, 0x50, 0xf2, 0x04,
        0x02, 0x00, IEEE, 0x28, IEEE, 0x02,      /* type 40, then PSK */
    };
    rsn_ie_t r;
    ASSERT_EQ(parse_exact(b, (int)sizeof b, &r), 1);
    ASSERT_EQ(r.group_sel, 0x0050f204u);
    ASSERT_EQ(RSN_SEL_STD(r.group_sel), 0);
    ASSERT_EQ(r.pairwise_count, 1);
    ASSERT_EQ(r.pairwise_bits, 0u);
    ASSERT_EQ(r.first_pairwise_sel, 0x0050f204u);
    ASSERT_EQ(r.akm_count, 2);
    ASSERT_EQ(r.akm_bits, 1u << 2);
    ASSERT_EQ(RSN_SEL_TYPE(r.first_akm_sel), 40);
    ASSERT_EQ(r.truncated, 0);
}

/* The RSNE is extensible: octets after Group Management Cipher belong
 * to a later amendment and are not a fault. */
static void test_trailing_octets_after_the_last_field(void) {
    static const uint8_t b[] = {
        0x01, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x08,
        0xc0, 0x00, 0x00, 0x00, IEEE, 0x06,
        0xaa, 0xbb, 0xcc,
    };
    rsn_ie_t r;
    ASSERT_EQ(parse_exact(b, (int)sizeof b, &r), 1);
    ASSERT_EQ(r.has_group_mgmt, 1);
    ASSERT_EQ(r.truncated, 0);
}

static void test_names_and_rank(void) {
    ASSERT_STR(rsn_cipher_name(4),  "CCMP");
    ASSERT_STR(rsn_cipher_name(2),  "TKIP");
    ASSERT_STR(rsn_cipher_name(9),  "GCMP-256");
    ASSERT_STR(rsn_cipher_name(3),  "?");
    ASSERT_STR(rsn_akm_name(8),     "SAE");
    ASSERT_STR(rsn_akm_name(24),    "SAE-EXT-KEY");
    ASSERT_STR(rsn_akm_name(25),    "FT-SAE-EXT-KEY");
    ASSERT_STR(rsn_akm_name(99),    "?");
    ASSERT_LT(rsn_cipher_rank(2), rsn_cipher_rank(4));
    ASSERT_LT(rsn_cipher_rank(4), rsn_cipher_rank(9));
    ASSERT_EQ(rsn_cipher_rank(4), rsn_cipher_rank(8));
    ASSERT_EQ(rsn_cipher_rank(0), 0);
    ASSERT_EQ(rsn_cipher_rank(13), 0);
    ASSERT_EQ(rsn_cipher_rank_best((1u << 2) | (1u << 4)), rsn_cipher_rank(4));
    ASSERT_EQ(rsn_cipher_rank_best(1u << 0), 0);
    ASSERT_EQ(rsn_cipher_rank_best(0), 0);
}

/* ── defect E: the beacon `enc` label ─────────────────────── */

static void beacon_enc(const uint8_t *akm, int nakm, char enc[10],
                       beacon_rsn_t *rsn) {
    uint8_t buf[96];
    fb_t b;
    static const uint8_t pw[] = { 4 };
    fb_init(&b, buf, (int)sizeof buf);
    fb_ssid(&b, "lab");
    fb_rsn_lists(&b, 4, pw, 1, akm, nakm, 0x00c0);
    ASSERT(fb_ok(&b));
    char ssid[33]; int ch = 0;
    beacon_parse_ies(buf, b.len, 1, 100, ssid, &ch, enc, rsn, NULL);
}

/* An AP offering only SAE-EXT-KEY is WPA3. Before #128 the label tested
 * AKM 8/9 while akm_bits counted 24/25 as SAE, so this read "WPA2"
 * beside an SAE bitmap.
 *
 * Mutation-proved: `RSN_AKM_FAMILY_SAE(r.akm_bits)` → `(r.akm_bits &
 * RSN_AKM_SAE)` in beacon_parse_ies() reddens the two SAE-EXT-KEY
 * cases and leaves {2} and {2,8} green. */
static void test_sae_ext_key_only_is_wpa3(void) {
    static const uint8_t a24[] = { 24 };
    static const uint8_t a25[] = { 25 };
    char enc[10]; beacon_rsn_t rsn;
    beacon_enc(a24, 1, enc, &rsn);
    ASSERT_STR(enc, "WPA3");
    ASSERT_EQ(rsn.akm_bits, RSN_AKM_SAE_EXT);
    ASSERT_STR(rsn.akm, "SAE-EXT-KEY");
    beacon_enc(a25, 1, enc, &rsn);
    ASSERT_STR(enc, "WPA3");
    ASSERT_EQ(rsn.akm_bits, RSN_AKM_FT_SAE_EXT);
}

static void test_psk_is_wpa2_and_transition_is_wpa3(void) {
    static const uint8_t a2[]  = { 2 };
    static const uint8_t a28[] = { 2, 8 };
    char enc[10]; beacon_rsn_t rsn;
    beacon_enc(a2, 1, enc, &rsn);
    ASSERT_STR(enc, "WPA2");
    ASSERT_STR(rsn.akm, "PSK");
    ASSERT_STR(rsn.pairwise, "CCMP");
    ASSERT_STR(rsn.group, "CCMP");
    ASSERT_EQ(rsn.mfp, 2);
    beacon_enc(a28, 2, enc, &rsn);
    ASSERT_STR(enc, "WPA3");
    ASSERT_STR(rsn.akm, "PSK,SAE");
    ASSERT_EQ(rsn.akm_bits, RSN_AKM_PSK | RSN_AKM_SAE);
}

/* A truncated RSNE reaches both counters once: the per-BSSID
 * truncated_rsn MGMT_FUZZ scores from, and the sensor-wide
 * rsn_malformed parse fault. The element itself tiles its list, so
 * ie_overrun does not move. */
static void test_truncated_rsn_through_the_beacon_path(void) {
    static const uint8_t ies[] = {
        0x00, 0x03, 'l', 'a', 'b',
        0x30, 0x0c,                              /* RSN, 12 octets */
        0x01, 0x00, IEEE, 0x04,
        0xc8, 0x00, IEEE, 0x04,                  /* 200 pairwise, 1 present */
    };
    char ssid[33]; char enc[10]; int ch = 0; beacon_rsn_t rsn;
    sh_parse_fault_reset();
    beacon_parse_ies(ies, (int)sizeof ies, 1, 100, ssid, &ch, enc, &rsn, NULL);
    ASSERT_EQ(rsn.truncated_rsn, 1);
    ASSERT_EQ((int)sh_parse_fault_count(SH_PF_RSN_MALFORMED), 1);
    ASSERT_EQ((int)sh_parse_fault_count(SH_PF_IE_OVERRUN), 0);
    ASSERT_STR(rsn.pairwise, "CCMP");
    ASSERT_STR(enc, "WPA2");
    sh_parse_fault_reset();
}

/* RSNEs shorter than the full decoder's 8-octet floor: a cut inside
 * Version or the Group cipher (1, 3, 4, 5, 7 octets) is a sensor-wide
 * rsn_malformed fault as well as a per-BSSID truncated_rsn; Version-only
 * (2) and Version+Group (6) are complete elements and are not faults.
 * The #128 review found the 1-7 octet cases never reached the tally. */
static void test_short_rsn_reaches_the_sensor_tally(void) {
    static const int cut[]  = { 1, 3, 4, 5, 7 };
    static const int whole[] = { 2, 6 };
    uint8_t ies[16];
    char ssid[33]; char enc[10]; int ch = 0; beacon_rsn_t rsn;
    for (size_t i = 0; i < sizeof cut / sizeof cut[0]; i++) {
        memset(ies, 0, sizeof ies);
        ies[0] = 0x30; ies[1] = (uint8_t)cut[i]; ies[2] = 0x01;
        sh_parse_fault_reset();
        beacon_parse_ies(ies, 2 + cut[i], 1, 100, ssid, &ch, enc, &rsn, NULL);
        ASSERT_EQ(rsn.truncated_rsn, 1);
        ASSERT_EQ((int)sh_parse_fault_count(SH_PF_RSN_MALFORMED), 1);
    }
    for (size_t i = 0; i < sizeof whole / sizeof whole[0]; i++) {
        memset(ies, 0, sizeof ies);
        ies[0] = 0x30; ies[1] = (uint8_t)whole[i]; ies[2] = 0x01;
        ies[4] = 0x00; ies[5] = 0x0f; ies[6] = 0xac; ies[7] = 0x04;
        sh_parse_fault_reset();
        beacon_parse_ies(ies, 2 + whole[i], 1, 100, ssid, &ch, enc, &rsn, NULL);
        ASSERT_EQ((int)sh_parse_fault_count(SH_PF_RSN_MALFORMED), 0);
    }
    sh_parse_fault_reset();
}

/* A well-formed RSNE adds nothing to either counter. Mutation-proved:
 * `if (r.truncated)` → `if (1)` in beacon_parse_ies() reddens both
 * zeros here. */
static void test_clean_rsn_adds_no_fault(void) {
    static const uint8_t a2[] = { 2 };
    char enc[10]; beacon_rsn_t rsn;
    sh_parse_fault_reset();
    beacon_enc(a2, 1, enc, &rsn);
    ASSERT_EQ(rsn.truncated_rsn, 0);
    ASSERT_EQ((int)sh_parse_fault_count(SH_PF_RSN_MALFORMED), 0);
}

/* An RSNE with an undefined Version still says "not open" — the label
 * is WPA2, as before #128 — but nothing is read out of it, so bytes
 * that would decode as SAE under version 1 do not make it WPA3. */
static void test_undefined_version_is_rsn_without_suites(void) {
    static const uint8_t ies[] = {
        0x30, 0x14,
        0x02, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x04,
        0x01, 0x00, IEEE, 0x08,
        0xc0, 0x00,
    };
    char ssid[33]; char enc[10]; int ch = 0; beacon_rsn_t rsn;
    beacon_parse_ies(ies, (int)sizeof ies, 1, 100, ssid, &ch, enc, &rsn, NULL);
    ASSERT_STR(enc, "WPA2");
    ASSERT_EQ(rsn.akm_bits, 0u);
    ASSERT_STR(rsn.akm, "");
}

void run_rsn_ie_tests(void) {
    RUN_TEST(test_every_field_is_decoded);
    RUN_TEST(test_any_field_boundary_is_a_clean_end);
    RUN_TEST(test_overstated_pairwise_count_keeps_what_fits);
    RUN_TEST(test_overstated_akm_count_keeps_what_fits);
    RUN_TEST(test_overstated_pmkid_count);
    RUN_TEST(test_partial_fixed_field_is_truncated);
    RUN_TEST(test_version_absent_or_undefined);
    RUN_TEST(test_non_ieee_and_high_types_stay_out_of_the_bitmaps);
    RUN_TEST(test_trailing_octets_after_the_last_field);
    RUN_TEST(test_names_and_rank);
    RUN_TEST(test_sae_ext_key_only_is_wpa3);
    RUN_TEST(test_psk_is_wpa2_and_transition_is_wpa3);
    RUN_TEST(test_truncated_rsn_through_the_beacon_path);
    RUN_TEST(test_clean_rsn_adds_no_fault);
    RUN_TEST(test_short_rsn_reaches_the_sensor_tally);
    RUN_TEST(test_undefined_version_is_rsn_without_suites);
}
