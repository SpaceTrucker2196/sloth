#include <string.h>
#include "runner.h"
#include "dot11_ie.h"
#include "beacon_snoop.h"
#include "probe_pnl.h"
#include "eap_parse.h"
#include "sensor_health.h"

/* Element helpers written once (#127). Element lists below are literal
 * bytes laid out per IEEE 802.11-2020 §9.4.2.1 (Element ID, Length,
 * body; ID 255 adds the Element ID Extension as the first body octet).
 * Expected strings are literals, never produced by the code under test. */

static uint64_t pf_ie(void) { return sh_parse_fault_count(SH_PF_IE_OVERRUN); }

/* ── find / find_ext ───────────────────────────────────────── */

static void test_find_returns_the_first_matching_body(void) {
    static const uint8_t ies[] = {
        1, 2, 0x82, 0x84,               /* Supported Rates */
        3, 1, 6,                        /* DS Parameter Set: ch 6 */
        3, 1, 11,                       /* a second one: not returned */
    };
    const uint8_t *b = NULL; int l = -1;
    ASSERT_EQ(dot11_ie_find(ies, (int)sizeof ies, 3, &b, &l), 1);
    ASSERT_EQ(l, 1);
    ASSERT_EQ(b[0], 6);
    ASSERT_EQ(dot11_ie_find(ies, (int)sizeof ies, 48, &b, &l), 0);
    ASSERT_EQ(dot11_ie_find(NULL, 0, 3, &b, &l), 0);
}

static void test_find_ext_body_excludes_the_extension_octet(void) {
    static const uint8_t ies[] = {
        255, 0,                         /* ext element with no ext ID */
        255, 3, 35, 0xaa, 0xbb,         /* HE Capabilities */
        255, 2, 108, 0xcc,              /* EHT Capabilities */
    };
    const uint8_t *b = NULL; int l = -1;
    ASSERT_EQ(dot11_ie_find_ext(ies, (int)sizeof ies, 108, &b, &l), 1);
    ASSERT_EQ(l, 1);
    ASSERT_EQ(b[0], 0xcc);
    ASSERT_EQ(dot11_ie_find_ext(ies, (int)sizeof ies, 35, &b, &l), 1);
    ASSERT_EQ(l, 2);
    ASSERT_EQ(b[0], 0xaa);
    ASSERT_EQ(dot11_ie_find_ext(ies, (int)sizeof ies, 106, &b, &l), 0);
}

/* A stop ahead of the match is a fault and counted once; a lying
 * element *after* the match is never reached, so it is not.
 * Mutation-proved: letting find_first() walk on past the match (first
 * match still returned) reddens the 0. */
static void test_find_tallies_only_a_stop_it_reached(void) {
    static const uint8_t bad_first[] = { 1, 8, 0x82, 0, 3, 'a', 'b', 'c' };
    static const uint8_t bad_after[] = { 0, 2, 'h', 'i', 1, 8, 0x82 };
    const uint8_t *b; int l;
    uint64_t pf0 = pf_ie();
    ASSERT_EQ(dot11_ie_find(bad_first, (int)sizeof bad_first, 0, &b, &l), 0);
    ASSERT_EQ((long long)(pf_ie() - pf0), 1);
    pf0 = pf_ie();
    ASSERT_EQ(dot11_ie_find(bad_after, (int)sizeof bad_after, 0, &b, &l), 1);
    ASSERT_EQ((long long)(pf_ie() - pf0), 0);
}

/* ── SSID (§9.4.2.2: 0..32 octets) ─────────────────────────── */

static const char SSID32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";   /* 32 */

static int ssid_ie(uint8_t *ies, int n) {
    ies[0] = 0; ies[1] = (uint8_t)n;
    for (int i = 0; i < n; i++) ies[2 + i] = (uint8_t)SSID32[i % 32];
    return 2 + n;
}

static void test_ssid_33_octets_is_oversize_and_clamped(void) {
    uint8_t ies[2 + 33];
    int n = ssid_ie(ies, 33);
    char out[33]; int over = -1;
    ASSERT_EQ(dot11_ie_ssid(ies, n, out, &over), 1);
    ASSERT_EQ(over, 1);
    ASSERT_EQ((int)strlen(out), 32);
    ASSERT_STR(out, "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
}

/* The boundary: 32 is the largest valid length and is not oversize.
 * Mutation-proved: `blen > 32` → `blen >= 32` in dot11_ie_ssid_copy()
 * reddens this and the beacon-path 0 below. */
static void test_ssid_32_octets_is_not_oversize(void) {
    uint8_t ies[2 + 32];
    int n = ssid_ie(ies, 32);
    char out[33]; int over = -1;
    ASSERT_EQ(dot11_ie_ssid(ies, n, out, &over), 1);
    ASSERT_EQ(over, 0);
    ASSERT_STR(out, "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
}

/* No SSID element leaves `out` empty, not as the caller left it —
 * capture/probe.c relies on that. Mutation-proved by deleting the
 * reset at the top of dot11_ie_ssid(). */
static void test_ssid_wildcard_and_absent(void) {
    static const uint8_t wild[] = { 0, 0, 1, 1, 0x82 };
    static const uint8_t none[] = { 1, 1, 0x82 };
    char out[33] = "junk"; int over = -1;
    ASSERT_EQ(dot11_ie_ssid(wild, (int)sizeof wild, out, &over), 1);
    ASSERT_STR(out, "");
    ASSERT_EQ(over, 0);
    memcpy(out, "junk", 5);
    ASSERT_EQ(dot11_ie_ssid(none, (int)sizeof none, out, NULL), 0);
    ASSERT_STR(out, "");
}

/* The beacon path is the one with a counter: the same 33-octet element
 * through beacon_parse_ies() bumps oversize_ssid and yields 32 octets. */
static void test_ssid_oversize_through_the_beacon_path(void) {
    uint8_t ies[2 + 33];
    int n = ssid_ie(ies, 33);
    char ssid[33]; int ch = 0; char enc[10]; beacon_rsn_t rsn;
    beacon_parse_ies(ies, n, 0, 100, ssid, &ch, enc, &rsn, NULL);
    ASSERT_EQ(rsn.oversize_ssid, 1);
    ASSERT_STR(ssid, "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");

    n = ssid_ie(ies, 32);
    beacon_parse_ies(ies, n, 0, 100, ssid, &ch, enc, &rsn, NULL);
    ASSERT_EQ(rsn.oversize_ssid, 0);
    ASSERT_STR(ssid, "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
}

/* ── PHY tier (Defect F) ───────────────────────────────────── */

static const char *tier_of(const uint8_t *ies, int n) {
    dot11_phy_t p;
    dot11_ie_phy(ies, n, &p);
    return dot11_phy_tier(&p);
}

static void test_phy_ladder(void) {
    static const uint8_t ht[]  = { 45, 1, 0 };
    static const uint8_t vht[] = { 45, 1, 0, 191, 1, 0 };
    static const uint8_t he[]  = { 45, 1, 0, 255, 1, 35 };
    static const uint8_t leg[] = { 1, 1, 0x82 };
    ASSERT_STR(tier_of(ht,  (int)sizeof ht),  "Wi-Fi 4");
    ASSERT_STR(tier_of(vht, (int)sizeof vht), "Wi-Fi 5");
    ASSERT_STR(tier_of(he,  (int)sizeof he),  "Wi-Fi 6");
    ASSERT_STR(tier_of(leg, (int)sizeof leg), "legacy");
    ASSERT_STR(dot11_phy_tier(NULL), "legacy");
    const uint8_t eht[] = { 106, 107, 108 };
    for (int i = 0; i < 3; i++) {
        uint8_t e[3] = { 255, 1, eht[i] };
        ASSERT_STR(tier_of(e, 3), "Wi-Fi 7");
    }
}

/* Defect F. Multi-Link is Element ID Extension 107 (mle.h MLE_EXT_ID,
 * IEEE 802.11be). probe_pnl.c read 81 instead and never looked at 107,
 * so a client advertising only a Multi-Link element was Wi-Fi 7 to the
 * beacon path and not to the probe path. Asserted through BOTH public
 * entry points, not only the shared helper, because the defect was the
 * two disagreeing.
 *
 * Mutation-proved: `ext == 107` → `ext == 81` in dot11_ie_phy_note()
 * reddens the 107 assertions; adding `|| ext == 81` back reddens the
 * 81 ones (the absence half). */
static void test_ext_107_is_wifi7_and_81_is_not_on_both_paths(void) {
    static const uint8_t mle[] = { 255, 3, 107, 0x00, 0x00 };
    static const uint8_t e81[] = { 255, 3, 81,  0x00, 0x00 };
    char ssid[33]; int ch = 0; char enc[10]; beacon_rsn_t rsn;

    ASSERT_STR(probe_pnl_phy_ies(mle, (int)sizeof mle), "Wi-Fi 7");
    beacon_parse_ies(mle, (int)sizeof mle, 0, 100, ssid, &ch, enc, &rsn, NULL);
    ASSERT_STR(rsn.phy, "Wi-Fi 7");

    ASSERT_STR(probe_pnl_phy_ies(e81, (int)sizeof e81), "legacy");
    beacon_parse_ies(e81, (int)sizeof e81, 0, 100, ssid, &ch, enc, &rsn, NULL);
    ASSERT_STR(rsn.phy, "legacy");
}

/* ── OUI → vendor (union of both former tables) ────────────── */

static void test_oui_union_resolves_every_former_entry(void) {
    static const struct { uint8_t oui[3]; const char *want; } t[] = {
        /* beacon_snoop.c's AP-vendor table */
        { { 0x00, 0x17, 0xf2 }, "Apple"          },
        { { 0x00, 0x40, 0x96 }, "Cisco"          },
        { { 0x00, 0x03, 0x7f }, "Atheros"        },
        { { 0x00, 0x10, 0x18 }, "Broadcom"       },
        { { 0x4c, 0x5e, 0x0c }, "Mikrotik"       },
        { { 0x00, 0x15, 0x6d }, "Ubiquiti"       },
        { { 0xdc, 0x9f, 0xdb }, "Ubiquiti"       },
        { { 0x24, 0x0a, 0xc4 }, "Espressif"      },
        { { 0x00, 0x0d, 0x97 }, "Ruckus"         },
        { { 0x00, 0x24, 0x6c }, "Aruba"          },
        { { 0xc0, 0xc9, 0xe3 }, "TP-Link"        },
        { { 0x00, 0x09, 0x5b }, "Netgear"        },
        { { 0x00, 0x18, 0xe7 }, "D-Link"         },
        { { 0x00, 0x14, 0x6c }, "Netgear"        },
        { { 0x50, 0x6f, 0x9a }, "Wi-Fi Alliance" },
        /* probe_pnl.c's fingerprint OUIs not already above */
        { { 0x00, 0x50, 0xf2 }, "Microsoft"      },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const char *v = dot11_oui_vendor(t[i].oui);
        ASSERT(v != NULL);
        if (v) ASSERT_STR(v, t[i].want);
    }
    static const uint8_t unknown[3] = { 0xab, 0xcd, 0xef };
    ASSERT(dot11_oui_vendor(unknown) == NULL);
    ASSERT(dot11_oui_vendor(NULL) == NULL);
}

/* The union names Microsoft, and nearly every AP emits a Microsoft WMM
 * element, so the beacon path must skip it or every AP would be
 * "Microsoft". Mutation-proved: removing `&& !is_microsoft` from the
 * vendor branch in beacon_parse_ies() reddens both assertions. */
static void test_beacon_vendor_skips_the_microsoft_oui(void) {
    static const uint8_t wmm_then_cisco[] = {
        221, 7, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00,   /* WMM */
        221, 4, 0x00, 0x40, 0x96, 0x01,                     /* Cisco */
    };
    char ssid[33]; int ch = 0; char enc[10]; beacon_rsn_t rsn;
    beacon_parse_ies(wmm_then_cisco, (int)sizeof wmm_then_cisco, 0, 100,
                     ssid, &ch, enc, &rsn, NULL);
    ASSERT_STR(rsn.vendor, "Cisco");
    beacon_parse_ies(wmm_then_cisco, 9, 0, 100, ssid, &ch, enc, &rsn, NULL);
    ASSERT_STR(rsn.vendor, "");
}

/* A vendor the probe fingerprint reads through the union still maps to
 * the same OS label as before the table moved, and a union vendor that
 * is not an OS signal yields nothing. Mutation-proved separately:
 * dropping `ty == 0x08` reddens only the WMM case; returning any union
 * vendor as the guess reddens the WMM and Cisco cases. */
static void test_fingerprint_labels_survive_the_table_move(void) {
    static const uint8_t esp[]  = { 221, 4, 0x24, 0x0a, 0xc4, 0x01 };
    static const uint8_t ms8[]  = { 221, 4, 0x00, 0x50, 0xf2, 0x08 };
    static const uint8_t ms2[]  = { 221, 4, 0x00, 0x50, 0xf2, 0x02 };
    static const uint8_t cisco[] = { 221, 4, 0x00, 0x40, 0x96, 0x01 };
    ASSERT_STR(probe_pnl_fingerprint_ies(esp, (int)sizeof esp), "ESP32");
    ASSERT_STR(probe_pnl_fingerprint_ies(ms8, (int)sizeof ms8), "Windows");
    ASSERT(probe_pnl_fingerprint_ies(ms2, (int)sizeof ms2) == NULL);
    /* Known to the union, but not an OS signal. */
    ASSERT(probe_pnl_fingerprint_ies(cisco, (int)sizeof cisco) == NULL);
}

/* ── The two 2+2 walks #126 left (WPS in beacons, WSC in EAP) ─ */

/* WPS IE (221, 00:50:F2 type 4) whose second attribute claims 16 octets
 * with 2 present (WSC 2.0 §12 attribute framing: ID(2) Len(2), BE).
 * The State attribute ahead of it is kept; the stop is tallied once and
 * does not touch the per-BSSID element fuzz counter.
 *
 * Mutation-proved: deleting the walk's sh_parse_fault_note() reddens
 * the 1; changing its `== TLV_OVERRUN` to `!= TLV_OK` (so a clean END
 * also counts) reddens the well-formed 0. */
static void test_wps_attribute_overrun_is_tallied(void) {
    static const uint8_t bad[] = {
        221, 15, 0x00, 0x50, 0xf2, 0x04,
        0x10, 0x44, 0x00, 0x01, 0x02,         /* WPS State: Configured */
        0x10, 0x47, 0x00, 0x10, 0xaa, 0xbb,   /* UUID-E claims 16, has 2 */
    };
    static const uint8_t good[] = {
        221, 14, 0x00, 0x50, 0xf2, 0x04,
        0x10, 0x44, 0x00, 0x01, 0x02,         /* WPS State: Configured */
        0x10, 0x57, 0x00, 0x01, 0x01,         /* AP Setup Locked */
    };
    char ssid[33]; int ch = 0; char enc[10]; beacon_rsn_t rsn;

    uint64_t pf0 = pf_ie();
    beacon_parse_ies(bad, (int)sizeof bad, 0, 100, ssid, &ch, enc, &rsn, NULL);
    ASSERT_EQ((long long)(pf_ie() - pf0), 1);
    ASSERT_EQ(rsn.has_wps, 1);
    ASSERT_EQ(rsn.wps_state, 2);
    ASSERT_EQ(rsn.ie_overruns, 0);

    pf0 = pf_ie();
    beacon_parse_ies(good, (int)sizeof good, 0, 100, ssid, &ch, enc, &rsn, NULL);
    ASSERT_EQ((long long)(pf_ie() - pf0), 0);
    ASSERT_EQ(rsn.wps_state, 2);
    ASSERT_EQ(rsn.wps_locked, 2);
}

/* EAP-WSC (RFC 3748 §5.7 expanded type, WFA vendor 00:37:2A type 1):
 * Code Id Len(2) Type(254) Vendor-Id(3) Vendor-Type(4) Op-Code Flags,
 * then attributes. A Message Type attribute, then a header cut to 3.
 *
 * Mutation-proved: deleting wsc_walk_tlvs()'s note reddens the 1; an
 * `else` that also notes a clean END reddens the 0 and nothing else.
 * (`== TLV_OVERRUN` → `!= TLV_OK` is not the mutation for the 0: it
 * also sets `truncated` on every clean walk and reddens 28 assertions
 * in tests/test_eap_parse.c, so it does not isolate the tally.) */
static void test_wsc_attribute_overrun_is_tallied(void) {
    static const uint8_t bad[] = {
        0x02, 0x09, 0x00, 0x16, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x22, 0x00, 0x01, 0x04,         /* Message Type: M1 */
        0x10, 0x47, 0x00,                     /* header cut short */
    };
    static const uint8_t good[] = {
        0x02, 0x09, 0x00, 0x13, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x10, 0x22, 0x00, 0x01, 0x04,         /* Message Type: M1 */
    };
    eap_wsc_info_t w;
    uint64_t pf0 = pf_ie();
    ASSERT_EQ(eap_wsc_parse(bad, (int)sizeof bad, &w), 1);
    ASSERT_EQ((long long)(pf_ie() - pf0), 1);
    ASSERT_EQ(w.truncated, 1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M1);

    pf0 = pf_ie();
    ASSERT_EQ(eap_wsc_parse(good, (int)sizeof good, &w), 1);
    ASSERT_EQ((long long)(pf_ie() - pf0), 0);
    ASSERT_EQ(w.truncated, 0);
    ASSERT_EQ(w.tlvs_walked, 1);
    ASSERT_EQ(w.msg_type, WSC_MSG_M1);
}

void run_dot11_ie_tests(void) {
    RUN_TEST(test_find_returns_the_first_matching_body);
    RUN_TEST(test_find_ext_body_excludes_the_extension_octet);
    RUN_TEST(test_find_tallies_only_a_stop_it_reached);
    RUN_TEST(test_ssid_33_octets_is_oversize_and_clamped);
    RUN_TEST(test_ssid_32_octets_is_not_oversize);
    RUN_TEST(test_ssid_wildcard_and_absent);
    RUN_TEST(test_ssid_oversize_through_the_beacon_path);
    RUN_TEST(test_phy_ladder);
    RUN_TEST(test_ext_107_is_wifi7_and_81_is_not_on_both_paths);
    RUN_TEST(test_oui_union_resolves_every_former_entry);
    RUN_TEST(test_beacon_vendor_skips_the_microsoft_oui);
    RUN_TEST(test_fingerprint_labels_survive_the_table_move);
    RUN_TEST(test_wps_attribute_overrun_is_tallied);
    RUN_TEST(test_wsc_attribute_overrun_is_tallied);
}
