#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "reg_6g.h"
#include "beacon_snoop.h"

/*
 * 6 GHz regulatory claims — issue #101 slice B.
 *
 * Every frame below is built from the clause text, never from a capture
 * (agents/AGENTS.md "no pcap fixtures"), and every expectation is a
 * literal, never the parser's own output fed back.
 *
 * HE Operation element — Element ID 255, Element ID Extension 36,
 * IEEE 802.11ax-2021 §9.4.2.249. Body after the Length octet:
 *   [0]     Element ID Extension (36)
 *   [1..3]  HE Operation Parameters, little-endian 24 bits:
 *             B14 VHT Operation Information Present  -> [2] & 0x40
 *             B15 Co-Hosted BSS                      -> [2] & 0x80
 *             B17 6 GHz Operation Information Present -> [3] & 0x02
 *   [4]     BSS Color Information
 *   [5..6]  Basic HE-MCS And NSS Set
 *   then, only when flagged and in this order:
 *           VHT Operation Information (3), Max Co-Hosted BSSID
 *           Indicator (1), 6 GHz Operation Information (5):
 *             Primary Channel, Control, CCFS0, CCFS1, Minimum Rate
 *   Control: B0-B1 Channel Width, B2 Duplicate Beacon, B3-B5 Regulatory
 *            Info (0 Indoor AP, 1 Standard Power AP, 2-7 reserved),
 *            B6-B7 reserved.
 *
 * Transmit Power Envelope element — tag 195, §9.4.2.161 as 802.11ax-2021
 * amends it:
 *   [0]  Transmit Power Information: B0-B2 Count, B3-B5 Interpretation
 *        (0 local EIRP, 1 local EIRP PSD, 2 regulatory client EIRP,
 *        3 regulatory client EIRP PSD), B6-B7 Category (0 default,
 *        1 subordinate device)
 *   [1..] Maximum Transmit Power values, signed, 0.5 dB steps. EIRP:
 *        Count + 1 values. PSD: Count 0 -> 1 value, 1-4 -> 1/2/4/8.
 */

static int put_ie(uint8_t *b, int off, uint8_t tag,
                  const uint8_t *body, int len) {
    b[off++] = tag;
    b[off++] = (uint8_t)len;
    memcpy(b + off, body, (size_t)len);
    return off + len;
}

/* An HE Operation body. `six` adds the 6 GHz Operation Information with
 * `ctrl` as its Control octet; `vht` / `cohost` add the fields that sit
 * in front of it. Returns the body length. */
static int he_op_body(uint8_t *b, int six, int vht, int cohost, uint8_t ctrl) {
    int n = 0;
    b[n++] = 36;
    b[n++] = 0x04;                                   /* params B0-B7  */
    b[n++] = (uint8_t)((vht ? 0x40 : 0) | (cohost ? 0x80 : 0));
    b[n++] = (uint8_t)(six ? 0x02 : 0);              /* B16-B23       */
    b[n++] = 0x05;                                   /* BSS colour 5  */
    b[n++] = 0xfc; b[n++] = 0xff;                    /* Basic MCS     */
    if (vht)    { b[n++] = 0x01; b[n++] = 42; b[n++] = 0; }
    if (cohost) { b[n++] = 0x03; }
    if (six) {
        b[n++] = 37;     /* primary channel */
        b[n++] = ctrl;
        b[n++] = 39;     /* CCFS0 */
        b[n++] = 0;      /* CCFS1 */
        b[n++] = 6;      /* min rate */
    }
    return n;
}

#define CTRL(width, reg) ((uint8_t)(((width) & 0x03) | (((reg) & 0x07) << 3)))

/* ── HE 6 GHz Regulatory Info ────────────────────────────── */

static void test_he6_regulatory_info_indoor_and_standard_power(void) {
    uint8_t b[32];
    reg_6g_t g;

    reg_6g_reset(&g);
    int n = he_op_body(b, 1, 0, 0, CTRL(2, 0));
    ASSERT_EQ(reg_6g_element(&g, 255, b, n), 1);
    ASSERT_EQ((int)g.he6_present, 1);
    ASSERT_EQ((int)g.he6_reg_info, REG_6G_INDOOR_AP);
    ASSERT_EQ((int)g.he6_control_raw, 0x02);
    ASSERT_STR(reg_6g_info_name(g.he6_reg_info), "indoor");

    reg_6g_reset(&g);
    n = he_op_body(b, 1, 0, 0, CTRL(2, 1));
    ASSERT_EQ(reg_6g_element(&g, 255, b, n), 1);
    ASSERT_EQ((int)g.he6_reg_info, REG_6G_STANDARD_AP);
    ASSERT_EQ((int)g.he6_control_raw, 0x0a);
    ASSERT_STR(reg_6g_info_name(g.he6_reg_info), "standard_power");
    ASSERT_EQ(g.malformed_he6, 0);
}

/* The width bits and the reserved top bits sit either side of B3-B5;
 * neither may leak into the value. 0xc8 = B7 B6 set, reg 1, width 0. */
static void test_he6_regulatory_info_masks_neighbouring_bits(void) {
    uint8_t b[32];
    reg_6g_t g; reg_6g_reset(&g);
    int n = he_op_body(b, 1, 0, 0, 0xcb);   /* width 3, dup beacon 0 */
    ASSERT_EQ(reg_6g_element(&g, 255, b, n), 1);
    ASSERT_EQ((int)g.he6_reg_info, 1);
    ASSERT_EQ((int)g.he6_control_raw, 0xcb);
}

static void test_he6_reserved_regulatory_info_is_kept_raw(void) {
    uint8_t b[32];
    for (int v = 2; v <= 7; v++) {
        reg_6g_t g; reg_6g_reset(&g);
        int n = he_op_body(b, 1, 0, 0, CTRL(1, v));
        ASSERT_EQ(reg_6g_element(&g, 255, b, n), 1);
        ASSERT_EQ((int)g.he6_reg_info, v);
        ASSERT_STR(reg_6g_info_name(g.he6_reg_info), "reserved");
    }
}

/* VHT Operation Information (3) and the Co-Hosted indicator (1) sit in
 * front of the 6 GHz field. Missing either offset reads Primary Channel
 * or CCFS0 as Control: 37 = 0x25 gives reg 4, 39 = 0x27 gives reg 4 —
 * plausible, wrong. Seen to fail with the cohost += 1 removed. */
static void test_he6_field_found_behind_vht_and_cohost(void) {
    uint8_t b[32];
    reg_6g_t g; reg_6g_reset(&g);
    int n = he_op_body(b, 1, 1, 1, CTRL(2, 1));
    ASSERT_EQ(n, 7 + 3 + 1 + 5);
    ASSERT_EQ(reg_6g_element(&g, 255, b, n), 1);
    ASSERT_EQ((int)g.he6_reg_info, 1);

    reg_6g_reset(&g);
    n = he_op_body(b, 1, 0, 1, CTRL(2, 0));
    ASSERT_EQ(reg_6g_element(&g, 255, b, n), 1);
    ASSERT_EQ((int)g.he6_reg_info, 0);

    reg_6g_reset(&g);
    n = he_op_body(b, 1, 1, 0, CTRL(2, 0));
    ASSERT_EQ(reg_6g_element(&g, 255, b, n), 1);
    ASSERT_EQ((int)g.he6_reg_info, 0);
}

/* A 2.4 / 5 GHz HE BSS carries no 6 GHz field. That is no claim and no
 * fault. Seen to fail with the `if (!six) return 0` removed (the pad
 * octets after the Co-Hosted indicator were read as a 6 GHz block). */
static void test_he_op_without_6ghz_field_is_not_a_claim(void) {
    uint8_t b[32];
    reg_6g_t g; reg_6g_reset(&g);
    int n = he_op_body(b, 0, 1, 1, 0);
    /* Pad so a reader that ignores the flag would find five octets. */
    memset(b + n, 0x3f, 5); n += 5;
    ASSERT_EQ(reg_6g_element(&g, 255, b, n), 0);
    ASSERT_EQ((int)g.he6_present, 0);
    ASSERT_EQ(g.malformed_he6, 0);
}

static void test_he6_field_flagged_but_cut_short_is_malformed(void) {
    uint8_t b[32];
    reg_6g_t g; reg_6g_reset(&g);
    int n = he_op_body(b, 1, 1, 0, CTRL(2, 1));
    /* Every length that ends inside the 6 GHz field. */
    for (int cut = 1; cut <= 5; cut++) {
        ASSERT_EQ(reg_6g_element(&g, 255, b, n - cut), 0);
    }
    ASSERT_EQ(g.malformed_he6, 5);
    ASSERT_EQ((int)g.he6_present, 0);
}

static void test_he_op_shorter_than_fixed_part_is_malformed(void) {
    uint8_t b[32];
    reg_6g_t g; reg_6g_reset(&g);
    he_op_body(b, 1, 0, 0, 0);
    for (int len = 1; len < 7; len++)
        ASSERT_EQ(reg_6g_element(&g, 255, b, len), 0);
    ASSERT_EQ(g.malformed_he6, 6);
    ASSERT_EQ((int)g.he6_present, 0);

    /* The same lengths with B17 clear. The 6 GHz walk's own bound cannot
     * reach these — a non-6 GHz body returns before it — so only the
     * fixed-part guard counts them. Each body is copied to a heap block
     * of exactly its length, so a guard weakened far enough to read
     * Parameters past the end is an ASan failure rather than a read of
     * the test's spare stack. Seen to fail with the guard at `len < 4`
     * (3 malformed, not 6). */
    int full = he_op_body(b, 0, 0, 0, 0);
    ASSERT_EQ(full, 7);
    reg_6g_reset(&g);
    for (int len = 1; len < 7; len++) {
        uint8_t *h = malloc((size_t)len);
        ASSERT(h != NULL);
        if (!h) continue;
        memcpy(h, b, (size_t)len);
        ASSERT_EQ(reg_6g_element(&g, 255, h, len), 0);
        free(h);
    }
    ASSERT_EQ(g.malformed_he6, 6);
    /* The whole fixed part with B17 clear is a valid non-6 GHz element:
     * no claim, and nothing malformed. */
    ASSERT_EQ(reg_6g_element(&g, 255, b, full), 0);
    ASSERT_EQ(g.malformed_he6, 6);
    ASSERT_EQ((int)g.he6_present, 0);
}

/* Other extension IDs (HE Capabilities 35, EHT Operation 106, MLE 107)
 * and other tags are not ours, and no counter moves for them. */
static void test_other_elements_are_not_claimed(void) {
    uint8_t b[32];
    int n = he_op_body(b, 1, 0, 0, CTRL(2, 1));
    reg_6g_t g; reg_6g_reset(&g);
    b[0] = 35;  ASSERT_EQ(reg_6g_element(&g, 255, b, n), 0);
    b[0] = 106; ASSERT_EQ(reg_6g_element(&g, 255, b, n), 0);
    b[0] = 36;  ASSERT_EQ(reg_6g_element(&g, 61,  b, n), 0);
    ASSERT_EQ(reg_6g_element(&g, 255, b, 0), 0);
    ASSERT_EQ(reg_6g_element(&g, 7,   b, n), 0);
    ASSERT_EQ(reg_6g_element(&g, 32,  b, 1), 0);
    ASSERT_EQ((int)g.he6_present, 0);
    ASSERT_EQ((int)g.tpe_count, 0);
    ASSERT_EQ(g.malformed_he6, 0);
    ASSERT_EQ(g.malformed_tpe, 0);
}

/* ── Transmit Power Envelope ─────────────────────────────── */

#define TPI(count, interp, cat) \
    ((uint8_t)(((count) & 0x07) | (((interp) & 0x07) << 3) | (((cat) & 0x03) << 6)))

static void test_tpe_local_eirp_values_are_signed_half_db(void) {
    /* Count 2: 20, 40 and 80 MHz. 46 = 23.0 dBm, 0x2f = 23.5 dBm,
     * 0xfc = -4 = -2.0 dBm. */
    const uint8_t body[] = { TPI(2, 0, 0), 46, 0x2f, 0xfc };
    reg_6g_t g; reg_6g_reset(&g);
    ASSERT_EQ(reg_6g_element(&g, 195, body, (int)sizeof(body)), 1);
    ASSERT_EQ((int)g.tpe_count, 1);
    const reg_tpe_t *e = &g.tpe[0];
    ASSERT_EQ((int)e->interp, REG_TPE_LOCAL_EIRP);
    ASSERT_EQ((int)e->category, REG_TPE_CAT_DEFAULT);
    ASSERT_EQ((int)e->count, 2);
    ASSERT_EQ((int)e->n_values, 3);
    ASSERT_EQ((int)e->values_half_db[0], 46);
    ASSERT_EQ((int)e->values_half_db[1], 47);
    ASSERT_EQ((int)e->values_half_db[2], -4);
    ASSERT_EQ((int)e->reserved, 0);
    ASSERT_EQ((int)e->ext_octets, 0);
    ASSERT_STR(reg_tpe_interp_name(e->interp), "local_eirp");
    ASSERT_EQ(reg_tpe_is_psd(e->interp), 0);
}

/* PSD and EIRP read the same Count differently; Count 2 is the case
 * where reading one as the other gives a plausible wrong length. Seen to
 * fail with the PSD branch replaced by the EIRP rule. */
static void test_tpe_psd_count_rule_differs_from_eirp(void) {
    static const struct { uint8_t count; int n; } c[] = {
        { 0, 1 }, { 1, 1 }, { 2, 2 }, { 3, 4 }, { 4, 8 },
    };
    for (size_t i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
        uint8_t body[1 + 8];
        body[0] = TPI(c[i].count, 3, 0);
        for (int v = 0; v < 8; v++) body[1 + v] = (uint8_t)(0xf0 + v);
        reg_6g_t g; reg_6g_reset(&g);
        ASSERT_EQ(reg_6g_element(&g, 195, body, 1 + c[i].n), 1);
        ASSERT_EQ((int)g.tpe[0].n_values, c[i].n);
        ASSERT_EQ((int)g.tpe[0].interp, REG_TPE_REG_CLIENT_EIRP_PSD);
        ASSERT_EQ((int)g.tpe[0].values_half_db[c[i].n - 1],
                  (int)(int8_t)(0xf0 + c[i].n - 1));
        ASSERT_EQ(reg_tpe_is_psd(g.tpe[0].interp), 1);
    }
    /* EIRP Count 0-3 is Count + 1. */
    for (uint8_t count = 0; count <= 3; count++) {
        uint8_t body[5] = { TPI(count, 2, 0), 1, 2, 3, 4 };
        reg_6g_t g; reg_6g_reset(&g);
        ASSERT_EQ(reg_6g_element(&g, 195, body, 2 + count), 1);
        ASSERT_EQ((int)g.tpe[0].n_values, count + 1);
    }
}

/* A reserved interpretation or count is well-formed but has no defined
 * value list: recorded, flagged reserved, no octet read as a power, no
 * malformed count. */
static void test_tpe_reserved_encodings_record_no_values(void) {
    const uint8_t eirp_c4[] = { TPI(4, 0, 0), 40, 40, 40, 40, 40 };
    const uint8_t psd_c5[]  = { TPI(5, 1, 0), 10 };
    const uint8_t interp5[] = { TPI(0, 5, 0), 10 };
    const uint8_t *bodies[] = { eirp_c4, psd_c5, interp5 };
    const int lens[] = { (int)sizeof(eirp_c4), (int)sizeof(psd_c5),
                         (int)sizeof(interp5) };
    for (int i = 0; i < 3; i++) {
        reg_6g_t g; reg_6g_reset(&g);
        ASSERT_EQ(reg_6g_element(&g, 195, bodies[i], lens[i]), 1);
        ASSERT_EQ((int)g.tpe_count, 1);
        ASSERT_EQ((int)g.tpe[0].reserved, 1);
        ASSERT_EQ((int)g.tpe[0].n_values, 0);
        ASSERT_EQ((int)g.tpe[0].values_half_db[0], 0);
        ASSERT_EQ(g.malformed_tpe, 0);
    }
    ASSERT_STR(reg_tpe_interp_name(5), "reserved");
}

/* Fewer value octets than the Count announces: malformed, and nothing
 * stored. Seen to fail with the `len < 1 + n` check removed (a value
 * past the element was stored). */
static void test_tpe_short_value_list_is_malformed(void) {
    const uint8_t body[] = { TPI(3, 0, 0), 40, 40, 40, 40 };
    reg_6g_t g; reg_6g_reset(&g);
    for (int len = 2; len < (int)sizeof(body); len++)
        ASSERT_EQ(reg_6g_element(&g, 195, body, len), 0);
    ASSERT_EQ(g.malformed_tpe, 3);
    ASSERT_EQ((int)g.tpe_count, 0);

    ASSERT_EQ(reg_6g_element(&g, 195, body, 0), 0);
    ASSERT_EQ(g.malformed_tpe, 4);
    ASSERT_EQ((int)g.tpe_count, 0);
}

/* Octets past the announced values: 802.11be appends a 320 MHz
 * extension field. Counted, not decoded, not malformed. */
static void test_tpe_trailing_octets_are_extension_not_fault(void) {
    const uint8_t body[] = { TPI(0, 0, 0), 30, 0x11, 0x22 };
    reg_6g_t g; reg_6g_reset(&g);
    ASSERT_EQ(reg_6g_element(&g, 195, body, (int)sizeof(body)), 1);
    ASSERT_EQ((int)g.tpe[0].n_values, 1);
    ASSERT_EQ((int)g.tpe[0].values_half_db[0], 30);
    ASSERT_EQ((int)g.tpe[0].ext_octets, 2);
    ASSERT_EQ(g.malformed_tpe, 0);
}

static void test_tpe_category_bits(void) {
    const uint8_t body[] = { TPI(0, 1, 1), 0xfe };
    reg_6g_t g; reg_6g_reset(&g);
    ASSERT_EQ(reg_6g_element(&g, 195, body, (int)sizeof(body)), 1);
    ASSERT_EQ((int)g.tpe[0].category, REG_TPE_CAT_SUBORDINATE);
    ASSERT_EQ((int)g.tpe[0].interp, REG_TPE_LOCAL_EIRP_PSD);
    ASSERT_EQ((int)g.tpe[0].values_half_db[0], -2);
    ASSERT_EQ((int)g.tpe[0].info_raw, 0x48);
}

/* Several TPEs in one frame: distinct (interpretation, category) pairs
 * are kept apart, a repeated pair keeps the last, and the store is
 * bounded with the overflow flagged. */
static void test_tpe_entries_keyed_by_interpretation_and_category(void) {
    reg_6g_t g; reg_6g_reset(&g);
    const uint8_t a[] = { TPI(0, 0, 0), 40 };
    const uint8_t b[] = { TPI(0, 3, 0), 0xfe };
    const uint8_t c[] = { TPI(0, 0, 0), 20 };     /* same pair as a */
    const uint8_t d[] = { TPI(0, 0, 1), 10 };     /* a, subordinate */
    reg_6g_element(&g, 195, a, 2);
    reg_6g_element(&g, 195, b, 2);
    reg_6g_element(&g, 195, c, 2);
    reg_6g_element(&g, 195, d, 2);
    ASSERT_EQ((int)g.tpe_count, 3);
    ASSERT_EQ((int)g.tpe[0].values_half_db[0], 20);
    ASSERT_EQ((int)g.tpe[1].interp, 3);
    ASSERT_EQ((int)g.tpe[2].category, 1);
    ASSERT_EQ((int)g.tpe_truncated, 0);

    reg_6g_reset(&g);
    for (int k = 0; k < 12; k++) {
        uint8_t e[2] = { TPI(0, k % 8, k / 8), (uint8_t)k };
        reg_6g_element(&g, 195, e, 2);
    }
    ASSERT_EQ((int)g.tpe_count, REG_6G_MAX_TPE);
    ASSERT_EQ((int)g.tpe_truncated, 1);
}

/* ── merge ───────────────────────────────────────────────── */

/* A frame without the 6 GHz field leaves a stored Regulatory Info alone;
 * a frame with only one TPE pair replaces that pair and keeps the
 * others. Seen to fail with the merge assigning the whole struct. */
static void test_merge_is_per_element_and_per_pair(void) {
    uint8_t b[32];
    reg_6g_t dst; reg_6g_reset(&dst);
    reg_6g_t f1;  reg_6g_reset(&f1);
    int n = he_op_body(b, 1, 0, 0, CTRL(2, 1));
    reg_6g_element(&f1, 255, b, n);
    const uint8_t loc[] = { TPI(0, 0, 0), 46 };
    const uint8_t psd[] = { TPI(0, 3, 0), 0xfe };
    reg_6g_element(&f1, 195, loc, 2);
    reg_6g_element(&f1, 195, psd, 2);
    reg_6g_merge(&dst, &f1);
    ASSERT_EQ((int)dst.he6_reg_info, 1);
    ASSERT_EQ((int)dst.tpe_count, 2);

    reg_6g_t f2; reg_6g_reset(&f2);
    const uint8_t psd2[] = { TPI(0, 3, 0), 0xfa };
    reg_6g_element(&f2, 195, psd2, 2);
    reg_6g_merge(&dst, &f2);
    ASSERT_EQ((int)dst.he6_present, 1);
    ASSERT_EQ((int)dst.he6_reg_info, 1);
    ASSERT_EQ((int)dst.tpe_count, 2);
    ASSERT_EQ((int)dst.tpe[0].values_half_db[0], 46);
    ASSERT_EQ((int)dst.tpe[1].values_half_db[0], -6);

    /* A later frame with a different claim does replace it. */
    reg_6g_t f3; reg_6g_reset(&f3);
    n = he_op_body(b, 1, 0, 0, CTRL(2, 0));
    reg_6g_element(&f3, 255, b, n);
    reg_6g_merge(&dst, &f3);
    ASSERT_EQ((int)dst.he6_reg_info, 0);
}

/* A frame that itself dropped TPE pairs passes the fact on. Merged into
 * an empty record its eight kept pairs fit without overflowing, so only
 * the explicit carry sets the flag there — the case a retained record
 * would otherwise lose. A later clean frame does not clear it. Seen to
 * fail with the `src->tpe_truncated` carry removed from the merge. */
static void test_merge_carries_tpe_truncation(void) {
    reg_6g_t f; reg_6g_reset(&f);
    for (int k = 0; k < 12; k++) {
        uint8_t e[2] = { TPI(0, k % 8, k / 8), (uint8_t)k };
        reg_6g_element(&f, 195, e, 2);
    }
    ASSERT_EQ((int)f.tpe_truncated, 1);
    reg_6g_t dst; reg_6g_reset(&dst);
    reg_6g_merge(&dst, &f);
    ASSERT_EQ((int)dst.tpe_count, REG_6G_MAX_TPE);
    ASSERT_EQ((int)dst.tpe_truncated, 1);

    reg_6g_t clean; reg_6g_reset(&clean);
    const uint8_t one[] = { TPI(0, 0, 0), 46 };
    reg_6g_element(&clean, 195, one, 2);
    reg_6g_merge(&dst, &clean);
    ASSERT_EQ((int)dst.tpe_truncated, 1);
}

static void test_merge_malformed_counts_accumulate_and_saturate(void) {
    reg_6g_t dst; reg_6g_reset(&dst);
    reg_6g_t f; reg_6g_reset(&f);
    f.malformed_he6 = 2; f.malformed_tpe = 3;
    reg_6g_merge(&dst, &f);
    reg_6g_merge(&dst, &f);
    ASSERT_EQ(dst.malformed_he6, 4);
    ASSERT_EQ(dst.malformed_tpe, 6);
    dst.malformed_tpe = INT_MAX - 1;
    reg_6g_merge(&dst, &f);
    ASSERT_EQ(dst.malformed_tpe, INT_MAX);
    reg_6g_merge(NULL, &f);
    reg_6g_merge(&dst, NULL);
}

/* ── through beacon_parse_ies and beacon_record ──────────── */

static const uint8_t BSSID_6G[6] = { 0x02, 0x6a, 0x00, 0x00, 0x00, 0x01 };

static int six_ghz_ies(uint8_t *ies, uint8_t reg_info, int with_tpe) {
    int off = 0;
    const uint8_t ssid[] = { 's', 'i', 'x' };
    off = put_ie(ies, off, 0, ssid, 3);
    uint8_t he[32];
    int n = he_op_body(he, 1, 0, 0, CTRL(2, reg_info));
    off = put_ie(ies, off, 255, he, n);
    if (with_tpe) {
        const uint8_t loc[] = { TPI(0, 0, 0), 46 };
        const uint8_t psd[] = { TPI(3, 3, 0), 0xfe, 0xfe, 0xfe, 0xfe };
        off = put_ie(ies, off, 195, loc, 2);
        off = put_ie(ies, off, 195, psd, 5);
    }
    return off;
}

static void test_six_ghz_claims_reach_the_unified_parser(void) {
    uint8_t ies[128];
    int len = six_ghz_ies(ies, 1, 1);
    char ssid[33]; int ch = 0; char enc[10];
    beacon_rsn_t rsn;
    beacon_parse_ies(ies, len, 0, 100, ssid, &ch, enc, &rsn, NULL);
    ASSERT_EQ((int)rsn.reg6g.he6_present, 1);
    ASSERT_EQ((int)rsn.reg6g.he6_reg_info, 1);
    ASSERT_EQ((int)rsn.reg6g.tpe_count, 2);
    ASSERT_EQ((int)rsn.reg6g.tpe[1].n_values, 4);
    /* The existing 6 GHz channel decode is untouched by the second
     * reader of the same element. */
    ASSERT_EQ((int)rsn.oper_primary_channel, 37);
    ASSERT_EQ((int)rsn.oper_channel_source, CH_SRC_HE_6GHZ);
    /* No rsn: nothing to publish into, and nothing breaks. */
    beacon_parse_ies(ies, len, 0, 100, ssid, &ch, enc, NULL, NULL);
}

static void test_no_six_ghz_elements_leave_the_record_absent(void) {
    const uint8_t ies[] = { 0, 3, 'f', 'i', 'v', 3, 1, 36 };
    char ssid[33]; int ch = 0; char enc[10];
    beacon_rsn_t rsn;
    memset(&rsn, 0x5a, sizeof(rsn));
    beacon_parse_ies(ies, (int)sizeof(ies), 0, 100, ssid, &ch, enc, &rsn, NULL);
    ASSERT_EQ((int)rsn.reg6g.he6_present, 0);
    ASSERT_EQ((int)rsn.reg6g.tpe_count, 0);
    ASSERT_EQ(rsn.reg6g.malformed_tpe, 0);
}

static const reg_6g_t *reg6g_of(const uint8_t *bssid) {
    static sloth_state_t st;
    memset(&st, 0, sizeof(st));
    beacon_snapshot(&st);
    for (int i = 0; i < st.beacon_count; i++)
        if (memcmp(st.beacon_aps[i].bssid, bssid, 6) == 0)
            return &st.beacon_aps[i].reg6g;
    return NULL;
}

static void record(const uint8_t *ies, int len) {
    char ssid[33]; int ch = 0; char enc[10];
    beacon_rsn_t rsn;
    beacon_parse_ies(ies, len, 0, 100, ssid, &ch, enc, &rsn, NULL);
    beacon_record(BSSID_6G, ssid, -55, 37, enc, 100, &rsn);
}

/* Retained per BSSID, and sticky across a beacon that omits the TPEs —
 * on a hopping radio that is a missed beacon, not a retraction. Seen to
 * fail with the update-path reg_6g_merge() removed. */
static void test_six_ghz_claims_retained_per_bssid(void) {
    beacon_clear();
    uint8_t ies[128];
    int len = six_ghz_ies(ies, 0, 1);
    record(ies, len);
    const reg_6g_t *g = reg6g_of(BSSID_6G);
    ASSERT(g != NULL);
    ASSERT_EQ((int)g->he6_present, 1);
    ASSERT_EQ((int)g->he6_reg_info, 0);
    ASSERT_EQ((int)g->tpe_count, 2);

    len = six_ghz_ies(ies, 1, 0);
    record(ies, len);
    g = reg6g_of(BSSID_6G);
    ASSERT(g != NULL);
    ASSERT_EQ((int)g->he6_reg_info, 1);
    ASSERT_EQ((int)g->tpe_count, 2);
    ASSERT_EQ((int)g->tpe[0].values_half_db[0], 46);
    beacon_clear();
}

void run_reg_6g_tests(void) {
    TEST_SUITE("HE 6 GHz Regulatory Info parse (#101 slice B, 802.11ax-2021 §9.4.2.249)");
    RUN_TEST(test_he6_regulatory_info_indoor_and_standard_power);
    RUN_TEST(test_he6_regulatory_info_masks_neighbouring_bits);
    RUN_TEST(test_he6_reserved_regulatory_info_is_kept_raw);
    RUN_TEST(test_he6_field_found_behind_vht_and_cohost);
    RUN_TEST(test_he_op_without_6ghz_field_is_not_a_claim);
    RUN_TEST(test_he6_field_flagged_but_cut_short_is_malformed);
    RUN_TEST(test_he_op_shorter_than_fixed_part_is_malformed);
    RUN_TEST(test_other_elements_are_not_claimed);

    TEST_SUITE("Transmit Power Envelope parse (#101 slice B, §9.4.2.161)");
    RUN_TEST(test_tpe_local_eirp_values_are_signed_half_db);
    RUN_TEST(test_tpe_psd_count_rule_differs_from_eirp);
    RUN_TEST(test_tpe_reserved_encodings_record_no_values);
    RUN_TEST(test_tpe_short_value_list_is_malformed);
    RUN_TEST(test_tpe_trailing_octets_are_extension_not_fault);
    RUN_TEST(test_tpe_category_bits);
    RUN_TEST(test_tpe_entries_keyed_by_interpretation_and_category);

    TEST_SUITE("6 GHz regulatory retention (#101 slice B)");
    RUN_TEST(test_merge_is_per_element_and_per_pair);
    RUN_TEST(test_merge_carries_tpe_truncation);
    RUN_TEST(test_merge_malformed_counts_accumulate_and_saturate);
    RUN_TEST(test_six_ghz_claims_reach_the_unified_parser);
    RUN_TEST(test_no_six_ghz_elements_leave_the_record_absent);
    RUN_TEST(test_six_ghz_claims_retained_per_bssid);
}
