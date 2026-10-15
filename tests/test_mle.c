#include <string.h>
#include "runner.h"
#include "mle.h"
#include "sensor_health.h"

/*
 * Multi-Link Element — issue #67, IEEE 802.11be §9.4.2.312.
 *
 * Element body, starting at the ext ID byte:
 *   ExtID(1) = 107
 *   Multi-Link Control(2)   bits 0-2 Type, bit 4 MLD MAC present
 *   Common Info Length(1)   covers itself and everything after it
 *   MLD MAC Address(6)
 *   ... optional Common Info fields
 *   Per-STA Profile subelements (ID 0)
 *
 * Per-STA Profile body:
 *   STA Control(2)   bits 0-3 Link ID, bit 5 MAC Address Present
 *   STA Info Length(1)
 *   Affiliated STA MAC(6)
 */

static const uint8_t MLD[6]  = { 0x02, 0xaa, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t LNK1[6] = { 0x02, 0xaa, 0x00, 0x00, 0x00, 0x11 };
static const uint8_t LNK2[6] = { 0x02, 0xaa, 0x00, 0x00, 0x00, 0x22 };
static const uint8_t LNK3[6] = { 0x02, 0xaa, 0x00, 0x00, 0x00, 0x33 };
static const uint8_t LNK4[6] = { 0x02, 0xaa, 0x00, 0x00, 0x00, 0x44 };

/* Append a Per-STA Profile subelement carrying `mac` on `link_id`. */
static int put_per_sta(uint8_t *b, int off, int link_id, const uint8_t *mac) {
    b[off++] = 0;                  /* subelement ID 0 */
    b[off++] = 9;                  /* length: control(2) + len(1) + mac(6) */
    uint16_t sc = (uint16_t)((link_id & 0x0f) | 0x0020);  /* MAC present */
    b[off++] = (uint8_t)(sc & 0xff);
    b[off++] = (uint8_t)(sc >> 8);
    b[off++] = 7;                  /* STA Info Length */
    memcpy(b + off, mac, 6); off += 6;
    return off;
}

/* Append an RSNE (IEEE 802.11-2020 §9.4.2.24) offering exactly one
 * pairwise cipher suite and the given MFPR/MFPC capability bits:
 *   tag(1) len(1) ver(2) group(4) N(2) pairwise(4N) M(2) akm(4M) caps(2) */
static int put_rsne(uint8_t *b, int off, uint8_t pairwise,
                    int mfpr, int mfpc) {
    b[off++] = 48;
    b[off++] = 20;
    b[off++] = 0x01; b[off++] = 0x00;                  /* version 1 */
    b[off++] = 0x00; b[off++] = 0x0f; b[off++] = 0xac; b[off++] = 0x04;
    b[off++] = 0x01; b[off++] = 0x00;                  /* 1 pairwise suite */
    b[off++] = 0x00; b[off++] = 0x0f; b[off++] = 0xac; b[off++] = pairwise;
    b[off++] = 0x01; b[off++] = 0x00;                  /* 1 AKM: SAE */
    b[off++] = 0x00; b[off++] = 0x0f; b[off++] = 0xac; b[off++] = 0x08;
    uint16_t caps = (uint16_t)((mfpr ? 0x0040 : 0) | (mfpc ? 0x0080 : 0));
    b[off++] = (uint8_t)(caps & 0xff);
    b[off++] = (uint8_t)(caps >> 8);
    return off;
}

/* Append a Per-STA Profile subelement whose STA Profile carries the
 * Capability Information field and, when `pairwise` is non-zero, one
 * RSNE. `complete` sets STA Control bit 4 (Complete Profile); without
 * it the profile is a delta against the reporting AP and must not be
 * read for posture. STA Info Length is 1 here — it counts itself and no
 * optional STA Info field is present. */
static int put_per_sta_profile(uint8_t *b, int off, int link_id,
                               uint8_t pairwise, int mfpr, int complete) {
    int lenpos = off + 1;
    b[off++] = 0;                  /* subelement ID 0 */
    b[off++] = 0;                  /* length, patched below */
    int body = off;
    uint16_t sc = (uint16_t)((link_id & 0x0f) | (complete ? 0x0010 : 0));
    b[off++] = (uint8_t)(sc & 0xff);
    b[off++] = (uint8_t)(sc >> 8);
    b[off++] = 1;                  /* STA Info Length */
    b[off++] = 0x31; b[off++] = 0x04;  /* Capability Information */
    if (pairwise) off = put_rsne(b, off, pairwise, mfpr, 1);
    b[lenpos] = (uint8_t)(off - body);
    return off;
}

/* Cipher suite types, IEEE 802.11-2020 Table 9-149. */
#define CIPH_TKIP      2
#define CIPH_CCMP128   4
#define CIPH_GCMP256   9

/* Build a Basic-variant MLE. `common_extra` pads the Common Info with
 * optional fields the parser must skip via the declared length. */
static int build_mle(uint8_t *b, int type, int mld_present,
                     const uint8_t *mld, int common_extra) {
    int off = 0;
    b[off++] = MLE_EXT_ID;
    uint16_t ctl = (uint16_t)((type & 0x07) | (mld_present ? 0x0010 : 0));
    b[off++] = (uint8_t)(ctl & 0xff);
    b[off++] = (uint8_t)(ctl >> 8);
    b[off++] = (uint8_t)(1 + 6 + common_extra);   /* Common Info Length */
    memcpy(b + off, mld, 6); off += 6;
    for (int i = 0; i < common_extra; i++) b[off++] = 0x5a;  /* filler */
    return off;
}

static void test_basic_mle_yields_the_mld_mac(void) {
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT(memcmp(m.mld_mac, MLD, 6) == 0);
    ASSERT_EQ(m.link_count, 0);
}

static void test_per_sta_profiles_yield_link_macs(void) {
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    n = put_per_sta(b, n, 1, LNK2);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.link_count, 2);
    ASSERT(memcmp(m.link_mac[0], LNK1, 6) == 0);
    ASSERT(memcmp(m.link_mac[1], LNK2, 6) == 0);
    ASSERT_EQ((int)m.link_id[1], 1);
}

static void test_common_info_length_is_how_link_info_is_found(void) {
    /* The Common Info carries optional fields whose presence is
     * declared in the bitmap. Summing the ones we know about to find
     * where Link Info starts means a later amendment adding one
     * silently shifts every link address; the declared length does not
     * have that failure mode. Here the parser must skip 5 bytes it has
     * no interpretation for and still find the profile. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 5);
    n = put_per_sta(b, n, 2, LNK3);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.link_count, 1);
    ASSERT(memcmp(m.link_mac[0], LNK3, 6) == 0);
}

static void test_non_basic_variants_rejected(void) {
    /* Probe Request, Reconfiguration and Priority Access MLEs share the
     * container and mean different things. Reading one as Basic takes
     * an "MLD address" from a field that is not one — worse than not
     * decoding it at all. */
    uint8_t b[128];
    for (int type = 1; type <= 3; type++) {
        int n = build_mle(b, type, 1, MLD, 0);
        sloth_mld_t m;
        ASSERT_EQ(mle_parse(b, n, &m), 0);
    }
}

static void test_mld_mac_absent_rejected(void) {
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 0 /* presence bit clear */, MLD, 0);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 0);
}

static void test_wrong_ext_id_rejected(void) {
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    b[0] = 106;                    /* EHT Operation, not Multi-Link */
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 0);
}

static void test_group_addressed_mld_rejected(void) {
    uint8_t b[128];
    static const uint8_t BAD[6] = { 0x01, 0, 0, 0, 0, 1 };
    int n = build_mle(b, MLE_TYPE_BASIC, 1, BAD, 0);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 0);
}

static void test_link_overflow_flagged(void) {
    uint8_t b[160];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    n = put_per_sta(b, n, 1, LNK2);
    n = put_per_sta(b, n, 2, LNK3);
    n = put_per_sta(b, n, 3, LNK4);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.link_count, SLOTH_MLD_MAX_LINKS);
    ASSERT_EQ(m.links_truncated, 1);
}

static void test_truncated_bodies_are_safe(void) {
    uint8_t b[160];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    for (int cut = 1; cut < n; cut++) {
        sloth_mld_t m;
        int rc = mle_parse(b, cut, &m);
        if (rc) {
            /* A successful parse must not have invented a link from
             * bytes that were not there. */
            ASSERT(m.link_count <= 1);
        }
    }
}

/* ── malformed link_id — CVE-2026-58374 / w1.fi 2026-1 (#104) ── */

static void test_link_id_15_flagged(void) {
    /* hostapd's links[] storage has no slot 15 — the out-of-bounds
     * write CVE-2026-58374 names exactly this value. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 15, LNK1);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_link_id, 1);
    ASSERT_EQ((int)m.bad_link_id, 15);
}

static void test_link_id_14_is_the_valid_boundary(void) {
    /* 0-14 is the sanctioned range. The boundary itself must not be
     * mistaken for the invalid value one above it. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 14, LNK1);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_link_id, 0);
    ASSERT_EQ(m.link_count, 1);
}

static void test_duplicate_link_id_flagged(void) {
    /* Two Per-STA Profiles naming the same link_id inside one MLE —
     * a conformant MLD never does this; it names the same link twice. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    n = put_per_sta(b, n, 0, LNK2);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_link_id, 1);
    ASSERT_EQ((int)m.bad_link_id, 0);
}

static void test_distinct_link_ids_not_flagged(void) {
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    n = put_per_sta(b, n, 1, LNK2);
    n = put_per_sta(b, n, 2, LNK3);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_link_id, 0);
}

static void test_malformed_link_id_persists_across_clean_frames(void) {
    /* mle_observe()'s lifetime count is sticky: one bad frame followed
     * by a hundred clean ones must still read as having happened. */
    mle_clear();
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 15, LNK1);
    sloth_mld_t m;
    mle_parse(b, n, &m);
    mle_observe(&m, 1000);

    n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    mle_parse(b, n, &m);
    mle_observe(&m, 1001);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    mle_snapshot(&st);
    ASSERT_EQ(st.mld_count, 1);
    ASSERT_EQ((int)st.mlds[0].malformed_link_id_total, 1);
    ASSERT_EQ((int)st.mlds[0].bad_link_id, 15);
    ASSERT_EQ((int)st.mlds[0].malformed_link_id_last_seen, 1000);
    mle_clear();
}

/* ── malformed Common Info Length — CVE-2026-58374 class / w1.fi 2026-1 (#104 slice 2) ── */

static void test_common_info_len_too_small_flagged(void) {
    /* The field covers itself (1) plus the mandatory MLD MAC (6): 7 is
     * the structural floor. A declared value under that cannot even
     * describe what presence bit 4 says is there. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    b[3] = 3;   /* declared Common Info Length, below the floor of 7 */
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_common_info_len, 1);
    ASSERT_EQ((int)m.bad_common_info_len, 3);
    ASSERT(memcmp(m.mld_mac, MLD, 6) == 0);  /* identity still captured */
}

static void test_common_info_len_overruns_element_flagged(void) {
    /* A declared length that pushes Link Info past the element's own
     * bounds is the buffer-overread shape itself: trusting it blindly
     * to find Link Info would read past the frame. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    b[3] = 200;   /* far past n */
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_common_info_len, 1);
    ASSERT_EQ((int)m.bad_common_info_len, 200);
}

static void test_common_info_len_7_is_the_valid_floor(void) {
    /* The boundary itself must parse clean, not be mistaken for the
     * invalid value just below it. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);   /* common_len = 7 */
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_common_info_len, 0);
}

static void test_malformed_common_info_len_persists_across_clean_frames(void) {
    mle_clear();
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    b[3] = 3;
    sloth_mld_t m;
    mle_parse(b, n, &m);
    mle_observe(&m, 1000);

    n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    mle_parse(b, n, &m);
    mle_observe(&m, 1001);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    mle_snapshot(&st);
    ASSERT_EQ(st.mld_count, 1);
    ASSERT_EQ((int)st.mlds[0].malformed_common_info_len_total, 1);
    ASSERT_EQ((int)st.mlds[0].bad_common_info_len, 3);
    ASSERT_EQ((int)st.mlds[0].malformed_common_info_len_last_seen, 1000);
    mle_clear();
}

/* ── subelement bounds overrun — CVE-2026-58374 class / w1.fi 2026-1 (#104 slice 3) ──
 *
 * `mle_len` handed to mle_parse() is the element's own declared length
 * (`src/beacon_snoop.c` passes the IE length byte), so the Link Info
 * subelement chain has to tile it exactly: ID(1) + Length(1) + body, no
 * padding defined between subelements. A declared length reaching past
 * that boundary is the summed-lengths-exceed-container overrun itself. */

static void test_subelem_len_overruns_element_by_one_flagged(void) {
    /* One byte past the element end is still past it. The off-by-one is
     * the shape a length-confusion bug is most likely to have, and the
     * one an "approximately in bounds" check would wave through. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    int p = n;
    n = put_per_sta(b, n, 0, LNK1);
    b[p + 1] = 10;              /* declared body length; 9 is the truth */
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_subelem_len, 1);
    ASSERT_EQ((int)m.bad_subelem_len, 10);
    ASSERT_EQ((int)m.subelem_overrun_bytes, 1);
    ASSERT(memcmp(m.mld_mac, MLD, 6) == 0);  /* identity still captured */
}

static void test_subelem_len_overruns_element_by_many_flagged(void) {
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    int p = n;
    n = put_per_sta(b, n, 0, LNK1);
    b[p + 1] = 200;
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_subelem_len, 1);
    ASSERT_EQ((int)m.bad_subelem_len, 200);
    ASSERT_EQ((int)m.subelem_overrun_bytes, p + 2 + 200 - n);
    /* The lying length must not have been believed: no affiliated link
     * address was taken from memory past the element. */
    ASSERT_EQ(m.link_count, 0);
}

static void test_subelem_chain_sum_overrun_flagged(void) {
    /* The issue states the rule as "the sum of subelement lengths
     * exceeds the enclosing MLE IE length" — so a first subelement that
     * tiles correctly must not excuse a second one that does not, and
     * the link the valid subelement carried is still evidence worth
     * keeping. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    int p = n;
    n = put_per_sta(b, n, 1, LNK2);
    b[p + 1] = 20;              /* second subelement overshoots */
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_subelem_len, 1);
    ASSERT_EQ((int)m.bad_subelem_len, 20);
    ASSERT_EQ((int)m.subelem_overrun_bytes, p + 2 + 20 - n);
    ASSERT_EQ(m.link_count, 1);
    ASSERT(memcmp(m.link_mac[0], LNK1, 6) == 0);
}

static void test_subelem_header_truncated_at_element_boundary_flagged(void) {
    /* A single byte left where Link Info continues can only be the
     * start of a subelement — nothing else is defined there — and that
     * subelement's mandatory 2-byte ID/length header already reaches
     * one byte past the element the sender declared. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    b[n++] = MLE_SUBELEM_PER_STA;   /* ID present, length byte missing */
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_subelem_len, 1);
    ASSERT_EQ((int)m.subelem_overrun_bytes, 1);
    ASSERT_EQ((int)m.bad_subelem_len, 0);   /* never read — it is not there */
}

static void test_subelem_exact_fit_not_flagged(void) {
    /* The boundary case that must stay quiet: a chain ending exactly on
     * the element's last byte is conformant, and the link it carries
     * proves the walk ran rather than bailing early. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    n = put_per_sta(b, n, 1, LNK2);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_subelem_len, 0);
    ASSERT_EQ((int)m.subelem_overrun_bytes, 0);
    ASSERT_EQ(m.link_count, 2);
}

static void test_zero_length_subelement_not_flagged(void) {
    /* A body-less subelement consumes its 2-byte header and nothing
     * else. Legal, carries nothing, and must neither fire nor stall the
     * walk — the chain still has to advance past it. */
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    b[n++] = 9;    /* some subelement ID sloth has no interpretation for */
    b[n++] = 0;    /* ...declaring no body */
    n = put_per_sta(b, n, 0, LNK1);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_subelem_len, 0);
    ASSERT_EQ(m.link_count, 1);     /* the walk got past the empty one */
    ASSERT(memcmp(m.link_mac[0], LNK1, 6) == 0);
}

static void test_malformed_subelem_len_persists_across_clean_frames(void) {
    mle_clear();
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    int p = n;
    n = put_per_sta(b, n, 0, LNK1);
    b[p + 1] = 10;
    sloth_mld_t m;
    mle_parse(b, n, &m);
    mle_observe(&m, 1000);

    n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    mle_parse(b, n, &m);
    mle_observe(&m, 1001);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    mle_snapshot(&st);
    ASSERT_EQ(st.mld_count, 1);
    ASSERT_EQ((int)st.mlds[0].malformed_subelem_len_total, 1);
    ASSERT_EQ((int)st.mlds[0].bad_subelem_len, 10);
    ASSERT_EQ((int)st.mlds[0].subelem_overrun_bytes, 1);
    ASSERT_EQ((int)st.mlds[0].malformed_subelem_len_last_seen, 1000);
    mle_clear();
}

/* ── the table and the canonical lookup ── */

static void test_observe_and_canonical_lookup(void) {
    mle_clear();
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    n = put_per_sta(b, n, 1, LNK2);
    sloth_mld_t m;
    mle_parse(b, n, &m);
    mle_observe(&m, 1000);

    uint8_t out[6];
    ASSERT_EQ(mle_canonical(LNK1, out), 1);
    ASSERT(memcmp(out, MLD, 6) == 0);
    ASSERT_EQ(mle_canonical(LNK2, out), 1);
    ASSERT(memcmp(out, MLD, 6) == 0);
    /* The MLD address resolves to itself — a caller that already holds
     * the canonical form must not be told there is no mapping and fall
     * back to a seqnum guess. */
    ASSERT_EQ(mle_canonical(MLD, out), 1);
    ASSERT(memcmp(out, MLD, 6) == 0);
    /* An unrelated address is not claimed. */
    ASSERT_EQ(mle_canonical(LNK4, out), 0);
    mle_clear();
}

static void test_links_merge_across_frames(void) {
    /* A device advertises different subsets of its links depending on
     * which band the frame was heard on. Replacing would make the link
     * set flap and the canonical lookup intermittent, which is worse
     * than not having it at all. */
    mle_clear();
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    sloth_mld_t m;
    mle_parse(b, n, &m);
    mle_observe(&m, 1000);

    n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 1, LNK2);
    mle_parse(b, n, &m);
    mle_observe(&m, 1001);

    ASSERT_EQ(mle_count(), 1);
    uint8_t out[6];
    ASSERT_EQ(mle_canonical(LNK1, out), 1);
    ASSERT_EQ(mle_canonical(LNK2, out), 1);
    mle_clear();
}

static void test_repeat_observation_does_not_duplicate_links(void) {
    mle_clear();
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    sloth_mld_t m;
    mle_parse(b, n, &m);
    for (int i = 0; i < 5; i++) mle_observe(&m, 1000 + i);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    mle_snapshot(&st);
    ASSERT_EQ(st.mld_count, 1);
    ASSERT_EQ(st.mlds[0].link_count, 1);
    mle_clear();
}

/* ── MLD MAC collision — IEEE 802.11be 9.4.2.312 (#104 slice 4) ──── */

static void test_conflicting_link_id_address_flags_collision(void) {
    mle_clear();
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    sloth_mld_t m;
    mle_parse(b, n, &m);
    mle_observe(&m, 1000);

    /* Same MLD MAC, same link_id, a different affiliated address. */
    n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK2);
    mle_parse(b, n, &m);
    mle_observe(&m, 1001);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    mle_snapshot(&st);
    ASSERT_EQ(st.mld_count, 1);
    ASSERT_EQ(st.mlds[0].mac_collision_total, 1);
    ASSERT_EQ(st.mlds[0].collision_link_id, 0);
    ASSERT(memcmp(st.mlds[0].collision_mac, LNK2, 6) == 0);
    /* The first-seen binding stays authoritative in the roster — the
     * conflicting address is reported, never merged in. */
    ASSERT_EQ(st.mlds[0].link_count, 1);
    uint8_t out[6];
    ASSERT_EQ(mle_canonical(LNK1, out), 1);
    ASSERT_EQ(mle_canonical(LNK2, out), 0);
    mle_clear();
}

static void test_new_link_id_not_flagged_as_collision(void) {
    /* The ordinary case this rule must not disturb: a genuinely new
     * link_id, not seen before, is a normal merge. */
    mle_clear();
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    sloth_mld_t m;
    mle_parse(b, n, &m);
    mle_observe(&m, 1000);

    n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 1, LNK2);
    mle_parse(b, n, &m);
    mle_observe(&m, 1001);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    mle_snapshot(&st);
    ASSERT_EQ(st.mlds[0].mac_collision_total, 0);
    ASSERT_EQ(st.mlds[0].link_count, 2);
    mle_clear();
}

static void test_repeated_same_binding_not_flagged_as_collision(void) {
    /* The same (link_id, address) seen again — not a conflict, not a
     * new link either. */
    mle_clear();
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    sloth_mld_t m;
    mle_parse(b, n, &m);
    for (int i = 0; i < 3; i++) mle_observe(&m, 1000 + i);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    mle_snapshot(&st);
    ASSERT_EQ(st.mlds[0].mac_collision_total, 0);
    ASSERT_EQ(st.mlds[0].link_count, 1);
    mle_clear();
}

static void test_mac_collision_persists_across_clean_frames(void) {
    /* Sticky lifetime count, same convention as the sibling MLE rules:
     * a later clean frame does not erase an earlier collision. */
    mle_clear();
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    sloth_mld_t m;
    mle_parse(b, n, &m);
    mle_observe(&m, 1000);

    n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK2);
    mle_parse(b, n, &m);
    mle_observe(&m, 1001);

    n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    mle_parse(b, n, &m);
    mle_observe(&m, 1002);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    mle_snapshot(&st);
    ASSERT_EQ(st.mlds[0].mac_collision_total, 1);
    mle_clear();
}

static void test_distinct_mlds_isolate_collision_counts(void) {
    mle_clear();
    static const uint8_t MLD2[6] = { 0x02, 0xaa, 0x00, 0x00, 0x00, 0x02 };
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK1);
    sloth_mld_t m;
    mle_parse(b, n, &m);
    mle_observe(&m, 1000);
    n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta(b, n, 0, LNK2);
    mle_parse(b, n, &m);
    mle_observe(&m, 1001);

    n = build_mle(b, MLE_TYPE_BASIC, 1, MLD2, 0);
    n = put_per_sta(b, n, 0, LNK3);
    mle_parse(b, n, &m);
    mle_observe(&m, 1002);

    sloth_state_t st; memset(&st, 0, sizeof(st));
    mle_snapshot(&st);
    ASSERT_EQ(st.mld_count, 2);
    int collided = 0, clean = 0;
    for (int i = 0; i < st.mld_count; i++) {
        if (memcmp(st.mlds[i].mld_mac, MLD, 6) == 0) collided = st.mlds[i].mac_collision_total;
        if (memcmp(st.mlds[i].mld_mac, MLD2, 6) == 0) clean = st.mlds[i].mac_collision_total;
    }
    ASSERT_EQ(collided, 1);
    ASSERT_EQ(clean, 0);
    mle_clear();
}

/* ── Cross-link cipher / PMF downgrade (#104 slice 5) ─────────────
 *
 * IEEE 802.11be §9.4.2.312: each Per-STA Profile of one Multi-Link
 * element describes one affiliated radio of the same MLD. A benign MLD
 * runs one security posture across all of them.
 *
 * Every frame below is a hand-built byte array per the clause — no
 * capture, no fixture, no Scapy. */

static void test_cross_link_cipher_and_pmf_downgrade_flagged(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, CIPH_GCMP256, 1, 1);
    n = put_per_sta_profile(b, n, 1, CIPH_CCMP128, 0, 1);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 1);
    ASSERT_EQ(m.downgrade_link_id, 1);
    ASSERT_EQ(m.downgrade_peer_link_id, 0);
    ASSERT_EQ(m.downgrade_pmf_mismatch, 1);
    ASSERT_EQ(m.downgrade_cipher_mismatch, 1);
}

/* PMF asymmetry ALONE is recorded and is NOT a downgrade.
 *
 * Owner ruling 2026-10-13. MFPR=1 on one link and MFPR=0 on another is
 * the posture pair the standard MANDATES for a tri-band AP where one
 * band requires PMF and the others negotiate it, so raising a downgrade
 * finding on it alone fires on CONFORMANT Wi-Fi 7 hardware — which, on
 * an issue about Wi-Fi 7, is the common case rather than an edge.
 *
 * The mismatch is still recorded with its own link pair, because PMF
 * genuinely absent on one link of an MLD is worth seeing; it just
 * cannot raise the alert by itself. */
static void test_pmf_mismatch_alone_is_recorded_not_a_downgrade(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, CIPH_CCMP128, 1, 1);
    n = put_per_sta_profile(b, n, 2, CIPH_CCMP128, 0, 1);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    /* Recorded... */
    ASSERT_EQ(m.downgrade_pmf_mismatch, 1);
    ASSERT_EQ(m.pmf_mismatch_link_id, 2);
    ASSERT_EQ(m.pmf_mismatch_peer_link_id, 0);
    /* ...and not a downgrade. This is the assertion that fires on
       conformant hardware if the arms are recoupled. */
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
    ASSERT_EQ(m.downgrade_cipher_mismatch, 0);
}

/* The exact frame review built to show the old rule firing on a
 * conformant tri-band AP: two links negotiating PMF, one requiring it,
 * identical CCMP-128 throughout. Nothing here is an attack and nothing
 * here is even a misconfiguration. */
static void test_conformant_tri_band_ap_does_not_fire(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, CIPH_CCMP128, 0, 1);  /* MFPC, !MFPR */
    n = put_per_sta_profile(b, n, 1, CIPH_CCMP128, 0, 1);
    n = put_per_sta_profile(b, n, 2, CIPH_CCMP128, 1, 1);  /* MFPR */
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
    ASSERT_EQ(m.downgrade_cipher_mismatch, 0);
    /* The observation is still available to a reader. */
    ASSERT_EQ(m.downgrade_pmf_mismatch, 1);
}

/* A repeated link_id already fires MLE_INVALID_LINK_ID; reading a
 * cross-link posture across it yields a "weaker link" and a "sibling"
 * that are the SAME link. Review built this input — two Complete
 * Profiles both at link_id 3 — and got
 * downgrade_link_id == downgrade_peer_link_id. A comparison between two
 * links needs two links. */
static void test_repeated_link_id_suppresses_the_posture_read(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 3, CIPH_TKIP,     0, 1);
    n = put_per_sta_profile(b, n, 3, CIPH_GCMP256,  1, 1);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_link_id, 1);
    /* No posture finding at all, so no self-comparison can be reported. */
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
    ASSERT_EQ(m.downgrade_cipher_mismatch, 0);
    ASSERT_EQ(m.downgrade_pmf_mismatch, 0);
}

/* Both mismatches present, on DIFFERENT link pairs. They used to share
 * one pair and whichever branch ran second overwrote it while both flags
 * stayed set, so the single pair reported was false of one clause in the
 * detail string. */
static void test_both_mismatches_keep_separate_link_pairs(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, CIPH_GCMP256, 1, 1);  /* strong, MFPR */
    n = put_per_sta_profile(b, n, 1, CIPH_TKIP,    1, 1);  /* weak,   MFPR */
    n = put_per_sta_profile(b, n, 2, CIPH_GCMP256, 0, 1);  /* strong, !MFPR */
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 1);
    /* The cipher pair is the weak link against a strong sibling... */
    ASSERT_EQ(m.downgrade_cipher_mismatch, 1);
    ASSERT_EQ(m.downgrade_link_id, 1);
    /* ...and the PMF pair is a different pair entirely. */
    ASSERT_EQ(m.downgrade_pmf_mismatch, 1);
    ASSERT_EQ(m.pmf_mismatch_link_id, 2);
    /* The two must not be the same link, which is what the overwrite
       used to produce. */
    ASSERT(m.downgrade_link_id != m.pmf_mismatch_link_id);
}

/* Isolates the cipher condition: identical MFPR, only strength differs.
 * TKIP against CCMP-128 rather than CCMP-128 against GCMP-256, so the
 * rank table is exercised at its other end. */
static void test_cipher_strength_mismatch_alone_flagged(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, CIPH_TKIP,    1, 1);
    n = put_per_sta_profile(b, n, 1, CIPH_CCMP128, 1, 1);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 1);
    ASSERT_EQ(m.downgrade_cipher_mismatch, 1);
    ASSERT_EQ(m.downgrade_pmf_mismatch, 0);
    ASSERT_EQ(m.downgrade_link_id, 0);        /* TKIP is the weaker one */
    ASSERT_EQ(m.downgrade_peer_link_id, 1);
}

static void test_identical_per_link_rsne_not_flagged(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, CIPH_GCMP256, 1, 1);
    n = put_per_sta_profile(b, n, 1, CIPH_GCMP256, 1, 1);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
}

/* The false-positive trap. Under 802.11be profile inheritance a link
 * that omits the RSNE inherits the reporting AP's, so an absent RSNE
 * means "same as the AP", never "no encryption". */
static void test_link_without_an_rsne_inherits_and_is_not_flagged(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, CIPH_GCMP256, 1, 1);
    n = put_per_sta_profile(b, n, 1, 0,            0, 1);   /* no RSNE */
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
}

/* A partial profile is a delta against the reporting AP, so its RSNE
 * (if any) is not that link's full posture. */
static void test_partial_profile_not_read_for_posture(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, CIPH_GCMP256, 1, 0);
    n = put_per_sta_profile(b, n, 1, CIPH_CCMP128, 0, 0);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
}

static void test_single_link_rsne_not_flagged(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, CIPH_TKIP, 0, 1);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
}

/* STA Profile of zero length: Complete Profile is set but there is
 * nothing after the STA Info field, so there is no RSNE to compare and
 * nothing to read past either. */
static void test_zero_length_sta_profile_not_flagged(void) {
    uint8_t b[64];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    for (int k = 0; k < 2; k++) {
        b[n++] = 0;              /* subelement ID 0 */
        b[n++] = 3;              /* control(2) + STA Info Length(1) */
        uint16_t sc = (uint16_t)(k | 0x0010);
        b[n++] = (uint8_t)(sc & 0xff);
        b[n++] = (uint8_t)(sc >> 8);
        b[n++] = 1;              /* STA Info Length counts itself */
    }
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
}

/* An STA Info Length that places the STA Profile past the subelement's
 * own end. The posture read must be skipped entirely — and the
 * link_id/subelement checks shipped by slices 1-3 must behave exactly
 * as before, since this frame is well-formed at the chain level.
 *
 * What this test does NOT prove: that the `prof_off + 2 <= slen` bound
 * in mle_parse() is load-bearing. Removing that bound leaves this test
 * green and ASan quiet, because the resulting non-positive region
 * length is rejected by sta_profile_rsn()'s tiling check before any
 * dereference. Measured, not assumed (#104 slice 5). */
static void test_sta_info_len_past_subelement_end_is_safe(void) {
    uint8_t b[128];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    for (int k = 0; k < 2; k++) {
        b[n++] = 0;
        b[n++] = 3;
        uint16_t sc = (uint16_t)(k | 0x0010);
        b[n++] = (uint8_t)(sc & 0xff);
        b[n++] = (uint8_t)(sc >> 8);
        b[n++] = 200;            /* far beyond the 3-byte subelement */
    }
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
    ASSERT_EQ(m.malformed_subelem_len, 0);
    ASSERT_EQ(m.malformed_link_id, 0);
}

/* #126: sta_profile_rsn() holds the STA Profile's element chain to
 * tlv_exact(). The weaker link's profile below is well-formed except
 * for one trailing octet inside its subelement, so its chain does not
 * tile and its RSNE is not believed: one RSNE-bearing link, nothing to
 * compare, no downgrade. Without that octet the same pair fires (see
 * test_cross_link_cipher_and_pmf_downgrade_flagged).
 *
 * And it is not a parse fault: a non-tiling profile chain is the
 * expected reading of an association request's per-STA profile, whose
 * prefix differs from the beacon form, so tallying it would report a
 * fault on every well-formed Wi-Fi 7 association. Mutation-proved:
 * dropping the tiling test (`if (!found) return 0;`) fires the
 * downgrade here. */
static void test_untiled_sta_profile_is_not_read_and_not_a_fault(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, CIPH_GCMP256, 1, 1);
    const int weak = n;
    n = put_per_sta_profile(b, n, 1, CIPH_CCMP128, 0, 1);
    b[n++] = 0x00;           /* one octet past the RSNE ... */
    b[weak + 1]++;           /* ... inside the subelement's own length */
    sloth_mld_t m;
    sh_parse_fault_reset();
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_subelem_len, 0);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
    ASSERT_EQ(m.downgrade_cipher_mismatch, 0);
    ASSERT_EQ((int)sh_parse_fault_total(), 0);
}

/* A selector newer than IEEE 802.11-2020 Table 9-149 is ranked
 * "unknown", not "weak" — otherwise every cipher suite added after this
 * table was written becomes an alert on a conformant AP. */
static void test_unrecognised_cipher_suite_is_not_ranked_weak(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, 99, 1, 1);   /* not in the table */
    n = put_per_sta_profile(b, n, 1, CIPH_GCMP256, 1, 1);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
}

/* A frame that already tripped MLE_SUBELEM_OVERRUN is not read for
 * posture: the two profiles before the bad subelement do disagree, but
 * a chain whose declared lengths do not add up is not evidence we are
 * willing to draw a posture conclusion from. */
static void test_downgrade_not_claimed_on_an_overrunning_chain(void) {
    uint8_t b[256];
    int n = build_mle(b, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(b, n, 0, CIPH_GCMP256, 1, 1);
    n = put_per_sta_profile(b, n, 1, CIPH_CCMP128, 0, 1);
    b[n++] = 0;        /* a third subelement whose body runs past the end */
    b[n++] = 40;
    b[n++] = 0x00;
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(b, n, &m), 1);
    ASSERT_EQ(m.malformed_subelem_len, 1);
    ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
}

static void test_cross_link_downgrade_persists_across_clean_frames(void) {
    mle_clear();
    uint8_t bad[256];
    int n = build_mle(bad, MLE_TYPE_BASIC, 1, MLD, 0);
    n = put_per_sta_profile(bad, n, 0, CIPH_GCMP256, 1, 1);
    n = put_per_sta_profile(bad, n, 1, CIPH_CCMP128, 0, 1);
    sloth_mld_t m;
    ASSERT_EQ(mle_parse(bad, n, &m), 1);
    mle_observe(&m, 1000);

    uint8_t good[256];
    int g = build_mle(good, MLE_TYPE_BASIC, 1, MLD, 0);
    g = put_per_sta_profile(good, g, 0, CIPH_GCMP256, 1, 1);
    g = put_per_sta_profile(good, g, 1, CIPH_GCMP256, 1, 1);
    for (int i = 0; i < 2; i++) {
        ASSERT_EQ(mle_parse(good, g, &m), 1);
        ASSERT_EQ(m.cross_link_cipher_downgrade, 0);
        mle_observe(&m, 1001 + i);
    }

    sloth_state_t st;
    memset(&st, 0, sizeof(st));
    mle_snapshot(&st);
    ASSERT_EQ(st.mld_count, 1);
    ASSERT_EQ(st.mlds[0].cross_link_cipher_downgrade_total, 1);
    ASSERT_EQ(st.mlds[0].downgrade_link_id, 1);
    mle_clear();
}

void run_mle_tests(void) {
    TEST_SUITE("Multi-Link Element parse (#67)");
    RUN_TEST(test_basic_mle_yields_the_mld_mac);
    RUN_TEST(test_per_sta_profiles_yield_link_macs);
    RUN_TEST(test_common_info_length_is_how_link_info_is_found);
    RUN_TEST(test_non_basic_variants_rejected);
    RUN_TEST(test_mld_mac_absent_rejected);
    RUN_TEST(test_wrong_ext_id_rejected);
    RUN_TEST(test_group_addressed_mld_rejected);
    RUN_TEST(test_link_overflow_flagged);
    RUN_TEST(test_truncated_bodies_are_safe);

    TEST_SUITE("MLE malformed link_id — CVE-2026-58374 (#104)");
    RUN_TEST(test_link_id_15_flagged);
    RUN_TEST(test_link_id_14_is_the_valid_boundary);
    RUN_TEST(test_duplicate_link_id_flagged);
    RUN_TEST(test_distinct_link_ids_not_flagged);
    RUN_TEST(test_malformed_link_id_persists_across_clean_frames);

    TEST_SUITE("MLE malformed Common Info Length — CVE-2026-58374 class (#104 slice 2)");
    RUN_TEST(test_common_info_len_too_small_flagged);
    RUN_TEST(test_common_info_len_overruns_element_flagged);
    RUN_TEST(test_common_info_len_7_is_the_valid_floor);
    RUN_TEST(test_malformed_common_info_len_persists_across_clean_frames);

    TEST_SUITE("MLE subelement bounds overrun — CVE-2026-58374 class (#104 slice 3)");
    RUN_TEST(test_subelem_len_overruns_element_by_one_flagged);
    RUN_TEST(test_subelem_len_overruns_element_by_many_flagged);
    RUN_TEST(test_subelem_chain_sum_overrun_flagged);
    RUN_TEST(test_subelem_header_truncated_at_element_boundary_flagged);
    RUN_TEST(test_subelem_exact_fit_not_flagged);
    RUN_TEST(test_zero_length_subelement_not_flagged);
    RUN_TEST(test_malformed_subelem_len_persists_across_clean_frames);

    TEST_SUITE("MLD table and canonical identity (#67)");
    RUN_TEST(test_observe_and_canonical_lookup);
    RUN_TEST(test_links_merge_across_frames);
    RUN_TEST(test_repeat_observation_does_not_duplicate_links);

    TEST_SUITE("MLD MAC collision — IEEE 802.11be 9.4.2.312 (#104 slice 4)");
    RUN_TEST(test_conflicting_link_id_address_flags_collision);
    RUN_TEST(test_new_link_id_not_flagged_as_collision);
    RUN_TEST(test_repeated_same_binding_not_flagged_as_collision);
    RUN_TEST(test_mac_collision_persists_across_clean_frames);
    RUN_TEST(test_distinct_mlds_isolate_collision_counts);

    TEST_SUITE("MLE cross-link cipher/PMF downgrade — IEEE 802.11be 9.4.2.312 (#104 slice 5)");
    RUN_TEST(test_cross_link_cipher_and_pmf_downgrade_flagged);
    RUN_TEST(test_pmf_mismatch_alone_is_recorded_not_a_downgrade);
    RUN_TEST(test_conformant_tri_band_ap_does_not_fire);
    RUN_TEST(test_repeated_link_id_suppresses_the_posture_read);
    RUN_TEST(test_both_mismatches_keep_separate_link_pairs);
    RUN_TEST(test_cipher_strength_mismatch_alone_flagged);
    RUN_TEST(test_identical_per_link_rsne_not_flagged);
    RUN_TEST(test_link_without_an_rsne_inherits_and_is_not_flagged);
    RUN_TEST(test_partial_profile_not_read_for_posture);
    RUN_TEST(test_single_link_rsne_not_flagged);
    RUN_TEST(test_zero_length_sta_profile_not_flagged);
    RUN_TEST(test_sta_info_len_past_subelement_end_is_safe);
    RUN_TEST(test_untiled_sta_profile_is_not_read_and_not_a_fault);
    RUN_TEST(test_unrecognised_cipher_suite_is_not_ranked_weak);
    RUN_TEST(test_downgrade_not_claimed_on_an_overrunning_chain);
    RUN_TEST(test_cross_link_downgrade_persists_across_clean_frames);
}
