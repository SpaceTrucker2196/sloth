#include <string.h>
#include "runner.h"
#include "mle.h"

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
}
