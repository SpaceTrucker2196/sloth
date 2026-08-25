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

    TEST_SUITE("MLD table and canonical identity (#67)");
    RUN_TEST(test_observe_and_canonical_lookup);
    RUN_TEST(test_links_merge_across_frames);
    RUN_TEST(test_repeat_observation_does_not_duplicate_links);
}
