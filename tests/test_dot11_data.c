#include <string.h>
#include "runner.h"
#include "dot11_data.h"
#include "frame_build.h"

/*
 * 802.11 data-frame payload location — issue #72.
 *
 * The header-length permutations are the whole test matrix, because
 * getting one wrong does not fail loudly: it produces a plausible
 * ethertype from payload bytes and feeds garbage to the IP decoder.
 *
 * Frame Control byte 0 = (subtype << 4) | (type << 2) | version.
 * Byte 1 carries the flags:
 *   bit 0 ToDS   bit 1 FromDS   bit 2 More Fragments
 *   bit 6 Protected              bit 7 +HTC/Order
 *
 * Bit 7 has two unrelated meanings (IEEE 802.11-2020 §9.2.4.1.10): in a
 * QoS data frame it means an HT Control field follows the QoS Control
 * field; in a NON-QoS data frame it is the StrictlyOrdered service
 * class and adds nothing to the header.
 */

#define FC1_TODS      0x01
#define FC1_FROMDS    0x02
#define FC1_MOREFRAG  0x04
#define FC1_PROTECTED 0x40
#define FC1_ORDER     0x80

/* Build a data frame with tests/frame_build.h (#122): `sub` selects the
 * subtype, `fc1` the flags, and the LLC/SNAP header plus four payload
 * bytes follow the header. `htc` states whether an HT Control field is
 * appended — the TEST says so, the builder never works it out from the
 * Order bit. The builder this replaced computed the header length with
 * the production formula (`if (order && qos) hdr += 4`), so it agreed
 * with the production bug for as long as the bug lived there and this
 * file asserted 28 for the StrictlyOrdered case until 2026-10-14. QoS
 * Control and Address 4 are likewise appended because the test's
 * subtype and flags say the frame has them, in clause order. Returns
 * the total length. */
static int build_data(uint8_t *f, int sub, uint8_t fc1, uint16_t ethertype,
                      int amsdu, int frag_num, int htc) {
    static const uint8_t a1[6] = {0x02, 0x00, 0x5e, 0x00, 0x00, 0x01};
    static const uint8_t a2[6] = {0x02, 0x00, 0x5e, 0x00, 0x00, 0x02};
    static const uint8_t a3[6] = {0x02, 0x00, 0x5e, 0x00, 0x00, 0x03};
    static const uint8_t a4[6] = {0x02, 0x00, 0x5e, 0x00, 0x00, 0x04};
    fb_t b; fb_init(&b, f, 128);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = (uint8_t)sub; h.flags = fc1;
    h.a1 = a1; h.a2 = a2; h.a3 = a3; h.a4 = a4;
    h.seq_ctl     = (uint16_t)(frag_num & 0x0f);
    h.a4_present  = (fc1 & FC1_TODS) && (fc1 & FC1_FROMDS);
    h.qos_present = (sub & 0x08) ? 1 : 0;
    h.qos         = amsdu ? 0x0080 : 0x0000;
    h.htc_present = htc;
    fb_dot11_hdr(&b, &h);
    fb_llc_snap(&b, ethertype);
    /* Four recognisable payload bytes so a wrong offset is visible. */
    fb_u8(&b, 0x45); fb_u8(&b, 0x00); fb_u8(&b, 0xde); fb_u8(&b, 0xad);
    return fb_ok(&b) ? b.len : -1;
}

/* Every permutation must find the same payload — that is the point. */
static void assert_finds_payload(uint8_t *f, int len, int expect_hdr) {
    int off = 0; uint16_t et = 0;
    ASSERT_EQ(dot11_data_payload(f, len, &off, &et), DOT11_DATA_OK);
    ASSERT_EQ(off, expect_hdr + 8);
    ASSERT_EQ((int)et, 0x0800);
    ASSERT_EQ((int)f[off], 0x45);      /* the payload, not a header byte */
}

static void test_base_header(void) {
    uint8_t f[128];
    int n = build_data(f, 0, 0, 0x0800, 0, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 24);
    assert_finds_payload(f, n, 24);
}

static void test_qos_adds_two(void) {
    uint8_t f[128];
    int n = build_data(f, 8, 0, 0x0800, 0, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 26);
    assert_finds_payload(f, n, 26);
}

static void test_four_address_adds_six(void) {
    uint8_t f[128];
    int n = build_data(f, 0, FC1_TODS | FC1_FROMDS, 0x0800, 0, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 30);
    assert_finds_payload(f, n, 30);
}

static void test_tods_alone_is_three_address(void) {
    /* Only *both* bits mean a fourth address. Adding six for either one
     * shifts every ordinary infrastructure frame. */
    uint8_t f[128];
    int n = build_data(f, 0, FC1_TODS, 0x0800, 0, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 24);
    assert_finds_payload(f, n, 24);
    n = build_data(f, 0, FC1_FROMDS, 0x0800, 0, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 24);
    assert_finds_payload(f, n, 24);
}

static void test_order_bit_adds_four(void) {
    /* QoS data frame: +HTC, so 24 + 2 (QoS Control) + 4 (HT Control). */
    uint8_t f[128];
    int n = build_data(f, 8, FC1_ORDER, 0x0800, 0, 0, 1);
    ASSERT_EQ(dot11_data_header_len(f, n), 30);
    assert_finds_payload(f, n, 30);
}

static void test_order_bit_adds_nothing_without_qos(void) {
    /* The same bit on a NON-QoS data frame is the StrictlyOrdered
       service class, not +HTC: IEEE 802.11-2020 §9.2.4.6 puts HT
       Control in QoS Data and Management frames only, and §9.2.4.1.10
       gives the bit its two meanings. No HT Control field follows, so
       the header is the plain 24.

       This file asserted 28 here until 2026-10-14, and the code agreed
       with it, so the suite was green on a shared wrong belief. It is a
       bit an attacker sets freely, and four bytes of skew put the LLC
       header inside the payload — which this file's own opening comment
       says "does not fail loudly: it produces a plausible ethertype
       from payload bytes and feeds garbage to the IP decoder". Found by
       reading the clause, not by fuzzing: every offset involved stays
       in bounds, so there is no memory error for a sanitiser to catch.
       See test_fragattack.c for the detector evasion it allowed. */
    uint8_t f[128];
    int n = build_data(f, 0, FC1_ORDER, 0x0800, 0, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 24);
    assert_finds_payload(f, n, 24);
}

static void test_order_bit_composes_with_four_address(void) {
    /* 24 + 6 (addr4) + 2 (QoS) + 4 (HTC) = 36 with QoS; without QoS the
       HT Control must drop out and leave 30, not 34. */
    uint8_t f[128];
    int n = build_data(f, 8, FC1_TODS | FC1_FROMDS | FC1_ORDER, 0x0800, 0, 0, 1);
    ASSERT_EQ(dot11_data_header_len(f, n), 36);
    assert_finds_payload(f, n, 36);
    n = build_data(f, 0, FC1_TODS | FC1_FROMDS | FC1_ORDER, 0x0800, 0, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 30);
    assert_finds_payload(f, n, 30);
}

static void test_all_modifiers_compose(void) {
    /* The case an additive bug hides in: 24 + 6 + 2 + 4 = 36. An
     * implementation treating the three as alternatives gets any single
     * modifier right and this one wrong. */
    uint8_t f[128];
    int n = build_data(f, 8, FC1_TODS | FC1_FROMDS | FC1_ORDER, 0x0800, 0, 0, 1);
    ASSERT_EQ(dot11_data_header_len(f, n), 36);
    assert_finds_payload(f, n, 36);
}

static void test_protected_frames_rejected(void) {
    /* Ciphertext. sloth does not crack and will not — and this is the
     * normal case on most networks, so it is its own status rather than
     * being lumped in with malformed. */
    uint8_t f[128];
    int n = build_data(f, 0, FC1_PROTECTED, 0x0800, 0, 0, 0);
    int off = 99; uint16_t et = 99;
    ASSERT_EQ(dot11_data_payload(f, n, &off, &et), DOT11_DATA_ENCRYPTED);
    ASSERT_EQ(off, 0);
    ASSERT_EQ((int)et, 0);
}

static void test_null_function_has_no_payload(void) {
    /* Subtype bit 2 means the frame carries no body — it exists to move
     * power-management state. Parsing one reads whatever follows the
     * header, which is the FCS. */
    uint8_t f[128];
    int n = build_data(f, 4, 0, 0x0800, 0, 0, 0);
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_NO_PAYLOAD);
    n = build_data(f, 12, 0, 0x0800, 0, 0, 0);      /* QoS Null */
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_NO_PAYLOAD);
}

static void test_continuation_fragment_rejected(void) {
    /* A fragment other than the first carries no LLC header of its own;
     * its first bytes are the middle of a packet. */
    uint8_t f[128];
    int n = build_data(f, 0, 0, 0x0800, 0, 1, 0);
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_FRAGMENT);
}

static void test_more_fragments_rejected(void) {
    uint8_t f[128];
    int n = build_data(f, 0, FC1_MOREFRAG, 0x0800, 0, 0, 0);
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_FRAGMENT);
}

static void test_amsdu_detected_not_misparsed(void) {
    /* An A-MSDU body is several subframes each with their own header,
     * not one LLC-encapsulated packet. Reading it as the latter yields
     * a valid-looking but wrong packet. */
    uint8_t f[128];
    int n = build_data(f, 8, 0, 0x0800, 1 /* A-MSDU */, 0, 0);
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_AMSDU);
}

static void test_amsdu_bit_read_at_the_right_offset(void) {
    /* The QoS Control field moves when a fourth address is present. A
     * fixed offset reads a payload byte instead and either invents an
     * A-MSDU or misses one. */
    uint8_t f[128];
    int n = build_data(f, 8, FC1_TODS | FC1_FROMDS, 0x0800, 1, 0, 0);
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_AMSDU);
}

static void test_non_snap_llc_rejected(void) {
    /* Bare LLC — IPX, NetBIOS over 802.2 — has no ethertype where SNAP
     * puts one. Reading it as SNAP invents a protocol. */
    uint8_t f[128];
    int n = build_data(f, 0, 0, 0x0800, 0, 0, 0);
    f[24] = 0xe0; f[25] = 0xe0;              /* IPX over bare LLC */
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_NOT_SNAP);
}

static void test_ipv6_ethertype_passes_through(void) {
    uint8_t f[128];
    int n = build_data(f, 0, 0, 0x86dd, 0, 0, 0);
    int off = 0; uint16_t et = 0;
    ASSERT_EQ(dot11_data_payload(f, n, &off, &et), DOT11_DATA_OK);
    ASSERT_EQ((int)et, 0x86dd);
}

static void test_management_and_control_rejected(void) {
    uint8_t f[128];
    int n = build_data(f, 8, 0, 0x0800, 0, 0, 0);
    f[0] = 0x80;                              /* beacon */
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_NOT_DATA);
    f[0] = 0xb4;                              /* RTS */
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_NOT_DATA);
}

static void test_truncation_at_every_boundary(void) {
    /* Mid-header, mid-LLC, and mid-ethertype. None may read past the
     * buffer or report a payload that is not there. */
    uint8_t f[128];
    int n = build_data(f, 8, FC1_TODS | FC1_FROMDS | FC1_ORDER, 0x0800, 0, 0, 1);
    for (int cut = 1; cut < n; cut++) {
        int off = -1; uint16_t et = 0;
        int rc = dot11_data_payload(f, cut, &off, &et);
        if (rc == DOT11_DATA_OK) {
            /* If it claims success the payload must be inside the
             * buffer we actually gave it. */
            ASSERT(off <= cut);
        } else {
            ASSERT(off == 0);
        }
    }
    ASSERT_EQ(dot11_data_header_len(f, 10), -1);
}

/* ── dot11_data_tid (#75 slice 2) ───────────────────────────────────── */

static void test_non_qos_tid_is_zero(void) {
    uint8_t f[128];
    int n = build_data(f, 0, 0, 0x0800, 0, 0, 0);
    ASSERT_EQ(dot11_data_tid(f, n), 0);
}

static void test_qos_tid_is_the_low_nibble(void) {
    uint8_t f[128];
    int n = build_data(f, 8, 0, 0x0800, 0, 0, 0);
    f[24] = 0x05;                          /* TID 5, A-MSDU bit clear */
    ASSERT_EQ(dot11_data_tid(f, n), 5);
}

static void test_qos_tid_moves_with_addr4(void) {
    /* Same trap as the A-MSDU bit: a fixed offset reads into the
     * address field on a WDS/mesh frame instead of QoS Control. */
    uint8_t f[128];
    int n = build_data(f, 8, FC1_TODS | FC1_FROMDS, 0x0800, 0, 0, 0);
    f[24] = 0xff;                          /* not QoS Control here */
    f[30] = 0x07;                          /* the real QoS Control byte */
    ASSERT_EQ(dot11_data_tid(f, n), 7);
}

static void test_tid_rejects_non_data_and_short(void) {
    uint8_t f[128];
    int n = build_data(f, 8, 0, 0x0800, 0, 0, 0);
    f[0] = 0x80;                           /* beacon */
    ASSERT_EQ(dot11_data_tid(f, n), -1);
    f[0] = (uint8_t)((8 << 4) | (2 << 2)); /* QoS data again */
    ASSERT_EQ(dot11_data_tid(f, 24), -1);  /* too short for QoS Control */
    ASSERT_EQ(dot11_data_tid(NULL, n), -1);
}

void run_dot11_data_tests(void) {
    TEST_SUITE("802.11 data-frame header length (#72)");
    RUN_TEST(test_base_header);
    RUN_TEST(test_qos_adds_two);
    RUN_TEST(test_four_address_adds_six);
    RUN_TEST(test_tods_alone_is_three_address);
    RUN_TEST(test_order_bit_adds_four);
    RUN_TEST(test_order_bit_adds_nothing_without_qos);
    RUN_TEST(test_order_bit_composes_with_four_address);
    RUN_TEST(test_all_modifiers_compose);

    TEST_SUITE("802.11 data-frame payload location (#72)");
    RUN_TEST(test_protected_frames_rejected);
    RUN_TEST(test_null_function_has_no_payload);
    RUN_TEST(test_continuation_fragment_rejected);
    RUN_TEST(test_more_fragments_rejected);
    RUN_TEST(test_amsdu_detected_not_misparsed);
    RUN_TEST(test_amsdu_bit_read_at_the_right_offset);
    RUN_TEST(test_non_snap_llc_rejected);
    RUN_TEST(test_ipv6_ethertype_passes_through);
    RUN_TEST(test_management_and_control_rejected);
    RUN_TEST(test_truncation_at_every_boundary);

    TEST_SUITE("802.11 QoS TID (#75 slice 2)");
    RUN_TEST(test_non_qos_tid_is_zero);
    RUN_TEST(test_qos_tid_is_the_low_nibble);
    RUN_TEST(test_qos_tid_moves_with_addr4);
    RUN_TEST(test_tid_rejects_non_data_and_short);
}
