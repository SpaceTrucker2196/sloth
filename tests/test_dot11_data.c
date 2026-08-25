#include <string.h>
#include "runner.h"
#include "dot11_data.h"

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
 *   bit 6 Protected              bit 7 Order (HT Control present)
 */

#define FC1_TODS      0x01
#define FC1_FROMDS    0x02
#define FC1_MOREFRAG  0x04
#define FC1_PROTECTED 0x40
#define FC1_ORDER     0x80

/* Build a data frame: `sub` selects QoS via bit 3, `fc1` the flags, and
 * the LLC/SNAP header plus four payload bytes go at the computed
 * offset. Returns the total length. */
static int build_data(uint8_t *f, int sub, uint8_t fc1, uint16_t ethertype,
                      int amsdu, int frag_num) {
    memset(f, 0, 128);
    f[0] = (uint8_t)((sub << 4) | (2 << 2));
    f[1] = fc1;
    /* Sequence Control at 22-23: fragment number in the low nibble. */
    f[22] = (uint8_t)(frag_num & 0x0f);

    int hdr = 24;
    if ((fc1 & FC1_TODS) && (fc1 & FC1_FROMDS)) hdr += 6;
    if (sub & 0x08) {
        int qos_off = 24 + (((fc1 & FC1_TODS) && (fc1 & FC1_FROMDS)) ? 6 : 0);
        if (amsdu) f[qos_off] = 0x80;
        hdr += 2;
    }
    if (fc1 & FC1_ORDER) hdr += 4;

    f[hdr + 0] = 0xaa; f[hdr + 1] = 0xaa; f[hdr + 2] = 0x03;
    f[hdr + 3] = 0x00; f[hdr + 4] = 0x00; f[hdr + 5] = 0x00;
    f[hdr + 6] = (uint8_t)(ethertype >> 8);
    f[hdr + 7] = (uint8_t)(ethertype & 0xff);
    /* Four recognisable payload bytes so a wrong offset is visible. */
    f[hdr + 8] = 0x45; f[hdr + 9] = 0x00;
    f[hdr + 10] = 0xde; f[hdr + 11] = 0xad;
    return hdr + 12;
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
    int n = build_data(f, 0, 0, 0x0800, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 24);
    assert_finds_payload(f, n, 24);
}

static void test_qos_adds_two(void) {
    uint8_t f[128];
    int n = build_data(f, 8, 0, 0x0800, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 26);
    assert_finds_payload(f, n, 26);
}

static void test_four_address_adds_six(void) {
    uint8_t f[128];
    int n = build_data(f, 0, FC1_TODS | FC1_FROMDS, 0x0800, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 30);
    assert_finds_payload(f, n, 30);
}

static void test_tods_alone_is_three_address(void) {
    /* Only *both* bits mean a fourth address. Adding six for either one
     * shifts every ordinary infrastructure frame. */
    uint8_t f[128];
    int n = build_data(f, 0, FC1_TODS, 0x0800, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 24);
    assert_finds_payload(f, n, 24);
    n = build_data(f, 0, FC1_FROMDS, 0x0800, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 24);
    assert_finds_payload(f, n, 24);
}

static void test_order_bit_adds_four(void) {
    uint8_t f[128];
    int n = build_data(f, 0, FC1_ORDER, 0x0800, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 28);
    assert_finds_payload(f, n, 28);
}

static void test_all_modifiers_compose(void) {
    /* The case an additive bug hides in: 24 + 6 + 2 + 4 = 36. An
     * implementation treating the three as alternatives gets any single
     * modifier right and this one wrong. */
    uint8_t f[128];
    int n = build_data(f, 8, FC1_TODS | FC1_FROMDS | FC1_ORDER, 0x0800, 0, 0);
    ASSERT_EQ(dot11_data_header_len(f, n), 36);
    assert_finds_payload(f, n, 36);
}

static void test_protected_frames_rejected(void) {
    /* Ciphertext. sloth does not crack and will not — and this is the
     * normal case on most networks, so it is its own status rather than
     * being lumped in with malformed. */
    uint8_t f[128];
    int n = build_data(f, 0, FC1_PROTECTED, 0x0800, 0, 0);
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
    int n = build_data(f, 4, 0, 0x0800, 0, 0);
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_NO_PAYLOAD);
    n = build_data(f, 12, 0, 0x0800, 0, 0);      /* QoS Null */
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_NO_PAYLOAD);
}

static void test_continuation_fragment_rejected(void) {
    /* A fragment other than the first carries no LLC header of its own;
     * its first bytes are the middle of a packet. */
    uint8_t f[128];
    int n = build_data(f, 0, 0, 0x0800, 0, 1);
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_FRAGMENT);
}

static void test_more_fragments_rejected(void) {
    uint8_t f[128];
    int n = build_data(f, 0, FC1_MOREFRAG, 0x0800, 0, 0);
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_FRAGMENT);
}

static void test_amsdu_detected_not_misparsed(void) {
    /* An A-MSDU body is several subframes each with their own header,
     * not one LLC-encapsulated packet. Reading it as the latter yields
     * a valid-looking but wrong packet. */
    uint8_t f[128];
    int n = build_data(f, 8, 0, 0x0800, 1 /* A-MSDU */, 0);
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_AMSDU);
}

static void test_amsdu_bit_read_at_the_right_offset(void) {
    /* The QoS Control field moves when a fourth address is present. A
     * fixed offset reads a payload byte instead and either invents an
     * A-MSDU or misses one. */
    uint8_t f[128];
    int n = build_data(f, 8, FC1_TODS | FC1_FROMDS, 0x0800, 1, 0);
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_AMSDU);
}

static void test_non_snap_llc_rejected(void) {
    /* Bare LLC — IPX, NetBIOS over 802.2 — has no ethertype where SNAP
     * puts one. Reading it as SNAP invents a protocol. */
    uint8_t f[128];
    int n = build_data(f, 0, 0, 0x0800, 0, 0);
    f[24] = 0xe0; f[25] = 0xe0;              /* IPX over bare LLC */
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_NOT_SNAP);
}

static void test_ipv6_ethertype_passes_through(void) {
    uint8_t f[128];
    int n = build_data(f, 0, 0, 0x86dd, 0, 0);
    int off = 0; uint16_t et = 0;
    ASSERT_EQ(dot11_data_payload(f, n, &off, &et), DOT11_DATA_OK);
    ASSERT_EQ((int)et, 0x86dd);
}

static void test_management_and_control_rejected(void) {
    uint8_t f[128];
    int n = build_data(f, 8, 0, 0x0800, 0, 0);
    f[0] = 0x80;                              /* beacon */
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_NOT_DATA);
    f[0] = 0xb4;                              /* RTS */
    ASSERT_EQ(dot11_data_payload(f, n, NULL, NULL), DOT11_DATA_NOT_DATA);
}

static void test_truncation_at_every_boundary(void) {
    /* Mid-header, mid-LLC, and mid-ethertype. None may read past the
     * buffer or report a payload that is not there. */
    uint8_t f[128];
    int n = build_data(f, 8, FC1_TODS | FC1_FROMDS | FC1_ORDER, 0x0800, 0, 0);
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

void run_dot11_data_tests(void) {
    TEST_SUITE("802.11 data-frame header length (#72)");
    RUN_TEST(test_base_header);
    RUN_TEST(test_qos_adds_two);
    RUN_TEST(test_four_address_adds_six);
    RUN_TEST(test_tods_alone_is_three_address);
    RUN_TEST(test_order_bit_adds_four);
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
}
