#include <string.h>
#include "runner.h"
#include "dot11_frame.h"
#include "dot11_data.h"
#include "frame_build.h"

/*
 * The one-decode 802.11 frame view — issue #122.
 *
 * Frames are built with tests/frame_build.h, which appends HT Control
 * only when the test says `htc_present`, so these cases are a check on
 * the §9.2.4.1.10 rule rather than a copy of it. Every MAC below is
 * locally administered (second-nibble 2) and no SSID names a real
 * site.
 */

static const uint8_t M_AP [6] = {0x02, 0x00, 0x5e, 0x00, 0x00, 0x01};
static const uint8_t M_STA[6] = {0x02, 0x00, 0x5e, 0x00, 0x00, 0x02};
static const uint8_t M_DA [6] = {0x02, 0x00, 0x5e, 0x00, 0x00, 0x03};
static const uint8_t M_SA [6] = {0x02, 0x00, 0x5e, 0x00, 0x00, 0x04};

/* A data frame with the stated additions and an LLC/SNAP IPv4 body.
 * `order` sets the Frame Control bit; `htc` appends the field. Keeping
 * the two separate is the whole point of the builder. */
static int data_frame(uint8_t *buf, int cap, int qos, int a4, int order,
                      int htc, uint8_t extra_flags, uint16_t seq_ctl) {
    fb_t b; fb_init(&b, buf, cap);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = qos ? 8 : 0;
    h.flags = (uint8_t)(extra_flags | (order ? FB_ORDER : 0) |
                        (a4 ? (FB_TODS | FB_FROMDS) : 0));
    h.a1 = M_DA; h.a2 = M_SA; h.a3 = M_AP; h.a4 = M_STA;
    h.seq_ctl = seq_ctl;
    h.a4_present = a4; h.qos_present = qos; h.htc_present = htc;
    fb_dot11_hdr(&b, &h);
    fb_llc_snap(&b, 0x0800);
    fb_u8(&b, 0x45); fb_u8(&b, 0x00); fb_u8(&b, 0xde); fb_u8(&b, 0xad);
    return fb_ok(&b) ? b.len : -1;
}

/* ── Header length: the view and the wrappers must agree ──────────── */

static void test_header_length_table(void) {
    /* The eight combinations the issue names, as a literal table. The
     * expected lengths come from §9.2.4.1 Figure 9-1, not from the
     * code: 24 base, +6 Address 4, +2 QoS Control, +4 HT Control, and
     * HT Control only where the clause puts it. */
    struct { int qos, a4, order, htc, expect; } tbl[] = {
        { 0, 0, 0, 0, 24 },
        { 1, 0, 0, 0, 26 },
        { 0, 1, 0, 0, 30 },
        { 1, 1, 0, 0, 32 },
        { 1, 0, 1, 1, 30 },   /* QoS + HTC */
        { 1, 1, 1, 1, 36 },   /* QoS + A4 + HTC */
        { 0, 0, 1, 0, 24 },   /* non-QoS + Order = StrictlyOrdered */
        { 0, 1, 1, 0, 30 },   /* non-QoS + A4 + Order: no HTC either */
    };
    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        uint8_t f[128];
        int n = data_frame(f, sizeof f, tbl[i].qos, tbl[i].a4,
                           tbl[i].order, tbl[i].htc, 0, 0);
        ASSERT(n > 0);
        dot11_frame_t v;
        ASSERT_EQ(dot11_frame_decode(f, n, NULL, &v), 1);
        ASSERT_EQ(v.hdr_len, tbl[i].expect);
        ASSERT_EQ(v.body_off, tbl[i].expect);
        ASSERT_EQ(v.has_htc, tbl[i].htc);
        ASSERT_EQ(dot11_data_header_len(f, n), tbl[i].expect);
        /* And the payload is found exactly where the builder put it. */
        int off = 0; uint16_t et = 0;
        ASSERT_EQ(dot11_frame_payload(&v, &off, &et), DOT11_DATA_OK);
        ASSERT_EQ(off, tbl[i].expect + 8);
        ASSERT_EQ((int)et, 0x0800);
        ASSERT_EQ((int)f[off], 0x45);
    }
    /* Management: 24, or 28 with HT Control. */
    uint8_t m[64];
    fb_t b; fb_init(&b, m, sizeof m);
    fb_mgmt(&b, 8, 0, M_DA, M_AP, M_AP, 0x0010, 0);
    fb_beacon_fixed(&b, 0, 100, 0x0411);
    dot11_frame_t v;
    ASSERT_EQ(dot11_frame_decode(m, b.len, NULL, &v), 1);
    ASSERT_EQ(v.hdr_len, 24);
    ASSERT_EQ(dot11_mgmt_hdr_len(m, b.len), 24);
    fb_init(&b, m, sizeof m);
    fb_mgmt(&b, 8, FB_ORDER, M_DA, M_AP, M_AP, 0x0010, 1);
    fb_beacon_fixed(&b, 0, 100, 0x0411);
    ASSERT_EQ(dot11_frame_decode(m, b.len, NULL, &v), 1);
    ASSERT_EQ(v.hdr_len, 28);
    ASSERT_EQ(v.has_htc, 1);
    ASSERT_EQ(dot11_mgmt_hdr_len(m, b.len), 28);
    ASSERT_EQ(v.body_len, 12);
}

/* ── Roles ────────────────────────────────────────────────────────── */

static void test_management_roles(void) {
    uint8_t m[64];
    fb_t b; fb_init(&b, m, sizeof m);
    fb_mgmt(&b, 5, 0, M_STA, M_AP, M_AP, (uint16_t)((0x0abc << 4) | 0), 0);
    dot11_frame_t v;
    ASSERT_EQ(dot11_frame_decode(m, b.len, NULL, &v), 1);
    ASSERT_EQ(v.type, 0); ASSERT_EQ(v.subtype, 5);
    ASSERT(v.da == v.a1 && memcmp(v.da, M_STA, 6) == 0);
    ASSERT(v.sa == v.a2 && memcmp(v.sa, M_AP, 6) == 0);
    ASSERT(v.bssid == v.a3);
    ASSERT(v.ra == v.a1 && v.ta == v.a2);
    ASSERT(v.a4 == NULL);
    ASSERT_EQ(v.seq_num, 0x0abc);
    ASSERT_EQ(v.frag_num, 0);
    ASSERT_EQ(v.tid, -1);
    ASSERT_EQ(v.amsdu, -1);
}

static void test_control_frame_roles_are_ra_ta_only(void) {
    uint8_t f[32];
    fb_t b;
    /* RTS (subtype 11): RA + TA, 16 octets, no Sequence Control. */
    fb_init(&b, f, sizeof f);
    fb_ctrl_hdr(&b, 11, 0, 0x00f0, M_STA, M_AP);
    dot11_frame_t v;
    ASSERT_EQ(dot11_frame_decode(f, b.len, NULL, &v), 1);
    ASSERT_EQ(v.type, 1);
    ASSERT_EQ(v.hdr_len, 16);
    ASSERT(v.ra && memcmp(v.ra, M_STA, 6) == 0);
    ASSERT(v.ta && memcmp(v.ta, M_AP, 6) == 0);
    ASSERT(v.bssid == NULL);
    ASSERT(v.sa == NULL && v.da == NULL && v.a3 == NULL);
    ASSERT_EQ(v.seq_num, -1);
    ASSERT_EQ(v.frag_num, -1);
    /* ACK (13): RA only, 10 octets. */
    fb_init(&b, f, sizeof f);
    fb_ctrl_hdr(&b, 13, 0, 0, M_STA, NULL);
    ASSERT_EQ(b.len, 10);
    ASSERT_EQ(dot11_frame_decode(f, b.len, NULL, &v), 1);
    ASSERT_EQ(v.hdr_len, 10);
    ASSERT(v.ra != NULL);
    ASSERT(v.ta == NULL);
    /* An ACK followed by junk does not grow a TA out of the junk. */
    fb_bad_bytes(&b, 8);
    ASSERT_EQ(dot11_frame_decode(f, b.len, NULL, &v), 1);
    ASSERT(v.ta == NULL);
    ASSERT_EQ(v.hdr_len, 10);
    /* A CTS cut to 9 octets is a runt. */
    fb_init(&b, f, sizeof f);
    fb_ctrl_hdr(&b, 12, 0, 0, M_STA, NULL);
    ASSERT_EQ(dot11_frame_decode(f, 9, NULL, &v), 0);
    ASSERT_EQ(v.hdr_len, -1);
    /* Payload on a control frame is NOT_DATA, never a guess. */
    ASSERT_EQ(dot11_frame_payload(&v, NULL, NULL), DOT11_DATA_NOT_DATA);
}

static void test_data_roles_follow_table_9_26(void) {
    uint8_t f[128];
    dot11_frame_t v;
    /* IBSS: DA SA BSSID. */
    int n = data_frame(f, sizeof f, 0, 0, 0, 0, 0, 0);
    ASSERT_EQ(dot11_frame_decode(f, n, NULL, &v), 1);
    ASSERT(v.da == v.a1 && v.sa == v.a2 && v.bssid == v.a3);
    /* FromDS: DA BSSID SA. */
    n = data_frame(f, sizeof f, 0, 0, 0, 0, FB_FROMDS, 0);
    ASSERT_EQ(dot11_frame_decode(f, n, NULL, &v), 1);
    ASSERT(v.da == v.a1 && v.bssid == v.a2 && v.sa == v.a3);
    /* ToDS: BSSID SA DA. */
    n = data_frame(f, sizeof f, 0, 0, 0, 0, FB_TODS, 0);
    ASSERT_EQ(dot11_frame_decode(f, n, NULL, &v), 1);
    ASSERT(v.bssid == v.a1 && v.sa == v.a2 && v.da == v.a3);
    /* RA/TA are positional in every row. */
    ASSERT(v.ra == v.a1 && v.ta == v.a2);
}

static void test_wds_has_no_bssid_and_sa_is_a4(void) {
    uint8_t f[128];
    int n = data_frame(f, sizeof f, 1, 1, 0, 0, 0, 0);
    dot11_frame_t v;
    ASSERT_EQ(dot11_frame_decode(f, n, NULL, &v), 1);
    ASSERT_EQ(v.has_addr4, 1);
    ASSERT(v.a4 == f + 24);
    ASSERT(v.sa == v.a4 && memcmp(v.sa, M_STA, 6) == 0);
    ASSERT(v.da == v.a3);
    ASSERT(v.bssid == NULL);
    ASSERT(v.ra == v.a1 && v.ta == v.a2);
    /* The wrapper reports the same absence. */
    uint8_t bssid[6] = {1,1,1,1,1,1}, sa[6], da[6];
    ASSERT_EQ(dot11_data_addrs(f, n, bssid, sa, da), DOT11_ADDRS_NO_BSSID);
    ASSERT_EQ(memcmp(sa, M_STA, 6), 0);
    ASSERT_EQ(memcmp(da, M_AP, 6), 0);
    ASSERT_EQ(bssid[0], 1);              /* not written */
}

/* ── Refusals ─────────────────────────────────────────────────────── */

static void test_protected_body_is_refused(void) {
    uint8_t f[128];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = 8; h.flags = FB_FROMDS | FB_PROTECTED;
    h.a1 = M_STA; h.a2 = M_AP; h.a3 = M_SA; h.qos_present = 1;
    fb_dot11_hdr(&b, &h);
    fb_ccmp_hdr(&b, 0x0000a1b2c3d4ull, 0);
    fb_ciphertext(&b, 24);
    dot11_frame_t v;
    ASSERT_EQ(dot11_frame_decode(f, b.len, NULL, &v), 1);
    ASSERT_EQ(v.protected_, 1);
    const uint8_t *body = (const uint8_t *)1; int blen = 7;
    ASSERT_EQ(dot11_frame_body(&v, &body, &blen), 0);
    ASSERT(body == NULL);
    ASSERT_EQ(blen, 0);
    int off = 5; uint16_t et = 5;
    ASSERT_EQ(dot11_frame_payload(&v, &off, &et), DOT11_DATA_ENCRYPTED);
    ASSERT_EQ(off, 0);
    ASSERT_EQ((int)et, 0);
    /* The plaintext CCMP header is still readable through the wrapper,
     * in the §12.5.3.2 octet order. */
    ASSERT(dot11_ccmp_pn(f, b.len) == (int64_t)0x0000a1b2c3d4ll);
}

static void test_runt_reports_no_header(void) {
    uint8_t f[128];
    int n = data_frame(f, sizeof f, 1, 1, 1, 1, 0, 0);   /* needs 36 */
    dot11_frame_t v;
    for (int cut = 0; cut < 36; cut++) {
        ASSERT_EQ(dot11_frame_decode(f, cut, NULL, &v), 0);
        ASSERT_EQ(v.hdr_len, -1);
        ASSERT_EQ(v.body_off, -1);
        ASSERT_EQ(v.body_len, 0);
        const uint8_t *body; int blen;
        ASSERT_EQ(dot11_frame_body(&v, &body, &blen), 0);
        ASSERT(dot11_frame_payload(&v, NULL, NULL) != DOT11_DATA_OK);
    }
    ASSERT_EQ(dot11_frame_decode(f, 36, NULL, &v), 1);
    ASSERT_EQ(v.hdr_len, 36);
    ASSERT_EQ(dot11_frame_decode(f, n, NULL, &v), 1);
    /* What a runt still tells you: type, flags, the addresses it has. */
    ASSERT_EQ(dot11_frame_decode(f, 10, NULL, &v), 0);
    ASSERT_EQ(v.type, 2);
    ASSERT_EQ(v.has_qos, 1);
    ASSERT(v.a1 != NULL && v.a2 == NULL);
    ASSERT_EQ(dot11_frame_decode(f, 23, NULL, &v), 0);
    ASSERT(v.a3 != NULL);
    ASSERT_EQ(v.seq_num, -1);
    /* NULL and sub-FC inputs. */
    ASSERT_EQ(dot11_frame_decode(NULL, 64, NULL, &v), 0);
    ASSERT_EQ(v.hdr_len, -1);
    ASSERT_EQ(dot11_frame_decode(f, 1, NULL, &v), 0);
    ASSERT_EQ(dot11_frame_decode(f, 0, NULL, &v), 0);
    ASSERT_EQ(dot11_frame_decode(f, -4, NULL, &v), 0);
    ASSERT_EQ(v.len, 0);
    ASSERT_EQ(dot11_frame_decode(f, n, NULL, NULL), 0);
}

static void test_extension_frames_are_not_decoded(void) {
    uint8_t f[32];
    memset(f, 0, sizeof f);
    f[0] = (uint8_t)(3 << 2);                     /* type 3 */
    dot11_frame_t v;
    ASSERT_EQ(dot11_frame_decode(f, sizeof f, NULL, &v), 0);
    ASSERT_EQ(v.type, 3);
    ASSERT_EQ(v.hdr_len, -1);
    ASSERT(v.a1 == f + 4);               /* loggable */
    ASSERT(v.a2 == NULL && v.a3 == NULL && v.bssid == NULL);
    ASSERT_EQ(v.seq_num, -1);
}

/* ── Payload status codes over the view ───────────────────────────── */

static void test_payload_status_codes(void) {
    uint8_t f[128];
    dot11_frame_t v;
    int n;

    n = data_frame(f, sizeof f, 0, 0, 0, 0, 0, 0x0001);     /* frag 1 */
    dot11_frame_decode(f, n, NULL, &v);
    ASSERT_EQ(v.frag_num, 1);
    ASSERT_EQ(dot11_frame_payload(&v, NULL, NULL), DOT11_DATA_FRAGMENT);

    n = data_frame(f, sizeof f, 0, 0, 0, 0, FB_MOREFRAG, 0);
    dot11_frame_decode(f, n, NULL, &v);
    ASSERT_EQ(dot11_frame_payload(&v, NULL, NULL), DOT11_DATA_FRAGMENT);

    /* QoS Null: no body. */
    fb_t b; fb_init(&b, f, sizeof f);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = 12; h.a1 = M_DA; h.a2 = M_SA; h.a3 = M_AP;
    h.qos_present = 1;
    fb_dot11_hdr(&b, &h);
    dot11_frame_decode(f, b.len, NULL, &v);
    ASSERT_EQ(dot11_frame_payload(&v, NULL, NULL), DOT11_DATA_NO_PAYLOAD);

    /* A-MSDU: QoS Control bit 7, body is subframes. */
    fb_init(&b, f, sizeof f);
    memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = 8; h.a1 = M_DA; h.a2 = M_SA; h.a3 = M_AP;
    h.qos_present = 1; h.qos = 0x0085;            /* TID 5, A-MSDU */
    fb_dot11_hdr(&b, &h);
    static const uint8_t msdu[10] = {0xaa,0xaa,0x03,0,0,0,0x08,0x00,0x45,0x00};
    fb_amsdu_subframe(&b, M_DA, M_SA, msdu, sizeof msdu);
    dot11_frame_decode(f, b.len, NULL, &v);
    ASSERT_EQ(v.tid, 5);
    ASSERT_EQ(v.amsdu, 1);
    ASSERT_EQ(dot11_frame_payload(&v, NULL, NULL), DOT11_DATA_AMSDU);

    /* Bare LLC. */
    n = data_frame(f, sizeof f, 0, 0, 0, 0, 0, 0);
    f[24] = 0xe0; f[25] = 0xe0;
    dot11_frame_decode(f, n, NULL, &v);
    ASSERT_EQ(dot11_frame_payload(&v, NULL, NULL), DOT11_DATA_NOT_SNAP);

    /* Header complete, LLC cut short. */
    n = data_frame(f, sizeof f, 0, 0, 0, 0, 0, 0);
    dot11_frame_decode(f, 24 + 7, NULL, &v);
    ASSERT_EQ(v.hdr_len, 24);
    int off = 3;
    ASSERT_EQ(dot11_frame_payload(&v, &off, NULL), DOT11_DATA_TRUNCATED);
    ASSERT_EQ(off, 0);

    /* Not a data frame. */
    fb_init(&b, f, sizeof f);
    fb_mgmt(&b, 8, 0, M_DA, M_AP, M_AP, 0, 0);
    fb_llc_snap(&b, 0x0800);
    dot11_frame_decode(f, b.len, NULL, &v);
    ASSERT_EQ(dot11_frame_payload(&v, NULL, NULL), DOT11_DATA_NOT_DATA);
    ASSERT_EQ(dot11_frame_payload(NULL, NULL, NULL), DOT11_DATA_TRUNCATED);
}

/* ── Radiotap hints: FCS and DATAPAD ──────────────────────────────── */

static void test_fcs_strip_length(void) {
    ASSERT_EQ(dot11_fcs_strip_len(100, 100, 1), 4);
    ASSERT_EQ(dot11_fcs_strip_len(100, 100, 0), 0);
    ASSERT_EQ(dot11_fcs_strip_len( 98, 100, 1), 2);   /* two FCS octets lost */
    ASSERT_EQ(dot11_fcs_strip_len( 96, 100, 1), 0);   /* whole FCS lost */
    ASSERT_EQ(dot11_fcs_strip_len( 40, 100, 1), 0);
    ASSERT_EQ(dot11_fcs_strip_len(100,  90, 1), 4);   /* nonsense: treated as untruncated */
}

static void test_fcs_is_not_part_of_the_body(void) {
    /* A frame delivered with its FCS: the caller strips, the view
     * records that it did, and the body length excludes the trailer. */
    uint8_t f[128];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = 0; h.flags = FB_FROMDS;
    h.a1 = M_STA; h.a2 = M_AP; h.a3 = M_SA;
    fb_dot11_hdr(&b, &h);
    fb_llc_snap(&b, 0x0800);
    fb_u8(&b, 0x45); fb_u8(&b, 0x00);
    int mpdu = b.len;
    fb_fcs(&b);
    ASSERT_EQ(b.len, mpdu + 4);

    dot11_rt_hints_t rt = { 1, 0, 0 };
    int strip = dot11_fcs_strip_len(b.len, b.len, rt.fcs_present);
    dot11_frame_t v;
    ASSERT_EQ(dot11_frame_decode(f, b.len - strip, &rt, &v), 1);
    ASSERT_EQ(v.len, mpdu);
    ASSERT_EQ(v.fcs_stripped, 1);
    ASSERT_EQ(v.bad_fcs, 0);
    ASSERT_EQ(v.body_len, 10);
    const uint8_t *body; int blen;
    ASSERT_EQ(dot11_frame_body(&v, &body, &blen), 1);
    ASSERT(body == f + 24);
    ASSERT_EQ(blen, 10);

    rt.bad_fcs = 1;
    dot11_frame_decode(f, b.len - strip, &rt, &v);
    ASSERT_EQ(v.bad_fcs, 1);
}

static void test_datapad_rounds_the_body_to_four(void) {
    /* RT_F_DATAPAD: the driver padded the MAC header to a 4-octet
     * boundary. A 26-octet QoS header puts the body at 28; a 24-octet
     * header is already aligned and moves nowhere. */
    uint8_t f[128];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = 8; h.flags = FB_TODS;
    h.a1 = M_AP; h.a2 = M_STA; h.a3 = M_DA; h.qos_present = 1;
    fb_dot11_hdr(&b, &h);
    ASSERT_EQ(b.len, 26);
    fb_datapad_to4(&b, 0);
    ASSERT_EQ(b.len, 28);
    fb_llc_snap(&b, 0x86dd);
    fb_u8(&b, 0x60);

    dot11_rt_hints_t pad = { 0, 1, 0 }, nopad = { 0, 0, 0 };
    dot11_frame_t v;
    ASSERT_EQ(dot11_frame_decode(f, b.len, &pad, &v), 1);
    ASSERT_EQ(v.hdr_len, 26);
    ASSERT_EQ(v.body_off, 28);
    ASSERT_EQ(v.body_len, b.len - 28);
    int off = 0; uint16_t et = 0;
    ASSERT_EQ(dot11_frame_payload(&v, &off, &et), DOT11_DATA_OK);
    ASSERT_EQ(off, 36);
    ASSERT_EQ((int)et, 0x86dd);
    ASSERT_EQ((int)f[off], 0x60);
    /* Without the hint the same bytes are not SNAP at 26. */
    ASSERT_EQ(dot11_frame_decode(f, b.len, &nopad, &v), 1);
    ASSERT_EQ(v.body_off, 26);
    ASSERT_EQ(dot11_frame_payload(&v, &off, &et), DOT11_DATA_NOT_SNAP);
    /* Padding never makes the body length negative. */
    ASSERT_EQ(dot11_frame_decode(f, 26, &pad, &v), 1);
    ASSERT_EQ(v.body_off, 28);
    ASSERT_EQ(v.body_len, 0);
    /* And the aligned case does not move. */
    int n = data_frame(f, sizeof f, 0, 0, 0, 0, 0, 0);
    ASSERT_EQ(dot11_frame_decode(f, n, &pad, &v), 1);
    ASSERT_EQ(v.body_off, 24);
}

/* ── Flags and the sequence fields ────────────────────────────────── */

static void test_flags_are_decoded_bit_for_bit(void) {
    uint8_t f[128];
    int n = data_frame(f, sizeof f, 1, 0, 0, 0,
                       FB_RETRY | FB_PWRMGT | FB_MOREDATA,
                       (uint16_t)((0x0fff << 4) | 0x0f));
    dot11_frame_t v;
    ASSERT_EQ(dot11_frame_decode(f, n, NULL, &v), 1);
    ASSERT_EQ(v.retry, 1);
    ASSERT_EQ(v.pwr_mgmt, 1);
    ASSERT_EQ(v.more_data, 1);
    ASSERT_EQ(v.to_ds, 0); ASSERT_EQ(v.from_ds, 0);
    ASSERT_EQ(v.more_frag, 0); ASSERT_EQ(v.protected_, 0); ASSERT_EQ(v.order, 0);
    ASSERT_EQ(v.seq_num, 0x0fff);
    ASSERT_EQ(v.frag_num, 0x0f);
    ASSERT_EQ(dot11_seq_num(f, n), 0x0fff);
    ASSERT_EQ(dot11_frag_num(f, n), 0x0f);
    ASSERT_EQ(dot11_more_frags(f, n), 0);
    ASSERT_EQ(v.fc1, (uint8_t)(FB_RETRY | FB_PWRMGT | FB_MOREDATA));
}

static void test_builder_refuses_to_overrun_its_buffer(void) {
    /* The builder is test code and the sanitiser treats it as code: a
     * frame that does not fit is reported, never written past the end. */
    uint8_t small[20];
    fb_t b; fb_init(&b, small, sizeof small);
    fb_mgmt(&b, 8, 0, M_DA, M_AP, M_AP, 0, 0);
    ASSERT_EQ(fb_ok(&b), 0);
    ASSERT_EQ(b.len, 20);
}

static void test_fcs_is_the_802_3_crc(void) {
    /* The CRC-32 check value: "123456789" -> CBF43926, transmitted
     * least-significant octet first (IEEE 802.3 §3.2.9). */
    uint8_t buf[16];
    fb_t b; fb_init(&b, buf, sizeof buf);
    fb_bytes(&b, "123456789", 9);
    fb_fcs(&b);
    ASSERT_EQ(b.len, 13);
    ASSERT_EQ(buf[9],  0x26);
    ASSERT_EQ(buf[10], 0x39);
    ASSERT_EQ(buf[11], 0xf4);
    ASSERT_EQ(buf[12], 0xcb);
}

void run_dot11_frame_tests(void) {
    TEST_SUITE("802.11 frame view: header length (#122)");
    RUN_TEST(test_header_length_table);

    TEST_SUITE("802.11 frame view: roles (#122)");
    RUN_TEST(test_management_roles);
    RUN_TEST(test_control_frame_roles_are_ra_ta_only);
    RUN_TEST(test_data_roles_follow_table_9_26);
    RUN_TEST(test_wds_has_no_bssid_and_sa_is_a4);

    TEST_SUITE("802.11 frame view: refusals (#122)");
    RUN_TEST(test_protected_body_is_refused);
    RUN_TEST(test_runt_reports_no_header);
    RUN_TEST(test_extension_frames_are_not_decoded);
    RUN_TEST(test_payload_status_codes);

    TEST_SUITE("802.11 frame view: radiotap hints (#122)");
    RUN_TEST(test_fcs_strip_length);
    RUN_TEST(test_fcs_is_not_part_of_the_body);
    RUN_TEST(test_datapad_rounds_the_body_to_four);

    TEST_SUITE("802.11 frame view: flags and builder (#122)");
    RUN_TEST(test_flags_are_decoded_bit_for_bit);
    RUN_TEST(test_builder_refuses_to_overrun_its_buffer);
    RUN_TEST(test_fcs_is_the_802_3_crc);
}
