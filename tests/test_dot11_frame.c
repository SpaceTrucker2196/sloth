#include <string.h>
#include <stdlib.h>
#include "runner.h"
#include "sloth.h"
#include "dot11_frame.h"
#include "dot11_data.h"
#include "frame_build.h"
#include "radiotap.h"        /* RT_F_DATAPAD */
#include "capture/probe.h"   /* the real on_probe_frame() under WITH_PCAP */
#include "pm_forge.h"
#include "queue_evict.h"
#include "fragattack.h"
#include "eapol_log.h"
#include "deauth_snoop.h"
#include "assoc_track.h"
#include "beacon_snoop.h"
#include "action_snoop.h"
#include "ctrl_frames.h"

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

/* ── Observers take the view (#130) ───────────────────────────────────
 *
 * Every 802.11 observer now has a view entry, which on_probe_frame()
 * calls, and keeps its (dot11, len) entry as a wrapper for the tests
 * and fuzz harnesses. One case per module: both entries over the same
 * hand-built frame, each against the same LITERAL expectation taken
 * from the clause, never from the other entry — so a view entry that
 * drifted from the byte entry, or both drifting together, goes red.
 *
 * Data observers get a QoS+HTC frame (the §9.2.4.1.10 case) and a WDS
 * frame (Table 9-26's four-address row, which has no single BSSID).
 * Management observers get +HTC and a frame with both DS bits set,
 * which a management header ignores: it is still three-address, 24 or
 * 28 octets (§9.3.3.1), so the expectation there is the SAME output. */

static const uint8_t M_A4[6] = {0x02, 0x00, 0x5e, 0x00, 0x00, 0x05};
#define OBS_T 1700000000   /* a sentinel capture time, not a clock read */

/* One frame, both entries. `via` 0 is the byte wrapper, 1 the view. */
typedef struct { const uint8_t *p; int n; } obs_frame_t;

static void obs_decode(const obs_frame_t *fr, dot11_frame_t *v) {
    dot11_frame_decode(fr->p, fr->n, NULL, v);
}

/* A data frame with QoS Control (TID 5), the stated DS bits and
 * optional Address 4 / HT Control, then `body`. */
static int obs_data(uint8_t *buf, int cap, uint8_t ds, int a4, int htc,
                    uint8_t extra, const uint8_t *a1, const uint8_t *a2,
                    const uint8_t *a3, uint16_t seq_ctl,
                    const uint8_t *body, int body_n) {
    fb_t b; fb_init(&b, buf, cap);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = 8;
    h.flags = (uint8_t)(ds | extra | (htc ? FB_ORDER : 0));
    h.a1 = a1; h.a2 = a2; h.a3 = a3; h.a4 = M_A4; h.seq_ctl = seq_ctl;
    h.a4_present = a4; h.qos_present = 1; h.qos = 0x0005;
    h.htc_present = htc;
    fb_dot11_hdr(&b, &h);
    if (body && body_n > 0) fb_bytes(&b, body, body_n);
    return fb_ok(&b) ? b.len : -1;
}

static void test_pm_forge_view_and_bytes_agree(void) {
    uint8_t f[96];
    /* STA -> AP (ToDS): A1 BSSID, A2 the station. */
    int n = obs_data(f, sizeof f, FB_TODS, 0, 1, 0, M_AP, M_STA, M_DA,
                     0x0100, NULL, 0);
    ASSERT_EQ(n, 30);                         /* 24 + QoS 2 + HTC 4 */
    obs_frame_t fr = { f, n };
    for (int via = 0; via < 2; via++) {
        pm_forge_clear();
        dot11_frame_t v; obs_decode(&fr, &v);
        if (via) pm_forge_observe_frame(&v, OBS_T, 0);
        else     pm_forge_observe(f, n, OBS_T, 0);
        pm_forge_t e;
        ASSERT_EQ(pm_forge_lookup(M_STA, &e), 1);
        ASSERT_EQ(memcmp(e.bssid, M_AP, 6), 0);
        ASSERT_EQ(e.last_pm0_data_tid, 5);
    }
    /* WDS: no single station to attribute a PwrMgt declaration to. */
    n = obs_data(f, sizeof f, FB_TODS | FB_FROMDS, 1, 1, 0, M_AP, M_STA,
                 M_DA, 0x0100, NULL, 0);
    ASSERT_EQ(n, 36);
    fr.n = n;
    for (int via = 0; via < 2; via++) {
        pm_forge_clear();
        dot11_frame_t v; obs_decode(&fr, &v);
        if (via) pm_forge_observe_frame(&v, OBS_T, 0);
        else     pm_forge_observe(f, n, OBS_T, 0);
        pm_forge_t e;
        ASSERT_EQ(pm_forge_lookup(M_STA, &e), 0);
        ASSERT_EQ(pm_forge_count(), 0);
    }
    pm_forge_clear();
}

static void test_queue_evict_view_and_bytes_agree(void) {
    uint8_t f[96];
    /* AP -> STA (FromDS): A1 the station, A2 the BSSID. Sequence 0x55. */
    int n = obs_data(f, sizeof f, FB_FROMDS, 0, 1, 0, M_STA, M_AP, M_SA,
                     0x0550, NULL, 0);
    obs_frame_t fr = { f, n };
    for (int via = 0; via < 2; via++) {
        queue_evict_clear();
        queue_evict_note_session_change(M_AP, M_STA, QUEUE_EVICT_SRC_ASSOC,
                                        OBS_T, 0);
        dot11_frame_t v; obs_decode(&fr, &v);
        if (via) queue_evict_observe_downlink_frame(&v, OBS_T, 1000);
        else     queue_evict_observe_downlink(f, n, OBS_T, 1000);
        queue_evict_t e;
        ASSERT_EQ(queue_evict_lookup(M_AP, M_STA, &e), 1);
        ASSERT_EQ((int)e.burst_frames, 1);
        ASSERT_EQ(e.burst_last_seq, 0x55);
    }
    /* WDS: not AP -> STA, so not a released downlink frame. */
    n = obs_data(f, sizeof f, FB_TODS | FB_FROMDS, 1, 1, 0, M_STA, M_AP,
                 M_SA, 0x0550, NULL, 0);
    fr.n = n;
    for (int via = 0; via < 2; via++) {
        queue_evict_clear();
        queue_evict_note_session_change(M_AP, M_STA, QUEUE_EVICT_SRC_ASSOC,
                                        OBS_T, 0);
        dot11_frame_t v; obs_decode(&fr, &v);
        if (via) queue_evict_observe_downlink_frame(&v, OBS_T, 1000);
        else     queue_evict_observe_downlink(f, n, OBS_T, 1000);
        queue_evict_t e;
        ASSERT_EQ(queue_evict_lookup(M_AP, M_STA, &e), 1);
        ASSERT_EQ((int)e.burst_frames, 0);
    }
    queue_evict_clear();
}

static void test_fragattack_view_and_bytes_agree(void) {
    /* A Protected first fragment, STA -> AP, with a CCMP header whose
     * PN only the view's body offset (30, past HT Control) reads. */
    uint8_t body[8 + 16];
    fb_t bb; fb_init(&bb, body, sizeof body);
    fb_ccmp_hdr(&bb, 0x000000000102ull, 0);
    fb_ciphertext(&bb, 16);
    ASSERT(fb_ok(&bb));
    uint8_t f[96];
    int n = obs_data(f, sizeof f, FB_TODS, 0, 1,
                     FB_PROTECTED | FB_MOREFRAG, M_AP, M_STA, M_DA,
                     0x0070, body, bb.len);
    obs_frame_t fr = { f, n };
    for (int via = 0; via < 2; via++) {
        frag_clear();
        dot11_frame_t v; obs_decode(&fr, &v);
        ASSERT(dot11_frame_ccmp_pn(&v) == 0x0102);
        if (via) frag_observe_frame(&v, OBS_T);
        else     frag_observe(f, n, OBS_T);
        int i = frag_find(M_AP);
        ASSERT(i >= 0);
        frag_bss_t row;
        ASSERT_EQ(frag_bss_copy(i, &row), 1);
        ASSERT_EQ((int)row.protected_frames, 1);
        ASSERT_EQ(frag_session_count(), 1);
    }
    /* WDS crosses two BSSes and is not attributed to a guessed one. */
    n = obs_data(f, sizeof f, FB_TODS | FB_FROMDS, 1, 1,
                 FB_PROTECTED | FB_MOREFRAG, M_AP, M_STA, M_DA, 0x0070,
                 body, bb.len);
    fr.n = n;
    for (int via = 0; via < 2; via++) {
        frag_clear();
        dot11_frame_t v; obs_decode(&fr, &v);
        if (via) frag_observe_frame(&v, OBS_T);
        else     frag_observe(f, n, OBS_T);
        ASSERT_EQ(frag_bss_count(), 0);
    }
    frag_clear();
}

/* EAPOL-Key M1 (§12.7.2 Figure 12-32): Key Information Pairwise | ACK,
 * descriptor version 2, a nonce, no MIC, no Key Data. */
static int obs_eapol_m1(uint8_t *out, int cap) {
    fb_t b; fb_init(&b, out, cap);
    fb_llc_snap(&b, 0x888E);
    fb_u8(&b, 0x02); fb_u8(&b, 0x03);         /* version 2, EAPOL-Key */
    fb_be16(&b, 95);                          /* body length */
    fb_u8(&b, 0x02);                          /* RSN descriptor */
    fb_be16(&b, (1 << 7) | (1 << 3) | 0x02);  /* ACK | Pairwise | v2 */
    fb_be16(&b, 16);                          /* Key Length */
    for (int i = 0; i < 8; i++)  fb_u8(&b, 0);            /* Replay */
    for (int i = 0; i < 32; i++) fb_u8(&b, (uint8_t)(0x40 + i)); /* ANonce */
    for (int i = 0; i < 16 + 8 + 8 + 16; i++) fb_u8(&b, 0); /* IV RSC Rsvd MIC */
    fb_be16(&b, 0);                           /* Key Data Length */
    return fb_ok(&b) ? b.len : -1;
}

static void test_eapol_view_and_bytes_agree(void) {
    uint8_t body[128];
    int bn = obs_eapol_m1(body, sizeof body);
    ASSERT_EQ(bn, 8 + 99);
    uint8_t f[192];
    /* AP -> STA: A1 the station, A2 the BSSID. */
    int n = obs_data(f, sizeof f, FB_FROMDS, 0, 1, 0, M_STA, M_AP, M_AP,
                     0, body, bn);
    obs_frame_t fr = { f, n };
    for (int via = 0; via < 2; via++) {
        eapol_clear();
        dot11_frame_t v; obs_decode(&fr, &v);
        int rc = via ? eapol_observe_frame(&v, -40, 6, OBS_T, 0)
                     : eapol_observe_dot11(f, n, -40, 6, OBS_T, 0);
        ASSERT_EQ(rc, 1);
        sloth_state_t *s = calloc(1, sizeof(*s));
        ASSERT(s != NULL);
        if (!s) return;
        eapol_snapshot(s);
        ASSERT_EQ(s->eapol_count, 1);
        ASSERT_EQ(s->eapol_events[0].msg_num, 1);
        ASSERT_EQ(memcmp(s->eapol_events[0].bssid,   M_AP,  6), 0);
        ASSERT_EQ(memcmp(s->eapol_events[0].sta_mac, M_STA, 6), 0);
        free(s);
    }
    /* WDS: no single BSSID to file a handshake under. */
    n = obs_data(f, sizeof f, FB_TODS | FB_FROMDS, 1, 1, 0, M_STA, M_AP,
                 M_AP, 0, body, bn);
    fr.n = n;
    for (int via = 0; via < 2; via++) {
        eapol_clear();
        dot11_frame_t v; obs_decode(&fr, &v);
        int rc = via ? eapol_observe_frame(&v, -40, 6, OBS_T, 0)
                     : eapol_observe_dot11(f, n, -40, 6, OBS_T, 0);
        ASSERT_EQ(rc, 0);
        ASSERT_EQ(eapol_event_count(), 0);
    }
    eapol_clear();
}

/* A management frame, A1 = DA, A2 = SA, A3 = BSSID, with the stated
 * flags and HT Control, then `body`. */
static int obs_mgmt(uint8_t *buf, int cap, uint8_t sub, uint8_t flags,
                    int htc, uint16_t seq_ctl, const uint8_t *body, int bn) {
    fb_t b; fb_init(&b, buf, cap);
    fb_mgmt(&b, sub, (uint8_t)(flags | (htc ? FB_ORDER : 0)),
            M_DA, M_SA, M_AP, seq_ctl, htc);
    if (body && bn > 0) fb_bytes(&b, body, bn);
    return fb_ok(&b) ? b.len : -1;
}

static void test_deauth_view_and_bytes_agree(void) {
    static const uint8_t reason[2] = { 0x07, 0x00 };   /* Class 3 frame */
    for (int ds = 0; ds < 2; ds++) {
        uint8_t f[64];
        int n = obs_mgmt(f, sizeof f, 12, ds ? (FB_TODS | FB_FROMDS) : 0,
                         1, 0x1230, reason, 2);
        ASSERT_EQ(n, 30);
        obs_frame_t fr = { f, n };
        for (int via = 0; via < 2; via++) {
            deauth_frame_t d;
            dot11_frame_t v; obs_decode(&fr, &v);
            int rc = via ? deauth_parse_frame(&v, &d) : deauth_parse(f, n, &d);
            ASSERT_EQ(rc, 1);
            ASSERT_EQ(d.reason_valid, 1);
            ASSERT_EQ(d.reason, 7);
            ASSERT_EQ(d.seq, 0x123);
            ASSERT_EQ(d.frag, 0);
            ASSERT_EQ(d.subtype, 12);
            ASSERT_EQ(memcmp(d.dst,   M_DA, 6), 0);
            ASSERT_EQ(memcmp(d.src,   M_SA, 6), 0);
            ASSERT_EQ(memcmp(d.bssid, M_AP, 6), 0);
        }
    }
}

static void test_assoc_request_view_and_bytes_agree(void) {
    uint8_t body[32];
    fb_t bb; fb_init(&bb, body, sizeof body);
    fb_le16(&bb, 0x0431);                     /* Capability Information */
    fb_le16(&bb, 10);                         /* Listen Interval */
    fb_ssid(&bb, "test-ssid");
    ASSERT(fb_ok(&bb));
    for (int ds = 0; ds < 2; ds++) {
        uint8_t f[96];
        int n = obs_mgmt(f, sizeof f, 0, ds ? (FB_TODS | FB_FROMDS) : 0,
                         1, 0, body, bb.len);
        obs_frame_t fr = { f, n };
        for (int via = 0; via < 2; via++) {
            assoc_req_t r;
            dot11_frame_t v; obs_decode(&fr, &v);
            int rc = via ? assoc_request_parse_frame(&v, &r)
                         : assoc_request_parse(f, n, &r);
            ASSERT_EQ(rc, 1);
            ASSERT_EQ(r.is_reassoc, 0);
            ASSERT_EQ(r.listen_interval, 10);
            ASSERT_EQ(r.capability_info, 0x0431);
            ASSERT(strcmp(r.requested_ssid, "test-ssid") == 0);
            ASSERT_EQ(memcmp(r.sta,   M_SA, 6), 0);
            ASSERT_EQ(memcmp(r.bssid, M_AP, 6), 0);
        }
    }
}

static void test_beacon_view_and_bytes_agree(void) {
    uint8_t body[48];
    fb_t bb; fb_init(&bb, body, sizeof body);
    fb_beacon_fixed(&bb, 0x0000000000abcdefull, 100, 0x0001);
    fb_ssid(&bb, "test-ssid");
    ASSERT(fb_ok(&bb));
    for (int ds = 0; ds < 2; ds++) {
        uint8_t f[96];
        int n = obs_mgmt(f, sizeof f, 8, ds ? (FB_TODS | FB_FROMDS) : 0,
                         1, 0, body, bb.len);
        obs_frame_t fr = { f, n };
        for (int via = 0; via < 2; via++) {
            char ssid[33], enc[10]; uint8_t bssid[6]; int ch = -1;
            uint16_t bms = 0; beacon_rsn_t rsn;
            dot11_frame_t v; obs_decode(&fr, &v);
            int rc = via
                ? beacon_parse_frame(&v, -40, ssid, bssid, &ch, enc, &bms, &rsn)
                : beacon_parse(f, n, -40, ssid, bssid, &ch, enc, &bms, &rsn);
            ASSERT_EQ(rc, 1);
            ASSERT(strcmp(ssid, "test-ssid") == 0);
            ASSERT_EQ(memcmp(bssid, M_AP, 6), 0);
            ASSERT_EQ(bms, 102);              /* 100 TU * 1024 / 1000 */
            ASSERT(strcmp(enc, "OPEN") == 0);
            ASSERT_EQ(rsn.has_tsf, 1);
            ASSERT(rsn.tsf == 0xabcdefull);
        }
    }
}

static void test_action_view_and_bytes_agree(void) {
    /* Spectrum Management / Channel Switch Announcement (§9.6.2.6):
     * Category 0, Action 4, then the CSA element (tag 37): mode 1, new
     * channel 11, count 5. A2 (the transmitter) differs from A3 (the
     * BSS it speaks for), so the recorded roles are checkable. */
    static const uint8_t body[] = { 0x00, 0x04, 37, 3, 0x01, 11, 5 };
    for (int ds = 0; ds < 2; ds++) {
        uint8_t f[64];
        int n = obs_mgmt(f, sizeof f, 13, ds ? (FB_TODS | FB_FROMDS) : 0,
                         1, 0, body, (int)sizeof body);
        obs_frame_t fr = { f, n };
        for (int via = 0; via < 2; via++) {
            csa_clear();
            dot11_frame_t v; obs_decode(&fr, &v);
            if (via) action_observe_frame(&v, OBS_T);
            else     action_observe(f, n, OBS_T);
            sloth_csa_event_t e;
            ASSERT_EQ(csa_latest(M_AP, OBS_T, 60, &e), 1);
            ASSERT_EQ(e.new_channel, 11);
            ASSERT_EQ(e.switch_count, 5);
            ASSERT_EQ(memcmp(e.ta, M_SA, 6), 0);
        }
    }
    csa_clear();
}

static void test_ctrl_view_and_bytes_agree(void) {
    /* Block Ack Request (§9.3.1.7): RA, TA, BAR Control with TID 3 in
     * B12-B15, then Starting Sequence Control with SSN 100. Order and
     * both DS bits are set: a control frame has no HT Control or
     * Address 4 to add, so the layout must not move. */
    uint8_t f[32];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_ctrl_hdr(&b, 8, FB_ORDER | FB_TODS | FB_FROMDS, 0x002c, M_AP, M_STA);
    fb_le16(&b, 0x3000);
    fb_le16(&b, (uint16_t)(100 << 4));
    ASSERT(fb_ok(&b));
    obs_frame_t fr = { f, b.len };
    for (int via = 0; via < 2; via++) {
        ctrl_clear();
        dot11_frame_t v; obs_decode(&fr, &v);
        if (via) ctrl_observe_frame(&v, 6, OBS_T);
        else     ctrl_observe(f, b.len, 6, OBS_T);
        sloth_bar_state_t s;
        ASSERT_EQ(bar_find(M_AP, M_STA, 3, &s), 1);
        ASSERT_EQ((int)s.total_bars, 1);
        ASSERT_EQ(s.last_ssn, 100);
    }
    ctrl_clear();
}

/* dot11_frame_depad() — the view carried onto the depadded copy. */
static void test_depad_moves_the_view_without_a_decode(void) {
    uint8_t f[64];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = 8; h.flags = FB_FROMDS;
    h.a1 = M_STA; h.a2 = M_AP; h.a3 = M_SA; h.qos_present = 1;
    fb_dot11_hdr(&b, &h);                     /* 26 octets */
    fb_datapad_to4(&b, 0);                    /* + 2 pad */
    fb_llc_snap(&b, 0x0800);
    ASSERT(fb_ok(&b));
    ASSERT_EQ(b.len, 36);
    const dot11_rt_hints_t pad = { 0, 1, 0 };
    dot11_frame_t v;
    ASSERT_EQ(dot11_frame_decode(f, b.len, &pad, &v), 1);
    ASSERT_EQ(v.body_off, 28);

    uint8_t copy[64];
    dot11_frame_decode_count_arm(1);
    ASSERT_EQ(dot11_frame_depad(&v, copy, sizeof copy, &v), 1);
    ASSERT_EQ((int)dot11_frame_decode_count(), 0);
    dot11_frame_decode_count_arm(0);
    ASSERT(v.p == copy);
    ASSERT_EQ(v.len, 34);
    ASSERT_EQ(v.hdr_len, 26);
    ASSERT_EQ(v.body_off, 26);
    ASSERT_EQ(v.body_len, 8);
    ASSERT(v.a1 == copy + 4 && v.a2 == copy + 10 && v.a3 == copy + 16);
    ASSERT(v.da == copy + 4 && v.bssid == copy + 10 && v.sa == copy + 16);
    ASSERT_EQ(memcmp(v.bssid, M_AP, 6), 0);
    ASSERT_EQ(copy[26], 0xAA);                /* LLC right after the header */
    int off; uint16_t et;
    ASSERT_EQ(dot11_frame_payload(&v, &off, &et), DOT11_DATA_OK);
    ASSERT_EQ(off, 34);
    ASSERT_EQ(et, 0x0800);

    /* Nothing to remove: the view is left exactly as decoded. */
    dot11_frame_t w, keep;
    ASSERT_EQ(dot11_frame_decode(copy, 34, NULL, &w), 1);
    keep = w;
    ASSERT_EQ(dot11_frame_depad(&w, f, sizeof f, &w), 0);
    ASSERT(memcmp(&w, &keep, sizeof w) == 0);
    /* Does not fit: refused, view unchanged. */
    ASSERT_EQ(dot11_frame_decode(f, 36, &pad, &w), 1);
    keep = w;
    ASSERT_EQ(dot11_frame_depad(&w, copy, 33, &w), 0);
    ASSERT(memcmp(&w, &keep, sizeof w) == 0);
}

/* ── One decode per frame, observers included (#130) ──────────────────
 *
 * The structural claim: on_probe_frame() decodes a frame once and every
 * observer reads that view. Each type below reaches a different set of
 * observers; the decode counter must advance by exactly one per frame.
 * A single observer called through its byte wrapper instead of its view
 * entry makes it two, which is how this was mutation-checked. */

static int obs_rt(uint8_t *buf, int cap, uint8_t rt_flags,
                  const uint8_t *frame, int n) {
    fb_t b; fb_init(&b, buf, cap);
    fb_rt_t rt; memset(&rt, 0, sizeof(rt));
    rt.has_flags = rt_flags != 0; rt.flags = rt_flags;
    fb_radiotap(&b, rt_flags ? &rt : NULL);
    fb_bytes(&b, frame, n);
    return fb_ok(&b) ? b.len : -1;
}

static sloth_state_t g_obs_s;

static void test_probe_path_decodes_each_frame_once(void) {
    enum { NF = 12 };
    static uint8_t raw[NF][256], wrapped[NF][300];
    int rn[NF];
    int k = 0;

    uint8_t bcn[48];
    fb_t bb; fb_init(&bb, bcn, sizeof bcn);
    fb_beacon_fixed(&bb, 1, 100, 0x0001);
    fb_ssid(&bb, "test-ssid");
    rn[k] = obs_mgmt(raw[k], 256, 8, 0, 1, 0, bcn, bb.len); k++;    /* beacon */
    uint8_t pr[16]; fb_t pb; fb_init(&pb, pr, sizeof pr);
    fb_ssid(&pb, "test-ssid");
    rn[k] = obs_mgmt(raw[k], 256, 4, 0, 0, 0x0010, pr, pb.len); k++; /* probe req */
    uint8_t ar[32]; fb_t ab; fb_init(&ab, ar, sizeof ar);
    fb_le16(&ab, 0x0431); fb_le16(&ab, 10); fb_ssid(&ab, "test-ssid");
    rn[k] = obs_mgmt(raw[k], 256, 0, 0, 1, 0, ar, ab.len); k++;     /* assoc req */
    uint8_t rs[32]; fb_t rb; fb_init(&rb, rs, sizeof rs);
    fb_assoc_resp_fixed(&rb, 0x0431, 0, 1); fb_ssid(&rb, "test-ssid");
    rn[k] = obs_mgmt(raw[k], 256, 1, 0, 0, 0, rs, rb.len); k++;     /* assoc resp */
    static const uint8_t auth[6] = { 0, 0, 1, 0, 0, 0 };
    rn[k] = obs_mgmt(raw[k], 256, 11, 0, 0, 0, auth, 6); k++;       /* auth */
    static const uint8_t rsn7[2] = { 7, 0 };
    rn[k] = obs_mgmt(raw[k], 256, 12, 0, 1, 0, rsn7, 2); k++;       /* deauth */
    static const uint8_t csa[] = { 0x00, 0x04, 37, 3, 0x01, 11, 5 };
    rn[k] = obs_mgmt(raw[k], 256, 13, 0, 1, 0, csa, (int)sizeof csa); k++;
    uint8_t m1[128];
    int m1n = obs_eapol_m1(m1, sizeof m1);
    rn[k] = obs_data(raw[k], 256, FB_FROMDS, 0, 1, 0, M_STA, M_AP, M_AP,
                     0, m1, m1n); k++;                              /* EAPOL */
    rn[k] = obs_data(raw[k], 256, FB_TODS | FB_FROMDS, 1, 0, 0, M_STA,
                     M_AP, M_AP, 0, m1, m1n); k++;                  /* WDS */
    /* QoS data on a DATAPAD radio: 26-octet header + 2 pad octets. */
    {
        fb_t b; fb_init(&b, raw[k], 256);
        fb_hdr_t h; memset(&h, 0, sizeof(h));
        h.type = 2; h.subtype = 8; h.flags = FB_FROMDS;
        h.a1 = M_STA; h.a2 = M_AP; h.a3 = M_AP; h.qos_present = 1;
        fb_dot11_hdr(&b, &h);
        fb_datapad_to4(&b, 0);
        fb_bytes(&b, m1, m1n);
        rn[k] = fb_ok(&b) ? b.len : -1; k++;
    }
    {   /* Block Ack Request */
        fb_t b; fb_init(&b, raw[k], 256);
        fb_ctrl_hdr(&b, 8, 0, 0, M_AP, M_STA);
        fb_le16(&b, 0x3000); fb_le16(&b, (uint16_t)(100 << 4));
        rn[k] = fb_ok(&b) ? b.len : -1; k++;
    }
    {   /* ACK: RA only */
        fb_t b; fb_init(&b, raw[k], 256);
        fb_ctrl_hdr(&b, 13, 0, 0, M_AP, NULL);
        rn[k] = fb_ok(&b) ? b.len : -1; k++;
    }
    ASSERT_EQ(k, NF);

    const uint8_t *fs[NF]; int ls[NF];
    for (int i = 0; i < NF; i++) {
        ASSERT(rn[i] > 0);
        ls[i] = obs_rt(wrapped[i], 300, i == 9 ? RT_F_DATAPAD : 0,
                       raw[i], rn[i]);
        ASSERT(ls[i] > 0);
        fs[i] = wrapped[i];
    }

    memset(&g_obs_s, 0, sizeof(g_obs_s));
    probe_clear();
    eapol_clear();
    csa_clear();
    ctrl_clear();
    dot11_frame_decode_count_arm(1);
    const int got = probe_test_dispatch(&g_obs_s, fs, ls, NULL, NULL, NF);
    const unsigned long decodes = dot11_frame_decode_count();
    dot11_frame_decode_count_arm(0);
    ASSERT_EQ(got, NF);
    ASSERT_EQ((int)decodes, NF);

    /* And the frames reached their observers: this is not a count of
     * frames dropped before anything looked at them. */
    ASSERT_EQ(eapol_event_count(), 2);        /* plain + DATAPAD M1 */
    sloth_csa_event_t e;
    ASSERT_EQ(csa_latest(M_AP, 0x7fffffff, 0x7fffffff, &e), 1);
    sloth_bar_state_t bar;
    ASSERT_EQ(bar_find(M_AP, M_STA, 3, &bar), 1);
    probe_clear();
    eapol_clear();
    csa_clear();
    ctrl_clear();
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

    TEST_SUITE("802.11 observers take the view (#130)");
    RUN_TEST(test_pm_forge_view_and_bytes_agree);
    RUN_TEST(test_queue_evict_view_and_bytes_agree);
    RUN_TEST(test_fragattack_view_and_bytes_agree);
    RUN_TEST(test_eapol_view_and_bytes_agree);
    RUN_TEST(test_deauth_view_and_bytes_agree);
    RUN_TEST(test_assoc_request_view_and_bytes_agree);
    RUN_TEST(test_beacon_view_and_bytes_agree);
    RUN_TEST(test_action_view_and_bytes_agree);
    RUN_TEST(test_ctrl_view_and_bytes_agree);
    RUN_TEST(test_depad_moves_the_view_without_a_decode);
    RUN_TEST(test_probe_path_decodes_each_frame_once);
}
