#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "ble_hci.h"
#include "ble_snoop.h"
#include "btle_ll.h"
#include "bredr_bb.h"
#include "bt_stream.h"
#include "jsonl.h"
#include "sensor_health.h"
#include "sloth_clock.h"
#ifdef WITH_PCAP
#include "capture/bt_capture.h"
#endif

/*
 * The Ubertooth capture stream — #144 slice 3.
 *
 * Every record is built by hand from the layout it is read by, never
 * captured (agents/AGENTS.md, "No pcap fixtures"):
 *
 *   classic pcap savefile (pcap-savefile(5)):
 *     file header  magic(4) major(2)=2 minor(2)=4 thiszone(4) sigfigs(4)
 *                  snaplen(4) linktype(4), writer's byte order
 *     record       ts_sec(4) ts_frac(4) incl_len(4) orig_len(4) data
 *
 *   DLT 256 LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (tcpdump.org), LE:
 *     rf_channel(1) signal(1) noise(1) aa_offenses(1) ref_aa(4) flags(2)
 *     then the LE packet.
 *   DLT 192 LINKTYPE_PPI: version(1)=0 flags(1) len(2 LE) dlt(4 LE)=251,
 *     fields, then the LE packet (LINKTYPE_BLUETOOTH_LE_LL).
 *   LE packet, Core Spec v5.4 Vol 6 Part B §2.1, §2.3:
 *     AA(4 LE, 0x8E89BED6 on advertising) header(2: type b0-3, ChSel b5,
 *     TxAdd b6, RxAdd b7; Length) payload CRC(3)
 *
 *   DLT 255 LINKTYPE_BLUETOOTH_BREDR_BB (tcpdump.org), LE:
 *     0 rf_channel  1 signal  2 noise  3 ac_offenses  4 transport/rate
 *     5 corr_hdr_bits  6 corr_payload_bits(2)  8 LAP(3)+rsv
 *     12 ref LAP(3)  15 ref UAP  16 packet header(4)  20 flags(2)
 *     flags 0x0002 signal valid, 0x0010 ref LAP valid, 0x0020 payload,
 *     0x0080 reference UAP valid for HEC/CRC checking
 */

#define TS 1700000000

static sloth_state_t g_s;
static time_t g_wall;
static time_t pinned_wall(void) { return g_wall; }

/* AdvA as transmitted (LSO first); displayed C1:22:33:44:55:66. */
static const uint8_t ADVA[6] = { 0x66, 0x55, 0x44, 0x33, 0x22, 0xC1 };
static const uint8_t PEER[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x46 };

static void put16(uint8_t *b, uint16_t v) { b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
}
static void put32be(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);  b[3] = (uint8_t)v;
}

/* LE packet: AA, header, payload. No CRC octets unless `crc`. */
static int le_pkt(uint8_t *b, uint32_t aa, uint8_t type, int txadd, int rxadd,
                  uint8_t len_field, const uint8_t *payload, int plen, int crc) {
    put32(b, aa);
    b[4] = (uint8_t)((type & 0x0F) | (txadd ? 0x40 : 0) | (rxadd ? 0x80 : 0));
    b[5] = len_field;
    if (plen) memcpy(b + 6, payload, (size_t)plen);
    int n = 6 + plen;
    if (crc) { b[n] = 0xAA; b[n + 1] = 0xBB; b[n + 2] = 0xCC; n += 3; }
    return n;
}

static int phdr(uint8_t *b, uint8_t rf, int8_t sig, uint16_t flags) {
    b[0] = rf; b[1] = (uint8_t)sig; b[2] = (uint8_t)(int8_t)-90; b[3] = 0;
    put32(b + 4, BTLE_ADV_AA);
    put16(b + 8, flags);
    return BTLE_PHDR_LEN;
}

/* AdvA + Flags(LE General, BR/EDR not supported) + Complete Local Name "node". */
static int adv_payload(uint8_t *p) {
    int n = 0;
    memcpy(p, ADVA, 6); n = 6;
    p[n++] = 0x02; p[n++] = 0x01; p[n++] = 0x06;
    p[n++] = 0x05; p[n++] = 0x09; p[n++] = 'n'; p[n++] = 'o'; p[n++] = 'd'; p[n++] = 'e';
    return n;
}

/* A DLT 256 record of an ADV_IND on RF channel `rf`. */
static int rec_adv_ind(uint8_t *b, uint8_t rf, int8_t sig, uint16_t flags) {
    uint8_t pl[40];
    int pn = adv_payload(pl);
    int n = phdr(b, rf, sig, flags);
    return n + le_pkt(b + n, BTLE_ADV_AA, BTLE_ADV_IND, 1, 0, (uint8_t)pn, pl, pn, 1);
}

/* ── RF channel mapping ─────────────────────────────────────────── */

static void test_rf_channel_maps_to_ll_index(void) {
    ASSERT_EQ(btle_rf_to_index(0), 37);    /* 2402 MHz */
    ASSERT_EQ(btle_rf_to_index(1), 0);
    ASSERT_EQ(btle_rf_to_index(11), 10);
    ASSERT_EQ(btle_rf_to_index(12), 38);   /* 2426 MHz */
    ASSERT_EQ(btle_rf_to_index(13), 11);
    ASSERT_EQ(btle_rf_to_index(38), 36);
    ASSERT_EQ(btle_rf_to_index(39), 39);   /* 2480 MHz */
    ASSERT_EQ(btle_rf_to_index(40), -1);
    ASSERT_EQ(btle_rf_to_index(-1), -1);
}

/* ── btle_ll ────────────────────────────────────────────────────── */

static void test_adv_ind_with_phdr_decodes(void) {
    uint8_t b[64];
    int n = rec_adv_ind(b, 12, -61, BTLE_PHDR_SIGNAL_VALID | 0x0001);
    btle_pkt_t p;
    ASSERT_EQ((int)btle_phdr_record_parse(b, (size_t)n, &p), (int)BTLE_V_ADV);
    ASSERT_EQ(p.has_phdr, 1);
    ASSERT_EQ(p.rf_channel, 12);
    ASSERT_EQ(p.channel_index, 38);
    ASSERT_EQ(p.signal_valid, 1);
    ASSERT_EQ(p.signal_dbm, -61);
    ASSERT_EQ(p.aa, BTLE_ADV_AA);
    ASSERT_EQ(p.pdu_type, BTLE_ADV_IND);
    ASSERT_EQ(p.txadd, 1);
    ASSERT_EQ(p.len_claimed, 15);
    ASSERT_EQ(p.len_trusted, 15);
    ASSERT_EQ(p.truncated, 0);
    ASSERT_EQ(p.has_adva, 1);
    ASSERT(memcmp(p.adva, ADVA, 6) == 0);
    ASSERT_EQ((int)p.data_len, 9);

    ble_adv_report_t r;
    ASSERT_EQ(btle_adv_report(&p, &r), 1);
    ASSERT_EQ(r.event_type, 0x00);      /* HCI ADV_IND */
    ASSERT_EQ(r.addr_type, 1);          /* random, from TxAdd */
    ASSERT(memcmp(r.addr, ADVA, 6) == 0);
    ASSERT(r.has_rssi);
    ASSERT_EQ(r.rssi, -61);
    ASSERT(r.has_flags);
    ASSERT_EQ(r.flags, 0x06);
    ASSERT(r.has_local_name);
    ASSERT_STR(r.local_name, "node");
    ASSERT(!r.truncated);
}

/* Seen to fail: with the signal-valid test in btle_adv_report() removed,
 * the -61 below becomes an RSSI. */
static void test_signal_power_used_only_when_flagged_valid(void) {
    uint8_t b[64];
    int n = rec_adv_ind(b, 0, -61, 0x0001);
    btle_pkt_t p;
    ASSERT_EQ((int)btle_phdr_record_parse(b, (size_t)n, &p), (int)BTLE_V_ADV);
    ble_adv_report_t r;
    ASSERT_EQ(btle_adv_report(&p, &r), 1);
    ASSERT(!r.has_rssi);
    ASSERT_EQ(r.rssi, 0);
}

static void test_each_advertising_type_maps_to_its_hci_event_type(void) {
    static const struct { uint8_t ll; uint8_t hci; } M[] = {
        { BTLE_ADV_IND, 0x00 }, { BTLE_ADV_SCAN_IND, 0x02 },
        { BTLE_ADV_NONCONN_IND, 0x03 }, { BTLE_SCAN_RSP, 0x04 },
    };
    uint8_t pl[40], b[64];
    int pn = adv_payload(pl);
    for (size_t i = 0; i < sizeof(M) / sizeof(M[0]); i++) {
        int n = le_pkt(b, BTLE_ADV_AA, M[i].ll, 0, 0, (uint8_t)pn, pl, pn, 1);
        btle_pkt_t p;
        ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_ADV);
        ble_adv_report_t r;
        ASSERT_EQ(btle_adv_report(&p, &r), 1);
        ASSERT_EQ(r.event_type, M[i].hci);
        ASSERT_EQ(r.addr_type, 0);
        ASSERT_STR(r.local_name, "node");
    }
    /* ADV_DIRECT_IND: AdvA then TargetA, exactly 12, no AdvData. */
    uint8_t d[12];
    memcpy(d, ADVA, 6); memcpy(d + 6, PEER, 6);
    int n = le_pkt(b, BTLE_ADV_AA, BTLE_ADV_DIRECT_IND, 0, 1, 12, d, 12, 1);
    btle_pkt_t p;
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_ADV);
    ASSERT_EQ(p.has_adva, 1);
    ASSERT_EQ(p.has_peer, 1);
    ASSERT(memcmp(p.peer, PEER, 6) == 0);
    ASSERT_EQ(p.rxadd, 1);
    ASSERT_EQ((int)p.data_len, 0);
    ble_adv_report_t r;
    ASSERT_EQ(btle_adv_report(&p, &r), 1);
    ASSERT_EQ(r.event_type, 0x01);
    ASSERT(!r.has_local_name);
}

static void test_scan_req_names_scanner_and_advertiser(void) {
    uint8_t d[12], b[32];
    memcpy(d, PEER, 6); memcpy(d + 6, ADVA, 6);   /* ScanA, AdvA */
    int n = le_pkt(b, BTLE_ADV_AA, BTLE_SCAN_REQ, 1, 0, 12, d, 12, 1);
    btle_pkt_t p;
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_SCAN_REQ);
    ASSERT_EQ(p.has_peer, 1);
    ASSERT(memcmp(p.peer, PEER, 6) == 0);
    ASSERT_EQ(p.has_adva, 1);
    ASSERT(memcmp(p.adva, ADVA, 6) == 0);
    ASSERT_EQ(p.txadd, 1);
    ASSERT_EQ(p.rxadd, 0);
    /* A scan request is not an advertisement: no device report. Seen to
     * fail: with btle_adv_report()'s default case mapping any PDU type to
     * an event type, this returns 1. */
    ble_adv_report_t r;
    ASSERT_EQ(btle_adv_report(&p, &r), 0);
}

/* CONNECT_IND LLData, §2.3.3.1: AA(4) CRCInit(3) WinSize(1)
 * WinOffset(2) Interval(2) Latency(2) Timeout(2) ChM(5) Hop:5|SCA:3. */
static void test_connect_ind_fields_and_hop_sca_packing(void) {
    uint8_t d[34], b[48];
    memcpy(d, PEER, 6);                 /* InitA */
    memcpy(d + 6, ADVA, 6);             /* AdvA */
    uint8_t *ll = d + 12;
    ll[0] = 0x12; ll[1] = 0x8B; ll[2] = 0x9A; ll[3] = 0xAF;   /* AA 0xAF9A8B12 */
    ll[4] = 0x56; ll[5] = 0x34; ll[6] = 0x12;                 /* CRCInit 0x123456 */
    ll[7] = 3;                                                /* WinSize */
    ll[8] = 0x05; ll[9] = 0x00;                               /* WinOffset 5 */
    ll[10] = 0x18; ll[11] = 0x00;                             /* Interval 24 */
    ll[12] = 0x02; ll[13] = 0x00;                             /* Latency 2 */
    ll[14] = 0x48; ll[15] = 0x00;                             /* Timeout 72 */
    ll[16] = 0xFF; ll[17] = 0xFF; ll[18] = 0xFF; ll[19] = 0xFF; ll[20] = 0x1F;
    ll[21] = (uint8_t)((5 << 5) | 7);                         /* SCA 5, Hop 7 */
    int n = le_pkt(b, BTLE_ADV_AA, BTLE_CONNECT_IND, 0, 1, 34, d, 34, 1);
    btle_pkt_t p;
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_CONNECT_IND);
    ASSERT_EQ(p.has_conn, 1);
    ASSERT(memcmp(p.peer, PEER, 6) == 0);
    ASSERT(memcmp(p.adva, ADVA, 6) == 0);
    ASSERT_EQ(p.conn.aa, 0xAF9A8B12u);
    ASSERT_EQ(p.conn.crc_init, 0x123456u);
    ASSERT_EQ(p.conn.win_size, 3);
    ASSERT_EQ(p.conn.win_offset, 5);
    ASSERT_EQ(p.conn.interval, 24);
    ASSERT_EQ(p.conn.latency, 2);
    ASSERT_EQ(p.conn.timeout, 72);
    ASSERT_EQ(p.conn.chm[0], 0xFF);
    ASSERT_EQ(p.conn.chm[4], 0x1F);
    ASSERT_EQ(p.conn.hop, 7);
    ASSERT_EQ(p.conn.sca, 5);
    /* The extremes of the packing: all-ones hop with zero SCA, and the
     * reverse, so neither field leaks into the other. */
    ll[21] = 0x1F;
    le_pkt(b, BTLE_ADV_AA, BTLE_CONNECT_IND, 0, 1, 34, d, 34, 1);
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_CONNECT_IND);
    ASSERT_EQ(p.conn.hop, 31);
    ASSERT_EQ(p.conn.sca, 0);
    ll[21] = 0xE0;
    le_pkt(b, BTLE_ADV_AA, BTLE_CONNECT_IND, 0, 1, 34, d, 34, 1);
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_CONNECT_IND);
    ASSERT_EQ(p.conn.hop, 0);
    ASSERT_EQ(p.conn.sca, 7);
}

/* Seen to fail: with the len_ok() verdict ignored, the five
 * out-of-range Lengths decode. */
static void test_lengths_outside_the_type_range_are_malformed(void) {
    uint8_t pl[40], b[64];
    memset(pl, 0, sizeof(pl));
    btle_pkt_t p;
    int n = le_pkt(b, BTLE_ADV_AA, BTLE_ADV_IND, 0, 0, 5, pl, 5, 0);
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_MALFORMED);
    n = le_pkt(b, BTLE_ADV_AA, BTLE_ADV_IND, 0, 0, 38, pl, 38, 0);
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_MALFORMED);
    n = le_pkt(b, BTLE_ADV_AA, BTLE_SCAN_REQ, 0, 0, 11, pl, 11, 0);
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_MALFORMED);
    n = le_pkt(b, BTLE_ADV_AA, BTLE_ADV_DIRECT_IND, 0, 0, 13, pl, 13, 0);
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_MALFORMED);
    n = le_pkt(b, BTLE_ADV_AA, BTLE_CONNECT_IND, 0, 0, 33, pl, 33, 0);
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_MALFORMED);
    /* Shorter than AA + header, and a pseudo-header with nothing after. */
    ASSERT_EQ((int)btle_ll_parse(b, 5, &p), (int)BTLE_V_MALFORMED);
    uint8_t h[BTLE_PHDR_LEN];
    phdr(h, 0, 0, 0);
    ASSERT_EQ((int)btle_phdr_record_parse(h, 9, &p), (int)BTLE_V_MALFORMED);
    ASSERT_EQ((int)btle_phdr_record_parse(h, sizeof(h), &p), (int)BTLE_V_MALFORMED);
    /* An RF channel this link type cannot carry. */
    n = rec_adv_ind(b, 40, 0, 0);
    ASSERT_EQ((int)btle_phdr_record_parse(b, (size_t)n, &p), (int)BTLE_V_MALFORMED);
}

/* The claim runs past the record: only the octets present are trusted,
 * and an AD structure crossing that line is dropped, not completed.
 *
 * The backing array holds the whole packet, name and all; only `len`
 * says it ends early. So this is a logical bound a memory sanitizer
 * cannot see. Seen to fail: with `if (trust > avail) trust = avail;`
 * removed from btle_ll_parse(), the name below decodes. */
static void test_claim_past_the_record_is_truncated_not_read(void) {
    uint8_t pl[40], b[64];
    int pn = 0;
    memcpy(pl, ADVA, 6); pn = 6;
    pl[pn++] = 0x02; pl[pn++] = 0x01; pl[pn++] = 0x06;
    pl[pn++] = 0x0A; pl[pn++] = 0x09;
    memcpy(pl + pn, "abcdefghi", 9); pn += 9;                  /* 20 */
    int full = le_pkt(b, BTLE_ADV_AA, BTLE_ADV_IND, 0, 0, (uint8_t)pn, pl, pn, 1);
    size_t cut = 6 + 6 + 3 + 4;          /* AdvA, Flags, 4 octets of the name AD */
    ASSERT((int)cut < full);
    btle_pkt_t p;
    ASSERT_EQ((int)btle_ll_parse(b, cut, &p), (int)BTLE_V_ADV);
    ASSERT_EQ(p.len_claimed, 20);
    ASSERT_EQ(p.len_trusted, 13);
    ASSERT_EQ(p.truncated, 1);
    ASSERT_EQ((int)p.data_len, 7);
    ble_adv_report_t r;
    ASSERT_EQ(btle_adv_report(&p, &r), 1);
    ASSERT(r.has_flags);
    ASSERT(!r.has_local_name);
    ASSERT(r.truncated);
    /* The whole packet, for contrast: the same bytes decode the name. */
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)full, &p), (int)BTLE_V_ADV);
    ASSERT_EQ(p.truncated, 0);
    ASSERT_EQ(btle_adv_report(&p, &r), 1);
    ASSERT(r.has_local_name);
    ASSERT_STR(r.local_name, "abcdefghi");
}

/* Cut so short the AdvA is not there: the packet is counted, and no
 * device can come of it. */
static void test_truncated_before_adva_gives_no_report(void) {
    uint8_t pl[40], b[64];
    int pn = adv_payload(pl);
    le_pkt(b, BTLE_ADV_AA, BTLE_ADV_IND, 0, 0, (uint8_t)pn, pl, pn, 0);
    btle_pkt_t p;
    ASSERT_EQ((int)btle_ll_parse(b, 6 + 4, &p), (int)BTLE_V_ADV);
    ASSERT_EQ(p.truncated, 1);
    ASSERT_EQ(p.has_adva, 0);
    ble_adv_report_t r;
    ASSERT_EQ(btle_adv_report(&p, &r), 0);
}

/* The Ubertooth delivers at most UBT_LE_PACKET_MAX octets from the AA,
 * so a longer claim is never trusted past it even when the record
 * carries more. Seen to fail: with the BTLE_PAYLOAD_TRUST_MAX bound
 * removed, len_trusted reads 100. */
static void test_ubertooth_capture_limit_bounds_the_trusted_length(void) {
    static uint8_t b[6 + 100];
    memset(b, 0x5A, sizeof(b));
    le_pkt(b, BTLE_ADV_AA, BTLE_ADV_EXT_IND, 0, 0, 200, NULL, 0, 0);
    btle_pkt_t p;
    ASSERT_EQ((int)btle_ll_parse(b, sizeof(b), &p), (int)BTLE_V_EXT_ADV);
    ASSERT_EQ(p.len_claimed, 200);
    ASSERT_EQ(p.len_trusted, BTLE_PAYLOAD_TRUST_MAX);
    ASSERT_EQ(BTLE_PAYLOAD_TRUST_MAX, 44);
    ASSERT_EQ(p.truncated, 1);
}

/* Seen to fail: with the advertising-Access-Address test removed from
 * btle_ll_parse(), the data-channel packet decodes an AdvA. */
static void test_data_channel_and_other_pdus_are_not_decoded(void) {
    uint8_t pl[40], b[64];
    int pn = adv_payload(pl);
    btle_pkt_t p;
    int n = le_pkt(b, 0xAF9A8B12u, BTLE_ADV_IND, 0, 0, (uint8_t)pn, pl, pn, 1);
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_DATA);
    ASSERT_EQ(p.has_adva, 0);
    ASSERT_EQ((int)p.data_len, 0);
    n = le_pkt(b, BTLE_ADV_AA, BTLE_AUX_CONNECT_RSP, 0, 0, 14, pl, 14, 0);
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_OTHER);
    ASSERT_EQ(p.has_adva, 0);
    n = le_pkt(b, BTLE_ADV_AA, 0x0F, 0, 0, 3, pl, 3, 0);
    ASSERT_EQ((int)btle_ll_parse(b, (size_t)n, &p), (int)BTLE_V_OTHER);
}

static void test_ppi_wrapped_le_ll_decodes_without_channel(void) {
    uint8_t pl[40], b[80];
    int pn = adv_payload(pl);
    /* PPI header (8) plus one 4-octet field whose contents are skipped. */
    b[0] = 0; b[1] = 0; put16(b + 2, 12); put32(b + 4, BTLE_DLT_LL);
    b[8] = 0x36; b[9] = 0x75; b[10] = 0; b[11] = 0;
    int n = 12 + le_pkt(b + 12, BTLE_ADV_AA, BTLE_ADV_IND, 1, 0, (uint8_t)pn, pl, pn, 1);
    btle_pkt_t p;
    ASSERT_EQ((int)btle_ppi_record_parse(b, (size_t)n, &p), (int)BTLE_V_ADV);
    ASSERT_EQ(p.has_phdr, 0);
    ASSERT_EQ(p.channel_index, -1);
    ble_adv_report_t r;
    ASSERT_EQ(btle_adv_report(&p, &r), 1);
    ASSERT(!r.has_rssi);
    ASSERT_STR(r.local_name, "node");
    /* Inner link type other than 251, a length past the record, a
     * version other than 0, a length under the fixed header. */
    put32(b + 4, BTLE_DLT_LL_PHDR);
    ASSERT_EQ((int)btle_ppi_record_parse(b, (size_t)n, &p), (int)BTLE_V_MALFORMED);
    put32(b + 4, BTLE_DLT_LL);
    put16(b + 2, (uint16_t)(n + 1));
    ASSERT_EQ((int)btle_ppi_record_parse(b, (size_t)n, &p), (int)BTLE_V_MALFORMED);
    put16(b + 2, 12);
    b[0] = 1;
    ASSERT_EQ((int)btle_ppi_record_parse(b, (size_t)n, &p), (int)BTLE_V_MALFORMED);
    b[0] = 0;
    put16(b + 2, 7);
    ASSERT_EQ((int)btle_ppi_record_parse(b, (size_t)n, &p), (int)BTLE_V_MALFORMED);
}

/* ── bredr_bb ───────────────────────────────────────────────────── */

static int bredr_rec(uint8_t *b, uint8_t rf, int8_t sig, uint32_t lap,
                     uint32_t ref_lap, uint8_t ref_uap, uint16_t flags) {
    memset(b, 0, BREDR_BB_HDR_LEN);
    b[0] = rf; b[1] = (uint8_t)sig; b[2] = (uint8_t)(int8_t)-95;
    b[8]  = (uint8_t)lap; b[9] = (uint8_t)(lap >> 8); b[10] = (uint8_t)(lap >> 16);
    b[11] = 0xEE;   /* reserved: never part of the LAP */
    b[12] = (uint8_t)ref_lap; b[13] = (uint8_t)(ref_lap >> 8);
    b[14] = (uint8_t)(ref_lap >> 16);
    b[15] = ref_uap;
    put16(b + 20, flags);
    return BREDR_BB_HDR_LEN;
}

static void test_bredr_header_decodes_lap_and_labels_reference_uap(void) {
    uint8_t b[32];
    int n = bredr_rec(b, 39, -48, 0x123456, 0x123456, 0x5A,
                      BREDR_F_SIGNAL_VALID | BREDR_F_REF_LAP_VALID |
                      BREDR_F_REF_UAP_VALID);
    bredr_bb_t x;
    ASSERT_EQ(bredr_bb_parse(b, (size_t)n, &x), 0);
    ASSERT_EQ(x.rf_channel, 39);
    ASSERT_EQ(x.signal_valid, 1);
    ASSERT_EQ(x.signal_dbm, -48);
    ASSERT_EQ(x.lap, 0x123456u);
    ASSERT_EQ(x.iac, 0);
    ASSERT_EQ(x.ref_lap_valid, 1);
    ASSERT_EQ(x.ref_lap, 0x123456u);
    ASSERT_EQ(x.ref_uap_configured, 1);
    ASSERT_EQ(x.ref_uap, 0x5A);
}

/* Octet 15 means something only under flag 0x0080. Seen to fail: with
 * the flag test in bredr_bb_parse() removed, ref_uap reads 0x5A. */
static void test_bredr_reference_uap_ignored_without_its_flag(void) {
    uint8_t b[32];
    int n = bredr_rec(b, 0, 0, 0x123456, 0x123456, 0x5A, BREDR_F_REF_LAP_VALID);
    bredr_bb_t x;
    ASSERT_EQ(bredr_bb_parse(b, (size_t)n, &x), 0);
    ASSERT_EQ(x.ref_uap_configured, 0);
    ASSERT_EQ(x.ref_uap, 0);
}

static void test_bredr_inquiry_access_code_and_bounds(void) {
    uint8_t b[32];
    bredr_bb_t x;
    int n = bredr_rec(b, 5, 0, BREDR_GIAC, 0, 0, 0);
    ASSERT_EQ(bredr_bb_parse(b, (size_t)n, &x), 0);
    ASSERT_EQ(x.iac, 1);
    ASSERT_EQ(bredr_lap_is_iac(0x9E8B00), 1);
    ASSERT_EQ(bredr_lap_is_iac(0x9E8B3F), 1);
    ASSERT_EQ(bredr_lap_is_iac(0x9E8B40), 0);
    ASSERT_EQ(bredr_lap_is_iac(0x9E8AFF), 0);
    ASSERT_EQ(bredr_bb_parse(b, BREDR_BB_HDR_LEN - 1, &x), -1);
    b[0] = 79;
    ASSERT_EQ(bredr_bb_parse(b, (size_t)n, &x), -1);
    ASSERT_EQ(x.lap, 0u);
}

/* The only printed form is the LAP: six hex digits, no colons, nothing
 * that reads as a BD_ADDR. Seen to fail: a colon-separated format in
 * bredr_lap_format() turns both assertions red. */
static void test_bredr_lap_format_is_lap_only(void) {
    char buf[32];
    bredr_lap_format(0xFF123456u, buf, sizeof(buf));
    ASSERT_STR(buf, "LAP 123456");
    ASSERT(strchr(buf, ':') == NULL);
    bredr_lap_format(0x9E8B33, buf, 4);
    ASSERT_STR(buf, "LAP");
}

/* ── Stream framing ─────────────────────────────────────────────── */

static uint8_t g_file[8192];

static int file_hdr(uint8_t *b, uint32_t dlt) {
    put32(b, 0xA1B2C3D4u);
    put16(b + 4, 2); put16(b + 6, 4);
    put32(b + 8, 0); put32(b + 12, 0);
    put32(b + 16, 65535); put32(b + 20, dlt);
    return 24;
}

static int file_rec(uint8_t *b, uint32_t ts, const uint8_t *d, uint32_t len,
                    uint32_t orig) {
    put32(b, ts); put32(b + 4, 0); put32(b + 8, len); put32(b + 12, orig);
    if (len) memcpy(b + 16, d, len);
    return 16 + (int)len;
}

static bt_stream_t g_st;

static void feed_all(const uint8_t *b, size_t n, int one_at_a_time) {
    if (one_at_a_time)
        for (size_t i = 0; i < n; i++) bt_stream_feed(&g_st, b + i, 1, g_wall);
    else
        bt_stream_feed(&g_st, b, n, g_wall);
}

static const ble_device_t *find_dev(const char *iface) {
    for (int i = 0; i < g_s.ble_device_count; i++)
        if (strcmp(g_s.ble_devices[i].sensor_iface, iface) == 0)
            return &g_s.ble_devices[i];
    return NULL;
}

static void test_stream_frames_dlt_256_octet_by_octet(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(NULL, pinned_wall);
    bt_stream_configure();
    bt_stream_init(&g_st);
    uint8_t r[64];
    int rn = rec_adv_ind(r, 0, -70, BTLE_PHDR_SIGNAL_VALID);
    int n = file_hdr(g_file, BTLE_DLT_LL_PHDR);
    n += file_rec(g_file + n, TS, r, (uint32_t)rn, (uint32_t)rn);
    n += file_rec(g_file + n, TS + 5, r, (uint32_t)rn, (uint32_t)rn);
    feed_all(g_file, (size_t)n, 1);
    ble_snapshot(&g_s);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.btcap.state, (int)BT_CAP_STREAMING);
    ASSERT_EQ(g_s.btcap.dlt, 256);
    ASSERT_EQ(g_s.btcap.channels_of, 40);
    ASSERT_EQ((int)g_s.btcap.recv, 2);
    ASSERT_EQ((int)g_s.btcap.adv, 2);
    ASSERT_EQ((int)g_s.btcap.drop, 0);
    ASSERT_EQ(g_s.btcap.last_frame_ts, (time_t)(TS + 5));
    ASSERT_EQ(g_s.btcap.stale_secs, 0);
    ASSERT_EQ(g_s.ble_device_count, 1);
    const ble_device_t *d = find_dev(BT_CAPTURE_IFACE);
    ASSERT(d != NULL);
    if (d) {
        ASSERT_EQ(d->sensor_kind, (int)SENSOR_BLE);
        ASSERT_EQ(d->sampled, 1);
        ASSERT_EQ(d->channel, 37);
        ASSERT_EQ((int)d->adv_count, 2);
        ASSERT_EQ(d->addr[0], 0xC1);      /* display order */
        ASSERT_EQ(d->addr[5], 0x66);
        ASSERT_EQ(d->addr_type, 1);
        ASSERT_EQ(d->rssi, -70);
        ASSERT_STR(d->name, "node");
        ASSERT_EQ(d->first_seen, (time_t)TS);
        ASSERT_EQ(d->last_seen, (time_t)(TS + 5));
    }
    sloth_clock_test_set(NULL, NULL);
}

/* A big-endian, nanosecond-resolution writer is the same stream. */
static void test_stream_reads_big_endian_nanosecond_files(void) {
    bt_stream_configure();
    bt_stream_init(&g_st);
    uint8_t r[64];
    int rn = rec_adv_ind(r, 39, 0, 0);
    uint8_t *b = g_file;
    put32be(b, 0xA1B23C4Du);
    b[4] = 0; b[5] = 2; b[6] = 0; b[7] = 4;
    put32be(b + 8, 0); put32be(b + 12, 0); put32be(b + 16, 65535);
    put32be(b + 20, BTLE_DLT_LL_PHDR);
    put32be(b + 24, TS); put32be(b + 28, 999999999u);
    put32be(b + 32, (uint32_t)rn); put32be(b + 36, (uint32_t)rn);
    memcpy(b + 40, r, (size_t)rn);
    ASSERT_EQ(bt_stream_feed(&g_st, b, (size_t)(40 + rn), 1), 1);
    bt_stream_snapshot(&g_s);
    ble_snapshot(&g_s);
    ASSERT_EQ((int)g_s.btcap.adv, 1);
    ASSERT_EQ((int)g_s.btcap.drop, 0);
    ASSERT_EQ(g_s.btcap.last_frame_ts, (time_t)TS);
    const ble_device_t *d = find_dev(BT_CAPTURE_IFACE);
    ASSERT(d != NULL);
    if (d) ASSERT_EQ(d->channel, 39);
}

/* Seen to fail: with the link-type check in take_file_header() removed,
 * the record after the DLT 1 header is read and counted. */
static void test_stream_refuses_other_link_types(void) {
    bt_stream_configure();
    bt_stream_init(&g_st);
    uint8_t r[64];
    int rn = rec_adv_ind(r, 0, 0, 0);
    int n = file_hdr(g_file, 1);
    n += file_rec(g_file + n, TS, r, (uint32_t)rn, (uint32_t)rn);
    ASSERT_EQ(bt_stream_feed(&g_st, g_file, (size_t)n, 1), 0);
    ASSERT_EQ(bt_stream_feed(&g_st, g_file, (size_t)n, 1), 0);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.btcap.state, (int)BT_CAP_REFUSED);
    ASSERT_EQ(g_s.btcap.refused_dlt, 1);
    ASSERT_EQ(g_s.btcap.dlt, -1);
    ASSERT(strstr(g_s.btcap.err, "link type 1 refused") != NULL);
    ASSERT_EQ((int)g_s.btcap.recv, 0);
    /* DLT 254 is a host source, not an Ubertooth one: refused here too. */
    bt_stream_init(&g_st);
    n = file_hdr(g_file, 254);
    ASSERT_EQ(bt_stream_feed(&g_st, g_file, (size_t)n, 1), 0);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.btcap.refused_dlt, 254);
}

static void test_stream_refuses_pcapng_and_garbage(void) {
    bt_stream_configure();
    bt_stream_init(&g_st);
    uint8_t b[24];
    memset(b, 0, sizeof(b));
    put32(b, 0x0A0D0D0Au);
    ASSERT_EQ(bt_stream_feed(&g_st, b, sizeof(b), 1), 0);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.btcap.state, (int)BT_CAP_REFUSED);
    ASSERT(strstr(g_s.btcap.err, "pcapng") != NULL);
    bt_stream_init(&g_st);
    memcpy(b, "GET / HTTP/1.1\r\n", 16);
    ASSERT_EQ(bt_stream_feed(&g_st, b, sizeof(b), 1), 0);
    bt_stream_snapshot(&g_s);
    ASSERT_STR(g_s.btcap.err, "not a pcap file");
    /* Right magic, wrong major version. */
    bt_stream_init(&g_st);
    file_hdr(b, BTLE_DLT_LL_PHDR);
    put16(b + 4, 1);
    ASSERT_EQ(bt_stream_feed(&g_st, b, sizeof(b), 1), 0);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.btcap.state, (int)BT_CAP_REFUSED);
}

/* A record over the per-record cap is skipped whole and the next one is
 * still found; a length past any real record ends the stream. */
static void test_stream_keeps_step_past_an_oversized_record(void) {
    bt_stream_configure();
    bt_stream_init(&g_st);
    static uint8_t big[16 + 70000];
    uint8_t r[64];
    int rn = rec_adv_ind(r, 0, 0, 0);
    int n = file_hdr(g_file, BTLE_DLT_LL_PHDR);
    ASSERT_EQ(bt_stream_feed(&g_st, g_file, (size_t)n, 1), 1);
    memset(big, 0x41, sizeof(big));
    put32(big, TS); put32(big + 4, 0); put32(big + 8, 70000); put32(big + 12, 70000);
    ASSERT_EQ(bt_stream_feed(&g_st, big, sizeof(big), 1), 1);
    n = file_rec(g_file, TS, r, (uint32_t)rn, (uint32_t)rn);
    ASSERT_EQ(bt_stream_feed(&g_st, g_file, (size_t)n, 1), 1);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ((int)g_s.btcap.recv, 2);
    ASSERT_EQ((int)g_s.btcap.drop, 1);
    ASSERT_EQ((int)g_s.btcap.adv, 1);
    ASSERT_EQ(g_s.btcap.state, (int)BT_CAP_STREAMING);

    uint8_t h[16];
    put32(h, TS); put32(h + 4, 0); put32(h + 8, BT_STREAM_REC_SANE + 1);
    put32(h + 12, BT_STREAM_REC_SANE + 1);
    ASSERT_EQ(bt_stream_feed(&g_st, h, sizeof(h), 1), 0);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.btcap.state, (int)BT_CAP_ERROR);
    ASSERT(strstr(g_s.btcap.err, "stream corrupt") != NULL);
}

/* The pcap-edge gate runs on every record: captured > original and a
 * microsecond field out of range are refused before any decoder. */
static void test_stream_records_pass_the_edge_gate(void) {
    bt_stream_configure();
    bt_stream_init(&g_st);
    sh_parse_fault_reset();
    uint8_t r[64];
    int rn = rec_adv_ind(r, 0, 0, 0);
    int n = file_hdr(g_file, BTLE_DLT_LL_PHDR);
    n += file_rec(g_file + n, TS, r, (uint32_t)rn, (uint32_t)rn - 1);
    int m = file_rec(g_file + n, TS, r, (uint32_t)rn, (uint32_t)rn);
    put32(g_file + n + 4, 1000000);
    n += m;
    ASSERT_EQ(bt_stream_feed(&g_st, g_file, (size_t)n, 1), 1);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ((int)g_s.btcap.recv, 2);
    ASSERT_EQ((int)g_s.btcap.drop, 2);
    ASSERT_EQ((int)g_s.btcap.adv, 0);
    ASSERT_EQ((int)sh_parse_fault_count(SH_PF_FRAME_EDGE), 2);
}

/* Every record lands in exactly one bucket, and they sum to recv.
 * Seen to fail: counting an AdvA-less advertisement as `adv` instead of
 * a drop turns the adv and drop assertions red. */
static void test_stream_buckets_sum_to_recv(void) {
    bt_stream_configure();
    uint8_t pl[40], b[80];
    memset(pl, 0, sizeof(pl));
    memcpy(pl, PEER, 6); memcpy(pl + 6, ADVA, 6);
    int h;
    h = phdr(b, 0, 0, 0);
    bt_stream_record(256, b, (size_t)(h + le_pkt(b + h, BTLE_ADV_AA, BTLE_SCAN_REQ, 0, 0, 12, pl, 12, 1)), TS, 1);
    bt_stream_record(256, b, (size_t)(h + le_pkt(b + h, BTLE_ADV_AA, BTLE_CONNECT_IND, 0, 0, 34, pl, 34, 0)), TS, 1);
    bt_stream_record(256, b, (size_t)(h + le_pkt(b + h, BTLE_ADV_AA, BTLE_ADV_EXT_IND, 0, 0, 10, pl, 10, 0)), TS, 1);
    bt_stream_record(256, b, (size_t)(h + le_pkt(b + h, 0x11223344u, 0, 0, 0, 10, pl, 10, 0)), TS, 1);
    bt_stream_record(256, b, (size_t)(h + le_pkt(b + h, BTLE_ADV_AA, BTLE_AUX_CONNECT_RSP, 0, 0, 14, pl, 14, 0)), TS, 1);
    bt_stream_record(256, b, (size_t)(h + le_pkt(b + h, BTLE_ADV_AA, BTLE_ADV_IND, 0, 0, 3, pl, 3, 0)), TS, 1);
    bt_stream_record(256, b, (size_t)(h + le_pkt(b + h, BTLE_ADV_AA, BTLE_ADV_IND, 0, 0, 30, pl, 2, 0)), TS, 1);
    bt_stream_record(255, b, 4, TS, 1);
    bt_stream_record(77, b, 30, TS, 1);
    bt_stream_snapshot(&g_s);
    const bt_capture_health_t *c = &g_s.btcap;
    ASSERT_EQ((int)c->recv, 9);
    ASSERT_EQ((int)c->scan_req, 1);
    ASSERT_EQ((int)c->connect_ind, 1);
    ASSERT_EQ((int)c->ext_adv, 1);
    ASSERT_EQ((int)c->data_pdus, 1);
    ASSERT_EQ((int)c->other, 1);
    ASSERT_EQ((int)c->adv, 0);
    /* Length 3 ADV_IND (malformed), the AdvA-less truncated one, the
     * short BR/EDR header and the unknown link type. */
    ASSERT_EQ((int)c->drop, 4);
    ASSERT_EQ((int)c->truncated, 1);
    ASSERT_EQ((int)(c->drop + c->adv + c->scan_req + c->connect_ind +
                    c->ext_adv + c->data_pdus + c->other + c->bredr),
              (int)c->recv);
}

/* Two sensors hearing one advertiser are two rows (#144 slice 3).
 * Seen to fail: with the sensor_iface comparison removed from
 * dev_key_eq(), the HCI and Ubertooth sightings share a row. */
static void test_host_and_ubertooth_sightings_do_not_merge(void) {
    /* Host source: one LE Advertising Report over the monitor channel. */
    uint8_t rec[64];
    int n = 0;
    rec[n++] = 0; rec[n++] = 0; rec[n++] = 0; rec[n++] = BT_MON_EVENT_PKT;
    rec[n++] = 0x3E; rec[n++] = 12; rec[n++] = 0x02; rec[n++] = 1;
    rec[n++] = 0x00; rec[n++] = 0x01;
    memcpy(rec + n, ADVA, 6); n += 6;
    rec[n++] = 0; rec[n++] = (uint8_t)(int8_t)-40;
    ASSERT_EQ((int)ble_mon_ingest(rec, (size_t)n, (size_t)n, TS, TS), (int)BLE_REC_ADV);
    uint8_t r[64];
    int rn = rec_adv_ind(r, 0, 0, 0);
    bt_stream_configure();
    bt_stream_record(256, r, (size_t)rn, TS, TS);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_device_count, 2);
    const ble_device_t *h = find_dev(BT_MONITOR_DEVICE);
    const ble_device_t *u = find_dev(BT_CAPTURE_IFACE);
    ASSERT(h != NULL);
    ASSERT(u != NULL);
    if (h && u) {
        ASSERT_EQ(h->sampled, 0);
        ASSERT_EQ(h->channel, -1);
        ASSERT_EQ(u->sampled, 1);
        ASSERT_EQ((int)h->adv_count, 1);
        ASSERT_EQ((int)u->adv_count, 1);
        ASSERT(memcmp(h->addr, u->addr, 6) == 0);
    }
}

/* Seen to fail, twice: with the inquiry-access-code test dropped from
 * bt_stream_record() the GIAC gets a row (count 3); with the
 * reference-LAP match dropped from lap_observe_locked() the second
 * piconet is credited the configured UAP. */
static void test_bredr_stream_fills_the_lap_table(void) {
    bt_stream_configure();
    bt_stream_init(&g_st);
    uint8_t r[32];
    int n = file_hdr(g_file, BREDR_DLT_BB);
    int rn = bredr_rec(r, 39, -50, 0x123456, 0x123456, 0x5A,
                       BREDR_F_SIGNAL_VALID | BREDR_F_REF_LAP_VALID |
                       BREDR_F_REF_UAP_VALID);
    n += file_rec(g_file + n, TS, r, (uint32_t)rn, (uint32_t)rn);
    n += file_rec(g_file + n, TS + 1, r, (uint32_t)rn, (uint32_t)rn);
    /* Another piconet while the tool's reference is still 0x123456: the
     * configured UAP does not belong to it. */
    rn = bredr_rec(r, 39, -60, 0xABCDEF, 0x123456, 0x5A,
                   BREDR_F_REF_LAP_VALID | BREDR_F_REF_UAP_VALID);
    n += file_rec(g_file + n, TS + 2, r, (uint32_t)rn, (uint32_t)rn);
    rn = bredr_rec(r, 39, 0, BREDR_GIAC, 0, 0, 0);
    n += file_rec(g_file + n, TS + 3, r, (uint32_t)rn, (uint32_t)rn);
    ASSERT_EQ(bt_stream_feed(&g_st, g_file, (size_t)n, 1), 1);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.btcap.dlt, 255);
    ASSERT_EQ(g_s.btcap.channels_of, 79);
    ASSERT_EQ((int)g_s.btcap.bredr, 4);
    ASSERT_EQ((int)g_s.btcap.bredr_iac, 1);
    ASSERT_EQ(g_s.bredr_lap_count, 2);
    const bredr_lap_t *a = NULL, *o = NULL;
    for (int i = 0; i < g_s.bredr_lap_count; i++) {
        if (g_s.bredr_laps[i].lap == 0x123456u) a = &g_s.bredr_laps[i];
        if (g_s.bredr_laps[i].lap == 0xABCDEFu) o = &g_s.bredr_laps[i];
    }
    ASSERT(a != NULL);
    ASSERT(o != NULL);
    if (a) {
        ASSERT_EQ((int)a->count, 2);
        ASSERT_EQ(a->channel, 39);
        ASSERT_EQ(a->rssi_best, -50);
        ASSERT_EQ(a->ref_uap_configured, 1);
        ASSERT_EQ(a->ref_uap, 0x5A);
    }
    if (o) {
        ASSERT_EQ(o->ref_uap_configured, 0);
        ASSERT_EQ(o->ref_uap, 0);
        ASSERT_EQ(o->has_rssi, 0);
    }
    /* No advertiser rows come out of a BR/EDR stream. Not isolable by
     * mutation: there is no path from DLT 255 to the device table to
     * remove, so this pins that none is added rather than a guard. */
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_device_count, 0);
}

static void test_lap_table_evicts_and_tallies(void) {
    sh_evict_reset();
    bt_stream_configure();
    uint8_t r[32];
    for (uint32_t i = 0; i < MAX_BREDR_LAPS + 3; i++) {
        int rn = bredr_rec(r, 1, 0, 0x100000 + i, 0, 0, 0);
        bt_stream_record(255, r, (size_t)rn, (time_t)(TS + i), 1);
    }
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.bredr_lap_count, MAX_BREDR_LAPS);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_BREDR_LAP), 3);
    ASSERT_STR(sh_evict_name(SH_EVICT_BREDR_LAP), "bredr_lap");
}

static void test_state_names(void) {
    ASSERT_STR(bt_cap_state_name(BT_CAP_OFF), "off");
    ASSERT_STR(bt_cap_state_name(BT_CAP_WAITING), "waiting");
    ASSERT_STR(bt_cap_state_name(BT_CAP_STREAMING), "streaming");
    ASSERT_STR(bt_cap_state_name(BT_CAP_EOF), "eof");
    ASSERT_STR(bt_cap_state_name(BT_CAP_REFUSED), "refused");
    ASSERT_STR(bt_cap_state_name(BT_CAP_ERROR), "error");
    ASSERT_STR(bt_cap_state_name(BT_CAP_STOPPED), "stopped");
    ASSERT_STR(bt_cap_state_name(99), "");
    /* Untouched, the stream reads off with nothing taken or refused. */
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.btcap.configured, 0);
    ASSERT_EQ(g_s.btcap.state, (int)BT_CAP_OFF);
    ASSERT_EQ(g_s.btcap.dlt, -1);
    ASSERT_EQ(g_s.btcap.refused_dlt, -1);
    ASSERT_EQ(g_s.btcap.stale_secs, -1);
}

/* ── sensor_health ──────────────────────────────────────────────── */

static char g_tmp[] = "/tmp/sloth_ubt_XXXXXX";

static int open_tmp_jsonl(void) {
    int fd = mkstemp(g_tmp);
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_tmp);
    return jsonl_open(g_tmp);
}

static char *slurp_tmp(void) {
    FILE *fp = fopen(g_tmp, "r");
    if (!fp) return NULL;
    static char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

static int count_lines(const char *b) {
    int n = 0;
    for (; b && *b; b++) if (*b == '\n') n++;
    return n;
}

static void snap_emit(void) {
    ble_snapshot(&g_s);
    bt_stream_snapshot(&g_s);
    jsonl_emit_sensor_health(&g_s);
}

/* The stream block, and its signature: a further record (recv moves)
 * is not a line, the first drop and the first truncation are, a second
 * of either is not.
 *
 * Seen to fail: with `sig.btcap_drop_any` set from the raw drop count,
 * the second drop below writes a fifth line. */
static void test_sensor_health_carries_the_stream_bucketed(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(NULL, pinned_wall);
    ASSERT(open_tmp_jsonl());
    memset(&g_s, 0, sizeof(g_s));
    bt_stream_configure();
    bt_stream_init(&g_st);
    uint8_t r[64];
    int rn = rec_adv_ind(r, 0, -70, BTLE_PHDR_SIGNAL_VALID);
    int n = file_hdr(g_file, BTLE_DLT_LL_PHDR);
    n += file_rec(g_file + n, TS, r, (uint32_t)rn, (uint32_t)rn);
    bt_stream_feed(&g_st, g_file, (size_t)n, g_wall);
    snap_emit();                                            /* 1 */
    n = file_rec(g_file, TS + 1, r, (uint32_t)rn, (uint32_t)rn);
    bt_stream_feed(&g_st, g_file, (size_t)n, g_wall);
    snap_emit();                                            /* suppressed */
    n = file_rec(g_file, TS + 2, r, 4, 4);                  /* malformed */
    bt_stream_feed(&g_st, g_file, (size_t)n, g_wall);
    snap_emit();                                            /* 2: first drop */
    bt_stream_feed(&g_st, g_file, (size_t)n, g_wall);
    snap_emit();                                            /* suppressed */
    n = file_rec(g_file, TS + 3, r, (uint32_t)rn - 4, (uint32_t)rn);
    bt_stream_feed(&g_st, g_file, (size_t)n, g_wall);
    snap_emit();                                            /* 3: truncated */
    g_wall += 120;
    snap_emit();                                            /* 4: fresh -> stale */
    jsonl_close();
    char *b = slurp_tmp();
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_lines(b), 4);
        ASSERT(strstr(b, "\"btcap_iface\":\"ubertooth\"") != NULL);
        ASSERT(strstr(b, "\"btcap_state\":\"streaming\"") != NULL);
        ASSERT(strstr(b, "\"btcap_dlt\":256") != NULL);
        ASSERT(strstr(b, "\"btcap_refused_dlt\":-1") != NULL);
        ASSERT(strstr(b, "\"btcap_sampling\":\"1_of_40_channels\"") != NULL);
        ASSERT(strstr(b, "\"btcap_recv\":1,") != NULL);
        ASSERT(strstr(b, "\"btcap_adv\":1,") != NULL);
        ASSERT(strstr(b, "\"btcap_drop\":1,") != NULL);
        ASSERT(strstr(b, "\"btcap_truncated\":1,") != NULL);
        ASSERT(strstr(b, "\"btcap_stale_secs\":120") != NULL);
        ASSERT(strstr(b, "\"evict_bredr_lap\":") != NULL);
    }
    unlink(g_tmp);
    sloth_clock_test_set(NULL, NULL);
}

static void test_sensor_health_names_a_refused_link_type(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(NULL, pinned_wall);
    ASSERT(open_tmp_jsonl());
    memset(&g_s, 0, sizeof(g_s));
    snap_emit();                                            /* 1: off */
    bt_stream_configure();
    bt_stream_init(&g_st);
    int n = file_hdr(g_file, 105);
    bt_stream_feed(&g_st, g_file, (size_t)n, g_wall);
    snap_emit();                                            /* 2: refused */
    jsonl_close();
    char *b = slurp_tmp();
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_lines(b), 2);
        ASSERT(strstr(b, "\"btcap_iface\":\"\"") != NULL);
        ASSERT(strstr(b, "\"btcap_state\":\"off\"") != NULL);
        ASSERT(strstr(b, "\"btcap_state\":\"refused\"") != NULL);
        ASSERT(strstr(b, "\"btcap_refused_dlt\":105") != NULL);
        ASSERT(strstr(b, "\"btcap_sampling\":\"\"") != NULL);
    }
    unlink(g_tmp);
    sloth_clock_test_set(NULL, NULL);
}

/* ── The reader: one open, off the main thread ──────────────────── */

#ifdef WITH_PCAP
static char g_dir[] = "/tmp/sloth_ubt_dir_XXXXXX";

static void nap_ms(int ms) {
    struct timespec t = { 0, (long)ms * 1000000L };
    nanosleep(&t, NULL);
}

/* Elapsed real milliseconds. Read off CLOCK_MONOTONIC directly, not
 * through the clock seam: the seam is pinned for these tests, and what
 * is measured here is how long run() and stop() really take. */
static long ms_since(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (long)(t1.tv_sec - t0->tv_sec) * 1000L +
           (t1.tv_nsec - t0->tv_nsec) / 1000000L;
}

static int wait_for(int (*cond)(void), int ms) {
    for (int i = 0; i < ms / 10; i++) {
        bt_stream_snapshot(&g_s);
        if (cond()) return 1;
        nap_ms(10);
    }
    bt_stream_snapshot(&g_s);
    return cond();
}

static int cond_adv1(void) { return g_s.btcap.adv >= 1; }
static int cond_eof(void)  { return g_s.btcap.state == BT_CAP_EOF; }
static int cond_refused(void) { return g_s.btcap.state == BT_CAP_REFUSED; }

static int capture_file_bytes(uint32_t dlt) {
    uint8_t r[64];
    int rn = rec_adv_ind(r, 0, 0, 0);
    int n = file_hdr(g_file, dlt);
    n += file_rec(g_file + n, TS, r, (uint32_t)rn, (uint32_t)rn);
    return n;
}

static void test_configure_refuses_missing_and_wrong_types(void) {
    char err[256];
    ASSERT(mkdtemp(g_dir) != NULL);
    char path[300];
    snprintf(path, sizeof(path), "%s/absent", g_dir);
    ASSERT_EQ(bt_capture_configure(path, err, sizeof(err)), -1);
    ASSERT(strstr(err, "absent") != NULL);
    ASSERT_EQ(bt_capture_configure(g_dir, err, sizeof(err)), -1);
    ASSERT(strstr(err, "not a regular file or FIFO") != NULL);
    ASSERT_EQ(bt_capture_configure("", err, sizeof(err)), -1);
    rmdir(g_dir);
    memcpy(g_dir + strlen(g_dir) - 6, "XXXXXX", 6);
}

/* A FIFO nobody writes to yet: run() returns at once and the stream
 * waits; a writer that comes later is read from the same descriptor;
 * its close is the end of the stream. */
static void test_fifo_without_writer_does_not_block_and_is_read_once(void) {
    ASSERT(mkdtemp(g_dir) != NULL);
    char path[300], err[256];
    snprintf(path, sizeof(path), "%s/ubt.fifo", g_dir);
    ASSERT_EQ(mkfifo(path, 0600), 0);
    ASSERT_EQ(bt_capture_configure(path, err, sizeof(err)), 0);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    bt_capture_run();
    ASSERT(ms_since(&t0) < 500);
    nap_ms(150);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.btcap.state, (int)BT_CAP_WAITING);
    ASSERT_EQ((int)g_s.btcap.recv, 0);

    /* The reader holds the FIFO open, so a non-blocking writer open
     * succeeds; ENXIO would mean the worker never opened it. */
    int w = -1;
    for (int i = 0; i < 100 && w < 0; i++) {
        w = open(path, O_WRONLY | O_NONBLOCK);
        if (w < 0) nap_ms(10);
    }
    ASSERT(w >= 0);
    if (w >= 0) {
        int n = capture_file_bytes(BTLE_DLT_LL_PHDR);
        ASSERT_EQ((int)write(w, g_file, (size_t)n), n);
        ASSERT(wait_for(cond_adv1, 3000));
        ASSERT_EQ(g_s.btcap.state, (int)BT_CAP_STREAMING);
        close(w);
        ASSERT(wait_for(cond_eof, 3000));
    }
    bt_capture_stop();
    unlink(path);
    rmdir(g_dir);
    memcpy(g_dir + strlen(g_dir) - 6, "XXXXXX", 6);
}

/* Stop while the FIFO has never had a writer: the worker is waiting,
 * not stuck in open(). Seen to fail: with O_NONBLOCK dropped from the
 * worker's open(), the worker blocks in open() and this test's
 * bt_capture_stop() never returns - a hang, killed by `timeout`, for
 * the same reason as the test below. */
static void test_stop_returns_with_no_writer_ever(void) {
    ASSERT(mkdtemp(g_dir) != NULL);
    char path[300], err[256];
    snprintf(path, sizeof(path), "%s/ubt.fifo", g_dir);
    ASSERT_EQ(mkfifo(path, 0600), 0);
    ASSERT_EQ(bt_capture_configure(path, err, sizeof(err)), 0);
    bt_capture_run();
    nap_ms(150);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    bt_capture_stop();
    ASSERT(ms_since(&t0) < 1000);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.btcap.state, (int)BT_CAP_STOPPED);
    ASSERT_EQ((int)g_s.btcap.recv, 0);
    unlink(path);
    rmdir(g_dir);
    memcpy(g_dir + strlen(g_dir) - 6, "XXXXXX", 6);
}

/* A writer holding the FIFO open and sending nothing cannot keep stop
 * from returning. Seen to fail: with the worker's poll() given no
 * timeout, the suite hangs in a bt_capture_stop() and is killed by
 * `timeout` — first in the no-writer test above, which that mutation
 * also defeats, so this test's own hang is shown only with that test
 * skipped. A hang, not a red assertion, is how these fail, because the
 * join never comes back to assert anything. */
static void test_stop_returns_with_a_silent_writer(void) {
    ASSERT(mkdtemp(g_dir) != NULL);
    char path[300], err[256];
    snprintf(path, sizeof(path), "%s/ubt.fifo", g_dir);
    ASSERT_EQ(mkfifo(path, 0600), 0);
    ASSERT_EQ(bt_capture_configure(path, err, sizeof(err)), 0);
    bt_capture_run();
    int w = -1;
    for (int i = 0; i < 100 && w < 0; i++) {
        w = open(path, O_WRONLY | O_NONBLOCK);
        if (w < 0) nap_ms(10);
    }
    ASSERT(w >= 0);
    nap_ms(50);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    bt_capture_stop();
    ASSERT(ms_since(&t0) < 1000);
    bt_stream_snapshot(&g_s);
    ASSERT_EQ(g_s.btcap.state, (int)BT_CAP_STOPPED);
    if (w >= 0) close(w);
    unlink(path);
    rmdir(g_dir);
    memcpy(g_dir + strlen(g_dir) - 6, "XXXXXX", 6);
}

/* A regular file is read to its end; one with a refused link type stops
 * at the header. */
static void test_regular_files_read_to_end_or_refused(void) {
    ASSERT(mkdtemp(g_dir) != NULL);
    char path[300], err[256];
    snprintf(path, sizeof(path), "%s/ubt.pcap", g_dir);
    int n = capture_file_bytes(BTLE_DLT_LL_PHDR);
    FILE *fp = fopen(path, "wb");
    ASSERT(fp != NULL);
    if (fp) { fwrite(g_file, 1, (size_t)n, fp); fclose(fp); }
    ASSERT_EQ(bt_capture_configure(path, err, sizeof(err)), 0);
    bt_capture_run();
    ASSERT(wait_for(cond_eof, 3000));
    ASSERT_EQ((int)g_s.btcap.adv, 1);
    bt_capture_stop();

    bt_stream_clear();
    n = capture_file_bytes(1);
    fp = fopen(path, "wb");
    ASSERT(fp != NULL);
    if (fp) { fwrite(g_file, 1, (size_t)n, fp); fclose(fp); }
    ASSERT_EQ(bt_capture_configure(path, err, sizeof(err)), 0);
    bt_capture_run();
    ASSERT(wait_for(cond_refused, 3000));
    ASSERT_EQ(g_s.btcap.refused_dlt, 1);
    ASSERT_EQ((int)g_s.btcap.recv, 0);
    bt_capture_stop();
    unlink(path);
    rmdir(g_dir);
    memcpy(g_dir + strlen(g_dir) - 6, "XXXXXX", 6);
}
#endif /* WITH_PCAP */

/* ── Never sends ────────────────────────────────────────────────── */

static char *slurp_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (buf) { buf[fread(buf, 1, (size_t)n, fp)] = '\0'; }
    fclose(fp);
    return buf;
}

/* MISSION §2: sloth reads the operator's file and never touches the
 * dongle — no libpcap send, no USB request, no child process that could
 * be an ubertooth tool. A source scan, not a behaviour test, and named
 * as such. Seen to fail: a popen( added to bt_capture.c turns it red. */
static void test_ubertooth_files_never_send_or_spawn(void) {
    static const char *const files[] = {
        "src/capture/bt_capture.c", "src/capture/bt_capture.h",
        "src/bt_stream.c", "src/btle_ll.c", "src/bredr_bb.c"
    };
    static const char *const banned[] = {
        "pcap_inject", "pcap_sendpacket", "libusb", "usbdevfs", "USBDEVFS",
        "ioctl(", "socket(", "popen(", "system(", "fork(", "execv", "execl",
        "posix_spawn", "write("
    };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        char *src = slurp_file(files[i]);
        ASSERT(src != NULL);
        if (!src) continue;
        for (size_t j = 0; j < sizeof(banned) / sizeof(banned[0]); j++) {
            if (strstr(src, banned[j]))
                printf("    %s contains %s\n", files[i], banned[j]);
            ASSERT(strstr(src, banned[j]) == NULL);
        }
        free(src);
    }
}

/* Every test here reaches bt_stream_snapshot(), which reads the wall
 * clock for stale_secs, so every test runs with it pinned: the default
 * setUp first, then the pin. The worker tests rely on the pin being set
 * before their thread starts. */
static void (*g_prev_setup)(void);
static void ubt_setup(void) {
    if (g_prev_setup) g_prev_setup();
    g_wall = 1800000000;
    sloth_clock_test_set(NULL, pinned_wall);
}

void run_ubertooth_tests(void) {
    TEST_SUITE("Ubertooth capture stream (#144 slice 3)");
    g_prev_setup = g_test_setup;
    g_test_setup = ubt_setup;
    RUN_TEST(test_rf_channel_maps_to_ll_index);
    RUN_TEST(test_adv_ind_with_phdr_decodes);
    RUN_TEST(test_signal_power_used_only_when_flagged_valid);
    RUN_TEST(test_each_advertising_type_maps_to_its_hci_event_type);
    RUN_TEST(test_scan_req_names_scanner_and_advertiser);
    RUN_TEST(test_connect_ind_fields_and_hop_sca_packing);
    RUN_TEST(test_lengths_outside_the_type_range_are_malformed);
    RUN_TEST(test_claim_past_the_record_is_truncated_not_read);
    RUN_TEST(test_truncated_before_adva_gives_no_report);
    RUN_TEST(test_ubertooth_capture_limit_bounds_the_trusted_length);
    RUN_TEST(test_data_channel_and_other_pdus_are_not_decoded);
    RUN_TEST(test_ppi_wrapped_le_ll_decodes_without_channel);
    RUN_TEST(test_bredr_header_decodes_lap_and_labels_reference_uap);
    RUN_TEST(test_bredr_reference_uap_ignored_without_its_flag);
    RUN_TEST(test_bredr_inquiry_access_code_and_bounds);
    RUN_TEST(test_bredr_lap_format_is_lap_only);
    RUN_TEST(test_stream_frames_dlt_256_octet_by_octet);
    RUN_TEST(test_stream_reads_big_endian_nanosecond_files);
    RUN_TEST(test_stream_refuses_other_link_types);
    RUN_TEST(test_stream_refuses_pcapng_and_garbage);
    RUN_TEST(test_stream_keeps_step_past_an_oversized_record);
    RUN_TEST(test_stream_records_pass_the_edge_gate);
    RUN_TEST(test_stream_buckets_sum_to_recv);
    RUN_TEST(test_host_and_ubertooth_sightings_do_not_merge);
    RUN_TEST(test_bredr_stream_fills_the_lap_table);
    RUN_TEST(test_lap_table_evicts_and_tallies);
    RUN_TEST(test_state_names);
    RUN_TEST(test_sensor_health_carries_the_stream_bucketed);
    RUN_TEST(test_sensor_health_names_a_refused_link_type);
#ifdef WITH_PCAP
    RUN_TEST(test_configure_refuses_missing_and_wrong_types);
    RUN_TEST(test_fifo_without_writer_does_not_block_and_is_read_once);
    RUN_TEST(test_stop_returns_with_no_writer_ever);
    RUN_TEST(test_stop_returns_with_a_silent_writer);
    RUN_TEST(test_regular_files_read_to_end_or_refused);
#endif
    RUN_TEST(test_ubertooth_files_never_send_or_spawn);
    g_test_setup = g_prev_setup;
    sloth_clock_test_set(NULL, NULL);
}
