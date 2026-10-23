#include <string.h>
#include "runner.h"
#include "ble_snoop.h"

/*
 * BLE HCI advertisement decoder — issue #144 slice 1.
 *
 * Every event buffer is hand-built from the Bluetooth Core Specification
 * v5.x rather than captured (agents/AGENTS.md "no pcap fixtures"): the
 * parser is proved against the spec, and a hand-built blob reaches the
 * truncated / malformed cases a capture cannot.
 *
 * HCI_EV_LE_Meta (0x3E), LE Advertising Report (subevent 0x02),
 * Vol 4 Part E §7.7.65.2:
 *   evt[0] = 0x3E                 event code
 *   evt[1] = param_len            (not cross-checked here; len is the
 *                                  authority, matching production)
 *   evt[2] = 0x02                 subevent code
 *   evt[3] = Num_Reports (N)
 *   evt[4 .. ]  then N consecutive records (Vol 4 Part E §5.2: arrayed
 *               parameters are ParameterA[0], ParameterB[0],
 *               ParameterA[1], ... unless the clause notes otherwise,
 *               and §7.7.65.2 does not):
 *                 Event_Type
 *                 Address_Type
 *                 Address[6]
 *                 Data_Length
 *                 Data[Data_Length]
 *                 RSSI          (signed, 127 = not available)
 *
 * AD structures inside Data, Vol 3 Part C §11 / Assigned Numbers:
 *   len(1) type(1) value(len-1)
 */

static int put_ad(uint8_t *b, int off, uint8_t type, const uint8_t *val, int vlen) {
    b[off++] = (uint8_t)(vlen + 1);
    b[off++] = type;
    if (vlen > 0) memcpy(b + off, val, (size_t)vlen);
    return off + vlen;
}

/* Builds a single-report HCI LE Advertising Report event around a
 * caller-supplied Data payload. Returns the total event length. */
static int build_single_report(uint8_t *evt, const uint8_t addr[6],
                               uint8_t addr_type, const uint8_t *data,
                               int data_len, int8_t rssi) {
    int off = 0;
    evt[off++] = 0x3E;
    evt[off++] = 0; /* param_len placeholder; not authoritative here */
    evt[off++] = 0x02;
    evt[off++] = 1; /* Num_Reports */
    evt[off++] = 0; /* Event_Type: ADV_IND */
    evt[off++] = addr_type;
    memcpy(evt + off, addr, 6); off += 6;
    evt[off++] = (uint8_t)data_len;
    memcpy(evt + off, data, (size_t)data_len); off += data_len;
    evt[off++] = (uint8_t)rssi;
    return off;
}

static void cb_capture(const ble_adv_report_t *r, void *ctx) {
    ble_adv_report_t *out = (ble_adv_report_t *)ctx;
    *out = *r;
}

typedef struct {
    ble_adv_report_t reports[4];
    int count;
} multi_capture_t;

static void cb_multi(const ble_adv_report_t *r, void *ctx) {
    multi_capture_t *mc = (multi_capture_t *)ctx;
    if (mc->count < 4) mc->reports[mc->count++] = *r;
}

/* ── ble_ad_parse: individual AD types ──────────────────────── */

static void test_flags(void) {
    uint8_t data[8];
    uint8_t flags = 0x06;
    int n = put_ad(data, 0, 0x01, &flags, 1);
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)n, &out);
    ASSERT(out.has_flags);
    ASSERT_EQ(out.flags, 0x06);
}

static void test_local_name_complete(void) {
    uint8_t data[32];
    const char *name = "Flipper";
    int n = put_ad(data, 0, 0x09, (const uint8_t *)name, (int)strlen(name));
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)n, &out);
    ASSERT(out.has_local_name);
    ASSERT(out.local_name_complete);
    ASSERT(strcmp(out.local_name, "Flipper") == 0);
}

static void test_local_name_shortened_marks_incomplete(void) {
    uint8_t data[32];
    const char *name = "Pixel";
    int n = put_ad(data, 0, 0x08, (const uint8_t *)name, (int)strlen(name));
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)n, &out);
    ASSERT(out.has_local_name);
    ASSERT(!out.local_name_complete);
}

static void test_local_name_clamped_at_max(void) {
    uint8_t data[64];
    uint8_t name[48];
    memset(name, 'A', sizeof(name));
    int n = put_ad(data, 0, 0x09, name, (int)sizeof(name));
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)n, &out);
    ASSERT(out.has_local_name);
    ASSERT_EQ((int)strlen(out.local_name), BLE_LOCAL_NAME_MAX);
    ASSERT(out.local_name[BLE_LOCAL_NAME_MAX] == '\0');
}

static void test_tx_power(void) {
    uint8_t data[8];
    uint8_t p = (uint8_t)(int8_t)(-12);
    int n = put_ad(data, 0, 0x0A, &p, 1);
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)n, &out);
    ASSERT(out.has_tx_power);
    ASSERT_EQ(out.tx_power, -12);
}

static void test_appearance(void) {
    uint8_t data[8];
    uint8_t app[2] = { 0xC0, 0x03 }; /* 0x03C0, HID Generic — WFA assigned numbers */
    int n = put_ad(data, 0, 0x19, app, 2);
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)n, &out);
    ASSERT(out.has_appearance);
    ASSERT_EQ(out.appearance, 0x03C0);
}

static void test_service_uuid16_complete(void) {
    uint8_t data[8];
    uint8_t uuid[2] = { 0x2C, 0xFE }; /* 0xFE2C, Google Fast Pair */
    int n = put_ad(data, 0, 0x03, uuid, 2);
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)n, &out);
    ASSERT(out.has_service_uuid16);
    ASSERT_EQ(out.service_uuid16, 0xFE2C);
}

static void test_service_uuid16_first_wins(void) {
    uint8_t data[16];
    uint8_t first[2]  = { 0x2C, 0xFE };
    uint8_t second[2] = { 0xED, 0xFE };
    int off = put_ad(data, 0, 0x02, first, 2);
    off = put_ad(data, off, 0x02, second, 2);
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)off, &out);
    ASSERT(out.has_service_uuid16);
    ASSERT_EQ(out.service_uuid16, 0xFE2C);
}

static void test_mfr_data_apple(void) {
    uint8_t data[16];
    /* Apple Continuity: company ID 0x004C, then subtype/len/payload. */
    uint8_t mfr[5] = { 0x4C, 0x00, 0x07, 0x02, 0x00 };
    int n = put_ad(data, 0, 0xFF, mfr, 5);
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)n, &out);
    ASSERT(out.has_mfr_data);
    ASSERT_EQ(out.mfr_id, 0x004C);
    ASSERT_EQ(out.mfr_data_len, 3);
    ASSERT_EQ(out.mfr_data[0], 0x07);
}

static void test_mfr_data_clamped_at_max(void) {
    uint8_t data[40];
    uint8_t mfr[2 + 30];
    mfr[0] = 0x6A; mfr[1] = 0x01; /* arbitrary company ID */
    memset(mfr + 2, 0x42, 30);
    int n = put_ad(data, 0, 0xFF, mfr, (int)sizeof(mfr));
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)n, &out);
    ASSERT(out.has_mfr_data);
    ASSERT_EQ(out.mfr_data_len, BLE_MFR_DATA_MAX);
}

static void test_unrecognised_ad_type_skipped_not_error(void) {
    uint8_t data[16];
    uint8_t v[2] = { 0xAA, 0xBB };
    int off = put_ad(data, 0, 0x5A /* not in our switch */, v, 2);
    uint8_t flags = 0x02;
    off = put_ad(data, off, 0x01, &flags, 1);
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)off, &out);
    ASSERT(!out.truncated);
    ASSERT(out.has_flags);
    ASSERT_EQ(out.flags, 0x02);
}

static void test_zero_length_ad_struct_ends_walk(void) {
    uint8_t data[16] = {0};
    uint8_t flags = 0x01;
    int off = put_ad(data, 0, 0x01, &flags, 1);
    data[off] = 0x00; /* zero-length AD struct: padding / end */
    /* Garbage after the zero must never be read as another AD type. */
    data[off + 1] = 0xFF;
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, sizeof(data), &out);
    ASSERT(out.has_flags);
    ASSERT(!out.has_mfr_data);
    ASSERT(!out.truncated);
}

static void test_truncated_ad_struct_sets_flag_keeps_prior(void) {
    uint8_t data[16];
    uint8_t flags = 0x04;
    int off = put_ad(data, 0, 0x01, &flags, 1);
    /* A declared length that runs past the buffer. */
    data[off++] = 0x10; /* claims 16 more bytes */
    data[off++] = 0x09; /* type: complete name */
    /* buffer ends here, far short of 15 value bytes */
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(data, (size_t)off, &out);
    ASSERT(out.truncated);
    ASSERT(out.has_flags); /* the earlier, valid structure is kept */
    ASSERT(!out.has_local_name); /* the truncated one is not */
}

static void test_empty_data_is_a_no_op(void) {
    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    ble_ad_parse(NULL, 0, &out);
    ASSERT(!out.has_flags);
    ASSERT(!out.truncated);
}

/* ── ble_hci_adv_walk: HCI event framing ────────────────────── */

static void test_walk_single_report_decodes(void) {
    uint8_t addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t data[8];
    uint8_t flags = 0x06;
    int dlen = put_ad(data, 0, 0x01, &flags, 1);

    uint8_t evt[64];
    int elen = build_single_report(evt, addr, 1, data, dlen, -40);

    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    int n = ble_hci_adv_walk(evt, (size_t)elen, cb_capture, &out);

    ASSERT_EQ(n, 1);
    ASSERT(out.has_rssi);
    ASSERT_EQ(out.rssi, -40);
    ASSERT_EQ(out.addr_type, 1);
    ASSERT(memcmp(out.addr, addr, 6) == 0);
    ASSERT(out.has_flags);
}

static void test_walk_rssi_not_available(void) {
    uint8_t addr[6] = { 0, 1, 2, 3, 4, 5 };
    uint8_t data[4]; int dlen = put_ad(data, 0, 0x01, (uint8_t[]){0x02}, 1);
    uint8_t evt[64];
    int elen = build_single_report(evt, addr, 0, data, dlen, (int8_t)127);

    ble_adv_report_t out; memset(&out, 0, sizeof(out));
    int n = ble_hci_adv_walk(evt, (size_t)elen, cb_capture, &out);
    ASSERT_EQ(n, 1);
    ASSERT(!out.has_rssi);
}

static void test_walk_wrong_event_code_rejected(void) {
    uint8_t addr[6] = {0};
    uint8_t data[4]; int dlen = put_ad(data, 0, 0x01, (uint8_t[]){0x02}, 1);
    uint8_t evt[64];
    int elen = build_single_report(evt, addr, 0, data, dlen, -50);
    evt[0] = 0x3D; /* not HCI_EV_LE_Meta */

    int calls = 0;
    int n = ble_hci_adv_walk(evt, (size_t)elen, NULL, &calls);
    ASSERT_EQ(n, 0);
}

static void test_walk_wrong_subevent_rejected(void) {
    uint8_t addr[6] = {0};
    uint8_t data[4]; int dlen = put_ad(data, 0, 0x01, (uint8_t[]){0x02}, 1);
    uint8_t evt[64];
    int elen = build_single_report(evt, addr, 0, data, dlen, -50);
    evt[2] = 0x01; /* Connection Complete, not Advertising Report */

    int n = ble_hci_adv_walk(evt, (size_t)elen, NULL, NULL);
    ASSERT_EQ(n, 0);
}

static void test_walk_zero_reports_rejected(void) {
    uint8_t evt[8] = { 0x3E, 0, 0x02, 0 /* Num_Reports */ };
    int n = ble_hci_adv_walk(evt, sizeof(evt), NULL, NULL);
    ASSERT_EQ(n, 0);
}

static void test_walk_short_fixed_fields_rejected(void) {
    /* Claims 2 reports but the buffer has no room for their fixed fields. */
    uint8_t evt[6] = { 0x3E, 0, 0x02, 2, 0x00, 0x00 };
    int n = ble_hci_adv_walk(evt, sizeof(evt), NULL, NULL);
    ASSERT_EQ(n, 0);
}

static void test_walk_short_data_rejected(void) {
    uint8_t addr[6] = {0};
    uint8_t data[8]; int dlen = put_ad(data, 0, 0x01, (uint8_t[]){0x02}, 1);
    uint8_t evt[64];
    int elen = build_single_report(evt, addr, 0, data, dlen, -50);
    /* Truncate the buffer so the declared Data_Length + RSSI octet don't fit. */
    int n = ble_hci_adv_walk(evt, (size_t)(elen - 2), NULL, NULL);
    ASSERT_EQ(n, 0);
}

static void test_walk_null_or_too_short_buffer(void) {
    ASSERT_EQ(ble_hci_adv_walk(NULL, 10, NULL, NULL), 0);
    uint8_t tiny[3] = { 0x3E, 0, 0x02 };
    ASSERT_EQ(ble_hci_adv_walk(tiny, sizeof(tiny), NULL, NULL), 0);
}

/* Two consecutive records (§5.2). Reading the clause's arrays as
 * per-field blocks instead (every Event_Type, then every Address_Type,
 * ...) would hand report 0 an address made of report 1's Event_Type and
 * Address_Type octets, and report 1 the wrong data slice.
 *
 * Seen to fail: with the second loop's per-record stride made
 * `ADV_REC_FIXED + dl` (the RSSI octet dropped), report 1 reads from
 * one octet early and its address and name are wrong. */
static void test_walk_two_reports_are_consecutive_records(void) {
    uint8_t addr_a[6] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    uint8_t addr_b[6] = { 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB };
    uint8_t data_a[4]; int dlen_a = put_ad(data_a, 0, 0x01, (uint8_t[]){0x01}, 1);
    uint8_t data_b[8];
    const char *name_b = "Tile";
    int dlen_b = put_ad(data_b, 0, 0x09, (const uint8_t *)name_b, (int)strlen(name_b));

    uint8_t evt[128];
    int off = 0;
    evt[off++] = 0x3E; evt[off++] = 0; evt[off++] = 0x02; evt[off++] = 2;
    evt[off++] = 0;                                  /* [0] Event_Type */
    evt[off++] = 0;                                  /* [0] Address_Type */
    memcpy(evt + off, addr_a, 6); off += 6;          /* [0] Address */
    evt[off++] = (uint8_t)dlen_a;                    /* [0] Data_Length */
    memcpy(evt + off, data_a, (size_t)dlen_a); off += dlen_a;
    evt[off++] = (uint8_t)(int8_t)-30;               /* [0] RSSI */
    evt[off++] = 0;                                  /* [1] Event_Type */
    evt[off++] = 1;                                  /* [1] Address_Type */
    memcpy(evt + off, addr_b, 6); off += 6;          /* [1] Address */
    evt[off++] = (uint8_t)dlen_b;                    /* [1] Data_Length */
    memcpy(evt + off, data_b, (size_t)dlen_b); off += dlen_b;
    evt[off++] = (uint8_t)(int8_t)-70;               /* [1] RSSI */

    multi_capture_t mc; memset(&mc, 0, sizeof(mc));
    int n = ble_hci_adv_walk(evt, (size_t)off, cb_multi, &mc);

    ASSERT_EQ(n, 2);
    ASSERT_EQ(mc.count, 2);

    ASSERT_EQ(mc.reports[0].addr_type, 0);
    ASSERT(memcmp(mc.reports[0].addr, addr_a, 6) == 0);
    ASSERT_EQ(mc.reports[0].rssi, -30);
    ASSERT(mc.reports[0].has_flags);
    ASSERT(!mc.reports[0].has_local_name);

    ASSERT_EQ(mc.reports[1].addr_type, 1);
    ASSERT(memcmp(mc.reports[1].addr, addr_b, 6) == 0);
    ASSERT_EQ(mc.reports[1].rssi, -70);
    ASSERT(mc.reports[1].has_local_name);
    ASSERT(strcmp(mc.reports[1].local_name, "Tile") == 0);
    ASSERT(!mc.reports[1].has_flags);

    /* The records must fill the buffer: one octet past the second RSSI
     * is not a third report, and the event decodes nothing.
     * Seen to fail: with `if (off != len) return 0;` removed, the walk
     * returns 2 and both callbacks run. */
    evt[off] = 0x00;
    memset(&mc, 0, sizeof(mc));
    ASSERT_EQ(ble_hci_adv_walk(evt, (size_t)off + 1, cb_multi, &mc), 0);
    ASSERT_EQ(mc.count, 0);
    /* And the same bytes under Num_Reports 1 are one report followed by
     * octets it does not own. */
    evt[3] = 1;
    ASSERT_EQ(ble_hci_adv_walk(evt, (size_t)off, cb_multi, &mc), 0);
    ASSERT_EQ(mc.count, 0);
}

/* ── LE Extended Advertising Report (subevent 0x0D) ──────────────────
 *
 * Core Specification v5.x Vol 4 Part E §7.7.65.13, reports as
 * consecutive records (§5.2, quoted in src/ble_snoop.h):
 *
 *   evt[0]  0x3E                 event code
 *   evt[1]  param_len            authoritative: must equal len - 2
 *   evt[2]  0x0D                 subevent code
 *   evt[3]  Num_Reports
 *   then per report (24 octets + Data):
 *     +0  Event_Type LE16        bit 0 connectable, 1 scannable,
 *                                2 directed, 3 scan response, 4 legacy,
 *                                5-6 data status (00 complete,
 *                                01 incomplete more to come,
 *                                10 incomplete truncated, 11 reserved)
 *     +2  Address_Type           0x00-0x03, 0xFF anonymous
 *     +3  Address[6]             LSO first
 *     +9  Primary_PHY            0x01 LE 1M, 0x03 LE Coded (S=8),
 *                                0x04 LE Coded S=2 (Core v5.4,
 *                                Advertising Coding Selection)
 *     +10 Secondary_PHY          0x00 none, 0x01 1M, 0x02 2M, 0x03 Coded
 *                                (S=8), 0x04 Coded S=2
 *     +11 Advertising_SID        0x00-0x0F, 0xFF no ADI
 *     +12 TX_Power               int8 dBm, 127 not available
 *     +13 RSSI                   int8 dBm, 127 not available
 *     +14 Periodic_Advertising_Interval LE16, x 1.25 ms, 0 none
 *     +16 Direct_Address_Type
 *     +17 Direct_Address[6]
 *     +23 Data_Length
 *     +24 Data[Data_Length]
 */
typedef struct {
    uint16_t et;
    uint8_t  atype;
    uint8_t  addr[6];
    uint8_t  pphy, sphy, sid;
    int8_t   tx, rssi;
    uint16_t pint;
    uint8_t  datype;
    uint8_t  daddr[6];
    const uint8_t *data;
    uint8_t  dlen;
} ext_rep_t;

/* An extended (non-legacy) report: any PHY pair and SID the clause
 * allows for one. */
static void ext_defaults(ext_rep_t *r) {
    static const uint8_t A[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0xC6 };
    memset(r, 0, sizeof(*r));
    r->et    = 0x0000;          /* extended, non-connectable, complete */
    r->atype = 0x01;
    memcpy(r->addr, A, 6);
    r->pphy  = 0x01;
    r->sphy  = 0x02;
    r->sid   = 0x03;
    r->tx    = 127;
    r->rssi  = -55;
}

static int put_ext_rep(uint8_t *b, const ext_rep_t *r) {
    int o = 0;
    b[o++] = (uint8_t)r->et; b[o++] = (uint8_t)(r->et >> 8);
    b[o++] = r->atype;
    memcpy(b + o, r->addr, 6); o += 6;
    b[o++] = r->pphy; b[o++] = r->sphy; b[o++] = r->sid;
    b[o++] = (uint8_t)r->tx; b[o++] = (uint8_t)r->rssi;
    b[o++] = (uint8_t)r->pint; b[o++] = (uint8_t)(r->pint >> 8);
    b[o++] = r->datype;
    memcpy(b + o, r->daddr, 6); o += 6;
    b[o++] = r->dlen;
    if (r->dlen) memcpy(b + o, r->data, r->dlen);
    return o + r->dlen;
}

/* §7.7.65.13: "If the Event_Type indicates a legacy PDU (bit 4 = 1),
 * the Primary_PHY parameter shall indicate the LE 1M PHY and the
 * Secondary_PHY parameter shall be set to 0x00." A legacy PDU has no
 * ADI, so the SID reads 0xFF. */
static void ext_legacy(ext_rep_t *r, uint16_t et) {
    ext_defaults(r);
    r->et   = et;
    r->pphy = 0x01;
    r->sphy = 0x00;
    r->sid  = 0xFF;
}

/* `n` reports back to back under Num_Reports `num`; param_len is what
 * the bytes hold. Returns the event length. */
static int ext_event(uint8_t *e, const ext_rep_t *reps, int n, uint8_t num) {
    int o = 4;
    for (int i = 0; i < n; i++) o += put_ext_rep(e + o, &reps[i]);
    e[0] = 0x3E; e[1] = (uint8_t)(o - 2); e[2] = 0x0D; e[3] = num;
    return o;
}

/* Walks `e` and keeps its first report in `out`; the walker's return,
 * so 1 for a decoded single-report event and 0 for a refused one. */
static int ext1(const uint8_t *e, size_t n, ble_adv_report_t *out) {
    memset(out, 0, sizeof(*out));
    multi_capture_t mc; memset(&mc, 0, sizeof(mc));
    int v = ble_hci_ext_adv_walk(e, n, cb_multi, &mc);
    if (mc.count > 0) *out = mc.reports[0];
    return v;
}

static void test_ext_single_report_decodes_every_field(void) {
    uint8_t data[32]; int dl = 0;
    dl = put_ad(data, dl, 0x09, (const uint8_t *)"ext-tag", 7);
    dl = put_ad(data, dl, 0xFF, (const uint8_t[]){ 0x4C, 0x00, 0x07, 0x19 }, 4);
    ext_rep_t r; ext_defaults(&r);
    r.et   = 0x0001;            /* connectable extended */
    r.pphy = 0x03; r.sphy = 0x02; r.sid = 0x07;
    r.tx   = -4;   r.rssi = -61;
    r.pint = 0x0640;            /* 2 s: a non-zero high octet */
    r.data = data; r.dlen = (uint8_t)dl;
    uint8_t e[260];
    int n = ext_event(e, &r, 1, 1);
    ble_adv_report_t out;
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
    ASSERT(out.ext);
    ASSERT_EQ(out.ext_event_type, 0x0001);
    ASSERT_EQ(out.event_type, BLE_EVT_EXT_ADV);
    ASSERT_EQ(out.data_status, BLE_EXT_DATA_COMPLETE);
    ASSERT_EQ(out.addr_type, 0x01);
    ASSERT(memcmp(out.addr, r.addr, 6) == 0);   /* HCI order kept */
    ASSERT_EQ(out.primary_phy, 0x03);
    ASSERT_EQ(out.secondary_phy, 0x02);
    ASSERT_EQ(out.sid, 0x07);
    ASSERT(out.has_adv_tx_power);
    ASSERT_EQ(out.adv_tx_power, -4);
    ASSERT(out.has_rssi);
    ASSERT_EQ(out.rssi, -61);
    ASSERT_EQ(out.periodic_interval, 0x0640);
    ASSERT(!out.directed);
    ASSERT_EQ(out.data_len, dl);
    ASSERT(out.has_local_name);
    ASSERT_STR(out.local_name, "ext-tag");
    ASSERT(out.has_mfr_data);
    ASSERT_EQ(out.mfr_id, 0x004C);
    ASSERT(!out.truncated);
    /* The header's TX_Power is not the AD TX Power Level structure. */
    ASSERT(!out.has_tx_power);
}

static void test_ext_not_available_values_set_nothing(void) {
    ext_rep_t r; ext_defaults(&r);
    r.tx = 127; r.rssi = 127;
    uint8_t e[64];
    int n = ext_event(e, &r, 1, 1);
    ble_adv_report_t out;
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
    ASSERT(!out.has_adv_tx_power);
    ASSERT(!out.has_rssi);
    /* Empty Data is a report with no AD structures, not an error. */
    ASSERT_EQ(out.data_len, 0);
    ASSERT(!out.truncated);
}

static void test_ext_directed_and_scan_response(void) {
    static const uint8_t D[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    ext_rep_t r; ext_defaults(&r);
    r.et = 0x0005;              /* connectable, directed */
    r.datype = 0xFE;            /* RPA the controller could not resolve */
    memcpy(r.daddr, D, 6);
    uint8_t e[64];
    int n = ext_event(e, &r, 1, 1);
    ble_adv_report_t out;
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
    ASSERT(out.directed);
    ASSERT_EQ(out.direct_addr_type, 0xFE);
    ASSERT(memcmp(out.direct_addr, D, 6) == 0);
    ASSERT_EQ(out.event_type, BLE_EVT_EXT_ADV);

    r.et = 0x000A;              /* scannable, scan response */
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
    ASSERT_EQ(out.event_type, BLE_EVT_EXT_SCAN_RSP);
    ASSERT(!out.directed);
}

/* The six Legacy-bit values the clause lists, each to its 0x02 code;
 * every other Legacy-bit combination is refused, not guessed at. Every
 * frame here is a conforming legacy report (ext_legacy()) apart from
 * the one field a case varies. */
static void test_ext_legacy_bit_maps_to_the_legacy_codes(void) {
    static const struct { uint16_t et; int code; } ok[] = {
        { 0x0013, 0x00 },       /* ADV_IND */
        { 0x0015, 0x01 },       /* ADV_DIRECT_IND */
        { 0x0012, 0x02 },       /* ADV_SCAN_IND */
        { 0x0010, 0x03 },       /* ADV_NONCONN_IND */
        { 0x001B, 0x04 },       /* SCAN_RSP to an ADV_IND */
        { 0x001A, 0x04 },       /* SCAN_RSP to an ADV_SCAN_IND */
    };
    ext_rep_t r;
    uint8_t e[300];
    ble_adv_report_t out;
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        ext_legacy(&r, ok[i].et);
        int n = ext_event(e, &r, 1, 1);
        ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
        ASSERT_EQ(out.event_type, ok[i].code);
        ASSERT_EQ(out.primary_phy, 0x01);
        ASSERT_EQ(out.secondary_phy, 0x00);
        ASSERT_EQ(out.sid, 0xFF);
    }
    static const uint16_t bad[] = { 0x0011, 0x0014, 0x0016, 0x0018, 0x001F };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ext_legacy(&r, bad[i]);
        int n = ext_event(e, &r, 1, 1);
        ASSERT_EQ(ext1(e, (size_t)n, &out), 0);
    }
    /* A Legacy-bit report saying "incomplete": legacy_code() compares
     * the data-status bits too, so no legacy code matches and that is
     * what refuses it (a legacy PDU is never fragmented). */
    ext_legacy(&r, 0x0013 | 0x0020);
    int n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 0);
    /* At most 31 octets (Vol 6 Part B §2.3.1). */
    uint8_t big[32]; memset(big, 0, sizeof(big));
    ext_legacy(&r, 0x0013);
    r.data = big; r.dlen = 31;
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
    r.dlen = 32;
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 0);
    /* The same 32 octets in an extended PDU are fine. */
    r.et = 0x0000; r.sphy = 0x02;
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
}

/* §7.7.65.13's "shall" for a legacy PDU's PHYs, and its SID.
 *
 * Seen to fail, each alone: with `r[9] != PHY_LE_1M ||` removed the
 * LE Coded primary decodes; with `|| r[10] != 0x00` removed the 2M
 * secondary decodes; with the SID taken as `r[11]` for a legacy report
 * too, the 0x03 SID reaches out.sid. */
static void test_ext_legacy_bit_phys_and_sid(void) {
    ext_rep_t r;
    uint8_t e[64];
    ble_adv_report_t out;
    ext_legacy(&r, 0x0013);
    r.pphy = 0x03;                      /* LE Coded: not allowed */
    int n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 0);
    ext_legacy(&r, 0x0013);
    r.sphy = 0x02;                      /* any secondary PHY: not allowed */
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 0);
    /* The SID field is ignored for a legacy PDU, which has no ADI. */
    ext_legacy(&r, 0x0013);
    r.sid = 0x03;
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
    ASSERT_EQ(out.sid, 0xFF);
    /* The same PHYs and SID on an extended PDU are its own. */
    ext_defaults(&r);
    r.pphy = 0x04; r.sphy = 0x04; r.sid = 0x03;   /* LE Coded S=2 */
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
    ASSERT_EQ(out.primary_phy, 0x04);
    ASSERT_EQ(out.secondary_phy, 0x04);
    ASSERT_EQ(out.sid, 0x03);
}

static void test_ext_data_status(void) {
    /* A whole Flags structure, then a name structure the fragment
     * boundary cut: length says 10, three octets follow. */
    const uint8_t data[] = { 0x02, 0x01, 0x06, 0x0A, 0x09, 'a', 'b' };
    ext_rep_t r; ext_defaults(&r);
    r.data = data; r.dlen = sizeof(data);
    uint8_t e[64];
    ble_adv_report_t out;
    r.et = 0x0020;              /* incomplete, more to come */
    int n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
    ASSERT_EQ(out.data_status, BLE_EXT_DATA_INCOMPLETE);
    ASSERT(out.has_flags);
    ASSERT(!out.has_local_name);
    ASSERT(out.truncated);
    r.et = 0x0040;              /* incomplete, truncated */
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
    ASSERT_EQ(out.data_status, BLE_EXT_DATA_TRUNCATED);
    r.et = 0x0060;              /* reserved */
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 0);
}

/* Seen to fail: with the anonymous test dropped from the Address copy,
 * out.addr carries the Address field's octets. */
static void test_ext_anonymous_address_is_zeroed(void) {
    ext_rep_t r; ext_defaults(&r);
    r.atype = 0xFF;             /* the Address field is still six octets */
    uint8_t e[64];
    int n = ext_event(e, &r, 1, 1);
    ble_adv_report_t out;
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
    ASSERT_EQ(out.addr_type, 0xFF);
    static const uint8_t Z[6] = { 0 };
    ASSERT(memcmp(out.addr, Z, 6) == 0);
    /* The fields after Address are still read at their offsets. */
    ASSERT_EQ(out.sid, 0x03);
    ASSERT_EQ(out.rssi, -55);
}

static void test_ext_lengths_are_exact(void) {
    const uint8_t data[] = { 0x02, 0x01, 0x06, 0x00, 0x00 };
    ext_rep_t r; ext_defaults(&r);
    r.data = data; r.dlen = 3;
    uint8_t e[64];
    ble_adv_report_t out;
    int n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ext1(e, (size_t)n, &out), 1);
    /* Captured shorter than param_len says. */
    ASSERT_EQ(ext1(e, (size_t)n - 1, &out), 0);
    /* Overlong Data_Length: five octets claimed, three present. */
    e[4 + 23] = 5;
    ASSERT_EQ(ext1(e, (size_t)n, &out), 0);
    e[4 + 23] = 3;
    /* A trailing octet after the Data. */
    e[n] = 0; e[1]++;
    ASSERT_EQ(ext1(e, (size_t)n + 1, &out), 0);
    e[1]--;
    /* Fixed fields cut: param_len and len agree, one octet short of a
     * report header. */
    uint8_t s[27];
    memcpy(s, e, sizeof(s));
    s[1] = 25;
    ASSERT_EQ(ext1(s, sizeof(s), &out), 0);
    /* Wrong codes, no reports, nothing at all. */
    e[2] = 0x02;
    ASSERT_EQ(ext1(e, (size_t)n, &out), 0);
    e[2] = 0x0D; e[0] = 0x3F;
    ASSERT_EQ(ext1(e, (size_t)n, &out), 0);
    e[0] = 0x3E; e[3] = 0;
    ASSERT_EQ(ext1(e, (size_t)n, &out), 0);
    ASSERT_EQ(ext1(NULL, (size_t)n, &out), 0);
    ASSERT_EQ(ext1(e, 3, &out), 0);
}

/* Num_Reports > 1: every report decoded, as consecutive records
 * (§5.2); a Num_Reports the bytes do not account for decodes nothing. */
static void test_ext_multi_report_events_decode_every_report(void) {
    const uint8_t d3[] = { 0x02, 0x01, 0x06 };
    ext_rep_t two[2];
    ext_defaults(&two[0]);
    ext_legacy(&two[1], 0x0010);         /* ADV_NONCONN_IND */
    two[0].data = d3; two[0].dlen = 3;
    two[0].sid  = 0x05;
    two[1].addr[0] ^= 0x01;
    two[1].rssi = -77;
    uint8_t e[128];
    multi_capture_t mc;

    int n = ext_event(e, two, 2, 2);
    memset(&mc, 0, sizeof(mc));
    ASSERT_EQ(ble_hci_ext_adv_walk(e, (size_t)n, cb_multi, &mc), 2);
    ASSERT_EQ(mc.count, 2);
    ASSERT_EQ(mc.reports[0].event_type, BLE_EVT_EXT_ADV);
    ASSERT_EQ(mc.reports[0].sid, 0x05);
    ASSERT(mc.reports[0].has_flags);
    ASSERT(memcmp(mc.reports[0].addr, two[0].addr, 6) == 0);
    ASSERT_EQ(mc.reports[1].event_type, 0x03);
    ASSERT(memcmp(mc.reports[1].addr, two[1].addr, 6) == 0);
    ASSERT_EQ(mc.reports[1].rssi, -77);
    ASSERT(!mc.reports[1].has_flags);
    ASSERT_EQ(mc.reports[1].data_len, 0);

    /* One report the clause rules out refuses the event: nothing of it
     * reaches the callback, the good report included.
     * Seen to fail: with the decode loop's refusal made
     * `(void)ext_decode(b + off, &reps[i]);`, the callback runs. */
    two[1].et = 0x0011;                  /* not a listed legacy value */
    n = ext_event(e, two, 2, 2);
    memset(&mc, 0, sizeof(mc));
    ASSERT_EQ(ble_hci_ext_adv_walk(e, (size_t)n, cb_multi, &mc), 0);
    ASSERT_EQ(mc.count, 0);
    two[1].et = 0x0010;

    /* The same bytes under Num_Reports 1: one report followed by octets
     * it does not own. */
    n = ext_event(e, two, 2, 1);
    ASSERT_EQ(ble_hci_ext_adv_walk(e, (size_t)n, NULL, NULL), 0);
    /* One report under Num_Reports 2: too short for a second header. */
    n = ext_event(e, two, 1, 2);
    ASSERT_EQ(ble_hci_ext_adv_walk(e, (size_t)n, NULL, NULL), 0);
    /* Two records and a stray octet. */
    n = ext_event(e, two, 2, 2);
    e[n] = 0xAA; e[1]++;
    ASSERT_EQ(ble_hci_ext_adv_walk(e, (size_t)n + 1, NULL, NULL), 0);
    /* Two records under Num_Reports 3. */
    n = ext_event(e, two, 2, 3);
    ASSERT_EQ(ble_hci_ext_adv_walk(e, (size_t)n, NULL, NULL), 0);
}

/* The first record's Data_Length sends the second record's header past
 * the end of the event. The buffer is exactly the event, so a read of
 * that header's Data_Length octet lands outside it.
 *
 * Seen to fail under ASan (stack-buffer-overflow in
 * ble_hci_ext_adv_walk) with `if (off + BLE_EXT_REPORT_FIXED > blen)
 * return 0;` removed, and likewise for the second case with the Data
 * bound `if (off + BLE_EXT_REPORT_FIXED + dlen > blen) return 0;`
 * removed (the AD walk reads past the event). Without the sanitiser
 * each stray read happens to be refused by a later check, so these
 * cases guard the bounds only in the sanitized runs. */
static void test_ext_second_header_past_the_end_is_refused(void) {
    /* Num_Reports 2, 51 parameter octets after Num_Reports: one 24-octet
     * header, Data_Length 5, then 22 octets, two short of a header. */
    uint8_t a[2 + 2 + 51];
    memset(a, 0, sizeof(a));
    a[0] = 0x3E; a[1] = 2 + 51; a[2] = 0x0D; a[3] = 2;
    uint8_t *b = a + 4;
    b[9]  = 0x01;                        /* Primary_PHY LE 1M */
    b[11] = 0xFF;
    b[23] = 5;                           /* Data_Length[0] */
    multi_capture_t mc; memset(&mc, 0, sizeof(mc));
    ASSERT_EQ(ble_hci_ext_adv_walk(a, sizeof(a), cb_multi, &mc), 0);
    ASSERT_EQ(mc.count, 0);
    /* The first record's Data overrunning the event: the Data bound. */
    b[23] = 52;
    b[24] = 0x30;                        /* an AD length that walks on past 51 */
    ASSERT_EQ(ble_hci_ext_adv_walk(a, sizeof(a), cb_multi, &mc), 0);
    ASSERT_EQ(mc.count, 0);
}

void run_ble_snoop_tests(void) {
    TEST_SUITE("BLE AD-structure parse (#144 slice 1, Core Spec Vol 3 Part C §11)");
    RUN_TEST(test_flags);
    RUN_TEST(test_local_name_complete);
    RUN_TEST(test_local_name_shortened_marks_incomplete);
    RUN_TEST(test_local_name_clamped_at_max);
    RUN_TEST(test_tx_power);
    RUN_TEST(test_appearance);
    RUN_TEST(test_service_uuid16_complete);
    RUN_TEST(test_service_uuid16_first_wins);
    RUN_TEST(test_mfr_data_apple);
    RUN_TEST(test_mfr_data_clamped_at_max);
    RUN_TEST(test_unrecognised_ad_type_skipped_not_error);
    RUN_TEST(test_zero_length_ad_struct_ends_walk);
    RUN_TEST(test_truncated_ad_struct_sets_flag_keeps_prior);
    RUN_TEST(test_empty_data_is_a_no_op);

    TEST_SUITE("BLE HCI LE Advertising Report framing (#144 slice 1, Vol 4 Part E §7.7.65.2)");
    RUN_TEST(test_walk_single_report_decodes);
    RUN_TEST(test_walk_rssi_not_available);
    RUN_TEST(test_walk_wrong_event_code_rejected);
    RUN_TEST(test_walk_wrong_subevent_rejected);
    RUN_TEST(test_walk_zero_reports_rejected);
    RUN_TEST(test_walk_short_fixed_fields_rejected);
    RUN_TEST(test_walk_short_data_rejected);
    RUN_TEST(test_walk_null_or_too_short_buffer);
    RUN_TEST(test_walk_two_reports_are_consecutive_records);
    RUN_TEST(test_ext_single_report_decodes_every_field);
    RUN_TEST(test_ext_not_available_values_set_nothing);
    RUN_TEST(test_ext_directed_and_scan_response);
    RUN_TEST(test_ext_legacy_bit_maps_to_the_legacy_codes);
    RUN_TEST(test_ext_data_status);
    RUN_TEST(test_ext_anonymous_address_is_zeroed);
    RUN_TEST(test_ext_lengths_are_exact);
    RUN_TEST(test_ext_legacy_bit_phys_and_sid);
    RUN_TEST(test_ext_multi_report_events_decode_every_report);
    RUN_TEST(test_ext_second_header_past_the_end_is_refused);
}
