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
 *   evt[4 .. ]  Event_Type[N]
 *               Address_Type[N]
 *               Address[N][6]
 *               Data_Length[N]
 *               Data[0] .. Data[N-1]   (back to back, Data_Length[i] each)
 *               RSSI[N]                (signed, 127 = not available)
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

/* The struct-of-arrays layout is the easy place to get this wrong: if the
 * walk read Event_Type/Address_Type/Address/Data_Length as if they were
 * interleaved per report (array-of-structs) instead of four separate
 * arrays, a 2-report event would hand each report the wrong address and
 * the wrong data slice. */
static void test_walk_two_reports_soa_layout(void) {
    uint8_t addr_a[6] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    uint8_t addr_b[6] = { 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB };
    uint8_t data_a[4]; int dlen_a = put_ad(data_a, 0, 0x01, (uint8_t[]){0x01}, 1);
    uint8_t data_b[8];
    const char *name_b = "Tile";
    int dlen_b = put_ad(data_b, 0, 0x09, (const uint8_t *)name_b, (int)strlen(name_b));

    uint8_t evt[128];
    int off = 0;
    evt[off++] = 0x3E; evt[off++] = 0; evt[off++] = 0x02; evt[off++] = 2;
    evt[off++] = 0; evt[off++] = 0;                 /* Event_Type[0..1] */
    evt[off++] = 0; evt[off++] = 1;                 /* Address_Type[0..1] */
    memcpy(evt + off, addr_a, 6); off += 6;          /* Address[0] */
    memcpy(evt + off, addr_b, 6); off += 6;          /* Address[1] */
    evt[off++] = (uint8_t)dlen_a; evt[off++] = (uint8_t)dlen_b; /* Data_Length[0..1] */
    memcpy(evt + off, data_a, (size_t)dlen_a); off += dlen_a;   /* Data[0] */
    memcpy(evt + off, data_b, (size_t)dlen_b); off += dlen_b;   /* Data[1] */
    evt[off++] = (uint8_t)(int8_t)-30; /* RSSI[0] */
    evt[off++] = (uint8_t)(int8_t)-70; /* RSSI[1] */

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
}

/* ── LE Extended Advertising Report (subevent 0x0D) ──────────────────
 *
 * Core Specification v5.x Vol 4 Part E §7.7.65.13. One report, as the
 * single-report shape where the clause's per-field arrays and the
 * kernel's per-report records are the same bytes:
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
 *     +9  Primary_PHY            0x01 LE 1M, 0x03 LE Coded
 *     +10 Secondary_PHY          0x00 none, 0x01 1M, 0x02 2M, 0x03 Coded
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

/* `n` reports back to back under Num_Reports `num`; param_len is what
 * the bytes hold. Returns the event length. */
static int ext_event(uint8_t *e, const ext_rep_t *reps, int n, uint8_t num) {
    int o = 4;
    for (int i = 0; i < n; i++) o += put_ext_rep(e + o, &reps[i]);
    e[0] = 0x3E; e[1] = (uint8_t)(o - 2); e[2] = 0x0D; e[3] = num;
    return o;
}

static void test_ext_single_report_decodes_every_field(void) {
    uint8_t data[32]; int dl = 0;
    dl = put_ad(data, dl, 0x09, (const uint8_t *)"ext-tag", 7);
    dl = put_ad(data, dl, 0xFF, (const uint8_t[]){ 0x4C, 0x00, 0x07, 0x19 }, 4);
    ext_rep_t r; ext_defaults(&r);
    r.et   = 0x0001;            /* connectable extended */
    r.pphy = 0x03; r.sphy = 0x02; r.sid = 0x07;
    r.tx   = -4;   r.rssi = -61;
    r.pint = 0x0050;
    r.data = data; r.dlen = (uint8_t)dl;
    uint8_t e[260];
    int n = ext_event(e, &r, 1, 1);
    ble_adv_report_t out;
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_OK);
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
    ASSERT_EQ(out.periodic_interval, 0x0050);
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
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_OK);
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
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_OK);
    ASSERT(out.directed);
    ASSERT_EQ(out.direct_addr_type, 0xFE);
    ASSERT(memcmp(out.direct_addr, D, 6) == 0);
    ASSERT_EQ(out.event_type, BLE_EVT_EXT_ADV);

    r.et = 0x000A;              /* scannable, scan response */
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_OK);
    ASSERT_EQ(out.event_type, BLE_EVT_EXT_SCAN_RSP);
    ASSERT(!out.directed);
}

/* The six Legacy-bit values the clause lists, each to its 0x02 code;
 * every other Legacy-bit combination is refused, not guessed at. */
static void test_ext_legacy_bit_maps_to_the_legacy_codes(void) {
    static const struct { uint16_t et; int code; } ok[] = {
        { 0x0013, 0x00 },       /* ADV_IND */
        { 0x0015, 0x01 },       /* ADV_DIRECT_IND */
        { 0x0012, 0x02 },       /* ADV_SCAN_IND */
        { 0x0010, 0x03 },       /* ADV_NONCONN_IND */
        { 0x001B, 0x04 },       /* SCAN_RSP to an ADV_IND */
        { 0x001A, 0x04 },       /* SCAN_RSP to an ADV_SCAN_IND */
    };
    ext_rep_t r; ext_defaults(&r);
    uint8_t e[300];
    ble_adv_report_t out;
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        r.et = ok[i].et;
        int n = ext_event(e, &r, 1, 1);
        ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_OK);
        ASSERT_EQ(out.event_type, ok[i].code);
    }
    static const uint16_t bad[] = { 0x0011, 0x0014, 0x0016, 0x0018, 0x001F };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        r.et = bad[i];
        int n = ext_event(e, &r, 1, 1);
        ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out),
                  BLE_EXT_PARSE_MALFORMED);
    }
    /* A legacy PDU is never fragmented. */
    r.et = 0x0013 | 0x0020;
    int n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_MALFORMED);
    /* And carries at most 31 octets (Vol 6 Part B §2.3.1). */
    uint8_t big[32]; memset(big, 0, sizeof(big));
    r.et = 0x0013; r.data = big; r.dlen = 31;
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_OK);
    r.dlen = 32;
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_MALFORMED);
    /* The same 32 octets in an extended PDU are fine. */
    r.et = 0x0000;
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_OK);
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
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_OK);
    ASSERT_EQ(out.data_status, BLE_EXT_DATA_INCOMPLETE);
    ASSERT(out.has_flags);
    ASSERT(!out.has_local_name);
    ASSERT(out.truncated);
    r.et = 0x0040;              /* incomplete, truncated */
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_OK);
    ASSERT_EQ(out.data_status, BLE_EXT_DATA_TRUNCATED);
    r.et = 0x0060;              /* reserved */
    n = ext_event(e, &r, 1, 1);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_MALFORMED);
}

/* Seen to fail: with the anonymous test dropped from the Address copy,
 * out.addr carries the Address field's octets. */
static void test_ext_anonymous_address_is_zeroed(void) {
    ext_rep_t r; ext_defaults(&r);
    r.atype = 0xFF;             /* the Address field is still six octets */
    uint8_t e[64];
    int n = ext_event(e, &r, 1, 1);
    ble_adv_report_t out;
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_OK);
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
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_OK);
    /* Captured shorter than param_len says. */
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n - 1, &out), BLE_EXT_PARSE_MALFORMED);
    /* Overlong Data_Length: five octets claimed, three present. */
    e[4 + 23] = 5;
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_MALFORMED);
    e[4 + 23] = 3;
    /* A trailing octet after the Data. */
    e[n] = 0; e[1]++;
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n + 1, &out), BLE_EXT_PARSE_MALFORMED);
    e[1]--;
    /* Fixed fields cut: param_len and len agree, one octet short of a
     * report header. */
    uint8_t s[27];
    memcpy(s, e, sizeof(s));
    s[1] = 25;
    ASSERT_EQ(ble_hci_ext_adv_parse(s, sizeof(s), &out), BLE_EXT_PARSE_MALFORMED);
    /* Wrong codes, no reports, nothing at all. */
    e[2] = 0x02;
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_MALFORMED);
    e[2] = 0x0D; e[0] = 0x3F;
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_MALFORMED);
    e[0] = 0x3E; e[3] = 0;
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_MALFORMED);
    ASSERT_EQ(ble_hci_ext_adv_parse(NULL, (size_t)n, &out), BLE_EXT_PARSE_MALFORMED);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, 3, &out), BLE_EXT_PARSE_MALFORMED);
}

/* Num_Reports > 1 is refused whole (ble_snoop.h), but only when the
 * event is a multi-report event under one of the two layouts; a
 * Num_Reports the bytes do not account for is malformed.
 *
 * Seen to fail: with the MALFORMED arm of the ext_multi_accounts()
 * ternary made MULTI, the stray-octet and array-short cases read as
 * MULTI. */
static void test_ext_num_reports_is_checked_against_the_bytes(void) {
    const uint8_t d3[] = { 0x02, 0x01, 0x06 };
    ext_rep_t two[2];
    ext_defaults(&two[0]); ext_defaults(&two[1]);
    two[0].data = d3; two[0].dlen = 3;
    two[1].addr[0] ^= 0x01;
    uint8_t e[128];
    ble_adv_report_t out;

    /* Two consecutive records under Num_Reports 2: refused, MULTI. */
    int n = ext_event(e, two, 2, 2);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_MULTI);
    /* The same bytes under Num_Reports 1: one report followed by
     * octets it does not own. */
    n = ext_event(e, two, 2, 1);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_MALFORMED);
    /* One report under Num_Reports 2: too short for two headers. */
    n = ext_event(e, two, 1, 2);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_MALFORMED);
    /* Two records and a stray octet: neither layout accounts for it. */
    n = ext_event(e, two, 2, 2);
    e[n] = 0xAA; e[1]++;
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n + 1, &out), BLE_EXT_PARSE_MALFORMED);
    /* Two empty-Data reports under Num_Reports 3: short. */
    two[0].dlen = 0;
    n = ext_event(e, two, 2, 3);
    ASSERT_EQ(ble_hci_ext_adv_parse(e, (size_t)n, &out), BLE_EXT_PARSE_MALFORMED);

    /* The clause's per-field arrays, Num_Reports 2, Data_Length 3 and 0:
     * Event_Type[2] at 0, Address_Type[2] at 4, Address[2] at 6,
     * Primary_PHY[2] at 18, Secondary_PHY[2] at 20, SID[2] at 22,
     * TX_Power[2] at 24, RSSI[2] at 26, Interval[2] at 28,
     * Direct_Address_Type[2] at 32, Direct_Address[2] at 34,
     * Data_Length[2] at 46, Data at 48. SID[1] = 0x05 sits where the
     * consecutive layout reads its first Data_Length, which sends its
     * second record past the end, so only the array layout accounts
     * for these bytes. */
    uint8_t a[2 + 2 + 51];
    memset(a, 0, sizeof(a));
    a[0] = 0x3E; a[1] = 2 + 51; a[2] = 0x0D; a[3] = 2;
    uint8_t *b = a + 4;
    b[22] = 0x01; b[23] = 0x05;          /* SID[0], SID[1] */
    b[46] = 3; b[47] = 0;                /* Data_Length[0..1] */
    b[48] = 0x02; b[49] = 0x01; b[50] = 0x06;
    ASSERT_EQ(ble_hci_ext_adv_parse(a, sizeof(a), &out), BLE_EXT_PARSE_MULTI);
    b[47] = 1;                           /* now one octet more than present */
    ASSERT_EQ(ble_hci_ext_adv_parse(a, sizeof(a), &out), BLE_EXT_PARSE_MALFORMED);
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
    RUN_TEST(test_walk_two_reports_soa_layout);
    RUN_TEST(test_ext_single_report_decodes_every_field);
    RUN_TEST(test_ext_not_available_values_set_nothing);
    RUN_TEST(test_ext_directed_and_scan_response);
    RUN_TEST(test_ext_legacy_bit_maps_to_the_legacy_codes);
    RUN_TEST(test_ext_data_status);
    RUN_TEST(test_ext_anonymous_address_is_zeroed);
    RUN_TEST(test_ext_lengths_are_exact);
    RUN_TEST(test_ext_num_reports_is_checked_against_the_bytes);
}
