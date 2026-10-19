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
}
