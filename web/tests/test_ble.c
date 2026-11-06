/* The BLE tables (web_ble.h): the advertisers and findings sloth's
 * Bluetooth receivers report, kept by slothweb from hand-built records
 * in the emitter's exact shape (src/jsonl.c jsonl_emit_ble_devices(),
 * jsonl_emit_ble_alerts(); no pcap, no capture), the routes through the
 * route table under each capture scope, the two global metrics, and
 * (WITH_SQLITE) the store's v7 tables: a round trip through the store
 * thread's flush, a seed on reopen, retention.
 *
 * Absence assertions, each seen red under a named mutation and restored
 * byte-identical (cmp against a copy): the Local out_of_scope with
 * route_ble()'s none_here forced 0 (a Local answer carried rows); the
 * resolve with resolve_apply()'s body emptied (standing stayed true); the
 * metrics guard with the source test removed from web_metrics.c
 * (ble.devices sampled with no Bluetooth source); the hostile name with
 * web_ssid_escape() replaced by a plain copy (name_np false, \u0001 on
 * the page); the LRU with dev_slot()'s eviction returning the
 * first used row (the newest row gone, not the oldest). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "web_ble.h"
#include "web_btsig.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_routes.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "wtest.h"
#include "wt_tmp.h"

#define T 1793000000LL

static web_ble_t B;
static web_jrec_t R;

static void feed_to(web_ble_t *b, const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_ble_record(b, &R, 1000);
}
static void feed(const char *line) { feed_to(&B, line); }

/* One ble_device line as the emitter writes it, every member present,
 * the ones a test does not vary at the record's "absent" value; extra
 * (",\"k\":v...") replaces the base's member of the same name, since
 * the decoder refuses a name twice (WEB_JL_EDUP). */
static const char *dev_line(const char *addr, int type, const char *iface,
                            const char *name, int rssi, long long adv,
                            long long first, long long last, const char *extra) {
    static char buf[4096];
    char base[2048];
    snprintf(base, sizeof(base),
             ",\"addr\":\"%s\",\"addr_type\":%d,"
             "\"sensor\":\"ble\",\"iface\":\"%s\",\"adapter\":0,\"sampled\":%d,"
             "\"channel\":%d,\"last_pdu\":\"ADV_IND\",\"pdu_mask\":1,\"name\":\"%s\","
             "\"name_complete\":1,\"uuid16\":-1,\"mfr_id\":-1,\"mfr_subtype\":-1,"
             "\"svc_data_uuid16\":-1,\"appearance\":-1,\"hid\":0,\"tx_power\":-128,"
             "\"flags\":-1,\"has_rssi\":%d,\"rssi\":%d,\"rssi_best\":%d,\"adv_count\":%lld,"
             "\"watch_category\":\"\",\"ext_adv\":0,\"primary_phy\":0,\"secondary_phy\":0,"
             "\"adv_sid\":-1,\"first_seen\":%lld,\"last_seen\":%lld",
             addr, type, iface, !strcmp(iface, "ubertooth"),
             !strcmp(iface, "ubertooth") ? 37 : -1, name, rssi != 0, rssi,
             rssi != 0 ? rssi + 5 : 0, adv, first, last);
    /* Each ,"name": of extra takes its member out of the base. */
    for (const char *e = extra; e && (e = strstr(e, ",\"")); e += 2) {
        const char *q = strchr(e + 2, '"');
        if (!q || q[1] != ':') continue;
        char key[64];
        snprintf(key, sizeof(key), ",%.*s:", (int)(q - e), e + 1);
        char *at = strstr(base, key);
        if (!at) continue;
        char *next = strstr(at + 1, ",\"");
        /* A string value may hold ,": step over it. */
        if (at[strlen(key)] == '"') {
            const char *close = strchr(at + strlen(key) + 1, '"');
            next = close ? strstr(close, ",\"") : NULL;
        }
        if (next) memmove(at, next, strlen(next) + 1);
        else *at = '\0';
    }
    snprintf(buf, sizeof(buf), "{\"type\":\"ble_device\",\"ts\":%lld%s%s}", last, base,
             extra ? extra : "");
    return buf;
}

static int rows_of(web_ble_t *b) {
    web_ble_stats_t st;
    web_ble_stats(b, &st);
    return st.rows;
}

/* ── the vocabularies ─────────────────────────────────────────────── */

static void test_vocabularies(void) {
    WT_ASSERT(!strcmp(web_ble_iface_name(WEB_BLE_IF_MONITOR), "bluetooth-monitor"));
    WT_ASSERT(!strcmp(web_ble_iface_name(WEB_BLE_IF_UBERTOOTH), "ubertooth"));
    WT_ASSERT(!strcmp(web_ble_iface_name(99), "other"));
    WT_ASSERT(!strcmp(web_ble_pdu_name(WEB_BLE_PDU_SCAN_RSP), "SCAN_RSP"));
    WT_ASSERT(!strcmp(web_ble_pdu_name(WEB_BLE_PDU_EXT_SCAN_RSP), "EXT_SCAN_RSP"));
    WT_ASSERT(!strcmp(web_ble_pdu_name(-1), "adv"));
    WT_ASSERT(!strcmp(web_ble_band_name(WEB_BLE_BAND_BUILDING), "building"));
    WT_ASSERT(!strcmp(web_ble_band_short(WEB_BLE_BAND_BUILDING), "bldg"));
    WT_ASSERT(!strcmp(web_ble_trend_name(WEB_BLE_TREND_LEAVING), "leaving"));
    WT_ASSERT(!strcmp(web_ble_trend_glyph(WEB_BLE_TREND_APPROACHING), "\xe2\x86\x98"));
    WT_ASSERT(!strcmp(web_ble_trend_glyph(WEB_BLE_TREND_UNKNOWN), ""));
    WT_ASSERT(!strcmp(web_ble_ptx_name(WEB_BLE_PTX_EXT), "ble_ext_tx_power"));
    WT_ASSERT(!strcmp(web_ble_ptx_short(WEB_BLE_PTX_AD), "ad"));
    WT_ASSERT(!strcmp(web_ble_kind_name(WEB_BLE_FIND_WATCH), "watchlist"));
    WT_ASSERT(!strcmp(web_ble_alert_name(WEB_BLE_ALERT_HID), "BLE_HID_UNEXPECTED"));
    WT_EQ(web_ble_type_ch(0), 'P'); WT_EQ(web_ble_type_ch(1), 'R');
    WT_EQ(web_ble_type_ch(2), 'p'); WT_EQ(web_ble_type_ch(3), 'r');
    WT_EQ(web_ble_type_ch(255), '?');
    /* The random address's two top bits (Core v5.4 Vol 6 Part B §1.3.2). */
    static const uint8_t ST[6] = { 0xde, 0, 0, 0, 0, 1 }, RP[6] = { 0x5e, 0, 0, 0, 0, 1 },
                         NR[6] = { 0x02, 0, 0, 0, 0, 1 }, RS[6] = { 0x9e, 0, 0, 0, 0, 1 };
    WT_ASSERT(!strcmp(web_ble_addr_kind(ST, 1), "random static"));
    WT_ASSERT(!strcmp(web_ble_addr_kind(RP, 1), "random RPA"));
    WT_ASSERT(!strcmp(web_ble_addr_kind(NR, 1), "random NRPA"));
    WT_ASSERT(!strcmp(web_ble_addr_kind(RS, 1), "random reserved"));
    WT_ASSERT(!strcmp(web_ble_addr_kind(ST, 0), "public"));
    WT_ASSERT(!strcmp(web_ble_addr_kind(ST, 2), "resolved public"));
    WT_ASSERT(!strcmp(web_ble_addr_kind(ST, 3), "resolved random"));
    WT_ASSERT(!strcmp(web_ble_addr_kind(ST, 255), "anonymous"));
    WT_ASSERT(!strcmp(web_ble_addr_kind(ST, 7), "unknown"));
    char h[17];
    web_ble_key_hash("", h);
    WT_ASSERT(!strcmp(h, "cbf29ce484222325"));   /* FNV-1a 64's offset basis */
    web_ble_key_hash("a", h);
    WT_ASSERT(!strcmp(h, "af63dc4c8601ec8c"));
}

/* ── the advertiser table ─────────────────────────────────────────── */

/* The host controller and an Ubertooth hearing the same address are two
 * rows; a heartbeat re-emit updates its row in place (the counts, the
 * sticky masks OR-ed, the earlier first_seen kept). */
static void test_rows_by_sensor_and_update(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    feed(dev_line("02:de:00:00:00:01", 0, "bluetooth-monitor", "demo-a", -60, 10, T - 100, T, NULL));
    feed(dev_line("02:de:00:00:00:01", 0, "ubertooth", "demo-a", -70, 3, T - 90, T, NULL));
    WT_EQ(rows_of(&B), 2);
    /* The heartbeat: the same key, the row taken over. */
    feed(dev_line("02:de:00:00:00:01", 0, "bluetooth-monitor", "demo-a", -58, 40, T - 100, T + 300,
                  ",\"pdu_mask\":16"));
    WT_EQ(rows_of(&B), 2);
    char body[65536];
    size_t len = 0;
    int status = 0;
    WT_EQ(web_ble_devices_route(&B, "sort=addr&dir=asc", T + 300, 0, body, sizeof(body), &len, &status), 0);
    WT_EQ(status, 200);
    WT_HAS(body, "\"total\":2");
    WT_HAS(body, "\"iface\":\"bluetooth-monitor\"");
    WT_HAS(body, "\"iface\":\"ubertooth\"");
    WT_HAS(body, "\"adv_count\":40");
    WT_HAS(body, "\"pdu_mask\":17");          /* 1 | 16, sticky */
    WT_HAS(body, "\"pdus\":[\"ADV_IND\",\"SCAN_RSP\"]");
    WT_HAS(body, "\"first_seen\":1792999900");
    WT_HAS(body, "\"sampled\":1");
    WT_HAS(body, "\"channel\":37");
    WT_HAS(body, "\"channel\":null");
    WT_HAS(body, "\"type\":\"P\"");
    /* The rate: two points on the host row, 30 reports over 300 s. */
    WT_HAS(body, "\"adv_rate\":0.100");
    WT_HAS(body, "\"adv_rate\":null");        /* the Ubertooth row: one point */
    web_ble_destroy(&B);
}

/* Every string is hostile: a control byte in the name is \x01 in the
 * display form and flagged; an over-long name is cut back to a
 * code-point boundary (never through a sequence, which would flag it); an empty name is null; a category that is not sloth's slug
 * is dropped and counted; an iface outside the two is "other" and
 * counted; a record with no address, or a bad one, is counted and kept
 * nowhere. */
static void test_hostile_strings(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    feed(dev_line("02:de:00:00:00:02", 1, "bluetooth-monitor", "bad\\u0001name", -60, 1, T, T, NULL));
    feed(dev_line("02:de:00:00:00:03", 1, "bluetooth-monitor",
                  "x\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"
                  "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"
                  "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"
                  "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"
                  "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"
                  "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"
                  "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9", -60, 1, T, T, NULL));
    feed(dev_line("02:de:00:00:00:04", 1, "bluetooth-monitor", "", -60, 1, T, T,
                  ",\"watch_category\":\"Not A Slug!\""));
    feed(dev_line("02:de:00:00:00:05", 1, "hci9", "x", -60, 1, T, T, NULL));
    feed("{\"type\":\"ble_device\",\"ts\":1,\"addr\":\"zz\",\"addr_type\":1,\"iface\":\"ubertooth\"}");
    feed("{\"type\":\"ble_device\",\"ts\":1,\"addr\":\"02:de:00:00:00:06\",\"addr_type\":7,\"iface\":\"ubertooth\"}");
    web_ble_stats_t st;
    web_ble_stats(&B, &st);
    WT_EQ(st.rows, 4);
    WT_EQ(st.bad_records, 2);
    WT_EQ(st.other_iface, 1);
    WT_EQ(st.other_word, 1);
    WT_EQ(st.name_escaped, 1);
    char body[65536];
    size_t len = 0;
    int status = 0;
    WT_EQ(web_ble_devices_route(&B, "sort=addr&dir=asc", T, 0, body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"name\":\"bad\\\\x01name\",\"name_np\":true");
    /* What a plain copy would put on the page: the writer's escape of
     * the raw control byte. */
    WT_LACKS(body, "\\u0001");
    WT_HAS(body, "\"name\":null");
    WT_HAS(body, "\"watch_category\":null");
    WT_HAS(body, "\"iface\":\"other\"");
    /* The long name: "x" and 67 é, read to 96 bytes (32 octets, three
     * each at most). Byte 96 is the second byte of the 48th é, so a
     * byte cut would leave its lead byte as \xc3 and flag the name; the
     * cut backs off to the boundary instead: "x" and 47 é, 95 bytes,
     * valid UTF-8 and not flagged. Seen red with the back-off loop in
     * dev_fill() removed (99 bytes with the \\xc3 escape, name_np true). */
    const char *p = strstr(body, "\"addr\":\"02:de:00:00:00:03\"");
    WT_ASSERT(p != NULL);
    if (p) {
        const char *nm = strstr(p, "\"name\":\"");
        WT_ASSERT(nm != NULL);
        if (nm) {
            nm += 8;
            const char *e = strchr(nm, '"');
            WT_ASSERT(e && (e - nm) == 1 + 47 * 2);
            WT_ASSERT(e && !strncmp(e, "\",\"name_np\":false", 16));
        }
    }
    web_ble_destroy(&B);
}

/* The absent values of the record: tx_power -128 and the id fields -1
 * are null, est_* absent is "est":null (never 0), an anonymous (type
 * 255) all-zero address is a row; an estimate carries sloth's four
 * fields as they came, the cell in rf_dist_cell()'s full form and the
 * description in rf_dist_describe()'s shape less the interval. */
static void test_absent_and_estimate(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    feed(dev_line("00:00:00:00:00:00", 255, "bluetooth-monitor", "", 0, 2, T, T, NULL));
    feed(dev_line("02:de:00:00:00:07", 0, "bluetooth-monitor", "beacon", -61, 500, T - 60, T,
                  ",\"uuid16\":6159,\"mfr_id\":76,\"mfr_subtype\":16,\"appearance\":961,\"hid\":1,"
                  "\"tx_power\":-8,\"flags\":6,\"est_dist_m\":4.5,\"est_dist_band\":\"room\","
                  "\"est_dist_trend\":\"approaching\",\"est_ptx_source\":\"ble_ad_tx_power\""));
    feed(dev_line("02:de:00:00:00:08", 0, "bluetooth-monitor", "far", -95, 1, T, T,
                  ",\"est_dist_m\":1200.00,\"est_dist_band\":\"far\",\"est_dist_trend\":\"unknown\","
                  "\"est_ptx_source\":\"assumed\""));
    char body[65536];
    size_t len = 0;
    int status = 0;
    WT_EQ(web_ble_devices_route(&B, "sort=addr&dir=asc", T, 0, body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"addr\":\"00:00:00:00:00:00\",\"addr_type\":255,\"type\":\"?\",\"addr_kind\":\"anonymous\"");
    WT_HAS(body, "\"addr\":\"02:de:00:00:00:07\",\"addr_type\":0,\"type\":\"P\",\"addr_kind\":\"public\"");
    WT_HAS(body, "\"tx_power\":null");
    WT_HAS(body, "\"rssi\":null,\"rssi_best\":null");
    WT_HAS(body, "\"est\":null");
    WT_HAS(body, "\"tx_power\":-8");
    WT_HAS(body, "\"uuid16\":6159,\"uuid16_name\":\"Battery\"");
    WT_HAS(body, "\"mfr_id\":76,\"mfr_name\":\"Apple, Inc.\"");
    WT_HAS(body, "\"appearance\":961,\"appearance_name\":\"Human Interface Device / Keyboard\"");
    WT_HAS(body, "\"est\":{\"m\":4.5,\"band\":\"room\",\"band_short\":\"room\",\"trend\":\"approaching\","
                 "\"glyph\":\"\xe2\x86\x98\",\"ptx\":\"ble_ad_tx_power\",\"ptx_short\":\"ad\","
                 "\"cell\":\"~5m room \xe2\x86\x98\",\"describe\":\"~4.5m room approaching, Ptx ad\"}");
    /* The writer's HTML-safe escape of '>' (web_json.c), as the page receives it. */
    WT_HAS(body, "\"cell\":\"~\\u003e1km far\",\"describe\":\"~1200m far unknown, Ptx assumed\"");
    WT_HAS(body, "\"hid\":1");
    /* Sorted by distance: the near one first, the row with no estimate
     * last either way. */
    WT_EQ(web_ble_devices_route(&B, "sort=dist", T, 0, body, sizeof(body), &len, &status), 0);
    const char *a = strstr(body, "02:de:00:00:00:07"), *b = strstr(body, "02:de:00:00:00:08"),
               *c = strstr(body, "00:00:00:00:00:00");
    WT_ASSERT(a && b && c && a < b && b < c);
    WT_EQ(web_ble_devices_route(&B, "sort=dist&dir=desc", T, 0, body, sizeof(body), &len, &status), 0);
    a = strstr(body, "02:de:00:00:00:07"); b = strstr(body, "02:de:00:00:00:08"); c = strstr(body, "00:00:00:00:00:00");
    WT_ASSERT(a && b && c && b < a && a < c);
    web_ble_destroy(&B);
}

/* The bound: 1025 distinct addresses are 1024 rows and one eviction, the
 * least recently heard row gone. */
static void test_lru_eviction(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    for (int i = 0; i < WEB_BLE_DEVICES + 1; i++) {
        char addr[18];
        snprintf(addr, sizeof(addr), "02:de:00:%02x:%02x:%02x", (i >> 16) & 255, (i >> 8) & 255, i & 255);
        /* Row 7 is the oldest by last_seen; everything else newer. */
        feed(dev_line(addr, 1, "bluetooth-monitor", "", -60, 1, T, i == 7 ? T - 1000 : T + i, NULL));
    }
    web_ble_stats_t st;
    web_ble_stats(&B, &st);
    WT_EQ(st.rows, WEB_BLE_DEVICES);
    WT_EQ(st.evictions, 1);
    char body[65536];
    size_t len = 0;
    int status = 0;
    WT_EQ(web_ble_device_route(&B, "02:de:00:00:00:07", "", T, 0, body, sizeof(body), &len, &status), 0);
    WT_EQ(status, 404);
    WT_EQ(web_ble_device_route(&B, "02:de:00:00:00:08", "", T, 0, body, sizeof(body), &len, &status), 0);
    WT_EQ(status, 200);
    web_ble_destroy(&B);
}

/* The larger-value rule in memory, as the store's upsert keeps it: a
 * record older than the row's newest (decreasing last_seen and
 * adv_count), and the newest one repeated, leave adv_count and
 * last_seen where the newest put them; a later one moves both on. Seen
 * red with dev_fill() assigning each from the record again, one at a
 * time (adv_count 10, and last_seen T - 600, after the older two). */
static void test_counts_only_move_up(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    char body[65536];
    size_t len = 0;
    int status = 0;
    feed(dev_line("02:de:00:00:00:61", 1, "bluetooth-monitor", "", -60, 120, T - 900, T, NULL));
    feed(dev_line("02:de:00:00:00:61", 1, "bluetooth-monitor", "", -60, 40, T - 900, T - 300, NULL));
    feed(dev_line("02:de:00:00:00:61", 1, "bluetooth-monitor", "", -60, 10, T - 900, T - 600, NULL));
    for (int rep = 0; rep < 2; rep++) {
        /* After the two older records, and again after the newest one
         * repeated. */
        WT_EQ(web_ble_device_route(&B, "02:de:00:00:00:61", "", T, 0, body, sizeof(body), &len, &status), 0);
        WT_EQ(status, 200);
        WT_HAS(body, "\"adv_count\":120,");
        WT_HAS(body, "\"last_seen\":1793000000");
        WT_ASSERT(strstr(body, "\"adv_count\":10,") == NULL);
        WT_ASSERT(strstr(body, "\"last_seen\":1792999400") == NULL);
        feed(dev_line("02:de:00:00:00:61", 1, "bluetooth-monitor", "", -60, 120, T - 900, T, NULL));
    }
    feed(dev_line("02:de:00:00:00:61", 1, "bluetooth-monitor", "", -60, 130, T - 900, T + 60, NULL));
    WT_EQ(web_ble_device_route(&B, "02:de:00:00:00:61", "", T + 60, 0, body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"adv_count\":130,");
    WT_HAS(body, "\"last_seen\":1793000060");
    web_ble_destroy(&B);
}

/* The drawer's presence strip: a quarter-hour bit per record's
 * last_seen over the row's last day, newest bucket first. A first
 * record marks its first_seen too; a later bucket shifts the strip
 * (within a word and across the 64-bit seam); a record from before the
 * day sets nothing; a gap longer than the day clears it. Seen red with
 * the full gate removed from dev_json() (the table's rows carried the
 * strip) and with the shift past 64 dropping the high word. */
static void test_presence_strip(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    char body[65536];
    size_t len = 0;
    int status = 0;
    const char *A = "02:de:00:00:00:41";
    feed(dev_line(A, 0, "bluetooth-monitor", "", -50, 1, T - 3600, T - 1800, NULL));
    feed(dev_line(A, 0, "bluetooth-monitor", "", -50, 2, T - 3600, T, NULL));
    feed(dev_line(A, 0, "bluetooth-monitor", "", -50, 3, T - 3600, T - 90000, NULL));
    WT_EQ(web_ble_device_route(&B, A, "", T, 0, body, sizeof(body), &len, &status), 0);
    WT_EQ(status, 200);
    WT_HAS(body, "\"presence\":{\"bucket_s\":900,\"n\":96,\"newest\":1792999800,"
                 "\"bits\":\"000000000000000000000015\"}");
    /* The table's rows do not carry it: the drawer's alone. */
    WT_EQ(web_ble_devices_route(&B, "", T, 0, body, sizeof(body), &len, &status), 0);
    WT_LACKS(body, "\"presence\"");
    web_ble_destroy(&B);
    WT_EQ(web_ble_init(&B, 0), 0);
    feed(dev_line(A, 0, "bluetooth-monitor", "", -50, 1, T - 1800, T - 1800, NULL));
    feed(dev_line(A, 0, "bluetooth-monitor", "", -50, 2, T - 1800, T, NULL));
    feed(dev_line(A, 0, "bluetooth-monitor", "", -50, 3, T - 1800, T + 70 * 900, NULL));
    WT_EQ(web_ble_device_route(&B, A, "", T + 70 * 900, 0, body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"bits\":\"000001400000000000000001\"");
    feed(dev_line(A, 0, "bluetooth-monitor", "", -50, 4, T - 1800, T + (70 + 96) * 900, NULL));
    WT_EQ(web_ble_device_route(&B, A, "", T + (70 + 96) * 900, 0, body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"newest\":1793149200,\"bits\":\"000000000000000000000001\"");
    web_ble_destroy(&B);
}

/* Every sort word the page's columns name orders by its own key. Four
 * rows a word, its key low on :03, middle on :01, high on :02 and empty
 * (or highest, for a key with no empty value) on :04, so neither
 * direction is the address order the tie-break falls back to: asc is
 * 03 01 02 04, desc 02 01 03 04 with an empty key last either way, or 04
 * 02 01 03 with none. mfr is three tiers in both directions (the SIG's
 * names by name, then ids it does not name, then none), so its desc is
 * 01 03 02 04. Seen red with each of the seven comparators' r set to 0
 * (every asc order failed, and desc where it differs from the address
 * order), and with mfr's old unnamed-after-named branch restored inside
 * the direction (desc put the unnamed id first). */
static const char *A4[5] = { "", "02:de:00:00:00:01", "02:de:00:00:00:02", "02:de:00:00:00:03",
                              "02:de:00:00:00:04" };

static void order_is(const char *q, const int want[4]) {
    char body[65536];
    size_t len = 0;
    int status = 0;
    WT_EQ(web_ble_devices_route(&B, q, T + 300, 0, body, sizeof(body), &len, &status), 0);
    WT_EQ(status, 200);
    const char *at[4];
    char key[40];
    for (int i = 0; i < 4; i++) {
        snprintf(key, sizeof(key), "\"addr\":\"%s\"", A4[want[i]]);
        at[i] = strstr(body, key);
        WT_ASSERT(at[i] != NULL);
    }
    int ok = at[0] && at[1] && at[2] && at[3] && at[0] < at[1] && at[1] < at[2] && at[2] < at[3];
    if (!ok) fprintf(stderr, "  %s: not %d %d %d %d\n", q, want[0], want[1], want[2], want[3]);
    WT_ASSERT(ok);
}

static void sorted(const char *word, int has_empty) {
    static const int ASC[4] = { 3, 1, 2, 4 }, DESC_E[4] = { 2, 1, 3, 4 }, DESC[4] = { 4, 2, 1, 3 };
    char q[64];
    snprintf(q, sizeof(q), "sort=%s&dir=asc", word);
    order_is(q, ASC);
    snprintf(q, sizeof(q), "sort=%s&dir=desc", word);
    order_is(q, has_empty ? DESC_E : DESC);
}

/* Four rows of one key: extra[i] the member for :0(i+1). */
static void four(const char *e1, const char *e2, const char *e3, const char *e4, int rssi4) {
    const char *ex[4] = { e1, e2, e3, e4 };
    web_ble_destroy(&B);
    WT_EQ(web_ble_init(&B, 0), 0);
    for (int i = 0; i < 4; i++)
        feed(dev_line(A4[i + 1], 0, "bluetooth-monitor", "", i == 3 ? rssi4 : -60, 1, T, T, ex[i]));
}

static void test_every_column_sorts(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    /* kind: "public" < "random NRPA" < "resolved public" < "resolved
     * random" (0x02 is a random address's 00 top bits). */
    four(",\"addr_type\":1", ",\"addr_type\":2", ",\"addr_type\":0", ",\"addr_type\":3", -60);
    sorted("kind", 0);
    /* best: rssi_best, the row with no RSSI last. */
    four(",\"rssi_best\":-80", ",\"rssi_best\":-70", ",\"rssi_best\":-90", "", 0);
    sorted("best", 1);
    /* hws: sampled 1 < watch 2 < hid 4 < all three 7. */
    four(",\"watch_category\":\"tag\"", ",\"hid\":1", ",\"sampled\":1",
         ",\"hid\":1,\"watch_category\":\"tag\",\"sampled\":1", -60);
    sorted("hws", 0);
    /* pdus: the mask, 1 < 16 < 32 < 64. */
    four(",\"pdu_mask\":16", ",\"pdu_mask\":32", ",\"pdu_mask\":1", ",\"pdu_mask\":64", -60);
    sorted("pdus", 0);
    /* watch: the category, none last. */
    four(",\"watch_category\":\"beta\"", ",\"watch_category\":\"gamma\"", ",\"watch_category\":\"alpha\"", "", -60);
    sorted("watch", 1);
    /* rate: adv/s between two records, a row of one record last. */
    web_ble_destroy(&B);
    WT_EQ(web_ble_init(&B, 0), 0);
    static const long long ADV[4] = { 160, 310, 40, 0 };   /* 0.5, 1, 0.1 /s; none */
    for (int i = 0; i < 4; i++) {
        feed(dev_line(A4[i + 1], 0, "bluetooth-monitor", "", -60, 10, T, T, NULL));
        if (ADV[i]) feed(dev_line(A4[i + 1], 0, "bluetooth-monitor", "", -60, ADV[i], T, T + 300, NULL));
    }
    sorted("rate", 1);
    /* mfr: Apple, Inc. (0x004c) < Microsoft (0x0006) by name, then an
     * id the table does not name, then none. Without the SIG table
     * every id is unnamed and orders by number. */
    const web_btsig_tab_t *sig = web_btsig_builtin();
    if (sig && !strcmp(sig->source, "sig")) {
        int un = 0xfff0;
        while (un > 0xff00 && web_btsig_company(sig, un)) un--;
        WT_ASSERT(web_btsig_company(sig, un) == NULL);
        char e2[32];
        snprintf(e2, sizeof(e2), ",\"mfr_id\":%d", un);
        four(",\"mfr_id\":6", e2, ",\"mfr_id\":76", "", -60);
        static const int ASC[4] = { 3, 1, 2, 4 }, DESC[4] = { 1, 3, 2, 4 };
        order_is("sort=mfr&dir=asc", ASC);
        order_is("sort=mfr&dir=desc", DESC);
    } else {
        four(",\"mfr_id\":200", ",\"mfr_id\":300", ",\"mfr_id\":100", "", -60);
        sorted("mfr", 1);
    }
    web_ble_destroy(&B);
}

/* ── the findings ─────────────────────────────────────────────────── */

static const char FLOOD[] =
    "{\"type\":\"ble_alert\",\"ts\":%lld,\"kind\":\"adv_flood\",\"alert\":\"BLE_ADV_FLOOD\","
    "\"ty\":87,\"key\":\"ble_flood:bluetooth-monitor:mfr:004c:07\",\"sensor\":\"ble\","
    "\"iface\":\"bluetooth-monitor\",\"sampled\":0,\"adv_type\":\"ADV_IND\",\"family\":\"mfr\","
    "\"id\":76,\"subtype\":7,\"window\":\"previous\",\"window_s\":10,\"distinct_addrs\":44,"
    "\"distinct_capped\":0,\"fresh_addrs\":40,\"total_adv\":812,\"rate\":81.2,\"has_rssi\":1,"
    "\"median_rssi\":-61,\"spam_source\":\"ble-spam-flood.md\"}";
static const char HIDOUI[] =
    "{\"type\":\"ble_alert\",\"ts\":%lld,\"kind\":\"hid_oui\",\"alert\":\"BLE_HID_UNEXPECTED\","
    "\"ty\":88,\"key\":\"ble_hid_oui:bluetooth-monitor:00:13:37:00:00:01\",\"sensor\":\"ble\","
    "\"iface\":\"bluetooth-monitor\",\"sampled\":0,\"addr\":\"00:13:37:00:00:01\",\"addr_type\":0,"
    "\"hid\":3,\"appearance\":961,\"oui_table\":\"Hak5\"}";

static void test_findings_and_resolve(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    char line[1024];
    snprintf(line, sizeof(line), FLOOD, T);
    feed(line);
    snprintf(line, sizeof(line), HIDOUI, T + 1);
    feed(line);
    feed("{\"type\":\"ble_alert\",\"ts\":1793000002,\"kind\":\"newfangled\",\"alert\":\"BLE_SOMETHING\","
         "\"ty\":90,\"key\":\"k3\",\"sensor\":\"ble\",\"iface\":\"bluetooth-monitor\",\"sampled\":0}");
    feed("{\"type\":\"ble_alert\",\"ts\":1793000002,\"kind\":\"watchlist\",\"alert\":\"BLE_WATCHLIST\","
         "\"ty\":89,\"sensor\":\"ble\",\"iface\":\"bluetooth-monitor\",\"sampled\":0}");   /* no key */
    web_ble_stats_t st;
    web_ble_stats(&B, &st);
    WT_EQ(st.alert_rows, 3);
    WT_EQ(st.bad_records, 1);
    WT_EQ(st.other_word, 2);          /* the kind and the alert name */
    char body[65536];
    size_t len = 0;
    int status = 0;
    WT_EQ(web_ble_alerts_route(&B, "", T + 2, 0, body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"standing\":3,");
    WT_HAS(body, "\"kind\":\"adv_flood\",\"alert\":\"BLE_ADV_FLOOD\",\"iface\":\"bluetooth-monitor\",\"sampled\":0,\"standing\":true");
    WT_HAS(body, "\"rate\":81.2");
    WT_HAS(body, "\"spam_source\":\"ble-spam-flood.md\"");
    WT_HAS(body, "\"kind\":\"hid_oui\"");
    WT_HAS(body, "\"oui_table\":\"Hak5\"");
    WT_HAS(body, "\"kind\":\"other\",\"alert\":\"other\"");
    /* The key is never rendered. */
    WT_LACKS(body, "ble_flood:bluetooth-monitor");
    WT_LACKS(body, "\"key\"");
    /* The drawer: the hid_oui finding names its address. */
    WT_EQ(web_ble_device_route(&B, "00%3A13%3A37%3A00%3A00%3A01", "", T + 2, 0, body, sizeof(body), &len, &status), 0);
    WT_EQ(status, 404);               /* no advertiser row, but the finding is listed */
    WT_HAS(body, "\"alerts\":[{\"kind\":\"hid_oui\"");
    /* The resolve of the flood's key: not standing, resolved_ts set; a
     * resolve of an unknown key changes nothing. */
    feed("{\"type\":\"alert.resolve\",\"ts\":1793000100,\"incident_id\":\"d1\",\"sev\":1,\"ty\":87,"
         "\"key\":\"ble_flood:bluetooth-monitor:mfr:004c:07\",\"title\":\"BLE_ADV_FLOOD\",\"reason\":\"expired\"}");
    feed("{\"type\":\"alert.resolve\",\"ts\":1793000100,\"incident_id\":\"d2\",\"sev\":1,\"ty\":0,"
         "\"key\":\"scan:10.0.0.1\",\"title\":\"PORT_SCAN\"}");
    web_ble_stats(&B, &st);
    WT_EQ(st.resolves, 1);
    WT_EQ(web_ble_alerts_route(&B, "", T + 101, 0, body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"standing\":2,");
    WT_HAS(body, "\"kind\":\"adv_flood\",\"alert\":\"BLE_ADV_FLOOD\",\"iface\":\"bluetooth-monitor\",\"sampled\":0,\"standing\":false");
    WT_HAS(body, "\"resolved_ts\":1793000100");
    /* Standing first, so the flood is last. */
    WT_ASSERT(strstr(body, "\"kind\":\"hid_oui\"") < strstr(body, "\"kind\":\"adv_flood\""));
    /* A finding quiet past WEB_BLE_STAND_S is no longer standing, whatever
     * resolve was missed; one resolved more than a day ago is not listed. */
    WT_EQ(web_ble_alerts_route(&B, "", T + 2 + WEB_BLE_STAND_S + 1, 0, body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"standing\":0,");
    WT_EQ(web_ble_alerts_route(&B, "", T + 100 + WEB_BLE_RESOLVED_S + 1, 0, body, sizeof(body), &len, &status), 0);
    WT_LACKS(body, "adv_flood");
    web_ble_destroy(&B);
}

/* ── sensor_health ─────────────────────────────────────────────────── */

static const char SH[] =
    "{\"type\":\"sensor_health\",\"ts\":%lld,\"capture_iface\":\"eth0\",\"capture_open\":1,"
    "\"capture_running\":1,\"btmon_iface\":\"%s\",\"btmon_err\":\"\",\"btmon_open\":1,"
    "\"btmon_running\":1,\"btmon_exit\":\"none\",\"btmon_exit_detail\":\"\",\"btmon_stats_valid\":0,"
    "\"btmon_recv\":0,\"btmon_drop\":0,\"btmon_ifdrop\":0,\"btmon_last_frame_ts\":%lld,"
    "\"btmon_stale_secs\":2,\"ble_controllers\":1,\"ble_devices\":%d,\"ble_records\":900,"
    "\"ble_adv_reports\":%d,\"ble_multi_report_rejected\":0,\"ble_ext_adv_undecoded\":0,"
    "\"ble_ext_adv_reports\":3,\"ble_ext_adv_fragments\":0,\"ble_ext_adv_partial\":0,"
    "\"ble_ext_trains_evicted\":0,\"ble_records_ignored\":4,\"ble_records_malformed\":0,"
    "\"ble_host_commands\":3,\"ble_scan_mode\":\"passive\",\"ble_scan_filter\":\"basic\","
    "\"ble_scan_accept_list\":0,\"ble_scan_enabled\":1,\"ble_own_tx\":\"never\","
    "\"ble_own_tx_kind\":\"none\",\"ble_own_tx_count\":0,\"ble_own_tx_secs\":-1,\"ble_own_tx_on\":\"\","
    "\"ble_own_tx_asserted\":\"\",\"ble_own_tx_baseline\":1,\"ble_index_records\":2,"
    "\"btcap_iface\":\"\",\"btcap_state\":\"off\"%s}";

static void test_sensor_health_members(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    char line[2048];
    web_ble_sh_t sh;
    web_ble_sensor(&B, &sh);
    WT_EQ(sh.seen, 0);
    /* An older sloth with no Bluetooth block: nothing said. */
    feed("{\"type\":\"sensor_health\",\"ts\":5,\"capture_iface\":\"eth0\",\"capture_open\":1}");
    web_ble_sensor(&B, &sh);
    WT_EQ(sh.seen, 0);
    snprintf(line, sizeof(line), SH, T, "bluetooth-monitor", T - 2, 82, 4263,
             ",\"ble_rot_hints\":\"10-99\",\"ble_rot_poisoned\":\"0\",\"ble_rot_seam_evictions\":\"1-9\"");
    feed(line);
    web_ble_sensor(&B, &sh);
    WT_EQ(sh.seen, 1);
    WT_ASSERT(!strcmp(sh.btmon_iface, "bluetooth-monitor"));
    WT_EQ(sh.ble_devices, 82);
    WT_EQ(sh.ble_adv_reports, 4263);
    WT_ASSERT(!strcmp(sh.ble_scan_mode, "passive"));
    WT_EQ(sh.ble_scan_enabled, 1);
    WT_EQ(sh.rot_present, 1);
    WT_ASSERT(!strcmp(sh.ble_rot_hints, "10-99"));
    char body[4096];
    web_jw_t w;
    web_jw_init(&w, body, sizeof(body));
    web_ble_live_json(&B, &w, T);
    body[w.len] = '\0';
    WT_HAS(body, "{\"configured\":true,\"seen\":true,\"rows\":0,");
    WT_HAS(body, "\"ble_devices\":82,\"ble_adv_reports\":4263,\"ble_scan_mode\":\"passive\"");
    WT_HAS(body, "\"rot\":{\"hints\":\"10-99\",\"poisoned\":\"0\",\"seam_evictions\":\"1-9\"}");
    /* The rotation block goes when the flag is off: the members are
     * absent from the record then. */
    snprintf(line, sizeof(line), SH, T + 1, "", T - 2, 0, 0, "");
    feed(line);
    web_jw_init(&w, body, sizeof(body));
    web_ble_live_json(&B, &w, T);
    body[w.len] = '\0';
    WT_HAS(body, "{\"configured\":false,\"seen\":true,");
    WT_HAS(body, "\"rot\":null");
    web_ble_destroy(&B);
}

/* ── the metrics ──────────────────────────────────────────────────── */

static long long g_clock = T;
static long long clock_fn(void *ctx) { (void)ctx; return g_clock; }

/* ble.devices is a gauge and ble.adv_rate a counter delta, both from
 * the sensor_health's Bluetooth block: nothing while neither source is
 * configured (btmon_iface and btcap_iface both ""). Seen red with the
 * guard removed. */
static void test_metrics_from_sensor_health(void) {
    web_rollup_t ru;
    web_metrics_t m;
    char err[64], line[2048];
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&m, &ru, clock_fn, NULL), 0);
    static web_jrec_t r;
    snprintf(line, sizeof(line), SH, T, "", T, 0, 0, "");
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_metrics_record(&m, &r);
    WT_ASSERT(!web_rollup_has(&ru, WM_BLE_DEVICES, ""));
    WT_ASSERT(!web_rollup_has(&ru, WM_BLE_ADV_REPORTS, ""));
    snprintf(line, sizeof(line), SH, T + 1, "bluetooth-monitor", T, 82, 4000, "");
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_metrics_record(&m, &r);
    WT_ASSERT(web_rollup_has(&ru, WM_BLE_DEVICES, ""));
    /* The first sight is a baseline: no delta yet. */
    WT_ASSERT(!web_rollup_has(&ru, WM_BLE_ADV_REPORTS, ""));
    g_clock = T + 10;
    snprintf(line, sizeof(line), SH, T + 11, "bluetooth-monitor", T, 83, 4060, "");
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_metrics_record(&m, &r);
    WT_ASSERT(web_rollup_has(&ru, WM_BLE_ADV_REPORTS, ""));
    web_metrics_destroy(&m);
    web_rollup_destroy(&ru);
    /* An Ubertooth alone (--bt-capture, no --bt-monitor): sloth's count
     * takes its rows, so ble.devices is sampled; ble_adv_reports is the
     * host stream's, so ble.adv_rate is not, however many records. Seen
     * red with the btcap_iface test taken out of web_metrics.c (nothing
     * sampled), and with the btmon-only gate on the adv delta removed
     * (a rate of the host stream's zeros). */
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&m, &ru, clock_fn, NULL), 0);
    for (int i = 0; i < 3; i++) {
        g_clock = T + 10 * i;
        snprintf(line, sizeof(line), SH, T + 10 * i, "", T, 12 + i, 100 + 50 * i, "");
        char *bc = strstr(line, "\"btcap_iface\":\"\"");
        WT_ASSERT(bc != NULL);
        if (!bc) break;
        char tail[1024];
        snprintf(tail, sizeof(tail), "%s", bc + strlen("\"btcap_iface\":\"\""));
        snprintf(bc, sizeof(line) - (size_t)(bc - line), "\"btcap_iface\":\"/run/ut.pipe\"%s", tail);
        WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
        web_metrics_record(&m, &r);
    }
    WT_ASSERT(web_rollup_has(&ru, WM_BLE_DEVICES, ""));
    WT_ASSERT(!web_rollup_has(&ru, WM_BLE_ADV_REPORTS, ""));
    WT_ASSERT(!strcmp(web_metric_defs[WM_BLE_DEVICES].name, "ble.devices"));
    WT_ASSERT(!strcmp(web_metric_defs[WM_BLE_ADV_REPORTS].name, "ble.adv_rate"));
    WT_EQ(web_metric_defs[WM_BLE_DEVICES].kclass, WEB_KC_GLOBAL);
    WT_EQ(web_scope_metric(WM_BLE_DEVICES), WEB_SC_M);
    WT_EQ(web_scope_metric(WM_BLE_ADV_REPORTS), WEB_SC_M);
    web_metrics_destroy(&m);
    web_rollup_destroy(&ru);
    g_clock = T;
}

/* ── the routes ───────────────────────────────────────────────────── */

static char g_out[65536];

static int route(const web_health_t *h, const char *path, const char *query) {
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    int rc = web_route(rq, h, 1, g_out, sizeof(g_out), &r);
    free(rq);
    if (rc != 0) return -1;
    g_out[r.out_len] = '\0';
    return r.status;
}

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static web_live_t L;

static void live_feed(const char *line) {
    static web_jrec_t r;
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_live_apply(&L, &r, 1000);
    web_ble_record(&B, &r, 1000);
}

/* Every route through the table: the sort words, the direction, the
 * refusals (never echoing the value), the search, the scope: Monitor
 * and Hybrid serve, Local answers out_of_scope with the query still
 * checked; /api/live's "ble" member, null under Local; /api/health's
 * counters; the BLE alert on the Alerts page, typed and Monitor's. */
static void test_routes(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    web_live_init(&L, "unix:/t.sock");
    web_live_sock_connected(&L, 1000);
    char line[2048];
    snprintf(line, sizeof(line), SH, T, "bluetooth-monitor", T, 3, 100, "");
    live_feed(line);
    live_feed(dev_line("02:de:00:00:00:11", 0, "bluetooth-monitor", "kettle", -50, 100, T - 500, T - 20, NULL));
    live_feed(dev_line("02:de:00:00:00:12", 1, "bluetooth-monitor", "Lamp", -70, 5, T - 300, T - 10,
                       ",\"watch_category\":\"tracker-tag\""));
    live_feed(dev_line("02:de:00:00:00:13", 0, "ubertooth", "", -80, 2, T - 100, T, ",\"hid\":2"));
    snprintf(line, sizeof(line), FLOOD, T);
    live_feed(line);
    live_feed("{\"type\":\"alert.create\",\"ts\":1793000000,\"incident_id\":\"e1\",\"sev\":1,\"ty\":87,"
              "\"key\":\"ble_flood:bluetooth-monitor:mfr:004c:07\",\"title\":\"BLE_ADV_FLOOD\","
              "\"detail\":\"BLE advertisement flood: mfr 004c/07 ADV_IND\"}");
    web_health_t H;
    memset(&H, 0, sizeof(H));
    H.live = &L;
    H.ble = &B;
    H.wall_s = T;
    H.now_ms = 2000;
    WT_EQ(route(&H, "/api/ble", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"sort\":\"last\"");
    WT_HAS(b, "\"total\":3,\"matched\":3,\"hid\":1,\"watch\":1,\"standing\":1,\"standing_floods\":1");
    /* last desc: 13, 12, 11. */
    WT_ASSERT(strstr(b, ":00:13\"") < strstr(b, ":00:12\"") && strstr(b, ":00:12\"") < strstr(b, ":00:11\""));
    static const char *const W[] = { "last", "first", "rssi", "dist", "adv", "addr", "type", "iface", "name",
                                     "kind", "best", "rate", "hws", "pdus", "watch", "mfr" };
    for (size_t i = 0; i < sizeof(W) / sizeof(W[0]); i++) {
        char q[64];
        snprintf(q, sizeof(q), "sort=%s", W[i]);
        WT_EQ(route(&H, "/api/ble", q), 200);
        snprintf(q, sizeof(q), "sort=%s&dir=asc", W[i]);
        WT_EQ(route(&H, "/api/ble", q), 200);
        WT_HAS(body_of(g_out), ",\"dir\":\"asc\"}");
    }
    WT_EQ(route(&H, "/api/ble", "sort=rssi"), 200);
    b = body_of(g_out);
    WT_ASSERT(strstr(b, ":00:11\"") < strstr(b, ":00:12\"") && strstr(b, ":00:12\"") < strstr(b, ":00:13\""));
    WT_EQ(route(&H, "/api/ble", "sort=name&dir=asc"), 200);
    b = body_of(g_out);  /* case folded: kettle before Lamp, the empty name last */
    WT_ASSERT(strstr(b, ":00:11\"") < strstr(b, ":00:12\"") && strstr(b, ":00:12\"") < strstr(b, ":00:13\""));
    /* hws: the three flags as the TUI's cell orders them. */
    WT_EQ(route(&H, "/api/ble", "sort=hws"), 200);
    WT_HAS(body_of(g_out), "\"sort\":\"hws\"");
    WT_EQ(route(&H, "/api/ble", "sort=hostname"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_sort\"}");
    WT_LACKS(body_of(g_out), "hostname");
    WT_EQ(route(&H, "/api/ble", "dir=up"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_dir\"}");
    WT_EQ(route(&H, "/api/ble", "limit=0"), 400);
    WT_EQ(route(&H, "/api/ble", "limit=1025"), 400);
    WT_EQ(route(&H, "/api/ble", "offset=x"), 400);
    WT_EQ(route(&H, "/api/ble", "bogus=1"), 400);
    WT_EQ(route(&H, "/api/ble", "sort=last&sort=first"), 400);
    WT_HAS(body_of(g_out), "repeated_parameter");
    /* The search: an address prefix, a name, a category, case folded. */
    WT_EQ(route(&H, "/api/ble", "q=02%3Ade%3A00%3A00%3A00%3A1"), 200);
    WT_HAS(body_of(g_out), "\"matched\":3");
    WT_EQ(route(&H, "/api/ble", "q=KETT"), 200);
    WT_HAS(body_of(g_out), "\"matched\":1");
    WT_HAS(body_of(g_out), "\"name\":\"kettle\"");
    WT_EQ(route(&H, "/api/ble", "q=tracker"), 200);
    WT_HAS(body_of(g_out), "\"matched\":1");
    WT_HAS(body_of(g_out), "\"watch_category\":\"tracker-tag\"");
    WT_EQ(route(&H, "/api/ble", "q=nothing-here"), 200);
    WT_HAS(body_of(g_out), "\"matched\":0,");
    WT_HAS(body_of(g_out), "\"rows\":[]");
    /* Paging. */
    WT_EQ(route(&H, "/api/ble", "limit=2"), 200);
    WT_HAS(body_of(g_out), "\"count\":2,\"more\":true,\"next_offset\":2");
    WT_EQ(route(&H, "/api/ble", "limit=2&offset=2"), 200);
    WT_HAS(body_of(g_out), "\"count\":1,\"more\":false,\"next_offset\":null");
    /* The scope. */
    WT_EQ(route(&H, "/api/ble", "scope=monitor&limit=1"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"monitor\",\"now\":");
    WT_EQ(route(&H, "/api/ble", "scope=hybrid"), 200);
    WT_HAS(body_of(g_out), "\"total\":3");
    WT_EQ(route(&H, "/api/ble", "scope=local"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"local\",\"out_of_scope\":true,\"reason\":\"BLE advertisers are the passive Bluetooth receivers");
    WT_LACKS(body_of(g_out), "\"rows\"");
    WT_EQ(route(&H, "/api/ble", "scope=local&sort=bogus"), 400);   /* still checked */
    WT_EQ(route(&H, "/api/ble/alerts", "scope=local"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true");
    WT_EQ(route(&H, "/api/ble/02%3Ade%3A00%3A00%3A00%3A11", "scope=local"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true");
    WT_EQ(route(&H, "/api/ble", "scope=wifi"), 400);
    WT_HAS(body_of(g_out), "bad_scope");
    /* The one-row route. */
    WT_EQ(route(&H, "/api/ble/02%3Ade%3A00%3A00%3A00%3A11", "type=0&iface=bluetooth-monitor"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"count\":1}");
    WT_HAS(b, "\"name\":\"kettle\"");
    WT_HAS(b, "\"points\":[[");
    WT_EQ(route(&H, "/api/ble/02:de:00:00:00:11", ""), 200);
    WT_EQ(route(&H, "/api/ble/02%3Ade%3A00%3A00%3A00%3A11", "type=9"), 400);
    WT_HAS(body_of(g_out), "bad_type");
    WT_EQ(route(&H, "/api/ble/02%3Ade%3A00%3A00%3A00%3A11", "iface=hci0"), 400);
    WT_HAS(body_of(g_out), "bad_iface");
    WT_EQ(route(&H, "/api/ble/nonsense", ""), 400);
    WT_HAS(body_of(g_out), "bad_mac");
    WT_EQ(route(&H, "/api/ble/02%3Ade%3A00%3A00%3A00%3Aff", ""), 404);
    WT_EQ(route(&H, "/api/ble/a/b", ""), 404);
    /* The alerts route. */
    WT_EQ(route(&H, "/api/ble/alerts", ""), 200);
    WT_HAS(body_of(g_out), "\"standing\":1,\"rows\":[{\"kind\":\"adv_flood\"");
    WT_EQ(route(&H, "/api/ble/alerts", "limit=0"), 400);
    /* query_too_long. */
    char longq[600];
    memset(longq, 'a', sizeof(longq) - 1);
    longq[sizeof(longq) - 1] = '\0';
    memcpy(longq, "q=", 2);
    WT_EQ(route(&H, "/api/ble", longq), 400);
    WT_HAS(body_of(g_out), "query_too_long");
    /* HEAD. */
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    snprintf(rq->path, sizeof(rq->path), "/api/ble");
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1");
    rq->host_count = 1;
    rq->is_head = 1;
    WT_EQ(web_route(rq, &H, 1, g_out, sizeof(g_out), &r), 0);
    WT_EQ(r.status, 200);
    g_out[r.out_len] = '\0';
    WT_LACKS(g_out, "\"rows\"");
    free(rq);
    /* /api/live: the "ble" member, Hybrid's and Monitor's; null under
     * Local. */
    WT_EQ(route(&H, "/api/live", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, ",\"ble\":{\"configured\":true,\"seen\":true,\"rows\":3,\"hid\":1,\"watch\":1,\"standing\":1,"
              "\"btmon_iface\":\"bluetooth-monitor\"");
    WT_HAS(b, "\"ble_devices\":3,\"ble_adv_reports\":100");
    WT_EQ(route(&H, "/api/live", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), ",\"ble\":{\"configured\":true");
    WT_EQ(route(&H, "/api/live", "scope=local"), 200);
    WT_HAS(body_of(g_out), ",\"ble\":null}");
    /* /api/health. */
    WT_EQ(route(&H, "/api/health", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, ",\"ble\":{\"rows\":3,\"cap\":1024,\"alert_rows\":1,\"alert_cap\":128,");
    WT_HAS(b, "\"sig\":\"");
    WT_HAS(b, ",\"ble_store\":null");
    /* Without the tables the M0 shape stands. */
    H.ble = NULL;
    WT_EQ(route(&H, "/api/health", ""), 200);
    WT_LACKS(body_of(g_out), "\"ble\"");
    WT_EQ(route(&H, "/api/live", ""), 200);
    WT_LACKS(body_of(g_out), "\"ble\"");
    WT_EQ(route(&H, "/api/ble", ""), 503);
    H.ble = &B;
    /* The BLE finding is an incident on the Alerts page too, typed and
     * Monitor's (web_scope.c). */
    WT_EQ(route(&H, "/api/alerts", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "BLE_ADV_FLOOD");
    WT_EQ(route(&H, "/api/alerts", "scope=local"), 200);
    WT_LACKS(body_of(g_out), "BLE_ADV_FLOOD");
    WT_EQ(route(&H, "/api/alerts", ""), 200);
    WT_HAS(body_of(g_out), "BLE_ADV_FLOOD");
    web_live_destroy(&L);
    web_ble_destroy(&B);
}

static void test_live_member_worst_case(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    web_live_init(&L, "unix:/t.sock");
    web_live_sock_connected(&L, 1000);
    web_health_t H;
    memset(&H, 0, sizeof(H));
    H.live = &L;
    H.ble = &B;
    H.wall_s = T;
    H.now_ms = 2000;
    const char *b;
    /* /api/live's "ble" member at its worst: every string the member
     * carries at its 32-byte cut and every byte one the writer turns
     * into a six-byte \u escape. The member fits, and /api/live is
     * whole. Seen red with live_body()'s buffer back at 1024 bytes (the
     * member null), and before the null fallback existed the whole
     * route failed. */
    char S32[33], big[2048];
    memset(S32, '<', 32);
    S32[32] = '\0';
    snprintf(big, sizeof(big),
             "{\"type\":\"sensor_health\",\"ts\":%lld,\"btmon_iface\":\"%s\",\"btmon_exit\":\"%s\","
             "\"ble_scan_mode\":\"%s\",\"ble_scan_filter\":\"%s\",\"ble_own_tx\":\"%s\","
             "\"ble_own_tx_kind\":\"%s\",\"btcap_iface\":\"%s\",\"btcap_state\":\"%s\","
             "\"btcap_sampling\":\"%s\",\"ble_rot_hints\":\"%s\",\"ble_rot_poisoned\":\"%s\","
             "\"ble_rot_seam_evictions\":\"%s\",\"ble_devices\":9223372036854775807,"
             "\"ble_controllers\":9223372036854775807,\"ble_adv_reports\":9223372036854775807,"
             "\"btmon_stale_secs\":-9223372036854775807}",
             T, S32, S32, S32, S32, S32, S32, S32, S32, S32, S32, S32, S32);
    live_feed(big);
    WT_EQ(route(&H, "/api/live", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, ",\"ble\":{\"configured\":true,\"seen\":true,");
    WT_HAS(b, "\"btcap_sampling\":\"\\u003c\\u003c");
    WT_HAS(b, "\"seam_evictions\":\"\\u003c");
    WT_LACKS(b, ",\"ble\":null");
    web_live_destroy(&L);
    web_ble_destroy(&B);
}

/* ── the page ─────────────────────────────────────────────────────── */

#include "web_assets.h"

/* The page's BLE view as served: the tab and its hotkey, the table
 * through the one DataTable, the cells' ports of the TUI's helpers, the
 * one-colour row rule, the TUI's lines verbatim, the kept controls, the
 * scope toggle, the Health block, the strip's fact. Pinned as the colour
 * suite pins its lines. Seen red with "0" taken out of the keydown. */
static void test_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<li><button type=\"button\" class=\"go\" id=\"nav-ble\"><span class=\"k\">0</span>BLE Devices</button></li>");
    WT_HAS(p, "    if (e.key === \"0\") show(\"ble\");");
    WT_HAS(p, "               \"lookup\", \"tacdb\", \"ble\", \"gnss\", \"adsb\", \"aprs\", \"radar\"];");
    WT_HAS(p, "    if (v === \"ble\") bleView();");
    /* The bundle module's hook in the drawer header: the container and
     * the guarded call, a no-op without bundle.js. Seen red with the
     * guard's window.SlothBundle test dropped. */
    WT_HAS(p, "<span id=\"bundle-btn-ble\"></span>");
    WT_HAS(p, "    if (bb && window.SlothBundle && SlothBundle.mount) SlothBundle.mount(bb, \"ble\", addr, scoped);");
    WT_HAS(p, "                 \"ble\": [\"q\"] };");
    WT_HAS(p, "  var DTB = DataTable({ id: \"ble\", label: \"ble advertisers\", box: $(\"b-box\"), head: $(\"b-thead\"),");
    WT_HAS(p, "  var DTBA = DataTable({ id: \"blealerts\", label: \"ble alerts\", box: $(\"b-al-box\"), head: $(\"b-al-head\"),");
    /* The row: one colour, bright for HID or watchlist, normal otherwise;
     * no swatch, no hash hue, no monitor ground. */
    WT_HAS(p, "    var cls = d.hid || d.watch_category ? \"d-bright\" : \"d-normal\";\n"
              "    var row = el(\"div\", \"blerow dt-row \" + cls + (sel ? \" on\" : \"\"));");
    WT_HAS(p, "    row.appendChild(el(\"span\", \"c-ad\", d.addr));");
    WT_LACKS(p, "keyColor(d.addr)");
    WT_LACKS(p, "ssidSpan(d.name");
    WT_HAS(p, ".blerow > span { color: inherit; }");
    /* The TUI's helpers, ported. */
    WT_HAS(p, "  function bleCount(c) {\n"
              "    if (!num(c)) return \"-\";\n"
              "    if (c < 100000) return String(c);\n"
              "    if (c < 100000000) return Math.floor(c / 1000) + \"k\";\n"
              "    return Math.floor(c / 1000000) + \"M\";\n"
              "  }");
    WT_HAS(p, "    if (a < 60) return a + \"s\";\n"
              "    if (a < 3600) return Math.floor(a / 60) + \"m\";\n"
              "    if (a < 86400) return Math.floor(a / 3600) + \"h\";\n"
              "    return Math.floor(a / 86400) + \"d\";");
    WT_HAS(p, "    return (d.hid ? \"H\" : \"-\") + (d.watch_category ? \"W\" : \"-\") + (d.sampled ? \"~\" : \"-\");");
    WT_HAS(p, "    if (num(d.mfr_id)) p.push(\"mfr \" + hex4(d.mfr_id) + (num(d.mfr_subtype) ? \"/\" + hex2(d.mfr_subtype) : \"\"));");
    /* The header line: count bright, HID and watchlist at tui_heat(0.5)
     * when above zero else dim, the rest dim. */
    WT_HAS(p, "    line.appendChild(el(\"span\", \"d-bright\", live !== null ? String(live) : \"-\"));");
    WT_HAS(p, "    line.appendChild(el(\"span\", j.hid > 0 ? \"h2\" : \"d-dim\", String(j.hid)));");
    WT_HAS(p, "    line.appendChild(el(\"span\", j.watch > 0 ? \"h2\" : \"d-dim\", String(j.watch)));");
    WT_HAS(p, "    line.appendChild(el(\"span\", \"d-dim\", \"  standing floods: \" + j.standing_floods));");
    /* The TUI's lines, verbatim. */
    WT_HAS(p, "T: P public R random p/r resolved  H HID  W watchlist  ~ sample  DIST: signal-strength estimate");
    WT_HAS(p, "(no advertisements decoded - start with --bt-monitor or");
    WT_HAS(p, " connects or reads GATT: the operator's stack runs the scan.)");
    WT_HAS(p, "  corroborates, does not confirm, and identifies no device or person.");
    WT_HAS(p, "  These records alone are not grounds for personnel action or physical identification.");
    WT_HAS(p, "  Links cover the recent window only: an address out of it counts on its own.");
    WT_HAS(p, "  May include timing-only hints. Weak: another advertiser leaving and arriving reads the same.");
    /* The drawer's TUI order and wording. */
    WT_HAS(p, "        [\"sensor\", \"ble on \" + d.iface + \", adapter \" + d.adapter + (d.sampled ? \" - one-channel sample, counts are a fraction\" : \"\")],");
    WT_HAS(p, "        [\"watchlist\", d.watch_category ? d.watch_category + \" - a category, never an identity\" : null],");
    WT_HAS(p, "        [\"distance (est)\", num(d.rssi) ? (d.est ? d.est.describe : \"no estimate\") : null],");
    /* Kept controls, the scope, the strip, the Health block. */
    WT_HAS(p, "\"q-sql\", \"b-q\", \"b-sort\", \"bledev-win\", \"bledev-metric\", \"bledev-n\",\n"
              "   \"gnss-seen-days\", \"adsb-seen-days\", \"adsb-seen-q\", \"gnss-trail-hours\",\n"
              "   \"aprs-seen-days\", \"aprs-seen-q\", \"radar-aprs-win\"].forEach(keepCtl);");
    /* The BLE Devices waterfall (web/ui/bledev.js): its module after
     * app.js, its four hooks guarded (reset since the 2026-11-02
     * review: the drawer's BLE lines never outlive their address), its
     * panels children of v-ble so Local's scoped-out rule hides them
     * with the rest. */
    WT_HAS(p, "    if (window.SlothBleDev) SlothBleDev.show();");
    WT_HAS(p, "      if (window.SlothBleDev) SlothBleDev.drawer(d, now);");
    WT_HAS(p, "  if (window.SlothBleDev) SlothBleDev.init({ el: el, set: set, getJSON: getJSON, theme: theme,");
    WT_HAS(p, "    if (window.SlothBleDev) SlothBleDev.reset();");
    WT_HAS(p, "  window.SlothBleDev = { init: init, show: show, drawer: drawer, reset: reset };");
    WT_HAS(p, "    $(\"v-ble\").classList.toggle(\"scoped-out\", SCOPE === \"local\");");
    WT_HAS(p, "<span title=\"BLE advertisers slothweb holds, from sloth's ble_device records (Monitor's; - under Local or with no Bluetooth source)\">ble <b id=\"s-ble\">-</b><canvas class=\"sg\" id=\"s-ble-g\" aria-label=\"BLE advertisers, 24 h\"></canvas></span>");
    WT_HAS(p, "        set(\"s-ble\", l.ble && l.ble.configured && num(l.ble.rows) ? l.ble.rows : \"-\");");
    WT_HAS(p, "        box.appendChild(el(\"div\", \"label\", \"bluetooth (sensor_health btmon_* / ble_* / btcap_*)\"));");
    WT_HAS(p, "    if (b && b.btmon_iface) bits.push(\"btmon \" + b.btmon_iface +");
    /* The address in words; every column a server sort word. */
    WT_HAS(p, "    row.appendChild(el(\"span\", \"c-ak\", d.addr_kind));");
    WT_HAS(p, "      { k: \"ak\", label: \"kind\", w: 14, min: 6, type: \"text\", srv: \"kind\", val: bv(\"addr_kind\") },");
    {
        const char *b = strstr(p, "  var DTB = DataTable({ id: \"ble\",");
        const char *e = b ? strstr(b, "    ] });") : NULL;
        WT_ASSERT(b && e);
        /* Each column runs from its "{ k: " to the next one's (or the
         * list's end), and names a sort word inside that span. */
        int cols = 0, srv = 0;
        const char *q = b && e ? strstr(b, "{ k: \"") : NULL;
        while (q && q < e) {
            const char *nx = strstr(q + 1, "{ k: \"");
            const char *end = nx && nx < e ? nx : e;
            const char *sw = strstr(q, "srv: \"");
            cols++;
            if (sw && sw < end) srv++;
            q = nx;
        }
        WT_EQ(cols, 16);
        WT_EQ(srv, 16);
    }
    /* The drawer's presence strip and the Overview's tile. */
    WT_HAS(p, "<canvas class=\"strip\" id=\"bdr-strip\" aria-label=\"this row's presence over the last 24 hours\"></canvas>");
    WT_HAS(p, "        if (i >= 0 && i < 96) on = (parseInt(p.bits.charAt(23 - (i >> 2)), 16) >> (i & 3)) & 1;");
    WT_HAS(p, "<a class=\"tile hud\" id=\"t-ble\" href=\"#ble\">");
    WT_HAS(p, "        bleTile(l.ble);");
    /* The tile's and the strip's G1 are web/ui/facts.js's since #171 V1:
     * ble.devices, Hybrid's and Monitor's, a dash under Local. */
    WT_HAS(p, "    { id: \"ble\", metric: \"ble.devices\", strip: \"s-ble-g\", tile: \"k-ble-spark\",\n"
              "      words: \"k-ble-w\", scopes: [\"hybrid\", \"monitor\"] }");
    WT_HAS(p, "      Promise.all([H.series(f.metric, \"\", tier, from, to), H.baseline(f.metric, \"\")]).then(function (r) {");
    /* MON_TYPES unchanged: no BLE row on the monitor ground. */
    WT_LACKS(p, "\"ble_device\", \"ble_alert\"");
    WT_LACKS(p, "blerow dt-row mon");
}

/* ── the store (v7) ───────────────────────────────────────────────── */

#ifdef WITH_SQLITE

#include <sqlite3.h>

static char g_dir[TEST_TMP_MAX];
static int  g_seeded, g_seeded_alerts;

/* The file through a second connection, as test_store.c's raw helpers. */
static long long raw_q(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    long long v = -1;
    if (sqlite3_open(path, &h) == SQLITE_OK) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    sqlite3_close(h);
    return v;
}

static int raw_exec_ok(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    int rc = -1;
    if (sqlite3_open(path, &h) == SQLITE_OK)
        rc = sqlite3_exec(h, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
    sqlite3_close(h);
    return rc;
}

static void rm_dir_store(void) {
    static const char *const SUF[3] = { "", "-wal", "-shm" };
    char f[TEST_TMP_MAX + 32];
    for (int i = 0; i < 3; i++) {
        snprintf(f, sizeof(f), "%s/slothweb.db%s", g_dir, SUF[i]);
        unlink(f);
    }
    rmdir(g_dir);
}
static void seed_dev(void *ctx, const web_store_bdev_t *r) { g_seeded += web_ble_seed(ctx, r); }
static void seed_alert(void *ctx, const web_store_balert_t *r) { g_seeded_alerts += web_ble_seed_alert(ctx, r); }

/* Rows and findings through the store thread's flush, then a new
 * process's seed from the file: the rows back with their text in its
 * display form and the estimate; a second flush of a changed row is one
 * row, upserted, with the earlier first_seen and the OR-ed mask; the
 * resolved finding comes back resolved; retention at compaction drops
 * rows older than --web-retain-days and counts them. */
static void test_store_round_trip(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-ble-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char p[160], err[512];
    snprintf(p, sizeof(p), "%s/slothweb.db", g_dir);
    web_store_t S;
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    WT_EQ(S.st.schema, WEB_STORE_SCHEMA);
    web_rollup_t ru;
    web_tsdb_t ts;
    WT_EQ(web_rollup_init(&ru, 64, 1, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &S, 30, 256, clock_fn, NULL), 0);
    WT_EQ(web_ble_init(&B, 1), 0);
    web_tsdb_set_ble(&ts, &B);
    feed(dev_line("02:de:00:00:00:21", 0, "bluetooth-monitor", "k\\u0001ttle", -50, 100, T - 500, T - 20,
                  ",\"est_dist_m\":2.5,\"est_dist_band\":\"near\",\"est_dist_trend\":\"steady\","
                  "\"est_ptx_source\":\"assumed\",\"hid\":1"));
    feed(dev_line("02:de:00:00:00:21", 0, "ubertooth", "k\\u0001ttle", -60, 9, T - 400, T - 10, NULL));
    feed(dev_line("02:de:00:00:00:22", 1, "bluetooth-monitor", "", -70, 5, T - 300, T - 40 * 86400,
                  ",\"watch_category\":\"tag\""));
    char line[1024];
    snprintf(line, sizeof(line), FLOOD, T);
    feed(line);
    snprintf(line, sizeof(line), HIDOUI, T);
    feed(line);
    feed("{\"type\":\"alert.resolve\",\"ts\":1793000050,\"incident_id\":\"d1\",\"sev\":1,\"ty\":88,"
         "\"key\":\"ble_hid_oui:bluetooth-monitor:00:13:37:00:00:01\",\"title\":\"BLE_HID_UNEXPECTED\"}");
    web_tsdb_flush_all(&ts);
    WT_EQ(web_store_ble_count(&S, 0), 3);
    WT_EQ(web_store_ble_count(&S, 1), 2);
    web_store_stats_t ss;
    web_store_stats(&S, &ss);
    WT_EQ(ss.ble_rows, 3);
    WT_EQ(ss.ble_alert_rows, 2);
    WT_EQ(ss.ble_batches, 1);
    /* A changed row: the heartbeat with a new mask and count; flushed,
     * the file holds one row of it. Nothing dirty: no batch. */
    web_tsdb_flush_all(&ts);
    web_store_stats(&S, &ss);
    WT_EQ(ss.ble_batches, 1);
    feed(dev_line("02:de:00:00:00:21", 0, "bluetooth-monitor", "k\\u0001ttle", -48, 160, T - 500, T,
                  ",\"pdu_mask\":16,\"hid\":1,\"est_dist_m\":2.50,\"est_dist_band\":\"near\","
                  "\"est_dist_trend\":\"steady\",\"est_ptx_source\":\"assumed\""));
    web_tsdb_flush_all(&ts);
    WT_EQ(web_store_ble_count(&S, 0), 3);
    web_store_stats(&S, &ss);
    WT_EQ(ss.ble_batches, 2);
    web_ble_destroy(&B);
    web_store_close(&S);
    /* A new process: the seed. */
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    WT_EQ(web_ble_init(&B, 1), 0);
    g_seeded = g_seeded_alerts = 0;
    int n = web_store_ble_load(&S, WEB_BLE_DEVICES, seed_dev, &B, T - WEB_BLE_RESOLVED_S, seed_alert, &B);
    WT_EQ(n, 5);
    WT_EQ(g_seeded, 3);
    WT_EQ(g_seeded_alerts, 2);
    /* main.c's start notice names the two apart, not the load's sum of
     * five. Seen red with web_ble_restored() printing seeded +
     * seeded_alerts as the advertisers ("5 advertisers"). */
    {
        char rs[96];
        web_ble_restored(&B, rs, sizeof(rs));
        WT_ASSERT(strcmp(rs, "3 advertisers and 2 findings") == 0);
    }
    char body[65536];
    size_t len = 0;
    int status = 0;
    WT_EQ(web_ble_devices_route(&B, "sort=addr&dir=asc", T, 0, body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"total\":3");
    WT_HAS(body, "\"name\":\"k\\\\x01ttle\",\"name_np\":true");
    WT_HAS(body, "\"adv_count\":160");
    WT_HAS(body, "\"pdu_mask\":17");
    WT_HAS(body, "\"first_seen\":1792999500");
    WT_HAS(body, "\"est\":{\"m\":2.5,\"band\":\"near\"");
    WT_HAS(body, "\"watch_category\":\"tag\"");
    WT_HAS(body, "\"hid\":1");
    WT_HAS(body, "\"iface\":\"ubertooth\"");
    /* The presence strip, from the file: the first record's first_seen
     * (T - 500, bucket 1) and its two last_seen (T - 20 and T, bucket
     * 0). Seen red with the seed's strip dropped (bits all zero). */
    WT_EQ(web_ble_device_route(&B, "02:de:00:00:00:21", "type=0&iface=bluetooth-monitor", T, 0,
                               body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"newest\":1792999800,\"bits\":\"000000000000000000000003\"");
    WT_EQ(web_ble_alerts_route(&B, "", T + 60, 0, body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"kind\":\"adv_flood\",\"alert\":\"BLE_ADV_FLOOD\",\"iface\":\"bluetooth-monitor\",\"sampled\":0,\"standing\":true");
    WT_HAS(body, "\"kind\":\"hid_oui\",\"alert\":\"BLE_HID_UNEXPECTED\",\"iface\":\"bluetooth-monitor\",\"sampled\":0,\"standing\":false");
    WT_HAS(body, "\"resolved_ts\":1793000050");
    WT_HAS(body, "\"oui_table\":\"Hak5\"");
    WT_HAS(body, "\"family\":\"mfr\",\"id\":76,\"subtype\":7");
    /* Everything the finding text renders came back, not zeros: the
     * flood's fresh count, rate, cap flag, window and citation line, and
     * the hid_oui finding's address, which the drawer matches on. Seen
     * red with al_to_row()'s n3..n7 and detail left unset (fresh_addrs
     * 0, rate 0.0, window current, the address all zeros). */
    WT_HAS(body, "\"window\":\"previous\",\"window_s\":10,\"distinct_addrs\":44,\"distinct_capped\":0,"
                 "\"fresh_addrs\":40,\"total_adv\":812,\"rate\":81.2,\"median_rssi\":-61,"
                 "\"spam_source\":\"ble-spam-flood.md\"");
    WT_HAS(body, "\"addr\":\"00:13:37:00:00:01\",\"addr_type\":0,\"hid\":3,\"appearance\":961");
    WT_EQ(web_ble_device_route(&B, "00%3A13%3A37%3A00%3A00%3A01", "", T + 60, 0, body, sizeof(body), &len,
                               &status), 0);
    WT_HAS(body, "\"alerts\":[{\"kind\":\"hid_oui\"");
    /* The resolve of a seeded finding, on its live key: the file's row
     * of it is resolved in place, not joined by a second row. Seen red
     * with al_to_row()'s seeded-hash branch removed (3 rows, the
     * original still standing). */
    feed("{\"type\":\"alert.resolve\",\"ts\":1793000070,\"incident_id\":\"d3\",\"sev\":1,\"ty\":87,"
         "\"key\":\"ble_flood:bluetooth-monitor:mfr:004c:07\",\"title\":\"BLE_ADV_FLOOD\"}");
    web_tsdb_flush_all(&ts);
    WT_EQ(web_store_ble_count(&S, 1), 2);
    {
        char fh[17], q[160];
        web_ble_key_hash("ble_flood:bluetooth-monitor:mfr:004c:07", fh);
        snprintf(q, sizeof(q), "SELECT resolved_ts FROM ble_alert WHERE key_hash='%s'", fh);
        WT_EQ(raw_q(p, q), 1793000070);
    }
    /* Fresh traffic on a seeded row: the strip shifts on from the stored
     * one (three buckets on: 0x3 << 3, the new bucket's bit, and the
     * first_seen bucket the first record after a seed marks again,
     * already set). Seen red with the seed's strip dropped. */
    feed(dev_line("02:de:00:00:00:21", 0, "bluetooth-monitor", "k\\u0001ttle", -48, 170, T - 500, T + 3 * 900, NULL));
    WT_EQ(web_ble_device_route(&B, "02:de:00:00:00:21", "type=0&iface=bluetooth-monitor", T + 3 * 900, 0,
                               body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"newest\":1793002500,\"bits\":\"000000000000000000000019\"");
    /* Retention: the row last seen 40 days ago goes at a compaction with
     * 30 days kept; the other two stay. */
    WT_EQ(web_store_compact(&S, T, 30, 256LL << 20), 0);
    WT_EQ(web_store_ble_count(&S, 0), 2);
    web_store_stats(&S, &ss);
    WT_EQ(ss.ble_dropped_expired, 1);
    WT_EQ(ss.ble_rows, 2);
    /* Everything older than now + 40 d: nothing left, the findings too. */
    WT_EQ(web_store_compact(&S, T + 40 * 86400, 30, 256LL << 20), 0);
    WT_EQ(web_store_ble_count(&S, 0), 0);
    WT_EQ(web_store_ble_count(&S, 1), 0);
    web_ble_destroy(&B);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    web_store_close(&S);
    unlink(p);
    snprintf(p, sizeof(p), "%s/slothweb.db-wal", g_dir); unlink(p);
    snprintf(p, sizeof(p), "%s/slothweb.db-shm", g_dir); unlink(p);
    rmdir(g_dir);
}

/* A failed write: a trigger on ble_alert (made from a second
 * connection, as an operator's sqlite3 could) aborts the transaction
 * after the advertiser rows were upserted in it. The transaction is
 * rolled back whole (no ble_device row either), the failure counted,
 * and the batch dirty again, so once the trigger is gone the next flush
 * writes both. Seen red with the redirty call taken out of flush_ble()
 * (the second flush wrote nothing), and with the ROLLBACK in
 * web_store_ble_write() replaced by a COMMIT (the advertiser row
 * written by the failed batch). */
static void test_store_failed_write_is_retried(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-blef-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char p[160], err[512];
    snprintf(p, sizeof(p), "%s/slothweb.db", g_dir);
    web_store_t S;
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    web_rollup_t ru;
    web_tsdb_t ts;
    WT_EQ(web_rollup_init(&ru, 64, 1, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &S, 30, 256, clock_fn, NULL), 0);
    WT_EQ(web_ble_init(&B, 1), 0);
    web_tsdb_set_ble(&ts, &B);
    feed(dev_line("02:de:00:00:00:51", 0, "bluetooth-monitor", "", -50, 1, T, T, NULL));
    char line[1024];
    snprintf(line, sizeof(line), FLOOD, T);
    feed(line);
    WT_EQ(raw_exec_ok(p, "CREATE TRIGGER no_al BEFORE INSERT ON ble_alert BEGIN"
                         " SELECT RAISE(ABORT, 'refused'); END"), 0);
    web_store_stats_t ss;
    web_store_stats(&S, &ss);
    unsigned long errs = ss.write_errors;
    web_tsdb_flush_all(&ts);
    WT_EQ(web_store_ble_count(&S, 0), 0);
    WT_EQ(web_store_ble_count(&S, 1), 0);
    /* flush_all flushes twice (before and after closing the buckets):
     * the second took the batch the first gave back, and failed too. */
    web_store_stats(&S, &ss);
    WT_EQ(ss.write_errors, errs + 2);
    WT_HAS(ss.last_error, "refused");
    web_ble_stats_t st;
    web_ble_stats(&B, &st);
    WT_EQ(st.redirtied, 4);
    WT_EQ(raw_exec_ok(p, "DROP TRIGGER no_al"), 0);
    web_tsdb_flush_all(&ts);
    WT_EQ(web_store_ble_count(&S, 0), 1);
    WT_EQ(web_store_ble_count(&S, 1), 1);
    web_ble_destroy(&B);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    web_store_close(&S);
    rm_dir_store();
}

/* An address flood against the rows that matter: the table filled
 * with HID and watchlisted rows older than everything after them (all
 * but 24 slots), then 2,000 plain random addresses, each heard once and
 * newer, with no flush between. The flood turns over the 24 plain slots
 * among itself: every flagged row is still in memory, and the flush
 * after it writes every one of them to slothweb.db. Then a table of
 * flagged rows only: a plain arrival evicts the oldest of them (the
 * fallback), not none. Seen red with dev_slot()'s plain-row choice
 * removed (age alone: the flagged rows, oldest, evicted first, none of
 * the 1000 left in memory or in the file, which held 1024 flood rows),
 * and with the fallback removed (a NULL row: the suite died on SIGSEGV). */
static void test_flood_keeps_flagged_rows(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-blev-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char p[160], err[512];
    snprintf(p, sizeof(p), "%s/slothweb.db", g_dir);
    web_store_t S;
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    web_rollup_t ru;
    web_tsdb_t ts;
    WT_EQ(web_rollup_init(&ru, 64, 1, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &S, 30, 256, clock_fn, NULL), 0);
    WT_EQ(web_ble_init(&B, 1), 0);
    web_tsdb_set_ble(&ts, &B);
    const int nflag = WEB_BLE_DEVICES - 24;
    char addr[18];
    for (int i = 0; i < nflag; i++) {
        snprintf(addr, sizeof(addr), "02:de:01:00:%02x:%02x", (i >> 8) & 255, i & 255);
        feed(dev_line(addr, 0, "bluetooth-monitor", "", -60, 5, T - 5000, T - 5000 + i,
                      i % 2 ? ",\"hid\":1" : ",\"watch_category\":\"tag\""));
    }
    for (int i = 0; i < 2000; i++) {
        /* Random static (the two top bits set), each one new. */
        snprintf(addr, sizeof(addr), "c2:de:02:00:%02x:%02x", (i >> 8) & 255, i & 255);
        feed(dev_line(addr, 1, "bluetooth-monitor", "", -80, 1, T + i, T + i, NULL));
    }
    web_ble_stats_t st;
    web_ble_stats(&B, &st);
    WT_EQ(st.rows, WEB_BLE_DEVICES);
    WT_EQ(st.evictions, 2000 - 24);
    WT_EQ(st.hid + st.watch, nflag);
    char body[65536];
    size_t len = 0;
    int status = 0, kept = 0;
    for (int i = 0; i < nflag; i++) {
        snprintf(addr, sizeof(addr), "02:de:01:00:%02x:%02x", (i >> 8) & 255, i & 255);
        status = 0;
        WT_EQ(web_ble_device_route(&B, addr, "", T + 2000, 0, body, sizeof(body), &len, &status), 0);
        kept += status == 200;
    }
    WT_EQ(kept, nflag);
    web_tsdb_flush_all(&ts);
    WT_EQ(raw_q(p, "SELECT COUNT(*) FROM ble_device WHERE addr LIKE '02:de:01:%'"
                   " AND (hid > 0 OR watch_category != '')"), nflag);
    WT_EQ(raw_q(p, "SELECT COUNT(*) FROM ble_device WHERE addr LIKE 'c2:de:02:%'"), 24);
    web_ble_destroy(&B);
    /* Every row flagged: the plain oldest of all goes. */
    WT_EQ(web_ble_init(&B, 0), 0);
    for (int i = 0; i < WEB_BLE_DEVICES; i++) {
        snprintf(addr, sizeof(addr), "02:de:03:00:%02x:%02x", (i >> 8) & 255, i & 255);
        feed(dev_line(addr, 0, "bluetooth-monitor", "", -60, 5, T, i == 9 ? T - 900 : T + i, ",\"hid\":1"));
    }
    feed(dev_line("c2:de:04:00:00:01", 1, "bluetooth-monitor", "", -80, 1, T + 5000, T + 5000, NULL));
    web_ble_stats(&B, &st);
    WT_EQ(st.rows, WEB_BLE_DEVICES);
    WT_EQ(st.evictions, 1);
    WT_EQ(web_ble_device_route(&B, "02:de:03:00:00:09", "", T, 0, body, sizeof(body), &len, &status), 0);
    WT_EQ(status, 404);
    WT_EQ(web_ble_device_route(&B, "c2:de:04:00:00:01", "", T, 0, body, sizeof(body), &len, &status), 0);
    WT_EQ(status, 200);
    web_ble_destroy(&B);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    web_store_close(&S);
    rm_dir_store();
}

/* The row caps: a write past WEB_STORE_BLE_ROWS keeps the cap, the
 * oldest advertisers by last seen gone, a flagged one (HID, watchlist)
 * kept past unflagged newer ones; a write past WEB_STORE_BLE_ALERT_ROWS
 * keeps that, the oldest findings gone; both counted. A row whose
 * address is not canonical (made by hand) is not seeded. Seen red with
 * the cap loop in web_store_ble_write() removed (cap + 10 rows, nothing
 * counted), with its slice ordered newest first (the newest rows gone),
 * and with the cap's flagged-last order dropped (the old HID row gone). */
static void test_store_row_caps(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-blec-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char p[160], err[512];
    snprintf(p, sizeof(p), "%s/slothweb.db", g_dir);
    web_store_t S;
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    const size_t nd = WEB_STORE_BLE_ROWS + 10, na = WEB_STORE_BLE_ALERT_ROWS + 5;
    web_store_bdev_t *d = calloc(nd, sizeof(*d));
    web_store_balert_t *a = calloc(na, sizeof(*a));
    WT_ASSERT(d && a);
    if (!d || !a) { free(d); free(a); web_store_close(&S); rm_dir_store(); return; }
    for (size_t i = 0; i < nd; i++) {
        snprintf(d[i].addr, sizeof(d[i].addr), "02:de:00:%02x:%02x:%02x", (unsigned)(i >> 16) & 255,
                 (unsigned)(i >> 8) & 255, (unsigned)i & 255);
        snprintf(d[i].iface, sizeof(d[i].iface), "bluetooth-monitor");
        d[i].uuid16 = d[i].mfr_id = d[i].mfr_subtype = d[i].svc_data_uuid16 = d[i].appearance = -1;
        d[i].tx_power = -128;
        d[i].flags = d[i].adv_sid = d[i].est_dist_dm = -1;
        d[i].rssi = d[i].rssi_best = -60;
        d[i].first_seen = T;
        d[i].last_seen = T + (long long)i;      /* row 0 the oldest */
    }
    d[2].hid = 1;                               /* old, but HID */
    snprintf(d[5].watch_category, sizeof(d[5].watch_category), "tag");
    for (size_t i = 0; i < na; i++) {
        snprintf(a[i].key_hash, sizeof(a[i].key_hash), "%016zx", i + 1);
        snprintf(a[i].alert, sizeof(a[i].alert), "BLE_ADV_FLOOD");
        snprintf(a[i].iface, sizeof(a[i].iface), "bluetooth-monitor");
        a[i].first_ts = T;
        a[i].last_ts = T + (long long)i;
        a[i].resolved_ts = -1;
    }
    WT_EQ(web_store_ble_write(&S, d, nd, a, na), 0);
    WT_EQ(web_store_ble_count(&S, 0), WEB_STORE_BLE_ROWS);
    WT_EQ(web_store_ble_count(&S, 1), WEB_STORE_BLE_ALERT_ROWS);
    web_store_stats_t ss;
    web_store_stats(&S, &ss);
    WT_EQ(ss.ble_dropped_cap, 15);
    WT_EQ(ss.ble_rows, WEB_STORE_BLE_ROWS);
    /* Gone: rows 0, 1, 3, 4 and 6..11 (the ten oldest unflagged); kept:
     * rows 2 and 5 (flagged), row 12 and the newest. */
    WT_EQ(raw_q(p, "SELECT COUNT(*) FROM ble_device WHERE addr IN ('02:de:00:00:00:00','02:de:00:00:00:01',"
                   "'02:de:00:00:00:03','02:de:00:00:00:04','02:de:00:00:00:0b')"), 0);
    WT_EQ(raw_q(p, "SELECT COUNT(*) FROM ble_device WHERE addr IN ('02:de:00:00:00:02','02:de:00:00:00:05',"
                   "'02:de:00:00:00:0c')"), 3);
    char q[200];
    snprintf(q, sizeof(q), "SELECT COUNT(*) FROM ble_device WHERE addr='%s'", d[nd - 1].addr);
    WT_EQ(raw_q(p, q), 1);
    /* The findings: the five oldest by last_ts gone. */
    WT_EQ(raw_q(p, "SELECT COUNT(*) FROM ble_alert WHERE key_hash<='0000000000000005'"), 0);
    WT_EQ(raw_q(p, "SELECT COUNT(*) FROM ble_alert WHERE key_hash='0000000000000006'"), 1);
    /* A non-canonical address in the file (upper case, as no write of
     * ours makes it) is passed over by the seed. */
    WT_EQ(raw_exec_ok(p, "UPDATE ble_device SET addr='02:DE:00:00:00:0C' WHERE addr='02:de:00:00:00:0c'"), 0);
    WT_EQ(web_ble_init(&B, 1), 0);
    g_seeded = 0;
    WT_EQ(web_store_ble_load(&S, WEB_STORE_BLE_ROWS, seed_dev, &B, 0, NULL, NULL), WEB_STORE_BLE_ROWS - 1);
    web_ble_destroy(&B);
    free(d);
    free(a);
    web_store_close(&S);
    rm_dir_store();
}

/* The memory-only path (no store): the tables still ingest and serve,
 * and a take gives nothing. */
static void test_without_store(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    feed(dev_line("02:de:00:00:00:31", 0, "bluetooth-monitor", "", -50, 1, T, T, NULL));
    web_store_bdev_t out[2];
    WT_EQ(web_ble_take(&B, out, 2), 0);
    WT_EQ(rows_of(&B), 1);
    web_ble_destroy(&B);
}

#else

static void test_without_store(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    feed(dev_line("02:de:00:00:00:31", 0, "bluetooth-monitor", "", -50, 1, T, T, NULL));
    web_store_bdev_t out[2];
    WT_EQ(web_ble_take(&B, out, 2), 0);
    WT_EQ(rows_of(&B), 1);
    char body[8192];
    size_t len = 0;
    int status = 0;
    WT_EQ(web_ble_devices_route(&B, "", T, 0, body, sizeof(body), &len, &status), 0);
    WT_HAS(body, "\"total\":1");
    web_ble_destroy(&B);
}

#endif

void run_ble_tests(void) {
    WT_RUN(test_vocabularies);
    WT_RUN(test_rows_by_sensor_and_update);
    WT_RUN(test_hostile_strings);
    WT_RUN(test_absent_and_estimate);
    WT_RUN(test_lru_eviction);
    WT_RUN(test_counts_only_move_up);
    WT_RUN(test_presence_strip);
    WT_RUN(test_every_column_sorts);
    WT_RUN(test_findings_and_resolve);
    WT_RUN(test_sensor_health_members);
    WT_RUN(test_metrics_from_sensor_health);
    WT_RUN(test_routes);
    WT_RUN(test_live_member_worst_case);
    WT_RUN(test_page);
#ifdef WITH_SQLITE
    WT_RUN(test_store_round_trip);
    WT_RUN(test_store_failed_write_is_retried);
    WT_RUN(test_store_row_caps);
    WT_RUN(test_flood_keeps_flagged_rows);
#endif
    WT_RUN(test_without_store);
}
