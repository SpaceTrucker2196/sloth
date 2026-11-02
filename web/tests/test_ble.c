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
 * metrics guard with the btmon_iface test removed from web_metrics.c
 * (ble.devices sampled with no Bluetooth block); the hostile name with
 * web_ssid_escape() replaced by a plain copy (name_np false, the
 * control byte raw); the LRU with dev_slot()'s eviction returning the
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
 * display form and flagged; an over-long name is cut on a code-point
 * boundary; an empty name is null; a category that is not sloth's slug
 * is dropped and counted; an iface outside the two is "other" and
 * counted; a record with no address, or a bad one, is counted and kept
 * nowhere. */
static void test_hostile_strings(void) {
    WT_EQ(web_ble_init(&B, 0), 0);
    feed(dev_line("02:de:00:00:00:02", 1, "bluetooth-monitor", "bad\\u0001name", -60, 1, T, T, NULL));
    feed(dev_line("02:de:00:00:00:03", 1, "bluetooth-monitor",
                  "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"
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
    WT_LACKS(body, "\x01");
    WT_HAS(body, "\"name\":null");
    WT_HAS(body, "\"watch_category\":null");
    WT_HAS(body, "\"iface\":\"other\"");
    /* The long name: the stream's form is read to 96 bytes (32 octets,
     * three each at most) and cut on a boundary, so every é is whole. */
    const char *p = strstr(body, "\"addr\":\"02:de:00:00:00:03\"");
    WT_ASSERT(p != NULL);
    if (p) {
        const char *nm = strstr(p, "\"name\":\"");
        WT_ASSERT(nm != NULL);
        if (nm) {
            nm += 8;
            const char *e = strchr(nm, '"');
            WT_ASSERT(e && (e - nm) == 32 * 3);
            if (e) WT_EQ((e - nm) % 2, 0);
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
 * the sensor_health's Bluetooth block and only while btmon_iface says
 * sloth is listening. Seen red with the btmon_iface guard removed. */
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
    WT_HAS(b, "\"total\":3,\"matched\":3,\"hid\":1,\"watch\":1,\"standing\":1,\"flood_keys\":1");
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

/* ── the page ─────────────────────────────────────────────────────── */

#include "web_assets.h"

/* The page's BLE view as served: the tab and its hotkey, the table
 * through the one DataTable, the cells' ports of the TUI's helpers, the
 * one-colour row rule, the TUI's lines verbatim, the kept controls, the
 * scope toggle, the Health block, the strip's fact. Pinned as the colour
 * suite pins its lines. Seen red with "0" taken out of the keydown. */
static void test_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<li><button type=\"button\" class=\"go\" id=\"nav-ble\"><span class=\"k\">0</span>BLE</button></li>");
    WT_HAS(p, "    if (e.key === \"0\") show(\"ble\");");
    WT_HAS(p, "               \"lookup\", \"tacdb\", \"ble\"];");
    WT_HAS(p, "    if (v === \"ble\") bleView();");
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
    WT_HAS(p, "    line.appendChild(el(\"span\", \"d-bright\", String(j.total)));");
    WT_HAS(p, "    line.appendChild(el(\"span\", j.hid > 0 ? \"h2\" : \"d-dim\", String(j.hid)));");
    WT_HAS(p, "    line.appendChild(el(\"span\", j.watch > 0 ? \"h2\" : \"d-dim\", String(j.watch)));");
    WT_HAS(p, "    line.appendChild(el(\"span\", \"d-dim\", \"  flood keys: \" + j.flood_keys));");
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
    WT_HAS(p, "\"q-sql\", \"b-q\", \"b-sort\"].forEach(keepCtl);");
    WT_HAS(p, "    $(\"v-ble\").classList.toggle(\"scoped-out\", SCOPE === \"local\");");
    WT_HAS(p, "<span title=\"BLE advertisers slothweb holds, from sloth's ble_device records (Monitor's; - under Local or with no Bluetooth source)\">ble <b id=\"s-ble\">-</b></span>");
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
    WT_HAS(p, "    series(\"ble.devices\", \"\", tier, from, to).then(function (s) {");
    /* MON_TYPES unchanged: no BLE row on the monitor ground. */
    WT_LACKS(p, "\"ble_device\", \"ble_alert\"");
    WT_LACKS(p, "blerow dt-row mon");
}

/* ── the store (v7) ───────────────────────────────────────────────── */

#ifdef WITH_SQLITE

static char g_dir[TEST_TMP_MAX];
static int  g_seeded, g_seeded_alerts;
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
    WT_RUN(test_presence_strip);
    WT_RUN(test_findings_and_resolve);
    WT_RUN(test_sensor_health_members);
    WT_RUN(test_metrics_from_sensor_health);
    WT_RUN(test_routes);
    WT_RUN(test_page);
#ifdef WITH_SQLITE
    WT_RUN(test_store_round_trip);
#endif
    WT_RUN(test_without_store);
}
