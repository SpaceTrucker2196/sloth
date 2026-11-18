/* The Victron tab (web_victron.h): the devices kept by slothweb from
 * hand-built records in the emitter's exact shape (src/jsonl.c
 * emit_victron_device() and the victron_* block of
 * jsonl_emit_sensor_health(); tests/test_victron.c pins those), the two
 * routes through the route table under each scope, the history read
 * off a sloth.db generated from sloth's own DDL, and the page's half.
 * Serials, addresses and readings are invented.
 *
 * Absence assertions, each seen red under a named mutation and then
 * restored (docs/wiki/log.md, the 2026-11-15 Victron tab entry):
 *   - test_victron_ranges_and_refusals: device_apply()'s bound test
 *     dropped (`d >= VALS[i].lo && d <= VALS[i].hi` removed: the SOC of
 *     150 landed on the row); clean()'s charset made "any printable"
 *     (the quoted model kept); jservices()'s charset test removed (the
 *     list with a space kept);
 *   - test_victron_scope: route_victron()'s none_here forced to 0 (a
 *     Local answer carried the device), and the history route's Local
 *     reason removed from route_m5() (a Local history answer read the
 *     file);
 *   - test_victron_age: age_out()'s TTL test made false (the silent row
 *     stayed);
 *   - test_victron_stale: row_json()'s `age > after` made `age > after
 *     * 10` (a device 400 s silent read live);
 *   - test_victronhist_older_file: the `schema >= 15` of "have" made
 *     `>= 14` (a v14 file said it had the table).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_assets.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_routes.h"
#include "web_scope.h"
#include "web_slothdb.h"
#include "web_victron.h"
#include "wtest.h"
#include "wt_tmp.h"

/* src/db_schema.c, linked into slothweb_test: sloth.db's
 * victron_readings value columns in order. */
const char *db_victron_col(int i);

#define T 1794654600LL

static web_victron_t A;
static web_jrec_t R;

static void feed(const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_victron_record(&A, &R, 1000);
}

/* sensor_health's victron_* block, in jsonl_emit_sensor_health()'s order. */
static const char SH[] =
    "{\"type\":\"sensor_health\",\"ts\":1794654600,\"capture_iface\":\"any\","
    "\"victron_state\":\"live\",\"victron_src\":\"file:/var/lib/sloth-va/victron.jsonl\","
    "\"victron_missing\":0,\"victron_last_read\":1794654599,\"victron_last_rec\":1794654570,"
    "\"victron_devices\":3,\"victron_bytes\":9000,\"victron_lines\":40,\"victron_records\":38,"
    "\"victron_bad_lines\":2,\"victron_rej_oversize\":0,\"victron_rej_not_object\":1,"
    "\"victron_rej_malformed\":1,\"victron_rej_not_victron\":0,\"victron_rej_no_mac\":0,"
    "\"victron_bad_values\":1,\"victron_other_keys\":4,\"victron_table_full\":0,"
    "\"victron_truncations\":0,\"victron_rotations\":1,\"victron_read_errors\":0,"
    "\"victron_err\":\"\",\"db_max_mb\":-1,\"jsonl_version\":\"1.8.0\"}";
/* A battery monitor, as emit_victron_device() writes it. */
static const char BMV[] =
    "{\"type\":\"victron_device\",\"ts\":1794654571,\"src\":\"file:/var/lib/sloth-va/victron.jsonl\","
    "\"mac\":\"c7:fe:23:b1:1c:5f\",\"serial\":\"HQ0000TEST1\",\"model\":\"BMV-712 Smart\","
    "\"record\":\"battery_monitor\",\"first_seen\":1794650000,\"last_seen\":1794654570,"
    "\"last_readout\":1794654570,\"last_gatt\":0,\"readings\":120,\"sessions\":0,\"rssi\":-71,"
    "\"values_src\":\"readout\",\"voltage_v\":13.200,\"alarm_reason\":0.000,\"aux_input\":3.000,"
    "\"current_a\":-1.500,\"consumed_ah\":-12.300,\"soc_pct\":87.500,\"ttg_min\":754.000}";
/* A DC-DC charger. */
static const char ORION[] =
    "{\"type\":\"victron_device\",\"ts\":1794654561,\"src\":\"file:/var/lib/sloth-va/victron.jsonl\","
    "\"mac\":\"f5:d8:0c:b6:31:cf\",\"serial\":\"HQ0000TEST2\",\"model\":\"Orion Smart 12V/12V-18A\","
    "\"record\":\"dcdc_converter\",\"first_seen\":1794650000,\"last_seen\":1794654560,"
    "\"last_readout\":1794654560,\"last_gatt\":0,\"readings\":100,\"sessions\":0,"
    "\"values_src\":\"readout\",\"device_state\":3.000,\"charger_error\":0.000,"
    "\"input_v\":14.100,\"output_v\":13.900,\"off_reason\":0.000}";
/* A device known only through its sessions: no supported service. */
static const char DONGLE[] =
    "{\"type\":\"victron_device\",\"ts\":1794654500,\"src\":\"file:/var/lib/sloth-va/victron.jsonl\","
    "\"mac\":\"e4:b9:aa:47:57:1f\",\"session\":\"no_supported_service\","
    "\"services\":\"306b0001-b081-4037-83dc-e59fcc3cdfd0,00001800-0000-1000-8000-00805f9b34fb\","
    "\"first_seen\":1794650000,\"last_seen\":1794654300,\"last_readout\":0,"
    "\"last_gatt\":1794654300,\"readings\":0,\"sessions\":14}";

static char g_out[262144];

static int route(const web_health_t *h, const char *path, const char *query) {
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    int rc = web_route(rq, h, 1, g_out, 65536, &r);
    free(rq);
    if (rc != 0) return -1;
    g_out[r.out_len < sizeof(g_out) ? r.out_len : sizeof(g_out) - 1] = '\0';
    return r.status;
}

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static void fresh(void) {
    web_victron_destroy(&A);
    WT_EQ(web_victron_init(&A), 0);
}

static void health(web_health_t *H, long long now) {
    memset(H, 0, sizeof(*H));
    H->victron = &A;
    H->wall_s = now;
}

/* slothweb's value list is sloth's: same names, in sloth.db's column
 * order, so a history metric is always a column sloth writes. */
static void test_victron_allow_list_is_sloths(void) {
    int n = 0;
    for (; web_victron_val_name(n); n++) {
        WT_ASSERT(db_victron_col(n) != NULL);
        if (db_victron_col(n)) WT_ASSERT(!strcmp(web_victron_val_name(n), db_victron_col(n)));
        WT_EQ(web_victron_val_index(web_victron_val_name(n)), n);
    }
    WT_EQ(n, WEB_VICTRON_VALS);
    WT_ASSERT(db_victron_col(n) == NULL);
    WT_EQ(web_victron_val_index("label"), -1);
    WT_EQ(web_victron_val_index(NULL), -1);
    WT_ASSERT(web_victron_val_name(-1) == NULL);
    WT_ASSERT(!strcmp(web_victron_val_unit(web_victron_val_index("soc_pct")), "%"));
    WT_ASSERT(!strcmp(web_victron_val_unit(web_victron_val_index("device_state")), ""));
}

/* The records land where the page reads them: the sensor block, the
 * devices most recently heard first, each value with its unit, the
 * service list split, absent members null or "". */
static void test_victron_ingest_and_route(void) {
    fresh();
    feed(DONGLE); feed(ORION); feed(BMV); feed(SH);
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/victron", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"now\":1794654600,\"src\":\"file:/var/lib/sloth-va/victron.jsonl\",\"records\":3,"
              "\"evictions\":0,\"aged\":0,\"rejected\":0,\"sensor\":{\"ts\":1794654600,"
              "\"state\":\"live\",\"src\":\"file:/var/lib/sloth-va/victron.jsonl\",\"missing\":0,"
              "\"last_read\":1794654599,\"last_rec\":1794654570,\"devices\":3,\"bytes\":9000,"
              "\"lines\":40,\"records\":38,\"bad_lines\":2,\"rej\":{\"oversize\":0,"
              "\"not_object\":1,\"malformed\":1,\"not_victron\":0,\"no_mac\":0},"
              "\"bad_values\":1,\"other_keys\":4,\"table_full\":0,\"truncations\":0,"
              "\"rotations\":1,\"read_errors\":0,\"err\":\"\"},\"total\":3,\"devices\":[");
    WT_HAS(b, "\"devices\":[{\"mac\":\"c7:fe:23:b1:1c:5f\",\"serial\":\"HQ0000TEST1\","
              "\"model\":\"BMV-712 Smart\",\"record\":\"battery_monitor\","
              "\"values_src\":\"readout\",\"first_seen\":1794650000,\"last_seen\":1794654570,"
              "\"last_readout\":1794654570,\"last_gatt\":0,\"age_s\":30,\"stale_after_s\":360,"
              "\"stale\":false,\"readings\":120,\"sessions\":0,\"session\":\"\","
              "\"services\":[],\"rssi\":-71,\"values\":{\"voltage_v\":{\"v\":13.200,"
              "\"unit\":\"V\"},\"current_a\":{\"v\":-1.500,\"unit\":\"A\"},"
              "\"consumed_ah\":{\"v\":-12.300,\"unit\":\"Ah\"},\"soc_pct\":{\"v\":87.500,"
              "\"unit\":\"%\"},\"ttg_min\":{\"v\":754.000,\"unit\":\"min\"},"
              "\"alarm_reason\":{\"v\":0,\"unit\":\"\"},\"aux_input\":{\"v\":3,\"unit\":\"\"}},"
              "\"ts\":1794654571,\"records\":1}");
    WT_HAS(b, "\"values\":{\"input_v\":{\"v\":14.100,\"unit\":\"V\"},\"output_v\":{\"v\":13.900,"
              "\"unit\":\"V\"},\"device_state\":{\"v\":3,\"unit\":\"\"},"
              "\"charger_error\":{\"v\":0,\"unit\":\"\"},\"off_reason\":{\"v\":0,\"unit\":\"\"}}");
    WT_HAS(b, "{\"mac\":\"e4:b9:aa:47:57:1f\",\"serial\":\"\",\"model\":\"\",\"record\":\"\","
              "\"values_src\":\"\",\"first_seen\":1794650000,\"last_seen\":1794654300,"
              "\"last_readout\":0,\"last_gatt\":1794654300,\"age_s\":300,\"stale_after_s\":660,"
              "\"stale\":false,\"readings\":0,\"sessions\":14,"
              "\"session\":\"no_supported_service\",\"services\":["
              "\"306b0001-b081-4037-83dc-e59fcc3cdfd0\",\"00001800-0000-1000-8000-00805f9b34fb\"],"
              "\"rssi\":null,\"values\":{},");
    WT_HAS(b, "\"shown\":3,\"cut\":false}");
    WT_EQ(route(&H, "/api/victron", "limit=1"), 200);
    WT_HAS(body_of(g_out), "\"total\":3,");
    WT_HAS(body_of(g_out), "\"shown\":1,");
    WT_EQ(route(&H, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), "\"victron\":{\"rows\":3,\"records\":3,\"evictions\":0,"
                           "\"aged\":0,\"rejected\":0,\"sensor_seen\":1}");
    /* sloth restarted without --victron: its sensor_health has no block. */
    feed("{\"type\":\"sensor_health\",\"ts\":1794654601}");
    WT_EQ(route(&H, "/api/victron", ""), 200);
    WT_HAS(body_of(g_out), "\"sensor\":null,");
}

/* Out of range absent, never clamped; a string off sloth's charset
 * absent; a record without a usable address or first_seen rejected and
 * counted; bad parameters 400. */
static void test_victron_ranges_and_refusals(void) {
    fresh();
    feed("{\"type\":\"victron_device\",\"ts\":1,\"first_seen\":1}");
    feed("{\"type\":\"victron_device\",\"ts\":1,\"mac\":\"C7:FE:23:B1:1C:5F\",\"first_seen\":1}");
    feed("{\"type\":\"victron_device\",\"ts\":1,\"mac\":\"c7:fe:23:b1:1c\",\"first_seen\":1}");
    feed("{\"type\":\"victron_device\",\"ts\":1,\"mac\":\"c7:fe:23:b1:1c:5f\"}");
    feed("{\"type\":\"victron_device\",\"ts\":1,\"mac\":\"c7:fe:23:b1:1c:5f\",\"first_seen\":-1}");
    feed("{\"type\":\"victron_device\",\"ts\":2,\"mac\":\"c7:fe:23:b1:1c:5f\",\"first_seen\":1,"
         "\"last_seen\":1,\"model\":\"BMV \\\"x\\\"\",\"serial\":\"<script>\","
         "\"session\":\"ok\",\"services\":\"306b0001 x\",\"values_src\":\"wire\","
         "\"soc_pct\":150.0,\"voltage_v\":401.0,\"device_state\":256,\"current_a\":2.5,"
         "\"label\":\"mine\",\"rssi\":-200}");
    web_health_t H;
    health(&H, 10);
    WT_EQ(route(&H, "/api/victron", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"rejected\":5,");
    WT_HAS(b, "\"total\":1,");
    WT_HAS(b, "\"serial\":\"\",\"model\":\"\",\"record\":\"\",\"values_src\":\"\",");
    WT_HAS(b, "\"session\":\"ok\",\"services\":[],\"rssi\":null,"
              "\"values\":{\"current_a\":{\"v\":2.500,\"unit\":\"A\"}},");
    WT_LACKS(b, "150");
    WT_LACKS(b, "401");
    WT_LACKS(b, "script");
    WT_LACKS(b, "mine");
    WT_LACKS(b, "306b0001");
    WT_EQ(route(&H, "/api/victron", "limit=0"), 400);
    WT_EQ(route(&H, "/api/victron", "limit=33"), 400);
    WT_EQ(route(&H, "/api/victron", "mac=x"), 400);
}

/* A row with no record for WEB_VICTRON_TTL_S is one sloth no longer
 * keeps: dropped and counted; a new first_seen starts the row over. */
static void test_victron_age(void) {
    fresh();
    feed(BMV); feed(ORION);
    feed("{\"type\":\"sensor_health\",\"ts\":1794655221}");      /* BMV + 650 */
    web_health_t H;
    health(&H, 1794655221);
    WT_EQ(route(&H, "/api/victron", ""), 200);
    WT_HAS(body_of(g_out), "\"total\":2,");
    feed("{\"type\":\"sensor_health\",\"ts\":1794655224}");      /* ORION + 663 */
    WT_EQ(route(&H, "/api/victron", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"aged\":1,");
    WT_HAS(b, "\"total\":1,");
    WT_LACKS(b, "f5:d8:0c:b6:31:cf");
    feed("{\"type\":\"victron_device\",\"ts\":1794655230,\"mac\":\"c7:fe:23:b1:1c:5f\","
         "\"first_seen\":1794655200,\"last_seen\":1794655229,\"readings\":1}");
    WT_EQ(route(&H, "/api/victron", ""), 200);
    WT_HAS(body_of(g_out), "\"first_seen\":1794655200,\"last_seen\":1794655229,");
    WT_HAS(body_of(g_out), "\"records\":1}");
    WT_LACKS(body_of(g_out), "HQ0000TEST1");
}

/* Stale is the record's last_seen past one heartbeat and a minute
 * (11 minutes for a GATT-only device), by the host's clock. */
static void test_victron_stale(void) {
    fresh();
    feed(BMV); feed(DONGLE);
    web_health_t H;
    health(&H, 1794654570 + 360);
    WT_EQ(route(&H, "/api/victron", ""), 200);
    WT_HAS(body_of(g_out), "\"age_s\":360,\"stale_after_s\":360,\"stale\":false,");
    health(&H, 1794654570 + 400);
    WT_EQ(route(&H, "/api/victron", ""), 200);
    WT_HAS(body_of(g_out), "\"age_s\":400,\"stale_after_s\":360,\"stale\":true,");
    /* The dongle at 670 s: past its 660. */
    WT_HAS(body_of(g_out), "\"age_s\":670,\"stale_after_s\":660,\"stale\":true,");
    /* A clock behind sloth's read: age 0, never negative. */
    health(&H, 1794654000);
    WT_EQ(route(&H, "/api/victron", ""), 200);
    WT_HAS(body_of(g_out), "\"age_s\":0,\"stale_after_s\":360,\"stale\":false,");
}

/* Monitor's record and a poll type; Monitor and Hybrid answer devices,
 * Local the out_of_scope body, the query checked first. The history
 * route the same. Not a fleet record: test_fleet.c holds the importer. */
static void test_victron_scope(void) {
    fresh();
    feed(SH); feed(BMV);
    WT_EQ(web_scope_record("victron_device"), WEB_SC_M);
    WT_ASSERT(web_live_is_poll_type("victron_device"));
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/victron", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&H, "/api/victron", "scope=hybrid"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&H, "/api/victron", "scope=local"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"local\",\"out_of_scope\":true,\"reason\":\"Victron devices");
    WT_LACKS(body_of(g_out), "c7:fe:23");
    WT_EQ(route(&H, "/api/victron", "scope=local&limit=0"), 400);
    /* History under Local: checked, then out of scope, no sloth.db read
     * (there is none here, which would otherwise be 503). */
    static web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    H.m4 = &m4;
    WT_EQ(route(&H, "/api/victron/history", "scope=local&mac=c7:fe:23:b1:1c:5f&metric=soc_pct"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true,\"reason\":\"Victron devices");
    WT_EQ(route(&H, "/api/victron/history", "scope=local&mac=x&metric=soc_pct"), 400);
    H.victron = NULL;
    WT_EQ(route(&H, "/api/victron", ""), 503);
}

/* The history route's refusals, with no sloth.db and with one: every
 * parameter checked before the file is touched. */
static void test_victronhist_no_db(void) {
    static web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    web_health_t H;
    memset(&H, 0, sizeof(H));
    H.wall_s = SDB_NOW;
    H.m4 = &m4;
    WT_EQ(route(&H, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=soc_pct"), 503);
    WT_HAS(body_of(g_out), "no_sloth_db");
    WT_EQ(route(&H, "/api/victron/history", "metric=soc_pct"), 400);
    WT_HAS(body_of(g_out), "bad_mac");
    WT_EQ(route(&H, "/api/victron/history", "mac=C7:FE:23:B1:1C:5F&metric=soc_pct"), 400);
    WT_EQ(route(&H, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f"), 400);
    WT_HAS(body_of(g_out), "bad_metric");
    WT_EQ(route(&H, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=mac"), 400);
    WT_EQ(route(&H, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=src"), 400);
    WT_EQ(route(&H, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=soc_pct%3B"), 400);
    WT_EQ(route(&H, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=soc_pct&hours=0"), 400);
    WT_HAS(body_of(g_out), "bad_hours");
    WT_EQ(route(&H, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=soc_pct&hours=721"), 400);
    WT_EQ(route(&H, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=soc_pct&days=1"), 400);
}

#ifdef WITH_SQLITE

static char g_dir[TEST_TMP_MAX];
static char g_db[128];
static web_slothdb_t sdb;
static web_m4_t      m4h;
static web_health_t  HH;

static void db_up(int version) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-victron-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, version, 0), 0);
    web_slothdb_init(&sdb, g_db, NULL);
    memset(&m4h, 0, sizeof(m4h));
    m4h.sdb = &sdb;
    memset(&HH, 0, sizeof(HH));
    HH.wall_s = SDB_NOW;
    HH.m4 = &m4h;
}

static void db_down(void) {
    web_slothdb_destroy(&sdb);
    unlink(g_db);
    rmdir(g_dir);
}

/* Rows as write_victron() leaves them: one a minute for the BMV over
 * the last two hours with a gap, the soc falling; the newest three a
 * GATT session's; one row for another device; one two days old. */
static void seed(void) {
    static char sql[65536];
    size_t o = 0;
    o += (size_t)snprintf(sql + o, sizeof(sql) - o,
        "INSERT INTO victron_readings (last_seen,mac,src,rssi,voltage_v,soc_pct,"
        "current_a,alarm_reason) VALUES");
    int first = 1;
    for (int i = 0; i < 120; i++) {
        if (i >= 30 && i < 60) continue;                 /* a half-hour gap */
        long long t = SDB_NOW - 7200 + i * 60;
        o += (size_t)snprintf(sql + o, sizeof(sql) - o,
            "%s(%lld,'c7:fe:23:b1:1c:5f','%s',-70,%.3f,%.2f,NULL,0)", first ? " " : ",",
            t, i >= 117 ? "gatt" : "readout", 13.0 + i * 0.001, 90.0 - i * 0.05);
        first = 0;
    }
    o += (size_t)snprintf(sql + o, sizeof(sql) - o,
        ",(%lld,'f5:d8:0c:b6:31:cf','readout',NULL,NULL,50.0,NULL,NULL)"
        ",(%lld,'c7:fe:23:b1:1c:5f','readout',NULL,12.0,10.0,NULL,0);",
        SDB_NOW - 600, SDB_NOW - 2 * 86400LL);
    WT_EQ(sdb_exec(g_db, sql), 0);
}

/* One metric of one device over a window, bucketed, oldest first: the
 * other device's and the two-day-old row not in it; a value never
 * written answers no points; the cap holds. */
static void test_victronhist_points(void) {
    db_up(db_schema_version());
    seed();
    WT_EQ(route(&HH, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=soc_pct&hours=2"), 200);
    const char *b = body_of(g_out);
    char want[512];
    snprintf(want, sizeof(want), "{\"now\":%lld,\"mac\":\"c7:fe:23:b1:1c:5f\",\"metric\":\"soc_pct\","
             "\"unit\":\"%%\",\"hours\":2,\"from\":%lld,\"bucket_s\":60,\"db_schema\":%d,"
             "\"have\":true,\"cols\":[\"t\",\"mean\",\"min\",\"max\",\"n\",\"gatt\"],"
             "\"points\":[[%lld,90.000,90.000,90.000,1,0],", SDB_NOW, SDB_NOW - 7200,
             db_schema_version(), SDB_NOW - 7200);
    WT_HAS(b, want);
    WT_HAS(b, "\"total\":90,\"cut\":false}");
    WT_LACKS(b, "50.000");
    WT_LACKS(b, "10.000");
    snprintf(want, sizeof(want), "[%lld,84.050,84.050,84.050,1,1]]", SDB_NOW - 60);
    WT_HAS(b, want);
    /* 24 h: 360 s buckets (24 * 3600 / 240), six rows each. */
    WT_EQ(route(&HH, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=voltage_v"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"hours\":24,");
    WT_HAS(b, "\"bucket_s\":360,");
    WT_HAS(b, ",6,0]");
    WT_HAS(b, ",6,3]]");               /* the last bucket: three GATT rows */
    /* An enumeration: whole numbers for min and max. */
    WT_EQ(route(&HH, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=alarm_reason&hours=1"), 200);
    WT_HAS(body_of(g_out), ",0.00,0,0,1,");
    /* Never written for this device: no points. */
    WT_EQ(route(&HH, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=current_a"), 200);
    WT_HAS(body_of(g_out), "\"points\":[],\"total\":0,\"cut\":false}");
    /* An address with no rows: no points, not an error. */
    WT_EQ(route(&HH, "/api/victron/history", "mac=00:00:00:00:00:01&metric=soc_pct&hours=720"), 200);
    WT_HAS(body_of(g_out), "\"bucket_s\":10800,");
    WT_HAS(body_of(g_out), "\"points\":[],\"total\":0,");
    db_down();
}

/* The bucket cap: a row every minute for 30 days of buckets would be
 * far more than WEB_VICTRON_HIST_POINTS; the answer holds at most that
 * many, the newest, and says cut when there were more. */
static void test_victronhist_cap(void) {
    db_up(db_schema_version());
    static char sql[262144];
    size_t o = (size_t)snprintf(sql, sizeof(sql),
        "INSERT INTO victron_readings (last_seen,mac,src,soc_pct) VALUES");
    for (int i = 0; i < 2000; i++)
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%s(%lld,'c7:fe:23:b1:1c:5f','readout',%d)",
                              i ? "," : " ", SDB_NOW - 3600 * 6 + i * 11, i % 100);
    WT_ASSERT(o < sizeof(sql));
    WT_EQ(sdb_exec(g_db, sql), 0);
    WT_EQ(route(&HH, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=soc_pct&hours=6"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"bucket_s\":90,");
    /* 6 h of 90 s buckets: 240, and one more where the epoch-aligned
     * edges straddle the window's start. */
    WT_ASSERT(strstr(b, "\"total\":240,") != NULL);
    int pts = 0;
    const char *p0 = strstr(b, "\"points\":["), *end = strstr(b, "],\"total\"");
    WT_ASSERT(p0 && end);
    for (const char *p = p0 ? p0 + 10 : NULL; p && end && p < end; p++) pts += *p == '[';
    WT_ASSERT(pts <= WEB_VICTRON_HIST_POINTS);
    db_down();
}

/* A v14 file has no victron_readings: "have":false and no points, not
 * an error. */
static void test_victronhist_older_file(void) {
    db_up(14);
    WT_EQ(sdb_exec(g_db, "DROP TABLE victron_readings; DROP TABLE victron_devices;"), 0);
    WT_EQ(route(&HH, "/api/victron/history", "mac=c7:fe:23:b1:1c:5f&metric=soc_pct"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"db_schema\":14,\"have\":false,");
    WT_HAS(b, "\"points\":[],\"total\":0,");
    db_down();
}

#endif /* WITH_SQLITE */

/* The page's half: the tab after rtl_433, the view, the module's hooks;
 * every remote string through textContent (el()), no markup sink. */
static void test_victron_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<li><button type=\"button\" class=\"go\" id=\"nav-rtl433\">rtl_433</button></li>\n"
              "      <li><button type=\"button\" class=\"go\" id=\"nav-victron\">Victron</button></li>");
    WT_HAS(p, "  VIEWS.push(\"victron\");");
    WT_HAS(p, "  $(\"nav-victron\").addEventListener(\"click\", function () { show(\"victron\"); });");
    WT_HAS(p, "    if (v === \"victron\" && window.SlothVictron) SlothVictron.show();");
    WT_HAS(p, "  if (window.SlothVictron) SlothVictron.init({ getJSON: getJSON, errText: errText,\n"
              "    shortStamp: shortStamp, tok: tok });");
    WT_HAS(p, "<div id=\"v-victron\" hidden>");
    WT_HAS(p, "<div id=\"vc-cards\"></div>");
    WT_HAS(p, "    H.getJSON(\"/api/victron\").then(function (j) {");
    WT_HAS(p, "    return \"/api/victron/history?mac=\" + encodeURIComponent(mac) + \"&metric=\" +\n"
              "      encodeURIComponent(metric) + \"&hours=\" + S.hours;");
    WT_HAS(p, "  function el(tag, cls, text) {\n"
              "    var e = document.createElement(tag);\n"
              "    if (cls) e.className = cls;\n"
              "    if (text !== undefined && text !== null) e.textContent = String(text);\n"
              "    return e;\n"
              "  }");
    /* Stale is the route's word, drawn on the card and its figures. */
    WT_HAS(p, "    var c = el(\"section\", \"vc-card\" + (d.stale ? \" vc-stale\" : \"\"));");
    WT_HAS(p, "    return (d.stale ? \"STALE: last heard \" : \"last heard \") + t + \" ago\";");
    WT_HAS(p, "        dl.appendChild(el(\"dd\", d.stale ? \"vc-old\" : null, f[i][1]));");
    /* The chart is glyph.paint()'s, from a pure mark list. */
    WT_HAS(p, "    glyph.paint(c, marks(pts, { w: c.clientWidth, h: c.clientHeight, from: from, to: to,");
    /* A chart with cached data is painted after its card is attached,
     * never at build time when the canvas has no width (2026-11-16: the
     * charts went blank on every poll between two history fetches). */
    WT_HAS(p, "    if (e && e.j) S.late.push(function () { paintChart(c, cap, e.j); });\n"
              "    else cap.textContent = \"loading \" + metric;");
    WT_HAS(p, "    S.late = [];\n"
              "    for (var i = 0; i < ds.length; i++) box.appendChild(card(ds[i]));\n"
              "    // The cards are attached now: paint the charts that had their data.\n"
              "    var late = S.late;\n"
              "    S.late = [];\n"
              "    for (var k = 0; k < late.length; k++) late[k]();");
    WT_ASSERT(strstr(p, "if (e && e.j) paintChart(c, cap, e.j);") == NULL);
    const char *s = strstr(p, "// slothweb: the Victron tab");
    const char *m = strstr(p, "    chartCaption: chartCaption\n  };\n})();");
    WT_ASSERT(s && m && s < m);
    if (s && m) {
        size_t n = (size_t)(m - s);
        char *mod = malloc(n + 1);
        WT_ASSERT(mod != NULL);
        if (mod) {
            memcpy(mod, s, n);
            mod[n] = '\0';
            WT_LACKS(mod, "innerHTML");
            WT_LACKS(mod, "insertAdjacentHTML");
            WT_LACKS(mod, "setAttribute");
            WT_LACKS(mod, "http://");
            WT_LACKS(mod, "https://");
            free(mod);
        }
    }
}

void run_victron_tests(void) {
    WT_RUN(test_victron_allow_list_is_sloths);
    WT_RUN(test_victron_ingest_and_route);
    WT_RUN(test_victron_ranges_and_refusals);
    WT_RUN(test_victron_age);
    WT_RUN(test_victron_stale);
    WT_RUN(test_victron_scope);
    WT_RUN(test_victronhist_no_db);
#ifdef WITH_SQLITE
    WT_RUN(test_victronhist_points);
    WT_RUN(test_victronhist_cap);
    WT_RUN(test_victronhist_older_file);
#endif
    WT_RUN(test_victron_page);
    web_victron_destroy(&A);
}
