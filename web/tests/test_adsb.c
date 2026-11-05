/* The ADS-B panel (web_adsb.h): the aircraft kept by slothweb from
 * hand-built records in the emitter's exact shape (src/jsonl.c
 * emit_adsb_row() and the adsb_* block of jsonl_emit_sensor_health()),
 * the route through the route table under each scope, the health
 * member, and the emergency words held to sloth's own table. Addresses,
 * callsigns and positions are invented (docs/wiki/adsb.md, Privacy).
 *
 * Absence assertions, each seen red under a named mutation and restored:
 * the Local out_of_scope answer with route_adsb()'s none_here forced to
 * 0 (a Local answer carried rows); the range checks with row_apply()'s
 * alt_baro bound widened to 1e6 (the 900000 landed on the row); the
 * gone-row keep with age_out()'s gone branch removed (the gone row
 * stayed past its TTL); the track reset with row_apply()'s `same` test
 * forced to 1 (a returning address kept its old track). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_adsb.h"
#include "web_assets.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_routes.h"
#include "web_scope.h"
#include "wtest.h"

#define T 1793059200LL

static web_adsb_t A;
static web_jrec_t R;

static void feed(const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_adsb_record(&A, &R, 1000);
}

static const char SH[] =
    "{\"type\":\"sensor_health\",\"ts\":1793059200,\"capture_iface\":\"any\","
    "\"adsb_state\":\"live\",\"adsb_src\":\"file:/run/readsb/aircraft.json\","
    "\"adsb_age_s\":1,\"adsb_last_read\":1793059199,\"adsb_aircraft\":3,"
    "\"adsb_messages\":48211,\"adsb_reads\":120,\"adsb_read_errors\":0,"
    "\"adsb_parse_errors\":0,\"adsb_overflow\":0,\"adsb_bad_entries\":1,"
    "\"adsb_expired\":4,\"adsb_err\":\"\"}";
/* A jet with everything, as emit_adsb_row() writes it. */
static const char AC1[] =
    "{\"type\":\"adsb_aircraft\",\"ts\":1793059200,\"hex\":\"a1b2c3\",\"non_icao\":0,"
    "\"state\":\"live\",\"src\":\"file:/run/readsb/aircraft.json\",\"source_type\":\"adsb_icao\","
    "\"flight\":\"TST123\",\"squawk\":\"2201\",\"category\":\"A3\",\"emergency\":\"none\","
    "\"on_ground\":0,\"alt_baro\":34000,\"alt_geom\":34650,\"alt_band\":16,\"gs\":451.2,"
    "\"track\":271.5,\"baro_rate\":-64,\"geom_rate\":-32,\"lat\":10.12345,\"lon\":20.54321,"
    "\"pos_ts\":1793059199,\"rssi\":-18.4,\"messages\":2210,\"first_seen\":1793059100,"
    "\"last_seen\":1793059199}";
/* Mode S only: no position, no callsign, the decoder's "" for absent. */
static const char AC2[] =
    "{\"type\":\"adsb_aircraft\",\"ts\":1793059200,\"hex\":\"0d0e0f\",\"non_icao\":0,"
    "\"state\":\"live\",\"src\":\"file:/run/readsb/aircraft.json\",\"source_type\":\"mode_s\","
    "\"flight\":\"\",\"squawk\":\"\",\"category\":\"\",\"emergency\":\"\",\"on_ground\":0,"
    "\"alt_geom\":2550,\"alt_band\":3,\"gs\":115.4,\"rssi\":-25.0,\"messages\":12,"
    "\"first_seen\":1793059150,\"last_seen\":1793059170}";
/* A non-ICAO address declaring an emergency. */
static const char AC3[] =
    "{\"type\":\"adsb_aircraft\",\"ts\":1793059200,\"hex\":\"~00abcd\",\"non_icao\":1,"
    "\"state\":\"live\",\"src\":\"file:/run/readsb/aircraft.json\",\"source_type\":\"tisb_other\","
    "\"flight\":\"EMG7\",\"squawk\":\"7700\",\"category\":\"A1\",\"emergency\":\"general\","
    "\"on_ground\":0,\"alt_baro\":4500,\"alt_band\":4,\"lat\":10.2,\"lon\":20.3,"
    "\"pos_ts\":1793059190,\"first_seen\":1793059180,\"last_seen\":1793059195}";

static char g_out[262144];

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

static void fresh(void) {
    web_adsb_destroy(&A);
    WT_EQ(web_adsb_init(&A), 0);
}

static void health(web_health_t *H, long long now) {
    memset(H, 0, sizeof(*H));
    H->adsb = &A;
    H->wall_s = now;
}

/* The records land where the page reads them: the sensor block, three
 * rows with the emergency first, then the most recently heard; absent
 * figures null, never 0. */
static void test_adsb_ingest_and_route(void) {
    fresh();
    feed(SH); feed(AC2); feed(AC1); feed(AC3);
    web_health_t H;
    health(&H, T + 5);
    WT_EQ(route(&H, "/api/adsb", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"now\":1793059205,\"src\":\"file:/run/readsb/aircraft.json\",\"records\":3,"
              "\"evictions\":0,\"aged\":0,\"rejected\":0,\"sensor\":{\"ts\":1793059200,"
              "\"state\":\"live\",\"src\":\"file:/run/readsb/aircraft.json\",\"age_s\":1,"
              "\"last_read\":1793059199,\"aircraft\":3,\"messages\":48211,\"reads\":120,"
              "\"read_errors\":0,\"parse_errors\":0,\"overflow\":0,\"bad_entries\":1,"
              "\"expired\":4,\"err\":\"\"},\"total\":3,\"live\":3,\"with_pos\":2,"
              "\"emergency\":1,\"rows\":[{\"hex\":\"~00abcd\",\"non_icao\":1,\"state\":\"live\"");
    const char *r1 = strstr(b, "\"hex\":\"~00abcd\"");
    const char *r2 = strstr(b, "\"hex\":\"a1b2c3\"");
    const char *r3 = strstr(b, "\"hex\":\"0d0e0f\"");
    WT_ASSERT(r1 && r2 && r3 && r1 < r2 && r2 < r3);
    WT_HAS(b, "{\"hex\":\"a1b2c3\",\"non_icao\":0,\"state\":\"live\",\"source_type\":\"adsb_icao\","
              "\"flight\":\"TST123\",\"squawk\":\"2201\",\"category\":\"A3\",\"emergency\":\"none\","
              "\"on_ground\":0,\"alt_baro\":34000,\"alt_geom\":34650,\"alt_band\":16,\"gs\":451.2,"
              "\"track\":271.5,\"baro_rate\":-64,\"geom_rate\":-32,\"lat\":10.12345,"
              "\"lon\":20.54321,\"pos_ts\":1793059199,\"rssi\":-18.4,\"messages\":2210,"
              "\"first_seen\":1793059100,\"last_seen\":1793059199,\"ts\":1793059200,"
              "\"records\":1,\"track_pts\":[[1793059199,10.12345,20.54321,34000]]}");
    WT_HAS(b, "{\"hex\":\"0d0e0f\",\"non_icao\":0,\"state\":\"live\",\"source_type\":\"mode_s\","
              "\"flight\":\"\",\"squawk\":\"\",\"category\":\"\",\"emergency\":\"\",\"on_ground\":0,"
              "\"alt_baro\":null,\"alt_geom\":2550,\"alt_band\":3,\"gs\":115.4,\"track\":null,"
              "\"baro_rate\":null,\"geom_rate\":null,\"lat\":null,\"lon\":null,\"pos_ts\":null,"
              "\"rssi\":-25.0,\"messages\":12,\"first_seen\":1793059150,\"last_seen\":1793059170,"
              "\"ts\":1793059200,\"records\":1,\"track_pts\":[]}");
    /* A later record with a new cell appends a point; one with the same
     * position (a heartbeat) does not. */
    static char line[1024];
    snprintf(line, sizeof(line), "%s", AC1);
    char *p = strstr(line, "\"lat\":10.12345");
    memcpy(p, "\"lat\":10.23456", 14);
    p = strstr(line, "\"ts\":1793059200");
    memcpy(p, "\"ts\":1793059260", 15);
    feed(line);
    feed(line);
    WT_EQ(route(&H, "/api/adsb", "limit=2"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"records\":3,\"track_pts\":[[1793059199,10.12345,20.54321,34000],"
              "[1793059199,10.23456,20.54321,34000]]}]}");
    WT_LACKS(b, "\"hex\":\"0d0e0f\"");     /* limit=2 */
    /* The health member. */
    WT_EQ(route(&H, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), "\"adsb\":{\"rows\":3,\"live\":3,\"records\":5,\"evictions\":0,"
                           "\"aged\":0,\"rejected\":0,\"sensor_seen\":1}");
    /* Nothing yet: nulls, not zeros; a sensor_health without the block
     * (a sloth with no --adsb) leaves the sensor null. */
    fresh();
    feed("{\"type\":\"sensor_health\",\"ts\":1793059200,\"capture_iface\":\"any\"}");
    WT_EQ(route(&H, "/api/adsb", ""), 200);
    WT_HAS(body_of(g_out), "\"src\":\"\",\"records\":0,\"evictions\":0,\"aged\":0,\"rejected\":0,"
                           "\"sensor\":null,\"total\":0,\"live\":0,\"with_pos\":0,"
                           "\"emergency\":0,\"rows\":[]}");
}

/* Every string and figure is checked and anything outside is absent,
 * never clamped; a bad hex or state is rejected and counted; the query
 * refusals never echo the value. */
static void test_adsb_ranges_and_refusals(void) {
    fresh();
    feed("{\"type\":\"adsb_aircraft\",\"ts\":1793059200,\"hex\":\"A1B2C3\",\"state\":\"live\"}");
    feed("{\"type\":\"adsb_aircraft\",\"ts\":1793059200,\"hex\":\"a1b2c\",\"state\":\"live\"}");
    feed("{\"type\":\"adsb_aircraft\",\"ts\":1793059200,\"hex\":\"a1b2c3\",\"state\":\"maybe\"}");
    feed("{\"type\":\"adsb_aircraft\",\"ts\":1793059200,\"hex\":\"abcdef\",\"non_icao\":0,"
         "\"state\":\"live\",\"src\":\"fi\\u0001le\",\"source_type\":\"ADSB\",\"flight\":\"TOOLONG99\","
         "\"squawk\":\"7800\",\"category\":\"E1\",\"emergency\":\"panic\",\"on_ground\":2,"
         "\"alt_baro\":900000,\"alt_geom\":\"high\",\"alt_band\":99,\"gs\":-1,\"track\":400,"
         "\"baro_rate\":1.5,\"lat\":91,\"lon\":0,\"rssi\":30,\"messages\":-3,"
         "\"first_seen\":1793059100,\"last_seen\":1793059199}");
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/adsb", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"src\":\"\",\"records\":4,\"evictions\":0,\"aged\":0,\"rejected\":3");
    WT_HAS(b, "{\"hex\":\"abcdef\",\"non_icao\":0,\"state\":\"live\",\"source_type\":\"\","
              "\"flight\":\"\",\"squawk\":\"\",\"category\":\"\",\"emergency\":\"\",\"on_ground\":0,"
              "\"alt_baro\":null,\"alt_geom\":null,\"alt_band\":-1,\"gs\":null,\"track\":null,"
              "\"baro_rate\":null,\"geom_rate\":null,\"lat\":null,\"lon\":null,\"pos_ts\":null,"
              "\"rssi\":null,\"messages\":null,");
    WT_EQ(route(&H, "/api/adsb", "limit=0"), 400);
    WT_HAS(body_of(g_out), "bad_limit");
    WT_EQ(route(&H, "/api/adsb", "limit=513"), 400);
    WT_EQ(route(&H, "/api/adsb", "sort=alt"), 400);
    WT_LACKS(body_of(g_out), "sort=alt");
    /* No panel: 503 with a reason. */
    H.adsb = NULL;
    WT_EQ(route(&H, "/api/adsb", ""), 503);
}

/* A gone row is marked, sorted after the live ones and dropped
 * WEB_ADSB_GONE_TTL_S later; a live row quiet past WEB_ADSB_TTL_S is
 * dropped and counted as aged; an address that comes back with a new
 * first_seen starts a new track. */
static void test_adsb_gone_and_age(void) {
    fresh();
    feed(AC1); feed(AC2);
    static char line[1024];
    snprintf(line, sizeof(line), "%s", AC1);
    char *p = strstr(line, "\"state\":\"live\"");
    memcpy(p, "\"state\":\"gone\"", 14);
    p = strstr(line, "\"ts\":1793059200");
    memcpy(p, "\"ts\":1793059300", 15);
    feed(line);
    web_health_t H;
    health(&H, T + 100);
    WT_EQ(route(&H, "/api/adsb", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"total\":2,\"live\":1,\"with_pos\":0,\"emergency\":0,\"rows\":[{\"hex\":\"0d0e0f\"");
    WT_HAS(b, "{\"hex\":\"a1b2c3\",\"non_icao\":0,\"state\":\"gone\",");
    /* The same address back with a new first_seen: a new sighting. */
    snprintf(line, sizeof(line), "%s", AC1);
    p = strstr(line, "\"first_seen\":1793059100");
    memcpy(p, "\"first_seen\":1793059350", 23);
    p = strstr(line, "\"lat\":10.12345");
    memcpy(p, "\"lat\":11.00000", 14);
    p = strstr(line, "\"ts\":1793059200");
    memcpy(p, "\"ts\":1793059360", 15);
    feed(line);
    WT_EQ(route(&H, "/api/adsb", ""), 200);
    WT_HAS(body_of(g_out), "\"first_seen\":1793059350,\"last_seen\":1793059199,\"ts\":1793059360,"
                           "\"records\":1,\"track_pts\":[[1793059199,11.00000,20.54321,34000]]}");
    /* 700 s on, a sensor_health: AC2 (live, last record at T) is past
     * the live TTL and aged; AC1 (live again at T+160) stays. */
    snprintf(line, sizeof(line), "%s", SH);
    p = strstr(line, "\"ts\":1793059200");
    memcpy(p, "\"ts\":1793059900", 15);
    feed(line);
    WT_EQ(route(&H, "/api/adsb", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"aged\":1,");
    WT_LACKS(b, "\"hex\":\"0d0e0f\"");
    WT_HAS(b, "\"hex\":\"a1b2c3\"");
    /* A gone row goes WEB_ADSB_GONE_TTL_S after its gone record, and
     * is not counted as aged. */
    fresh();
    feed(AC2);
    snprintf(line, sizeof(line), "%s", AC2);
    p = strstr(line, "\"state\":\"live\"");
    memcpy(p, "\"state\":\"gone\"", 14);
    feed(line);
    snprintf(line, sizeof(line), "%s", SH);
    p = strstr(line, "\"ts\":1793059200");
    memcpy(p, "\"ts\":1793059850", 15);    /* 650 s: past the 600 s keep */
    feed(line);
    WT_EQ(route(&H, "/api/adsb", ""), 200);
    WT_HAS(body_of(g_out), "\"aged\":0,");
    WT_HAS(body_of(g_out), "\"total\":0,");
}

/* WEB_ADSB_ROWS rows; the least recently reported evicted and counted. */
static void test_adsb_eviction(void) {
    fresh();
    static char line[512];
    for (int i = 0; i < WEB_ADSB_ROWS + 1; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"adsb_aircraft\",\"ts\":%lld,\"hex\":\"%06x\",\"non_icao\":0,"
                 "\"state\":\"live\",\"src\":\"file:/x\",\"first_seen\":%lld,\"last_seen\":%lld}",
                 T + i, 0x100000 + i, T, T + i);
        feed(line);
    }
    web_health_t H;
    health(&H, T + 600);
    WT_EQ(route(&H, "/api/adsb", "limit=1"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"evictions\":1,");
    WT_HAS(b, "\"total\":512,");
    WT_EQ(route(&H, "/api/adsb", ""), 200);
    WT_LACKS(body_of(g_out), "\"hex\":\"100000\"");
    WT_HAS(body_of(g_out), "\"hex\":\"100200\"");
}

/* The SDR is passive radio: the record is Monitor's and a poll type;
 * Monitor and Hybrid answer rows, Local the one out_of_scope body (its
 * query still checked). */
static void test_adsb_scope(void) {
    fresh();
    feed(SH); feed(AC1);
    WT_EQ(web_scope_record("adsb_aircraft"), WEB_SC_M);
    WT_ASSERT(web_live_is_poll_type("adsb_aircraft"));
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/adsb", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&H, "/api/adsb", "scope=hybrid"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&H, "/api/adsb", "scope=local"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"local\",\"out_of_scope\":true,\"reason\":\"aircraft are the ADS-B decoder");
    WT_LACKS(body_of(g_out), "a1b2c3");
    WT_EQ(route(&H, "/api/adsb", "scope=local&limit=0"), 400);
}

/* The emergency words are sloth's (src/adsb.c k_emerg). */
static void test_adsb_vocabulary_is_sloths(void) {
    FILE *f = fopen("src/adsb.c", "rb");
    WT_ASSERT(f != NULL);
    if (!f) return;
    static char src[1 << 17];
    size_t n = fread(src, 1, sizeof(src) - 1, f);
    src[n] = '\0';
    fclose(f);
    WT_HAS(src, "static const char *const k_emerg[] = {\n"
                "    \"none\", \"general\", \"lifeguard\", \"minfuel\", \"nordo\", \"unlawful\",\n"
                "    \"downed\", \"reserved\"\n};");
    WT_ASSERT(!strcmp(web_adsb_emergency_name(0), "none"));
    WT_ASSERT(!strcmp(web_adsb_emergency_name(7), "reserved"));
    WT_ASSERT(!strcmp(web_adsb_emergency_name(8), ""));
    WT_ASSERT(!strcmp(web_adsb_emergency_name(-1), ""));
}

/* The page's half: the tab, the view, the module's hook; the table is
 * app.js's one DataTable, not a hand-rolled <table>; Local scopes the
 * view out as it does BLE's. */
static void test_adsb_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<li><button type=\"button\" class=\"go\" id=\"nav-adsb\">ADS-B</button></li>");
    WT_HAS(p, "  $(\"nav-adsb\").addEventListener(\"click\", function () { show(\"adsb\"); });");
    WT_HAS(p, "    if (v === \"adsb\" && window.SlothAdsb) SlothAdsb.show();");
    WT_HAS(p, "    $(\"v-adsb\").classList.toggle(\"scoped-out\", SCOPE === \"local\");");
    WT_HAS(p, "<div id=\"v-adsb\" hidden>");
    WT_HAS(p, "<div class=\"hscroll\" id=\"adsb-box\"><div class=\"adsbrow dhead\" id=\"adsb-thead\"></div><div id=\"adsb-rows\"></div></div>");
    WT_HAS(p, "    T = window.SlothTables.make({ id: \"adsb\", label: \"aircraft\", box: $(\"adsb-box\"),\n"
              "      head: $(\"adsb-thead\"), reset: $(\"adsb-tools\"), redraw: drawRows, cols: COLS });");
    WT_HAS(p, "    var cls = a.state === \"gone\" ? \"d-dim\" : num(a.lat) ? \"d-bright\" : \"d-normal\";\n"
              "    var r = el(\"div\", \"adsbrow dt-row \" + cls + (on ? \" on\" : \"\"));");
    WT_HAS(p, "      if (j.out_of_scope) return;");
    WT_LACKS(p, "class=\"adsb-table\"");
}

void run_adsb_tests(void) {
    WT_RUN(test_adsb_ingest_and_route);
    WT_RUN(test_adsb_ranges_and_refusals);
    WT_RUN(test_adsb_gone_and_age);
    WT_RUN(test_adsb_eviction);
    WT_RUN(test_adsb_scope);
    WT_RUN(test_adsb_vocabulary_is_sloths);
    WT_RUN(test_adsb_page);
    web_adsb_destroy(&A);
}
