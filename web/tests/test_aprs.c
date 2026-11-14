/* The APRS panel (web_aprs.h) and its history (web_aprshist.h): the
 * stations kept by slothweb from hand-built records in the emitter's
 * exact shape (src/jsonl.c emit_aprs_packet(), emit_aprs_station() and
 * the aprs_* block of jsonl_emit_sensor_health(); tests/test_aprs.c pins
 * those), the routes through the route table under each scope, the
 * health member, and the two sloth.db routes over a file built from
 * sloth's own DDL (sdb_gen.c) with rows in the --db writer's shape
 * (src/db.c write_aprs(); tests/test_db.c pins it). Callsigns (N0TEST-n,
 * N0CALL-n) and positions are invented (docs/wiki/aprs.md, Privacy).
 *
 * Absence assertions, each seen red under a named mutation and restored:
 * the Local answer with route_aprs()'s none_here forced to 0 (a Local
 * answer carried stations); the range checks with packet_apply()'s
 * speed bound widened to 1e6 (the 5000 kt landed on the row); the
 * object rule with packet_apply()'s ';' / ')' return removed (the
 * sender took the object's position); the gone keep with age_out()'s
 * gone branch removed (the gone station stayed past its TTL); the
 * budget with the list's WEB_APRS_ROW_WORST check removed (the answer
 * overflowed and the route went 503); the history window with
 * web_sdb_aprs_seen()'s "last_seen >= ?1" dropped (the 9-day-old
 * station came back in a 7-day answer); the Local history answer with
 * route_m5()'s RF_APRS_* none_here branch removed; the q refusal with
 * '%' and '_' admitted by q_take(). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_aprs.h"
#include "web_aprshist.h"
#include "web_assets.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_routes.h"
#include "web_slothdb.h"
#include "web_scope.h"
#include "wtest.h"
#include "wt_tmp.h"

#define T 1793930100LL

static web_aprs_t A;
static web_jrec_t R;

static void feed(const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_aprs_record(&A, &R, 1000);
}

static const char SH[] =
    "{\"type\":\"sensor_health\",\"ts\":1793930100,\"capture_iface\":\"any\","
    "\"aprs_state\":\"live\",\"aprs_src\":\"file:/var/lib/direwolf/aprs.log\","
    "\"aprs_missing\":0,\"aprs_last_read\":1793930099,\"aprs_last_packet\":1793930060,"
    "\"aprs_stations\":2,\"aprs_bytes\":4096,\"aprs_lines\":12,\"aprs_packets\":11,"
    "\"aprs_bad_lines\":1,\"aprs_overflow\":0,\"aprs_expired\":3,\"aprs_truncations\":1,"
    "\"aprs_rotations\":0,\"aprs_read_errors\":0,\"aprs_err\":\"\"}";
/* A fixed station heard direct, as emit_aprs_packet() writes it. */
static const char P1[] =
    "{\"type\":\"aprs_packet\",\"ts\":1793930036,\"src\":\"file:/var/lib/direwolf/aprs.log\","
    "\"seq\":1,\"chan\":0,\"utime\":1793930035,\"source\":\"N0TEST-5\",\"heard\":\"N0TEST-5\","
    "\"direct\":1,\"level\":50,\"error\":0,\"dti\":\"!\",\"name\":\"N0TEST-5\",\"symbol\":\"/#\","
    "\"lat\":10.000000,\"lon\":-20.000000,\"system\":\"DireWolf, WB2OSZ\","
    "\"comment\":\"Test station\"}";
/* Its station record, as emit_aprs_station() writes it. */
static const char S1[] =
    "{\"type\":\"aprs_station\",\"ts\":1793930036,\"call\":\"N0TEST-5\",\"state\":\"live\","
    "\"src\":\"file:/var/lib/direwolf/aprs.log\",\"first_seen\":1793930035,"
    "\"last_seen\":1793930035,\"packets\":1,\"via\":\"N0TEST-5\",\"direct\":1,"
    "\"heard_direct\":1,\"level\":50,\"best_level\":50,\"dti\":\"!\",\"symbol\":\"/#\","
    "\"lat\":10.000000,\"lon\":-20.000000,\"pos_ts\":1793930035,"
    "\"system\":\"DireWolf, WB2OSZ\",\"comment\":\"Test station\"}";
/* A moving station through a digipeater. */
static const char P2[] =
    "{\"type\":\"aprs_packet\",\"ts\":1793930061,\"src\":\"file:/var/lib/direwolf/aprs.log\","
    "\"seq\":2,\"chan\":0,\"utime\":1793930060,\"source\":\"N0TEST-9\",\"heard\":\"N0CALL-1\","
    "\"direct\":0,\"level\":20,\"error\":0,\"dti\":\"=\",\"name\":\"N0TEST-9\",\"symbol\":\"/>\","
    "\"lat\":10.205667,\"lon\":-20.535000,\"speed_kt\":45.0,\"course\":90.0,\"alt_m\":376.1,"
    "\"system\":\"Generic, (obsolete. Digis should use APNxxx instead)\",\"comment\":\" moving\"}";
/* The fixed station sending an object: its position is the object's. */
static const char P3[] =
    "{\"type\":\"aprs_packet\",\"ts\":1793930070,\"src\":\"file:/var/lib/direwolf/aprs.log\","
    "\"seq\":3,\"chan\":0,\"utime\":1793930069,\"source\":\"N0TEST-5\",\"heard\":\"N0CALL-1\","
    "\"direct\":0,\"level\":30,\"dti\":\";\",\"name\":\"TESTOBJ\",\"symbol\":\"/r\","
    "\"lat\":11.000000,\"lon\":-21.000000,\"comment\":\"object note\"}";

static char g_out[262144];

static int route(const web_health_t *h, const char *path, const char *query) {
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    /* The connection's own buffer size: an answer must fit it. */
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
    web_aprs_destroy(&A);
    WT_EQ(web_aprs_init(&A), 0);
}

static void health(web_health_t *H, long long now) {
    memset(H, 0, sizeof(*H));
    H->aprs = &A;
    H->wall_s = now;
}

/* The records land where the page reads them: the sensor block, the
 * stations most recently heard first, absent figures null; the object
 * moves neither the sender's position nor its comment, but is one of
 * its packets; ?call= carries the track and the recent packets. */
static void test_aprs_ingest_and_route(void) {
    fresh();
    feed(P1); feed(S1); feed(P2); feed(P3); feed(SH);
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"now\":1793930100,\"src\":\"file:/var/lib/direwolf/aprs.log\",\"records\":1,"
              "\"packet_records\":3,\"evictions\":0,\"aged\":0,\"rejected\":0,\"sensor\":{"
              "\"ts\":1793930100,\"state\":\"live\",\"src\":\"file:/var/lib/direwolf/aprs.log\","
              "\"missing\":0,\"last_read\":1793930099,\"last_packet\":1793930060,\"stations\":2,"
              "\"bytes\":4096,\"lines\":12,\"packets\":11,\"bad_lines\":1,\"overflow\":0,"
              "\"expired\":3,\"truncations\":1,\"rotations\":0,\"read_errors\":0,\"err\":\"\","
              "\"region\":null,\"region_hz\":0,\"freq_hz\":0,\"freq_mismatch\":0,\"silent\":0,"
              "\"silent_after_s\":0,\"quiet_since\":0},"
              "\"total\":2,\"live\":2,\"with_pos\":2,\"heard_direct\":1,\"stations\":["
              "{\"call\":\"N0TEST-5\",\"state\":\"live\",\"first_seen\":1793930035,"
              "\"last_seen\":1793930069,\"packets\":2,\"via\":\"N0CALL-1\",\"direct\":0,"
              "\"heard_direct\":1,\"level\":30,\"best_level\":50,\"dti\":\";\",\"symbol\":\"/#\","
              "\"lat\":10.00000,\"lon\":-20.00000,\"pos_ts\":1793930035,\"speed_kt\":null,"
              "\"course\":null,\"alt_m\":null,\"comment\":\"Test station\",\"status\":\"\","
              "\"system\":\"DireWolf, WB2OSZ\",\"ts\":1793930070,\"records\":3,\"track_n\":1},"
              "{\"call\":\"N0TEST-9\",\"state\":\"live\",\"first_seen\":1793930060,"
              "\"last_seen\":1793930060,\"packets\":1,\"via\":\"N0CALL-1\",\"direct\":0,"
              "\"heard_direct\":0,\"level\":20,\"best_level\":20,\"dti\":\"=\",\"symbol\":\"/\\u003e\","
              "\"lat\":10.20567,\"lon\":-20.53500,\"pos_ts\":1793930060,\"speed_kt\":45.0,"
              "\"course\":90,\"alt_m\":376,\"comment\":\" moving\",\"status\":\"\",");
    WT_HAS(b, "],\"shown\":2,\"cut\":false}");
    WT_LACKS(b, "\"lat\":11.0");
    WT_LACKS(b, "track_pts");
    WT_EQ(route(&H, "/api/aprs", "call=N0TEST-5"), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"now\":1793930100,\"src\":\"file:/var/lib/direwolf/aprs.log\",\"call\":\"N0TEST-5\","
              "\"station\":{\"call\":\"N0TEST-5\",\"state\":\"live\",");
    WT_HAS(b, "\"track_n\":1,\"track_pts\":[[1793930035,10.00000,-20.00000]],"
              "\"packet_cols\":[\"ts\",\"dti\",\"via\",\"direct\",\"level\",\"has_pos\",\"comment\"],"
              "\"packets_recent\":[[1793930035,\"!\",\"N0TEST-5\",1,50,1,\"Test station\"],"
              "[1793930069,\";\",\"N0CALL-1\",0,30,1,\"object note\"]]}}");
    WT_EQ(route(&H, "/api/aprs", "call=N0TEST-7"), 200);
    WT_HAS(body_of(g_out), "\"call\":\"N0TEST-7\",\"station\":null}");
    WT_EQ(route(&H, "/api/aprs", "limit=1"), 200);
    WT_HAS(body_of(g_out), "],\"shown\":1,\"cut\":false}");
    WT_LACKS(body_of(g_out), "N0TEST-9");
    /* The health member. */
    WT_EQ(route(&H, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), "\"aprs\":{\"rows\":2,\"live\":2,\"records\":1,\"packets\":3,"
                           "\"evictions\":0,\"aged\":0,\"rejected\":0,\"sensor_seen\":1}");
    /* Nothing yet: a sensor_health without the block (a sloth with no
     * --aprs) leaves the sensor null. */
    fresh();
    feed("{\"type\":\"sensor_health\",\"ts\":1793930100,\"capture_iface\":\"any\"}");
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    WT_HAS(body_of(g_out), "\"src\":\"\",\"records\":0,\"packet_records\":0,\"evictions\":0,"
                           "\"aged\":0,\"rejected\":0,\"sensor\":null,\"total\":0,\"live\":0,"
                           "\"with_pos\":0,\"heard_direct\":0,\"stations\":[],\"shown\":0,"
                           "\"cut\":false}");
}

/* #204: the region block as jsonl_emit_sensor_health() appends it
 * (tests/test_aprs.c test_sensor_health_region_fields pins that shape):
 * kept and served; a region not in sloth's list, a channel outside the
 * 2 m band and a flag outside 0/1 are absent, never taken. A sloth from
 * before #204 writes none of it and the sensor says region null. Seen
 * red with the REGIONS check removed from sh_apply() (the made-up name
 * was served) and with the Hz range widened to 0..1e12. */
static const char SH204[] =
    "{\"type\":\"sensor_health\",\"ts\":1793930100,\"capture_iface\":\"any\","
    "\"aprs_state\":\"live\",\"aprs_src\":\"file:/var/lib/direwolf/aprs.log\","
    "\"aprs_missing\":0,\"aprs_last_read\":1793930099,\"aprs_last_packet\":0,"
    "\"aprs_stations\":0,\"aprs_bytes\":0,\"aprs_lines\":0,\"aprs_packets\":0,"
    "\"aprs_bad_lines\":0,\"aprs_overflow\":0,\"aprs_expired\":0,\"aprs_truncations\":0,"
    "\"aprs_rotations\":0,\"aprs_read_errors\":0,\"aprs_err\":\"\","
    "\"twin193_excl_any\":0,\"aprs_region\":\"north-america\",\"aprs_region_hz\":144390000,"
    "\"aprs_freq_hz\":144800000,\"aprs_freq_mismatch\":1,\"aprs_silent\":1,"
    "\"aprs_silent_after_s\":21600,\"aprs_quiet_since\":1793900000,\"db_max_mb\":-1,"
    "\"jsonl_version\":\"1.7.0\"}";

static void test_aprs_region_and_silent(void) {
    fresh();
    feed(SH204);
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    WT_HAS(body_of(g_out), "\"err\":\"\",\"region\":\"north-america\",\"region_hz\":144390000,"
                           "\"freq_hz\":144800000,\"freq_mismatch\":1,\"silent\":1,"
                           "\"silent_after_s\":21600,\"quiet_since\":1793900000}");
    /* Hostile values: each absent. */
    fresh();
    feed("{\"type\":\"sensor_health\",\"ts\":1793930100,\"aprs_state\":\"live\","
         "\"aprs_region\":\"<b>atlantis</b>\",\"aprs_region_hz\":915000000,"
         "\"aprs_freq_hz\":-1,\"aprs_freq_mismatch\":2,\"aprs_silent\":7,"
         "\"aprs_silent_after_s\":99999999,\"aprs_quiet_since\":-5}");
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    WT_HAS(body_of(g_out), "\"region\":null,\"region_hz\":0,\"freq_hz\":0,\"freq_mismatch\":0,"
                           "\"silent\":0,\"silent_after_s\":0,\"quiet_since\":0}");
    WT_LACKS(body_of(g_out), "atlantis");
    /* No position reaches the page through the block: the line's
     * loc_* are not read by the panel. */
    fresh();
    feed("{\"type\":\"sensor_health\",\"ts\":1793930100,\"loc_lat\":10.00000,"
         "\"loc_lon\":-20.00000,\"aprs_state\":\"live\",\"aprs_region\":\"unknown\","
         "\"aprs_region_hz\":0}");
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    WT_HAS(body_of(g_out), "\"region\":\"unknown\",\"region_hz\":0,");
    WT_LACKS(body_of(g_out), "-20.0");
}

/* The page: the notice container, the two notices' wording, and the
 * hard-coded channel gone from the note. */
static void test_aprs_page_region(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<div class=\"aprsline aprs-notice\" id=\"aprs-notice\" role=\"status\" hidden></div>");
    WT_HAS(p, ".aprs-notice { color: var(--sev-warn); font-weight: bold; }");
    WT_HAS(p, "      n.appendChild(el(\"div\", \"\", \"silent for \" + (hrs === null ? \"?\" : hrs) + \"h: the decoder's log is readable but no packet arrived\" +");
    WT_HAS(p, "      n.appendChild(el(\"div\", \"\", \"frequency mismatch: the decoder is declared on \" + mhz(s.freq_hz) +");
    WT_HAS(p, "    if (s.region === \"unknown\") return \"  region unknown (no APRS channel known here)\";");
    WT_HAS(p, "    n.hidden = !any;");
    const char *note = strstr(p, "id=\"aprs-note\"");
    WT_ASSERT(note != NULL);
    if (note) {
        const char *end = strstr(note, "</span>");
        WT_ASSERT(end != NULL);
        if (end) {
            size_t n = (size_t)(end - note);
            char *t = malloc(n + 1);
            WT_ASSERT(t != NULL);
            if (t) {
                memcpy(t, note, n);
                t[n] = '\0';
                WT_LACKS(t, "144.390");
                WT_HAS(t, "--aprs-freq");
                free(t);
            }
        }
    }
}

/* Every string and figure is checked: a call that is not an AX.25 call
 * rejects the record and counts it; anything else outside its range is
 * absent, never clamped; the query refusals never echo the value. */
static void test_aprs_ranges_and_refusals(void) {
    fresh();
    feed("{\"type\":\"aprs_packet\",\"ts\":1793930100,\"utime\":1793930100,\"source\":\"n0test\"}");
    feed("{\"type\":\"aprs_packet\",\"ts\":1793930100,\"utime\":1793930100,\"source\":\"N0TEST-123\"}");
    feed("{\"type\":\"aprs_packet\",\"ts\":1793930100,\"source\":\"N0TEST\"}");
    feed("{\"type\":\"aprs_station\",\"ts\":1793930100,\"call\":\"N0TEST\",\"state\":\"maybe\","
         "\"first_seen\":1793930100}");
    feed("{\"type\":\"aprs_packet\",\"ts\":1793930100,\"utime\":1793930100,\"source\":\"N0TEST-2\","
         "\"heard\":\"WIDE1 1\",\"level\":1000,\"dti\":\"!!\",\"symbol\":\"/\",\"lat\":91,\"lon\":0,"
         "\"speed_kt\":5000,\"course\":400,\"alt_m\":-2000,\"system\":\"a\\u0001b\","
         "\"comment\":\"ok\"}");
    feed("{\"type\":\"aprs_packet\",\"ts\":1793930101,\"utime\":1793930101,\"source\":\"N0TEST-3\","
         "\"lat\":10.5,\"lon\":20.5,\"speed_kt\":5000,\"course\":400,\"alt_m\":-2000}");
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"rejected\":4,");
    WT_HAS(b, "{\"call\":\"N0TEST-2\",\"state\":\"live\",\"first_seen\":1793930100,"
              "\"last_seen\":1793930100,\"packets\":1,\"via\":\"\",\"direct\":0,"
              "\"heard_direct\":0,\"level\":null,\"best_level\":null,\"dti\":\"\",\"symbol\":\"\","
              "\"lat\":null,\"lon\":null,\"pos_ts\":null,\"speed_kt\":null,\"course\":null,"
              "\"alt_m\":null,\"comment\":\"ok\",\"status\":\"\",\"system\":\"\",");
    WT_HAS(b, "{\"call\":\"N0TEST-3\",\"state\":\"live\",");
    WT_HAS(b, "\"lat\":10.50000,\"lon\":20.50000,\"pos_ts\":1793930101,\"speed_kt\":null,"
              "\"course\":null,\"alt_m\":null,");
    WT_EQ(route(&H, "/api/aprs", "limit=0"), 400);
    WT_HAS(body_of(g_out), "bad_limit");
    WT_EQ(route(&H, "/api/aprs", "limit=1025"), 400);
    WT_EQ(route(&H, "/api/aprs", "call=n0test"), 400);
    WT_HAS(body_of(g_out), "bad_call");
    WT_LACKS(body_of(g_out), "n0test");
    WT_EQ(route(&H, "/api/aprs", "call=N0TEST%27"), 400);
    WT_EQ(route(&H, "/api/aprs", "sort=x"), 400);
    WT_LACKS(body_of(g_out), "sort=x");
    H.aprs = NULL;
    WT_EQ(route(&H, "/api/aprs", ""), 503);
}

/* A gone station is marked, sorted after the live ones and dropped
 * WEB_APRS_GONE_TTL_S later (not counted as aged); a live station quiet
 * past WEB_APRS_TTL_S is dropped and counted; a packet from a gone
 * station starts its next visit afresh. */
static void test_aprs_gone_and_age(void) {
    fresh();
    feed(P1); feed(S1); feed(P2);
    static char line[1024];
    snprintf(line, sizeof(line), "%s", S1);
    char *p = strstr(line, "\"state\":\"live\"");
    memcpy(p, "\"state\":\"gone\"", 14);
    p = strstr(line, "\"ts\":1793930036");
    memcpy(p, "\"ts\":1793933700", 15);
    feed(line);
    web_health_t H;
    health(&H, T + 3600);
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    const char *b = body_of(g_out);
    /* N0TEST-9's last record (ts 1793930061) is past WEB_APRS_TTL_S of
     * the gone record's ts: aged. */
    WT_HAS(b, "\"aged\":1,");
    WT_HAS(b, "\"total\":1,\"live\":0,");
    WT_HAS(b, "{\"call\":\"N0TEST-5\",\"state\":\"gone\",");
    /* Back on the air: a new visit, one packet, a fresh track. */
    snprintf(line, sizeof(line), "%s", P1);
    p = strstr(line, "\"utime\":1793930035");
    memcpy(p, "\"utime\":1793933800", 18);
    p = strstr(line, "\"ts\":1793930036");
    memcpy(p, "\"ts\":1793933801", 15);
    feed(line);
    WT_EQ(route(&H, "/api/aprs", "call=N0TEST-5"), 200);
    WT_HAS(body_of(g_out), "\"state\":\"live\",\"first_seen\":1793933800,\"last_seen\":1793933800,"
                           "\"packets\":1,");
    WT_HAS(body_of(g_out), "\"track_pts\":[[1793933800,10.00000,-20.00000]]");
    /* A gone station goes WEB_APRS_GONE_TTL_S after its gone record. */
    fresh();
    feed(S1);
    snprintf(line, sizeof(line), "%s", S1);
    p = strstr(line, "\"state\":\"live\"");
    memcpy(p, "\"state\":\"gone\"", 14);
    feed(line);
    snprintf(line, sizeof(line), "%s", SH);
    p = strstr(line, "\"ts\":1793930100");
    memcpy(p, "\"ts\":1793931900", 15);    /* 1864 s on: past the 1800 s keep */
    feed(line);
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    WT_HAS(body_of(g_out), "\"aged\":0,");
    WT_HAS(body_of(g_out), "\"total\":0,");
}

/* WEB_APRS_ROWS stations; the least recently reported evicted and
 * counted. Every row with a comment of 128 '<' (six bytes each once
 * escaped): the list stops where the 64 KB answer would not fit and
 * says so, and the route still answers 200. */
static void test_aprs_eviction_and_budget(void) {
    fresh();
    static char line[2048];
    char cm[WEB_APRS_COMMENT_MAX + 1];
    memset(cm, '<', WEB_APRS_COMMENT_MAX);
    cm[WEB_APRS_COMMENT_MAX] = '\0';
    for (int i = 0; i < WEB_APRS_ROWS + 1; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"aprs_packet\",\"ts\":%lld,\"utime\":%lld,\"source\":\"N%dT\","
                 "\"lat\":10.0,\"lon\":20.0,\"comment\":\"%s\"}", T, T + i, i, cm);
        feed(line);
    }
    web_health_t H;
    health(&H, T + 600);
    WT_EQ(route(&H, "/api/aprs", "limit=1"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"evictions\":1,");
    WT_HAS(b, "\"total\":1024,");
    WT_HAS(b, "{\"call\":\"N1024T\",");
    WT_EQ(route(&H, "/api/aprs", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"cut\":true}");
    WT_LACKS(b, "\"call\":\"N0T\"");
    WT_EQ(route(&H, "/api/aprs", "call=N0T"), 200);
    WT_HAS(body_of(g_out), "\"station\":null}");
}

/* The receiver is passive radio: both records are Monitor's and poll
 * types; Monitor and Hybrid answer stations, Local the one out_of_scope
 * body (its query still checked). */
static void test_aprs_scope(void) {
    fresh();
    feed(SH); feed(P1); feed(S1);
    WT_EQ(web_scope_record("aprs_packet"), WEB_SC_M);
    WT_EQ(web_scope_record("aprs_station"), WEB_SC_M);
    WT_ASSERT(web_live_is_poll_type("aprs_packet"));
    WT_ASSERT(web_live_is_poll_type("aprs_station"));
    web_health_t H;
    health(&H, T);
    WT_EQ(route(&H, "/api/aprs", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&H, "/api/aprs", "scope=hybrid"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&H, "/api/aprs", "scope=local"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"local\",\"out_of_scope\":true,\"reason\":\"APRS stations are the Dire Wolf decoder");
    WT_LACKS(body_of(g_out), "N0TEST");
    WT_EQ(route(&H, "/api/aprs", "scope=local&limit=0"), 400);
    WT_EQ(route(&H, "/api/aprs", "scope=local&call=N0TEST-5"), 200);
    WT_LACKS(body_of(g_out), "Test station");
}

/* The call rule is sloth's (src/aprs.c aprs_call_ok()). */
static void test_aprs_call_rule_is_sloths(void) {
    WT_ASSERT(web_aprs_call_ok("N0TEST"));
    WT_ASSERT(web_aprs_call_ok("N0TEST-15"));
    WT_ASSERT(web_aprs_call_ok("N0CALL-AB"));
    WT_ASSERT(!web_aprs_call_ok("N0TESTX"));
    WT_ASSERT(!web_aprs_call_ok("N0TEST-"));
    WT_ASSERT(!web_aprs_call_ok("N0TEST-123"));
    WT_ASSERT(!web_aprs_call_ok("n0test"));
    WT_ASSERT(!web_aprs_call_ok(""));
    WT_ASSERT(!web_aprs_call_ok(NULL));
}

/* The page's half: the tab after ADS-B, the view, the module's hook,
 * the scope rule; the tables are app.js's DataTable; every remote
 * string goes through textContent (el()); the history routes. */
static void test_aprs_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<li><button type=\"button\" class=\"go\" id=\"nav-adsb\">ADS-B</button></li>\n"
              "      <li><button type=\"button\" class=\"go\" id=\"nav-aprs\">APRS</button></li>");
    WT_HAS(p, "  $(\"nav-aprs\").addEventListener(\"click\", function () { show(\"aprs\"); });");
    WT_HAS(p, "    if (v === \"aprs\" && window.SlothAprs) SlothAprs.show();");
    WT_HAS(p, "    $(\"v-aprs\").classList.toggle(\"scoped-out\", SCOPE === \"local\");");
    WT_HAS(p, "<div id=\"v-aprs\" hidden>");
    WT_HAS(p, "<section class=\"panel scope-empty\" id=\"aprs-scope-empty\">");
    WT_HAS(p, "<div class=\"hscroll\" id=\"aprs-box\"><div class=\"aprsrow dhead\" id=\"aprs-thead\"></div><div id=\"aprs-rows\"></div></div>");
    WT_HAS(p, "<div class=\"hscroll\" id=\"aprs-seen-box\"><div class=\"histrow dhead\" id=\"aprs-seen-thead\"></div><div id=\"aprs-seen-rows\"></div></div>");
    WT_HAS(p, "  function table() {\n"
              "    if (T || !window.SlothTables || !$(\"aprs-box\")) return T;\n"
              "    T = window.SlothTables.make({ id: \"aprs\", label: \"stations\", box: $(\"aprs-box\"),\n"
              "      head: $(\"aprs-thead\"), reset: $(\"aprs-tools\"), redraw: drawRows, cols: COLS });\n"
              "    return T;\n"
              "  }");
    WT_HAS(p, "    ST = window.SlothTables.make({ id: \"aprs-seen\", label: \"stations seen\", box: $(\"aprs-seen-box\"),\n"
              "      head: $(\"aprs-seen-thead\"), reset: $(\"aprs-seen-tools\"), redraw: drawSeen, cols: SEEN_COLS });");
    WT_HAS(p, "  function el(tag, cls, text) {\n"
              "    var e = document.createElement(tag);\n"
              "    if (cls) e.className = cls;\n"
              "    if (text !== undefined && text !== null) e.textContent = String(text);\n"
              "    return e;\n"
              "  }");
    WT_HAS(p, "    getJSON(\"/api/aprs?call=\" + encodeURIComponent(call)).then(function (j) {");
    WT_HAS(p, "    getJSON(\"/api/aprs/seen?days=\" + encodeURIComponent(seenDays()) + \"&limit=\" + SEEN_PAGE +\n"
              "            \"&offset=\" + off + (q ? \"&q=\" + encodeURIComponent(q) : \"\")).then(function (j) {");
    WT_HAS(p, "    getJSON(\"/api/aprs/station?call=\" + encodeURIComponent(call) + \"&days=\" + encodeURIComponent(seenDays())).then(function (j) {");
    WT_HAS(p, "    if (q && !/^[0-9A-Za-z-]{1,9}$/.test(q)) { set(\"aprs-seen-count\", \"search: letters, digits and - only\"); return; }");
    WT_HAS(p, "      if (j.out_of_scope) return;");
    WT_HAS(p, "  window.SlothAprs = { show: show, select: select };");
    /* No markup built from a string in the module. */
    const char *m = strstr(p, "window.SlothAprs = { show: show, select: select };");
    const char *s = strstr(p, "// slothweb: the APRS panel");
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
            WT_LACKS(mod, "http://");
            WT_LACKS(mod, "https://");
            free(mod);
        }
    }
}

/* ── history (web_aprshist.h) ─────────────────────────────────────── */

static web_m4_t     m4;
static web_health_t HH;

/* No sloth.db: 503 no_sloth_db after the query is checked. */
static void test_aprshist_no_db(void) {
    memset(&m4, 0, sizeof(m4));
    memset(&HH, 0, sizeof(HH));
    HH.wall_s = SDB_NOW;
    HH.m4 = &m4;
    WT_EQ(route(&HH, "/api/aprs/seen", ""), 503);
    WT_HAS(body_of(g_out), "no_sloth_db");
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST-5"), 503);
    WT_EQ(route(&HH, "/api/aprs/seen", "days=0"), 400);
    WT_HAS(body_of(g_out), "bad_days");
    WT_EQ(route(&HH, "/api/aprs/seen", "days=401"), 400);
    WT_EQ(route(&HH, "/api/aprs/seen", "limit=101"), 400);
    WT_EQ(route(&HH, "/api/aprs/seen", "q=n0%25"), 400);
    WT_HAS(body_of(g_out), "bad_q");
    WT_EQ(route(&HH, "/api/aprs/seen", "q=n0_"), 400);
    WT_EQ(route(&HH, "/api/aprs/seen", "q=N0TEST-123"), 400);
    WT_EQ(route(&HH, "/api/aprs/seen", "offset=100001"), 400);
    WT_EQ(route(&HH, "/api/aprs/station", ""), 400);
    WT_HAS(body_of(g_out), "bad_call");
    WT_EQ(route(&HH, "/api/aprs/station", "call=n0test"), 400);
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST&sort=x"), 400);
    WT_EQ(route(&HH, "/api/aprs/tracks", ""), 503);
    WT_HAS(body_of(g_out), "no_sloth_db");
    WT_EQ(route(&HH, "/api/aprs/tracks", "hours=0"), 400);
    WT_HAS(body_of(g_out), "bad_hours");
}

#ifdef WITH_SQLITE

#define TN SDB_NOW

static char g_dir[TEST_TMP_MAX];
static char g_db[128];
static web_slothdb_t sdb;

static void db_up(int version) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-aprs-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, version, 0), 0);
    web_slothdb_init(&sdb, g_db, NULL);
    memset(&m4, 0, sizeof(m4));
    m4.sdb = &sdb;
    memset(&HH, 0, sizeof(HH));
    HH.wall_s = TN;
    HH.m4 = &m4;
}

static void db_down(void) {
    web_slothdb_destroy(&sdb);
    unlink(g_db);
    rmdir(g_dir);
}

/* Rows as write_aprs() leaves them: two stations in the week, one nine
 * days old; N0TEST-5's packets, one an object. */
static void seed_aprs(void) {
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "INSERT INTO aprs_stations (call,first_seen,last_seen,visit_first,visits,packets,"
        "via,heard_direct,best_level,dti,symbol,lat,lon,pos_ts,comment,status,system) VALUES"
        " ('N0TEST-5',%lld,%lld,%lld,2,3,'N0CALL-1',1,70,';','/#',10.0,-20.0,%lld,"
        "'on the air',NULL,'DireWolf, WB2OSZ'),"
        " ('N0TEST-9',%lld,%lld,%lld,1,1,NULL,0,NULL,'=','/>',10.2,-20.5,%lld,' moving',"
        "'En Route',NULL),"
        " ('N0CALL-1',%lld,%lld,%lld,1,4,'N0CALL-1',1,40,'!','/#',NULL,NULL,NULL,NULL,NULL,NULL);"
        "INSERT INTO aprs_packets (last_seen,source,heard,dti,name,symbol,lat,lon,speed_kt,"
        "course,alt_m,level,status,comment) VALUES"
        " (%lld,'N0TEST-5','N0TEST-5','!','N0TEST-5','/#',10.0,-20.0,NULL,NULL,NULL,50,NULL,"
        "'Test station'),"
        " (%lld,'N0TEST-5','N0CALL-1','>','N0TEST-5',NULL,NULL,NULL,NULL,NULL,NULL,20,NULL,"
        "'on the air'),"
        " (%lld,'N0TEST-5','N0CALL-1',';','TESTOBJ','/r',11.0,-21.0,NULL,NULL,NULL,70,NULL,"
        "'object note'),"
        " (%lld,'N0TEST-9',NULL,'=','N0TEST-9','/>',10.2,-20.5,45.0,90.0,376.1,NULL,'En Route',"
        "' moving'),"
        " (%lld,'N0TEST-5','N0TEST-5','!','N0TEST-5','/#',10.0,-20.0,NULL,NULL,NULL,50,NULL,"
        "'old');",
        TN - 7200, TN - 60, TN - 3000, TN - 7200,
        TN - 600, TN - 600, TN - 600, TN - 600,
        TN - 9 * 86400LL, TN - 9 * 86400LL, TN - 9 * 86400LL,
        TN - 7200, TN - 3000, TN - 60, TN - 600, TN - 9 * 86400LL);
    WT_EQ(sdb_exec(g_db, sql), 0);
}

static void test_aprshist_seen_and_station(void) {
    db_up(db_schema_version());
    seed_aprs();
    WT_EQ(route(&HH, "/api/aprs/seen", ""), 200);
    const char *b = body_of(g_out);
    char want[1024];
    snprintf(want, sizeof(want), "\"have\":true,\"stations\":[{\"call\":\"N0TEST-5\","
             "\"first_seen\":%lld,\"last_seen\":%lld,\"visits\":2,\"packets\":3,"
             "\"via\":\"N0CALL-1\",\"heard_direct\":1,\"best_level\":70,\"dti\":\";\","
             "\"symbol\":\"/#\",\"lat\":10.00000,\"lon\":-20.00000,\"pos_ts\":%lld,"
             "\"comment\":\"on the air\"},{\"call\":\"N0TEST-9\",", TN - 7200, TN - 60, TN - 7200);
    WT_HAS(b, want);
    WT_HAS(b, "\"via\":\"\",\"heard_direct\":0,\"best_level\":null,");
    WT_HAS(b, "\"total\":2,\"more\":false}");
    WT_LACKS(b, "N0CALL-1\",\"first_seen");     /* 9 days: outside 7 */
    WT_LACKS(b, "DireWolf");                    /* the inventory has no system */
    WT_EQ(route(&HH, "/api/aprs/seen", "days=30"), 200);
    WT_HAS(body_of(g_out), "{\"call\":\"N0CALL-1\",");
    WT_EQ(route(&HH, "/api/aprs/seen", "limit=1"), 200);
    WT_HAS(body_of(g_out), "\"total\":1,\"more\":true}");
    WT_EQ(route(&HH, "/api/aprs/seen", "limit=1&offset=1"), 200);
    WT_HAS(body_of(g_out), "\"stations\":[{\"call\":\"N0TEST-9\"");
    WT_EQ(route(&HH, "/api/aprs/seen", "q=n0test-9"), 200);
    WT_HAS(body_of(g_out), "\"q\":\"N0TEST-9\",");
    WT_HAS(body_of(g_out), "\"total\":1,");
    WT_EQ(route(&HH, "/api/aprs/seen", "q=N0T"), 200);
    WT_HAS(body_of(g_out), "\"total\":2,");
    WT_EQ(route(&HH, "/api/aprs/seen", "q=ZZ"), 200);
    WT_HAS(body_of(g_out), "\"stations\":[],\"total\":0,");
    /* One station: its row (with status and system) and its packets in
     * the window, oldest first; the object is its own packet. */
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST-5"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"station\":{\"call\":\"N0TEST-5\",");
    WT_HAS(b, "\"comment\":\"on the air\",\"status\":\"\",\"system\":\"DireWolf, WB2OSZ\"}");
    snprintf(want, sizeof(want),
             "\"cols\":[\"ts\",\"heard\",\"dti\",\"name\",\"symbol\",\"lat\",\"lon\",\"speed_kt\","
             "\"course\",\"alt_m\",\"level\",\"status\",\"comment\"],\"packets\":["
             "[%lld,\"N0TEST-5\",\"!\",\"N0TEST-5\",\"/#\",10.00000,-20.00000,null,null,null,50,"
             "\"\",\"Test station\"],[%lld,\"N0CALL-1\",\"\\u003e\",\"N0TEST-5\",\"\",null,null,null,null,"
             "null,20,\"\",\"on the air\"],[%lld,\"N0CALL-1\",\";\",\"TESTOBJ\",\"/r\",11.00000,"
             "-21.00000,null,null,null,70,\"\",\"object note\"]],\"total\":3,\"cut\":false}",
             TN - 7200, TN - 3000, TN - 60);
    WT_HAS(b, want);
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST-5&days=30"), 200);
    WT_HAS(body_of(g_out), "\"total\":4,\"cut\":false}");
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST-7"), 200);
    WT_HAS(body_of(g_out), "\"station\":null,");
    WT_HAS(body_of(g_out), "\"packets\":[],\"total\":0,\"cut\":false}");
    /* Local: the receiver is passive radio. */
    WT_EQ(route(&HH, "/api/aprs/seen", "scope=local"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true,\"reason\":\"APRS stations are the Dire Wolf decoder");
    WT_LACKS(body_of(g_out), "N0TEST");
    WT_EQ(route(&HH, "/api/aprs/station", "scope=local&call=N0TEST-5"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true");
    WT_LACKS(body_of(g_out), "on the air");
    WT_EQ(route(&HH, "/api/aprs/station", "scope=local&call=zz"), 400);
    WT_EQ(route(&HH, "/api/aprs/seen", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"total\":2,");
    db_down();
}

/* 400 packets whose comment is 128 '<' (768 bytes escaped): the answer
 * keeps the newest that fit the 64 KB buffer, says "cut", answers 200.
 * 100 stations with that comment: one whole inventory page. */
static void test_aprshist_budget(void) {
    db_up(db_schema_version());
    char cm[129];
    memset(cm, '<', 128);
    cm[128] = '\0';
    static char sql[1 << 18];
    int off = snprintf(sql, sizeof(sql), "INSERT INTO aprs_stations (call,first_seen,"
                       "last_seen,visit_first,comment) VALUES ");
    for (int i = 0; i < 100; i++)
        off += snprintf(sql + off, sizeof(sql) - (size_t)off, "%s('N%dT',%lld,%lld,%lld,'%s')",
                        i ? "," : "", i, TN - 100, TN - 100 + i, TN - 100, cm);
    snprintf(sql + off, sizeof(sql) - (size_t)off, ";");
    WT_EQ(sdb_exec(g_db, sql), 0);
    off = snprintf(sql, sizeof(sql), "INSERT INTO aprs_packets (last_seen,source,comment,"
                   "status) VALUES ");
    for (int i = 0; i < 400; i++)
        off += snprintf(sql + off, sizeof(sql) - (size_t)off, "%s(%lld,'N0T','%s','%.64s')",
                        i ? "," : "", TN - 1000 + i, cm, cm);
    snprintf(sql + off, sizeof(sql) - (size_t)off, ";");
    WT_EQ(sdb_exec(g_db, sql), 0);
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0T"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"cut\":true}");
    char newest[32];
    snprintf(newest, sizeof(newest), "[%lld,", TN - 1000 + 399);
    WT_HAS(b, newest);
    snprintf(newest, sizeof(newest), "[%lld,", TN - 1000);
    WT_LACKS(b, newest);
    /* A full inventory page of such rows fits whole: the comment is cut
     * to WEB_APRSHIST_SEEN_CM there, so its byte guard is a backstop
     * these caps never reach (not claimed as exercised here). */
    WT_EQ(route(&HH, "/api/aprs/seen", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"total\":100,\"more\":false}");
    WT_HAS(b, "{\"call\":\"N99T\",");
    WT_HAS(b, "{\"call\":\"N0T\",");
    db_down();
}

/* /api/aprs/tracks (the Radar, 2026-11-06): stations, and objects keyed
 * by their own name with the station that reported them; last_seen the
 * newest packet of any kind (a status-only packet advances it and its
 * status is the entity's) while the position stays the newest that had
 * one; moving from two distinct cells or a speed; a trail only when
 * moving, bucketed to at most 48 points; the window; the refusals and
 * Local. Seen red, each in web_sdb_aprs_tracks() unless named: with the
 * status's `!t->status[0]` guard dropped (an older empty status won),
 * with the speed test made `>= 0` (the fixed station at 0 kt moved),
 * with rows without a position skipped before the entity is taken (the
 * status-only packet no longer advanced last_seen: the mobile left the
 * hour), and with route_m5()'s RF_APRS_TRK taken out of the Local list
 * (Local served entities). */
static void test_aprshist_tracks(void) {
    db_up(db_schema_version());
    char sql[8192];
    snprintf(sql, sizeof(sql),
        "INSERT INTO aprs_packets (last_seen,source,heard,dti,name,symbol,lat,lon,speed_kt,"
        "course,alt_m,level,status,comment) VALUES"
        /* N0TEST-9: a mobile, three positions, then a status-only packet. */
        " (%lld,'N0TEST-9',NULL,'=','N0TEST-9','/>',10.20,-20.50,40.0,90.0,376.0,NULL,NULL,'leaving'),"
        " (%lld,'N0TEST-9',NULL,'=','N0TEST-9','/>',10.21,-20.48,45.0,80.0,380.0,NULL,NULL,NULL),"
        " (%lld,'N0TEST-9',NULL,'=','N0TEST-9','/>',10.22,-20.46,50.0,70.0,390.0,NULL,'',NULL),"
        " (%lld,'N0TEST-9',NULL,'>','N0TEST-9',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'At the pass',NULL),"
        /* N0TEST-5: a fixed station, the same position twice, a later empty status. */
        " (%lld,'N0TEST-5','N0TEST-5','!','N0TEST-5','/#',10.00000,-20.00000,NULL,NULL,NULL,50,'QRV 2m',NULL),"
        " (%lld,'N0TEST-5','N0TEST-5','!','N0TEST-5','/#',10.00001,-20.00001,0.0,NULL,NULL,50,'','home'),"
        /* An object N0TEST-5 reports, and an item N0CALL-1 does. */
        " (%lld,'N0TEST-5','N0CALL-1',';','TESTOBJ','/r',11.0,-21.0,NULL,NULL,NULL,70,NULL,'object note'),"
        " (%lld,'N0CALL-1','N0CALL-1',')','ITEM1','/j',12.0,-22.0,NULL,NULL,NULL,NULL,NULL,NULL),"
        /* An object packet with an empty name is its source's. */
        " (%lld,'N0CALL-1','N0CALL-1',';','',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'unnamed'),"
        /* Two days old: outside every window. */
        " (%lld,'N0OLD','N0OLD','!','N0OLD','/#',9.0,-19.0,NULL,NULL,NULL,NULL,NULL,NULL);",
        TN - 7200, TN - 5400, TN - 3600, TN - 60,
        TN - 9000, TN - 120, TN - 300, TN - 1000, TN - 30, TN - 2 * 86400LL);
    WT_EQ(sdb_exec(g_db, sql), 0);
    WT_EQ(route(&HH, "/api/aprs/tracks", ""), 200);
    const char *b = body_of(g_out);
    char want[2048];
    snprintf(want, sizeof(want), "{\"now\":%lld,\"hours\":24,\"bucket_s\":1800,\"have\":true,"
             "\"cols\":[\"key\",\"object\",\"via\",\"symbol\",\"last_seen\",\"lat\",\"lon\",\"alt_m\","
             "\"speed_kt\",\"course\",\"pos_ts\",\"moving\",\"status\",\"comment\",\"pts\"],\"entities\":["
             "[\"N0CALL-1\",0,\"\",\"\",%lld,null,null,null,null,null,null,0,\"\",\"unnamed\",[]],"
             "[\"N0TEST-9\",0,\"\",\"/\\u003e\",%lld,10.22000,-20.46000,390,50.0,70,%lld,1,\"At the pass\","
             "\"leaving\",[[%lld,10.20000,-20.50000],[%lld,10.21000,-20.48000],[%lld,10.22000,-20.46000]]],"
             "[\"N0TEST-5\",0,\"\",\"/#\",%lld,10.00001,-20.00001,null,0.0,null,%lld,0,\"QRV 2m\",\"home\",[]],"
             "[\"TESTOBJ\",1,\"N0TEST-5\",\"/r\",%lld,11.00000,-21.00000,null,null,null,%lld,0,\"\","
             "\"object note\",[]],"
             "[\"ITEM1\",1,\"N0CALL-1\",\"/j\",%lld,12.00000,-22.00000,",
             TN, TN - 30, TN - 60, TN - 3600, TN - 7200, TN - 5400, TN - 3600,
             TN - 120, TN - 120, TN - 300, TN - 300, TN - 1000);
    WT_HAS(b, want);
    WT_HAS(b, "\"total\":5,\"cut\":false}");
    WT_LACKS(b, "N0OLD");
    WT_LACKS(b, "[\"\",");
    /* The last hour: the mobile (its status packet is the newest) stays
     * with its older position; the object 1000 s old too; nothing
     * heard only before the hour. */
    WT_EQ(route(&HH, "/api/aprs/tracks", "hours=1"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"hours\":1,\"bucket_s\":75,");
    snprintf(want, sizeof(want), "[\"N0TEST-9\",0,\"\",\"/\\u003e\",%lld,10.22000,-20.46000,", TN - 60);
    WT_HAS(b, want);
    WT_HAS(b, "\"total\":5,");
    WT_EQ(route(&HH, "/api/aprs/tracks", "hours=0"), 400);
    WT_HAS(body_of(g_out), "bad_hours");
    WT_EQ(route(&HH, "/api/aprs/tracks", "hours=25"), 400);
    WT_EQ(route(&HH, "/api/aprs/tracks", "days=1"), 400);
    WT_HAS(body_of(g_out), "unknown_parameter");
    WT_EQ(route(&HH, "/api/aprs/tracks", "scope=local"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true,\"reason\":\"APRS stations are the Dire Wolf decoder");
    WT_LACKS(body_of(g_out), "N0TEST");
    WT_EQ(route(&HH, "/api/aprs/tracks", "scope=local&hours=99"), 400);
    WT_EQ(route(&HH, "/api/aprs/tracks", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"total\":5,");
    db_down();
}

/* A moving station's 24 h of packets, one a minute: its trail is the
 * newest row of each 30 min bucket, at most 48, oldest first. Then the
 * caps: 301 entities answer 300 and cut; 300 moving entities whose
 * status and comment are 64 '<' (six bytes each escaped), each with a
 * full trail, stop at the budget and say cut, inside the buffer. And
 * the query's time on 86,400 packets (a 1200 bit/s channel's day) from
 * 2,000 entities, inside the request budget. */
static void test_aprshist_tracks_caps(void) {
    db_up(db_schema_version());
    WT_EQ(sdb_exec(g_db, "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 1439)"
                         " INSERT INTO aprs_packets (last_seen,source,dti,name,lat,lon,speed_kt)"
                         " SELECT 1792627200 - 60 * i, 'N0MOV-1', '=', 'N0MOV-1', 10.0 + i * 0.001,"
                         " -20.0, 30.0 FROM n;"), 0);
    WT_EQ(route(&HH, "/api/aprs/tracks", ""), 200);
    const char *b = body_of(g_out);
    const char *pts = strstr(b, ",1,\"\",\"\",[");
    WT_ASSERT(pts != NULL);
    if (pts) {
        int np = 0;
        for (const char *q = pts + 10; *q && !(q[0] == ']' && q[1] == ']' && q[2] == ']'); q++) if (*q == '[') np++;
        WT_EQ(np, WEB_APRSHIST_TRK_POINTS);
    }
    WT_HAS(b, "[\"N0MOV-1\",0,\"\",\"\",");
    char newest[64];
    snprintf(newest, sizeof(newest), "[%lld,10.00000,-20.00000]]]],", TN);
    WT_HAS(b, newest);
    db_down();

    db_up(db_schema_version());
    WT_EQ(sdb_exec(g_db, "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 300)"
                         " INSERT INTO aprs_packets (last_seen,source,dti,name,lat,lon)"
                         " SELECT 1792627200 - i, 'N' || i, '!', 'N' || i, 10.0, -20.0 FROM n;"), 0);
    WT_EQ(route(&HH, "/api/aprs/tracks", ""), 200);
    WT_HAS(body_of(g_out), "\"total\":300,\"cut\":true}");
    WT_HAS(body_of(g_out), "[\"N0\",0,");
    WT_LACKS(body_of(g_out), "[\"N300\",");
    db_down();

    db_up(db_schema_version());
    WT_EQ(sdb_exec(g_db, "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 14399)"
                         " INSERT INTO aprs_packets (last_seen,source,dti,name,lat,lon,speed_kt,course,"
                         "alt_m,symbol,status,comment)"
                         " SELECT 1792627200 - (i / 300) * 1800, 'N0' || (i % 300) || '-15', '=', '', 10.123456 + i * 0.00001,"
                         " -120.123456, 999.9, 359.0, 9999.0, '<<', printf('%.64c', '<'), printf('%.64c', '<') FROM n;"), 0);
    WT_EQ(route(&HH, "/api/aprs/tracks", ""), 200);
    b = body_of(g_out);
    size_t n = strlen(b);
    fprintf(stderr, "    /api/aprs/tracks worst case (300 moving, 48 points, text escaped): %zu bytes\n", n);
    WT_HAS(b, "\"cut\":true}");
    WT_ASSERT(n < 65536 - 1024);
    WT_HAS(b, ",1,\"\\u003c\\u003c");
    WT_LACKS(b, "<");
    db_down();

    db_up(db_schema_version());
    WT_EQ(sdb_exec(g_db, "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 86399)"
                         " INSERT INTO aprs_packets (last_seen,source,heard,dti,name,symbol,lat,lon,speed_kt,"
                         "course,level,comment)"
                         " SELECT 1792627200 - i, 'N' || (i % 2000) || '-9', 'N0DIGI', CASE WHEN i % 7 = 0 THEN ';' ELSE '!' END,"
                         " CASE WHEN i % 7 = 0 THEN 'OBJ' || (i % 50) ELSE NULL END, '/>', 10.0 + (i % 13) * 0.01,"
                         " -20.0, i % 3, i % 360, 40, 'a comment of ordinary length' FROM n;"), 0);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    WT_EQ(route(&HH, "/api/aprs/tracks", ""), 200);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (long)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
    fprintf(stderr, "    /api/aprs/tracks on 86400 packets, 2050 entities: %ld ms, %zu bytes\n", ms,
            strlen(body_of(g_out)));
    WT_HAS(body_of(g_out), "\"have\":true,");
    WT_ASSERT(ms < WEB_SDB_HTTP_MS * web_sdb_test_budget_scale);
    db_down();
}

/* A file older than the tables: an empty answer that says so. */
static void test_aprshist_tracks_older_file(void) {
    db_up(12);
    WT_EQ(route(&HH, "/api/aprs/tracks", ""), 200);
    WT_HAS(body_of(g_out), "\"have\":false,\"cols\":[");
    WT_HAS(body_of(g_out), "\"entities\":[],\"total\":0,\"cut\":false}");
    db_down();
}

/* A sloth.db from before the tables: an empty answer that says so,
 * never an error. */
static void test_aprshist_older_file(void) {
    db_up(12);
    WT_EQ(route(&HH, "/api/aprs/seen", ""), 200);
    WT_HAS(body_of(g_out), "\"db_schema\":12,\"have\":false,\"stations\":[],\"total\":0,");
    WT_EQ(route(&HH, "/api/aprs/station", "call=N0TEST-5"), 200);
    WT_HAS(body_of(g_out), "\"have\":false,\"station\":null,");
    db_down();
}

#endif

/* Count of `needle` between `from` and the first `to` after it in the
 * page, or -1 when either is missing. */
static int count_in(const char *p, const char *from, const char *to, const char *needle) {
    const char *a = strstr(p, from), *b = a ? strstr(a + 1, to) : NULL;
    if (!a || !b) return -1;
    int n = 0;
    for (const char *q = a; q < b; q++) if (!strncmp(q, needle, strlen(needle))) n++;
    return n;
}

/* The positions scope (owner request 2026-11-13: an ATC-style radar
 * with the sensor at the centre). ppi.js is shared with ADS-B; its
 * whole functions are pinned here (#171 V1: a pinned line misses its
 * neighbours' mutations): the centre is radar.js's rule (fresh fix,
 * else last fix, else --location), bearing and range are great-circle,
 * auto range holds `share` of the distances, the afterglow stays in
 * 0.35..1, a static fallback stops the loop, reduced motion stops the
 * sweep. The sensor's coordinates are never drawn: ppi.js's scope()
 * names ctr.lat and ctr.lon only in its two geo() calls, and APRS's
 * spec and frame never name them (seen red with a fillText(ctr.lat...)
 * added to scope()). */
static void test_aprs_page_scope(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  window.SlothPPI = { centre: centre, geo: geo, autoRange: autoRange, make: make, still: still, fmt: fmt, pad3: pad3 };");
    WT_HAS(p, "<canvas id=\"aprs-plot\" class=\"heat\" aria-label=\"aprs station positions on a radar scope centred on this sensor, north up\"></canvas>");
    WT_HAS(p, "<label class=\"sub\">range <select id=\"aprs-range\"><option value=\"0\" selected>auto</option>");
    WT_HAS(p, "  var EARTH_M = 6371008.8, FIX_FRESH_S = 60, SWEEP_MS = 6000, GLOW_MS = 2000;");
    WT_HAS(p, "  var PICK_PX = 10, FRAME_MS = 33, RINGS = 5;");
    WT_HAS(p, "  var mq = window.matchMedia ? window.matchMedia(\"(prefers-reduced-motion: reduce)\") : null;");
    WT_HAS(p, "  var RANGES_KM = [2, 5, 10, 25, 50, 100, 250, 500];");
    WT_HAS(p, "  var LEAD_S = 300, RANGE_DFLT_KM = 25, AUTO_SHARE = 0.8;");
    WT_HAS(p, "  function centre(j) {\n"
              "    if (!j) return null;\n"
              "    var now = num(j.now) ? j.now : Math.floor(Date.now() / 1000), f = j.fix, l = j.loc;\n"
              "    if (f && num(f.mode) && f.mode >= 2 && num(f.lat) && num(f.lon) && num(f.ts) && now - f.ts <= FIX_FRESH_S)\n"
              "      return { lat: f.lat, lon: f.lon, from: \"gps fix\", age: now - f.ts };\n"
              "    if (l && num(l.lat) && num(l.lon))\n"
              "      return { lat: l.lat, lon: l.lon, from: l[\"src\"] === \"gps\" ? \"last gps fix\" : \"--location\",\n"
              "               age: num(l.ts) ? now - l.ts : null };\n"
              "    return null;\n"
              "  }");
    WT_HAS(p, "  function geo(lat0, lon0, lat, lon) {\n"
              "    var d = Math.PI / 180, p0 = lat0 * d, p1 = lat * d, dl = (lon - lon0) * d, dp = p1 - p0;\n"
              "    var a = Math.sin(dp / 2) * Math.sin(dp / 2) + Math.cos(p0) * Math.cos(p1) * Math.sin(dl / 2) * Math.sin(dl / 2);\n"
              "    var range = 2 * EARTH_M * Math.atan2(Math.sqrt(a), Math.sqrt(Math.max(0, 1 - a)));\n"
              "    var y = Math.sin(dl) * Math.cos(p1), x = Math.cos(p0) * Math.sin(p1) - Math.sin(p0) * Math.cos(p1) * Math.cos(dl);\n"
              "    return { range: range, az: (Math.atan2(y, x) / d + 360) % 360 };\n"
              "  }");
    WT_HAS(p, "  function autoRange(d, ranges, share, dflt) {\n"
              "    var ks = d.filter(num).sort(function (x, y) { return x - y; });\n"
              "    if (!ks.length) return dflt;\n"
              "    var far = ks[Math.max(0, Math.ceil(ks.length * share) - 1)];\n"
              "    for (var i = 0; i < ranges.length; i++) if (ranges[i] >= far * 1.08) return ranges[i];\n"
              "    return ranges[ranges.length - 1];\n"
              "  }");
    WT_HAS(p, "      function glow(az) {\n"
              "        if (sw < 0) return 1;\n"
              "        var ms = ((sw - az + 360) % 360) / 360 * SWEEP_MS;\n"
              "        return 0.35 + 0.65 * Math.exp(-ms / GLOW_MS);\n"
              "      }");
    WT_HAS(p, "    function frame(t) {\n"
              "      raf = 0;\n"
              "      if (!drawFn || !visible() || document.hidden) return;\n"
              "      if (t - frameAt >= FRAME_MS || still()) {\n"
              "        frameAt = t;\n"
              "        marks = [];\n"
              "        if (drawFn(t) === false) return;   // the static fallback: no sweep\n"
              "      }\n"
              "      if (!still()) raf = requestAnimationFrame(frame);\n"
              "    }\n"
              "");
    WT_HAS(p, "  function rangeKm(ctr, list) {\n"
              "    var s = $(\"aprs-range\"), v = s ? Number(s.value) : 0;\n"
              "    if (RANGES_KM.indexOf(v) >= 0) return v;\n"
              "    var d = list.filter(function (a) { return a.state !== \"gone\" && num(a.lat) && num(a.lon); })\n"
              "      .map(function (a) { return SlothPPI.geo(ctr.lat, ctr.lon, a.lat, a.lon).range / 1000; });\n"
              "    return SlothPPI.autoRange(d, RANGES_KM, AUTO_SHARE, RANGE_DFLT_KM);\n"
              "  }");
    WT_HAS(p, "  function frameDraw(t) {\n"
              "    var ctr = SlothPPI.centre(gnss);\n"
              "    if (!ctr) { plotFit(pj); return false; }\n"
              "    var r = ppi.scope(scopeSpec(pj, ctr), t);\n"
              "    if (r) setNote(\"centred on this sensor (\" + ctr.from + (num(ctr.age) ? \", \" + age(nowOf(gnss) - ctr.age, nowOf(gnss)) + \" old\" : \"\") +\n"
              "                   \"), range \" + r.range + \" km, rings \" + SlothPPI.fmt(r.range / 5) + \" km\" +\n"
              "                   (r.beyond ? \", \" + r.beyond + \" beyond range on the rim\" : \"\"));\n"
              "    return true;\n"
              "  }");
    WT_HAS(p, "  function load() {\n    var my = ++gen;\n    loadGnss();\n");
    WT_EQ(count_in(p, "    function scope(spec, t) {", "\n    canvas.addEventListener(", "ctr.lat"), 2);
    WT_EQ(count_in(p, "    function scope(spec, t) {", "\n    canvas.addEventListener(", "ctr.lon"), 2);
    WT_EQ(count_in(p, "  function scopeSpec(j, ctr) {\n    var ph = ", "\n  function plot(j) {", "ctr.l"), 0);
}

void run_aprs_tests(void) {
    WT_RUN(test_aprs_ingest_and_route);
    WT_RUN(test_aprs_ranges_and_refusals);
    WT_RUN(test_aprs_gone_and_age);
    WT_RUN(test_aprs_eviction_and_budget);
    WT_RUN(test_aprs_scope);
    WT_RUN(test_aprs_call_rule_is_sloths);
    WT_RUN(test_aprs_page);
    WT_RUN(test_aprs_region_and_silent);
    WT_RUN(test_aprs_page_region);
    WT_RUN(test_aprs_page_scope);
    WT_RUN(test_aprshist_no_db);
#ifdef WITH_SQLITE
    WT_RUN(test_aprshist_seen_and_station);
    WT_RUN(test_aprshist_budget);
    WT_RUN(test_aprshist_older_file);
    WT_RUN(test_aprshist_tracks);
    WT_RUN(test_aprshist_tracks_caps);
    WT_RUN(test_aprshist_tracks_older_file);
#endif
    web_aprs_destroy(&A);
}
