/* The KARMA and key-harvest evidence (web_lure.h): sloth's
 * `karma_suspect`, `harvest_station` and `harvest_chain` records in the
 * shape src/jsonl.c writes them (the lines below are the ones
 * tests/test_jsonl_lures.c asserts sloth writes), kept by slothweb,
 * answered on /api/lures, and the page's half pinned out of the served
 * page.
 *
 * Absence assertions, each seen red under the mutation named beside it
 * and restored. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_alertkb.h"
#include "web_assets.h"
#include "web_ingest.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_lure.h"
#include "web_routes.h"
#include "web_scope.h"
#include "web_secret.h"
#include "wtest.h"

static web_lure_t L;
static web_jrec_t R;
static int inited;
static char g_out[131072];

#define MONO0 900000LL
#define T     1800000000LL

static void feed_at(const char *line, long long ms) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_lure_record(&L, &R, ms);
}
static void feed(const char *line) { feed_at(line, MONO0); }

static void fresh(void) {
    if (inited) web_lure_destroy(&L);
    WT_EQ(web_lure_init(&L), 0);
    inited = 1;
}

static int route_at(const char *path, const char *query, long long now_ms, web_live_t *live) {
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.lure = &L;
    h.live = live;
    h.wall_s = T + 5;
    h.now_ms = now_ms;
    web_req_t *rq = calloc(1, sizeof(*rq));
    web_resp_t r;
    if (!rq) return -1;
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query);
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    int rc = web_route(rq, &h, 1, g_out, sizeof(g_out), &r);
    free(rq);
    if (rc != 0) return -1;
    g_out[r.out_len] = '\0';
    return r.status;
}
static int route(const char *query, long long now_ms) {
    return route_at("/api/lures", query, now_ms, NULL);
}
static int detail(const char *query, long long now_ms, web_live_t *live) {
    return route_at("/api/lures/bssid", query, now_ms, live);
}

static const char *body(void) {
    const char *sep = strstr(g_out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static const char KARMA[] =
    "{\"type\":\"karma_suspect\",\"ts\":1800000000,\"bssid\":\"02:11:22:33:44:55\","
    "\"state\":\"live\",\"ssids\":1,\"ie_postures\":1,\"ie_collapsed\":0,\"forged\":3,"
    "\"forge_stations\":2,\"pnl_best\":2,\"lure_chain\":1,\"score\":4,"
    "\"top_ssid\":\"Cafe <b>\\\"Free\\\"\\u0001\",\"tool\":\"airbase-ng\",\"last_seen\":1799999990}";
static const char STA[] =
    "{\"type\":\"harvest_station\",\"ts\":1800000000,\"sta\":\"02:aa:00:00:00:01\","
    "\"state\":\"live\",\"asked\":5,\"m1_bssids\":4,\"unanswered\":4,\"unanswered_kde\":3,"
    "\"answered\":0,\"dropped\":0,\"first_seen\":1799999000,\"last_seen\":1799999900}";
static const char CHAIN[] =
    "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00:09\","
    "\"state\":\"live\",\"victims\":2,\"disconnects\":6,\"dropped\":0,"
    "\"first_seen\":1799999500,\"last_seen\":1799999800}";
static const char HEALTH13[] = "{\"type\":\"sensor_health\",\"ts\":1800000000,\"jsonl_version\":\"1.3.0\"}";

/* Before anything: "not known", never "none". With a 1.2.0 stream:
 * "does not report". Seen red with web_lure_reported() answering 0
 * before any sensor_health. */
static void test_lure_reported(void) {
    fresh();
    WT_EQ(web_lure_reported(&L), -1);
    WT_EQ(web_lure_reported(NULL), -1);
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"reported\":null,\"jsonl_version\":null,\"karma\":[],\"stations\":[],\"chains\":[]");
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"1.2.0\"}");
    WT_EQ(web_lure_reported(&L), 0);
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"reported\":false,\"jsonl_version\":\"1.2.0\"");
    feed("{\"type\":\"sensor_health\",\"ts\":1}");            /* before 1.0.0 */
    WT_EQ(web_lure_reported(&L), 0);
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"one\"}");   /* ignored */
    WT_EQ(web_lure_reported(&L), 0);
    feed(HEALTH13);
    WT_EQ(web_lure_reported(&L), 1);
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"2.0.0\"}");
    WT_EQ(web_lure_reported(&L), 1);
    feed("{\"type\":\"sensor_health\",\"ts\":1,\"jsonl_version\":\"1.10.0\"}");
    WT_EQ(web_lure_reported(&L), 1);
}

/* The three rows on the route, every member, the SSID through the JSON
 * writer (markup inert, the control byte escaped). */
static void test_lure_route(void) {
    fresh();
    feed(HEALTH13);
    feed(KARMA);
    feed(STA);
    feed(CHAIN);
    WT_EQ(L.records, 3);
    WT_EQ(L.rejected, 0);
    WT_EQ(route("", MONO0 + 4000), 200);
    const char *b = body();
    WT_HAS(b, "{\"now\":1800000005,\"reported\":true,\"jsonl_version\":\"1.3.0\",\"karma\":["
              "{\"bssid\":\"02:11:22:33:44:55\",\"ts\":1800000000,\"age_s\":4,\"ssids\":1,"
              "\"ie_postures\":1,\"ie_collapsed\":false,\"forged\":3,\"forge_stations\":2,"
              "\"pnl_best\":2,\"lure_chain\":true,\"score\":4,\"top_ssid\":\"Cafe ");
    WT_LACKS(b, "<b>");
    WT_LACKS(b, "\x01");
    WT_HAS(b, "\"tool\":\"airbase-ng\",\"last_seen\":1799999990}]");
    WT_HAS(b, "\"stations\":[{\"sta\":\"02:aa:00:00:00:01\",\"ts\":1800000000,\"age_s\":4,"
              "\"asked\":5,\"m1_bssids\":4,\"unanswered\":4,\"unanswered_kde\":3,\"answered\":0,"
              "\"dropped\":0,\"first_seen\":1799999000,\"last_seen\":1799999900}]");
    WT_HAS(b, "\"chains\":[{\"bssid\":\"0a:bb:00:00:00:09\",\"ts\":1800000000,\"age_s\":4,"
              "\"victims\":2,\"disconnects\":6,\"dropped\":0,\"first_seen\":1799999500,"
              "\"last_seen\":1799999800}]");
    WT_HAS(b, "\"stale\":0,\"records\":3,\"rejected\":0,\"overflow\":0}");
    /* No parameters. */
    WT_EQ(route("limit=3", MONO0), 400);
    WT_HAS(body(), "unknown_parameter");
    /* No tables bound. */
    size_t len = 0;
    int st = 0;
    WT_EQ(web_lure_route(NULL, "", T, MONO0, 0, g_out, sizeof(g_out), &len, &st), 0);
    WT_EQ(st, 503);
}

/* A newer record replaces its key's row; gone removes it at once. Seen
 * red (the row still listed) with the gone branch returning before the
 * memset. */
static void test_lure_replace_and_gone(void) {
    fresh();
    feed(HEALTH13);
    feed(KARMA);
    feed("{\"type\":\"karma_suspect\",\"ts\":1800000030,\"bssid\":\"02:11:22:33:44:55\","
         "\"state\":\"live\",\"ssids\":1,\"ie_postures\":1,\"ie_collapsed\":0,\"forged\":5,"
         "\"forge_stations\":3,\"pnl_best\":2,\"lure_chain\":0,\"score\":4,"
         "\"top_ssid\":\"Cafe\",\"tool\":\"\",\"last_seen\":1800000020}");
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"forged\":5,\"forge_stations\":3");
    WT_LACKS(body(), "\"forged\":3");
    feed("{\"type\":\"karma_suspect\",\"ts\":1800000060,\"bssid\":\"02:11:22:33:44:55\",\"state\":\"gone\"}");
    WT_EQ(L.gone, 1);
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"karma\":[]");
    /* A gone for a key never held changes nothing. */
    feed("{\"type\":\"harvest_chain\",\"ts\":1800000060,\"bssid\":\"0a:bb:00:00:00:09\",\"state\":\"gone\"}");
    WT_EQ(L.gone, 1);
    WT_EQ(L.rejected, 0);
}

/* Malformed records are refused whole: a missing or out-of-range
 * member, a bad MAC, a bad state, an SSID past 32 code points. Seen red
 * (the long SSID kept) with jtext()'s code-point bound removed. */
static void test_lure_refuses(void) {
    fresh();
    static const char *const BAD[] = {
        "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00:09\","
        "\"state\":\"live\",\"victims\":2,\"dropped\":0,\"first_seen\":1,\"last_seen\":1}",
        "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00:09\","
        "\"state\":\"live\",\"victims\":-1,\"disconnects\":6,\"dropped\":0,\"first_seen\":1,\"last_seen\":1}",
        "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00\","
        "\"state\":\"live\",\"victims\":2,\"disconnects\":6,\"dropped\":0,\"first_seen\":1,\"last_seen\":1}",
        "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00:09\","
        "\"state\":\"maybe\",\"victims\":2,\"disconnects\":6,\"dropped\":0,\"first_seen\":1,\"last_seen\":1}",
        "{\"type\":\"harvest_station\",\"ts\":1800000000,\"bssid\":\"02:aa:00:00:00:01\","
        "\"state\":\"live\",\"asked\":5,\"m1_bssids\":4,\"unanswered\":4,\"unanswered_kde\":3,"
        "\"answered\":0,\"dropped\":0,\"first_seen\":1,\"last_seen\":1}",
        "{\"type\":\"karma_suspect\",\"ts\":1800000000,\"bssid\":\"02:11:22:33:44:55\","
        "\"state\":\"live\",\"ssids\":1,\"ie_postures\":1,\"ie_collapsed\":2,\"forged\":3,"
        "\"forge_stations\":2,\"pnl_best\":2,\"lure_chain\":1,\"score\":4,"
        "\"top_ssid\":\"x\",\"tool\":\"\",\"last_seen\":1}",
        "{\"type\":\"karma_suspect\",\"ts\":1800000000,\"bssid\":\"02:11:22:33:44:55\","
        "\"state\":\"live\",\"ssids\":1,\"ie_postures\":1,\"ie_collapsed\":0,\"forged\":3,"
        "\"forge_stations\":2,\"pnl_best\":2,\"lure_chain\":1,\"score\":4,"
        "\"top_ssid\":\"0123456789012345678901234567890123\",\"tool\":\"\",\"last_seen\":1}",
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) feed(BAD[i]);
    WT_EQ(L.rejected, sizeof(BAD) / sizeof(BAD[0]));
    WT_EQ(route("", MONO0), 200);
    WT_HAS(body(), "\"karma\":[],\"stations\":[],\"chains\":[]");
    /* 32 code points of three octets each is an SSID sloth can write. */
    char ok[1024];
    char ss[200] = "";
    for (int i = 0; i < 32; i++) strcat(ss, "\\ufffd");
    snprintf(ok, sizeof(ok),
             "{\"type\":\"karma_suspect\",\"ts\":1800000000,\"bssid\":\"02:11:22:33:44:55\","
             "\"state\":\"live\",\"ssids\":1,\"ie_postures\":1,\"ie_collapsed\":0,\"forged\":3,"
             "\"forge_stations\":2,\"pnl_best\":2,\"lure_chain\":1,\"score\":4,"
             "\"top_ssid\":\"%s\",\"tool\":\"\",\"last_seen\":1}", ss);
    feed(ok);
    WT_EQ(L.rejected, sizeof(BAD) / sizeof(BAD[0]));
}

/* A row not refreshed for WEB_LURE_STALE_MS is left out and counted;
 * a full table refuses a new key, unless a stale row gives its slot. */
static void test_lure_stale_and_bounds(void) {
    fresh();
    char line[512];
    for (int i = 0; i < WEB_LURE_CHAIN; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:00:%02x\","
                 "\"state\":\"live\",\"victims\":1,\"disconnects\":2,\"dropped\":0,"
                 "\"first_seen\":1,\"last_seen\":1}", i);
        feed_at(line, MONO0 + i);
    }
    feed_at("{\"type\":\"harvest_chain\",\"ts\":1800000000,\"bssid\":\"0a:bb:00:00:01:00\","
            "\"state\":\"live\",\"victims\":1,\"disconnects\":2,\"dropped\":0,"
            "\"first_seen\":1,\"last_seen\":1}", MONO0 + 100);
    WT_EQ(L.overflow, 1);
    /* Past the stale bound: every row left out, and a new key takes a
     * stale slot. */
    long long later = MONO0 + WEB_LURE_STALE_MS + 1000;
    WT_EQ(route("", later), 200);
    WT_HAS(body(), "\"chains\":[],\"stale\":16");
    feed_at("{\"type\":\"harvest_chain\",\"ts\":1800000700,\"bssid\":\"0a:bb:00:00:01:00\","
            "\"state\":\"live\",\"victims\":1,\"disconnects\":2,\"dropped\":0,"
            "\"first_seen\":1,\"last_seen\":1}", later);
    WT_EQ(L.overflow, 1);
    WT_EQ(route("", later), 200);
    WT_HAS(body(), "\"bssid\":\"0a:bb:00:00:01:00\"");
    WT_HAS(body(), "\"stale\":15");
}

/* The worst-case answer fits: every table full, every string at its
 * bound and every octet one the writer expands. */
static void test_lure_worst_case_fits(void) {
    fresh();
    feed(HEALTH13);
    char ssid[256] = "", tool[400] = "", line[2048];
    for (int i = 0; i < 32; i++) strcat(ssid, "\\u0001");
    for (int i = 0; i < WEB_LURE_TOOL_MAX; i++) strcat(tool, "<");
    for (int i = 0; i < WEB_LURE_KARMA; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"karma_suspect\",\"ts\":1800000000,\"bssid\":\"02:11:22:33:%02x:55\","
                 "\"state\":\"live\",\"ssids\":1000000,\"ie_postures\":1000000,\"ie_collapsed\":1,"
                 "\"forged\":1000000,\"forge_stations\":1000000,\"pnl_best\":1000000,\"lure_chain\":1,"
                 "\"score\":1000000,\"top_ssid\":\"%s\",\"tool\":\"%s\",\"last_seen\":1099511627776}",
                 i, ssid, tool);
        feed(line);
    }
    for (int i = 0; i < WEB_LURE_STA; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"harvest_station\",\"ts\":1099511627776,\"sta\":\"02:aa:00:00:00:%02x\","
                 "\"state\":\"live\",\"asked\":1000000,\"m1_bssids\":1000000,\"unanswered\":1000000,"
                 "\"unanswered_kde\":1000000,\"answered\":1000000,\"dropped\":1000000,"
                 "\"first_seen\":1099511627776,\"last_seen\":1099511627776}", i);
        feed(line);
    }
    for (int i = 0; i < WEB_LURE_CHAIN; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"harvest_chain\",\"ts\":1099511627776,\"bssid\":\"0a:bb:00:00:00:%02x\","
                 "\"state\":\"live\",\"victims\":1000000,\"disconnects\":1000000,\"dropped\":1000000,"
                 "\"first_seen\":1099511627776,\"last_seen\":1099511627776}", i);
        feed(line);
    }
    WT_EQ(L.rejected, 0);
    WT_EQ(L.overflow, 0);
    /* The space an answer has behind its header (web_routes.h). */
    static char out[65536 - WEB_LIVE_HDR_RESERVE];
    size_t len = 0;
    int st = 0;
    WT_EQ(web_lure_route(&L, "", T, MONO0, 0, out, sizeof(out), &len, &st), 0);
    WT_EQ(st, 200);
    WT_ASSERT(len > 40000);
}

/* Local: the query is still checked, then the one out_of_scope answer. */
static void test_lure_scope(void) {
    fresh();
    feed(KARMA);
    WT_EQ(route("scope=local", MONO0), 200);
    WT_HAS(body(), "\"out_of_scope\":true");
    WT_LACKS(body(), "02:11:22");
    WT_EQ(route("scope=local&x=1", MONO0), 400);
    WT_EQ(route("scope=monitor", MONO0), 200);
    WT_HAS(body(), "02:11:22:33:44:55");
}

/* The page: the module, its containers, its hook, and its words. */
static void test_lure_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "window.SlothLure = {");
    WT_HAS(p, "id=\"w-lure\"");
    WT_HAS(p, "id=\"w-lure-karma\"");
    WT_HAS(p, "id=\"w-lure-sta\"");
    WT_HAS(p, "id=\"w-lure-chain\"");
    WT_HAS(p, "if (v === \"wifi\" && window.SlothLure) SlothLure.show();");
    WT_HAS(p, "if (window.SlothLure) SlothLure.init({ getJSON: getJSON, errText: errText, shortStamp: shortStamp });");
    WT_HAS(p,
        "  function stateText(j) {\n"
        "    if (!j) return \"not known\";\n"
        "    if (j.out_of_scope) return String(j.reason || \"\");\n"
        "    if (j.reported === false)\n"
        "      return \"not reported: this sloth's stream (JSONL \" + (j.jsonl_version || \"before 1.0.0\") +\n"
        "             \") does not carry KARMA or key-harvest evidence; it needs 1.3.0\";\n"
        "    if (j.reported === null)\n"
        "      return \"not known: sloth has not reported its stream version on this connection yet\";\n");
    WT_HAS(p, "    var t = k + s + c === 0 ? \"none: sloth's KARMA and key-harvest tables are empty\"\n");
    /* textContent only: the module writes no markup. */
    const char *m = strstr(p, "// slothweb: the KARMA and key-harvest card");
    const char *e = m ? strstr(m, "window.SlothLure = {") : NULL;
    WT_ASSERT(m && e);
    if (m && e) {
        size_t n = (size_t)(e - m);
        char *mod = malloc(n + 1);
        WT_ASSERT(mod != NULL);
        if (mod) {
            memcpy(mod, m, n);
            mod[n] = '\0';
            WT_LACKS(mod, "innerHTML");
            WT_LACKS(mod, "insertAdjacentHTML");
            WT_LACKS(mod, "setAttribute");
            WT_LACKS(mod, "document.write");
            free(mod);
        }
    }
}

/* ── one BSSID's KARMA detail (#187, /api/lures/bssid) ───────────── */

#define B55 "02:11:22:33:44:55"

static int w_count(const char *s, const char *w) {
    int n = 0;
    for (const char *q = strstr(s, w); q; q = strstr(q + 1, w)) n++;
    return n;
}

static void karma_at(long long ts, int forged, int score, const char *ssid, long long ms) {
    char line[1024];
    snprintf(line, sizeof(line),
             "{\"type\":\"karma_suspect\",\"ts\":%lld,\"bssid\":\"" B55 "\",\"state\":\"live\","
             "\"ssids\":2,\"ie_postures\":1,\"ie_collapsed\":1,\"forged\":%d,\"forge_stations\":2,"
             "\"pnl_best\":1,\"lure_chain\":0,\"score\":%d,\"top_ssid\":\"%s\",\"tool\":\"\","
             "\"last_seen\":%lld}", ts, forged, score, ssid, ts - 5);
    feed_at(line, ms);
}

/* Nothing held is "none", not an error; then the row over time: a
 * heartbeat that repeats the newest change stretches it, a moved count
 * is a new change, a gone keeps the history and says when, a row back
 * after it starts a new change, and the ring keeps the newest
 * WEB_LURE_HIST. Seen red (two entries for the heartbeat) with
 * hent_same() answering 0, and (the history gone) with the gone branch
 * clearing the detail. */
static void test_lure_detail_history(void) {
    fresh();
    feed(HEALTH13);
    WT_EQ(detail("bssid=" B55, MONO0, NULL), 200);
    WT_HAS(body(), "{\"bssid\":\"" B55 "\",\"now\":1800000005,\"reported\":true,"
                   "\"jsonl_version\":\"1.3.0\",\"state\":\"none\",\"current\":null,\"gone_ts\":null,"
                   "\"history\":[],\"history_changes\":0,\"hw\":null,\"probe_lat\":null,"
                   "\"alerts\":[],\"alerts_more\":false,\"alerts_held\":false}");
    karma_at(T, 3, 4, "Cafe", MONO0);
    karma_at(T + 300, 3, 4, "Cafe", MONO0 + 300000);          /* the heartbeat */
    karma_at(T + 330, 5, 4, "Cafe", MONO0 + 330000);
    WT_EQ(detail("bssid=" B55, MONO0 + 330000, NULL), 200);
    const char *b = body();
    WT_HAS(b, "\"state\":\"live\",\"current\":{\"bssid\":\"" B55 "\",\"ts\":1800000330,");
    WT_HAS(b, "\"history\":[{\"ts\":1800000000,\"ts_last\":1800000300,\"ssids\":2,\"ie_postures\":1,"
              "\"ie_collapsed\":true,\"forged\":3,\"forge_stations\":2,\"pnl_best\":1,"
              "\"lure_chain\":false,\"score\":4,\"top_ssid\":\"Cafe\",\"tool\":\"\","
              "\"last_seen\":1800000295},{\"ts\":1800000330,\"ts_last\":1800000330,");
    WT_HAS(b, "\"history_changes\":2,");
    /* Gone: no current row, the history kept and the time said. */
    feed("{\"type\":\"karma_suspect\",\"ts\":1800000400,\"bssid\":\"" B55 "\",\"state\":\"gone\"}");
    WT_EQ(detail("bssid=" B55, MONO0 + 400000, NULL), 200);
    WT_HAS(body(), "\"state\":\"gone\",\"current\":null,\"gone_ts\":1800000400,\"history\":[{");
    WT_HAS(body(), "\"history_changes\":2,");
    /* Back with the same counts: a new change, the gone time cleared. */
    karma_at(T + 500, 5, 4, "Cafe", MONO0 + 500000);
    WT_EQ(detail("bssid=" B55, MONO0 + 500000, NULL), 200);
    WT_HAS(body(), "\"state\":\"live\"");
    WT_HAS(body(), "\"gone_ts\":null");
    WT_HAS(body(), "\"history_changes\":3,");
    /* The ring: the newest WEB_LURE_HIST, oldest first. */
    for (int i = 0; i < 20; i++) karma_at(T + 600 + i, 5, 10 + i, "Cafe", MONO0 + 600000);
    WT_EQ(detail("bssid=" B55, MONO0 + 600000, NULL), 200);
    WT_HAS(body(), "\"history_changes\":23,");
    WT_EQ(w_count(body(), "\"ts_last\":"), WEB_LURE_HIST);
    WT_LACKS(body(), "\"ts\":1800000000,");
    WT_HAS(body(), "\"history\":[{\"ts\":1800000604,");
    /* Stale: a row not refreshed is not "live", and not current. */
    WT_EQ(detail("bssid=" B55, MONO0 + 600000 + WEB_LURE_STALE_MS + 1000, NULL), 200);
    WT_HAS(body(), "\"state\":\"stale\",\"current\":null");
    /* The BSSID percent-encoded and in capitals is the same one. */
    WT_EQ(detail("bssid=02%3A11%3A22%3A33%3A44%3A55", MONO0 + 600000, NULL), 200);
    WT_HAS(body(), "\"state\":\"live\"");
    WT_EQ(detail("bssid=0A:BB:00:00:00:09", MONO0, NULL), 200);
    WT_HAS(body(), "{\"bssid\":\"0a:bb:00:00:00:09\",");
}

/* The hardware verdict from the newest KARMA_AP record (its key at the
 * field, never a substring: karmaforge's is another BSSID's verdict
 * nowhere), a verdict that is not sloth's word refused whole, and a
 * record without one standing as "none". Seen red (the karmaforge
 * verdict on :66) with hw_record() reading the MAC after any key's
 * first colon, and (the forged verdicts kept) with hw_word_ok()
 * answering 1. */
static void test_lure_detail_hw(void) {
    fresh();
    feed("{\"type\":\"alert\",\"ts\":1800000000,\"title\":\"KARMA_AP\",\"key\":\"karma:" B55 "\","
         "\"sev\":1,\"ty\":20,\"count\":1,\"hw_verdict\":\"suspected-pineapple-mk7\","
         "\"hw_signals\":\"tool+oui\"}");
    WT_EQ(detail("bssid=" B55, MONO0, NULL), 200);
    WT_HAS(body(), "\"hw\":{\"verdict\":\"suspected-pineapple-mk7\",\"signals\":\"tool+oui\","
                   "\"ts\":1800000000}");
    static const char *const BAD[] = {
        "{\"type\":\"alert.update\",\"ts\":1800000001,\"key\":\"karma:" B55 "\",\"hw_verdict\":\"identified-pineapple\"}",
        "{\"type\":\"alert.update\",\"ts\":1800000001,\"key\":\"karma:" B55 "\",\"hw_verdict\":\"suspected-<b>x</b>\"}",
        "{\"type\":\"alert.update\",\"ts\":1800000001,\"key\":\"karma:" B55 "\",\"hw_verdict\":\"suspected-\"}",
        "{\"type\":\"alert.update\",\"ts\":1800000001,\"key\":\"karma:" B55 "\",\"hw_verdict\":1}",
        "{\"type\":\"alert.update\",\"ts\":1800000001,\"key\":\"karma:" B55 "\",\"hw_verdict\":\"suspected-x\",\"hw_signals\":\"tool; DROP\"}",
        "{\"type\":\"alert.update\",\"ts\":1800000001,\"key\":\"karma:" B55 "\",\"hw_signals\":\"tool\"}",
        "{\"type\":\"alert.update\",\"ts\":1800000001,\"key\":\"karma:" B55 "\",\"hw_verdict\":"
        "\"suspected-0123456789012345678901234567890123456789\"}",
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) feed(BAD[i]);
    WT_EQ(L.hw_rejected, sizeof(BAD) / sizeof(BAD[0]));
    WT_EQ(detail("bssid=" B55, MONO0, NULL), 200);
    WT_HAS(body(), "\"verdict\":\"suspected-pineapple-mk7\"");
    WT_LACKS(body(), "<b>");
    /* A newer record without one: no verdict now. */
    feed("{\"type\":\"alert.update\",\"ts\":1800000060,\"key\":\"karma:" B55 "\",\"sev\":1,\"ty\":20}");
    WT_EQ(detail("bssid=" B55, MONO0, NULL), 200);
    WT_HAS(body(), "\"hw\":{\"verdict\":null,\"signals\":null,\"ts\":1800000060}");
    /* KARMA_PROBE_FORGE's key, and a key that only begins with a MAC. */
    feed("{\"type\":\"alert\",\"ts\":1800000000,\"key\":\"karmaforge:02:11:22:33:44:66\","
         "\"hw_verdict\":\"corroborated-esp32-marauder\",\"hw_signals\":\"tool+stack\"}");
    feed("{\"type\":\"alert\",\"ts\":1800000000,\"key\":\"karma:02:11:22:33:44:667\","
         "\"hw_verdict\":\"corroborated-esp32-marauder\",\"hw_signals\":\"tool+stack\"}");
    WT_EQ(detail("bssid=02:11:22:33:44:66", MONO0, NULL), 200);
    WT_HAS(body(), "\"hw\":null");
    WT_HAS(body(), "\"state\":\"none\"");
}

/* probe_lat (JSONL 1.6.0) on a beacon record: the decoder keeps the
 * object's scalars under its allow-list, the detail shows them, a
 * malformed one is refused and drops what was held, and a beacon
 * without it drops it too. The kept member names are none of the words
 * web_secret.h withholds. Seen red (the old figures still shown) with
 * lat_record()'s absent branch returning before the memset. */
static void test_lure_detail_probe_lat(void) {
    fresh();
    static const char BEACON[] =
        "{\"type\":\"beacon\",\"ts\":1800000000,\"bssid\":\"" B55 "\",\"ssid\":\"Cafe\","
        "\"channel\":6,\"probe_lat\":{\"src\":\"tsft\",\"n_dir\":5,\"med_dir_us\":1800,"
        "\"p10_dir_us\":900,\"p90_dir_us\":4000,\"min_dir_us\":700,\"n_wild\":2,\"med_wild_us\":2500}}";
    WT_EQ(web_jl_parse(BEACON, strlen(BEACON), &R), WEB_JL_OK);
    WT_EQ(web_jl_int(&R, "probe_lat.n_dir", -1), 5);
    WT_ASSERT(web_jl_str(&R, "probe_lat.src") && !strcmp(web_jl_str(&R, "probe_lat.src"), "tsft"));
    static const char *const MEMBERS[] = { "src", "n_dir", "med_dir_us", "p10_dir_us", "p90_dir_us",
                                           "min_dir_us", "n_wild", "med_wild_us" };
    for (size_t i = 0; i < sizeof(MEMBERS) / sizeof(MEMBERS[0]); i++) {
        WT_EQ(web_sdb_is_secret("beacon", MEMBERS[i], "TEXT"), 0);
        char k[48];
        snprintf(k, sizeof(k), "probe_lat.%s", MEMBERS[i]);
        WT_EQ(web_sdb_is_secret("beacon", k, "TEXT"), 0);
    }
    feed_at(BEACON, MONO0);
    WT_EQ(detail("bssid=" B55, MONO0 + 2000, NULL), 200);
    WT_HAS(body(), "\"probe_lat\":{\"src\":\"tsft\",\"n_dir\":5,\"med_dir_us\":1800,\"p10_dir_us\":900,"
                   "\"p90_dir_us\":4000,\"min_dir_us\":700,\"n_wild\":2,\"med_wild_us\":2500,"
                   "\"ts\":1800000000,\"age_s\":2}");
    /* A beacon without it: not measured on this run. */
    feed("{\"type\":\"beacon\",\"ts\":1800000010,\"bssid\":\"" B55 "\",\"ssid\":\"Cafe\"}");
    WT_EQ(detail("bssid=" B55, MONO0, NULL), 200);
    WT_HAS(body(), "\"probe_lat\":null");
    /* Malformed: refused, and what was held dropped. */
    static const char *const BAD[] = {
        "{\"type\":\"beacon\",\"ts\":1,\"bssid\":\"" B55 "\",\"probe_lat\":{\"src\":\"wall\",\"n_dir\":1,"
        "\"med_dir_us\":1,\"p10_dir_us\":1,\"p90_dir_us\":1,\"min_dir_us\":1,\"n_wild\":0,\"med_wild_us\":0}}",
        "{\"type\":\"beacon\",\"ts\":1,\"bssid\":\"" B55 "\",\"probe_lat\":{\"src\":\"pcap\",\"n_dir\":1,"
        "\"med_dir_us\":-1,\"p10_dir_us\":1,\"p90_dir_us\":1,\"min_dir_us\":1,\"n_wild\":0,\"med_wild_us\":0}}",
        "{\"type\":\"beacon\",\"ts\":1,\"bssid\":\"" B55 "\",\"probe_lat\":{\"src\":\"pcap\",\"n_dir\":1,"
        "\"med_dir_us\":10000001,\"p10_dir_us\":1,\"p90_dir_us\":1,\"min_dir_us\":1,\"n_wild\":0,\"med_wild_us\":0}}",
        "{\"type\":\"beacon\",\"ts\":1,\"bssid\":\"" B55 "\",\"probe_lat\":{\"src\":\"pcap\",\"n_dir\":1}}",
        "{\"type\":\"beacon\",\"ts\":1,\"bssid\":\"" B55 "\",\"probe_lat\":[1,2]}",
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        feed_at(BEACON, MONO0);
        feed(BAD[i]);
        WT_EQ(detail("bssid=" B55, MONO0, NULL), 200);
        WT_HAS(body(), "\"probe_lat\":null");
    }
    WT_EQ(L.lat_rejected, sizeof(BAD) / sizeof(BAD[0]));
    /* A top-level member cannot pose as the object's. */
    static const char SHADOW[] =
        "{\"type\":\"beacon\",\"bssid\":\"" B55 "\",\"probe_lat.n_dir\":9,\"probe_lat\":{\"n_dir\":5}}";
    WT_EQ(web_jl_parse(SHADOW, strlen(SHADOW), &R), WEB_JL_EDUP);
    /* The table's bound: the least recently written BSSID gives its slot. */
    char line[512];
    for (int i = 0; i <= WEB_LURE_LAT; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"beacon\",\"ts\":1,\"bssid\":\"02:00:00:00:%02x:%02x\",\"probe_lat\":{"
                 "\"src\":\"pcap\",\"n_dir\":1,\"med_dir_us\":1,\"p10_dir_us\":1,\"p90_dir_us\":1,"
                 "\"min_dir_us\":1,\"n_wild\":0,\"med_wild_us\":0}}", i >> 8, i & 255);
        feed_at(line, MONO0 + i);
    }
    WT_EQ(L.lat_evicted, 1);
    WT_EQ(detail("bssid=02:00:00:00:00:00", MONO0, NULL), 200);
    WT_HAS(body(), "\"probe_lat\":null");
    WT_EQ(detail("bssid=02:00:00:00:01:00", MONO0, NULL), 200);
    WT_HAS(body(), "\"probe_lat\":{\"src\":\"pcap\"");
}

/* The decoder's text bound with the longer prefix: a line that fits
 * WEB_JL_MAX_LINE, whose "probe_lat." composites would outgrow the
 * record's text, is refused whole as WEB_JL_ELONG; the same members
 * under "loc." fit. Seen red (the line accepted, its composites written
 * past the record's text) with the bound check taken out of
 * flatten_obj(). */
static void test_lure_probe_lat_text_bound(void) {
    size_t cap = WEB_JL_MAX_LINE + 1;
    char *line = malloc(cap);
    web_jrec_t *r = malloc(sizeof(*r));
    WT_ASSERT(line && r);
    if (!line || !r) { free(line); free(r); return; }
    for (int pass = 0; pass < 2; pass++) {
        size_t n = (size_t)snprintf(line, cap, "{\"type\":\"beacon\",\"pad\":\"");
        memset(line + n, 'x', 13000);
        n += 13000;
        n += (size_t)snprintf(line + n, cap - n, "\",\"%s\":{", pass ? "loc" : "probe_lat");
        for (int i = 0; i < 300; i++)
            n += (size_t)snprintf(line + n, cap - n, "%s\"m%03d\":1", i ? "," : "", i);
        n += (size_t)snprintf(line + n, cap - n, "}}");
        WT_ASSERT(n <= WEB_JL_MAX_LINE);
        WT_EQ(web_jl_parse(line, n, r), pass ? WEB_JL_OK : WEB_JL_ELONG);
    }
    free(line);
    free(r);
}

/* The alerts: web_live's incidents of KARMA_AP and KARMA_PROBE_FORGE
 * whose key names the BSSID at its field, by the alert page's id, the
 * whole path through the ingest (which also hands the lure its
 * verdict). Another BSSID's, another type's with the BSSID in its key,
 * and a key that merely begins with it are not listed. Seen red (the
 * :550 incident listed) with alerts_json() comparing by strncmp() on
 * the key's length. */
static void test_lure_detail_alerts(void) {
    fresh();
    web_live_t *lv = calloc(1, sizeof(*lv));
    web_feed_t *f = calloc(1, sizeof(*f));
    WT_ASSERT(lv && f);
    if (!lv || !f) { free(lv); free(f); return; }
    web_live_init(lv, "unix:/t/s.sock");
    web_live_sock_connected(lv, 0);
    web_feed_reset(f);
    f->lure = &L;
    int ka = web_akb_find("KARMA_AP"), kf = web_akb_find("KARMA_PROBE_FORGE");
    int et = web_akb_find("EVIL_TWIN");
    WT_ASSERT(ka >= 0 && kf >= 0 && et >= 0);
    char b[4096];
    int n = snprintf(b, sizeof(b),
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"a1a1\",\"key\":\"karma:" B55 "\","
        "\"title\":\"KARMA_AP\",\"detail\":\"x\",\"sev\":1,\"ty\":%d,\"observations\":4,\"count\":5,"
        "\"first_detected\":%lld,\"confidence\":35,\"hw_verdict\":\"suspected-pineapple-mk7\","
        "\"hw_signals\":\"pair\"}\n"
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"b2b2\",\"key\":\"karmaforge:" B55 "\","
        "\"title\":\"KARMA_PROBE_FORGE\",\"detail\":\"x\",\"sev\":2,\"ty\":%d,\"observations\":2,"
        "\"count\":2,\"first_detected\":%lld}\n"
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"c3c3\",\"key\":\"karma:" B55 "0\","
        "\"title\":\"KARMA_AP\",\"detail\":\"x\",\"sev\":1,\"ty\":%d,\"count\":1}\n"
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"d4d4\",\"key\":\"twin:" B55 ":02:00:00:00:00:01\","
        "\"title\":\"EVIL_TWIN\",\"detail\":\"x\",\"sev\":2,\"ty\":%d,\"count\":1}\n"
        "{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"e5e5\",\"key\":\"karma:02:11:22:33:44:56\","
        "\"title\":\"KARMA_AP\",\"detail\":\"x\",\"sev\":1,\"ty\":%d,\"count\":1}\n",
        T - 100, ka, T - 200, T - 50, kf, T - 60, T - 40, ka, T - 30, et, T - 20, ka);
    WT_ASSERT(n > 0 && (size_t)n < sizeof(b));
    web_feed_bytes(f, lv, b, (size_t)n, 1000);
    char ida[48] = "", idb[48] = "", idc[48] = "";
    for (int i = 0; i < lv->ninc; i++) {
        if (!strcmp(lv->inc[i].id, "a1a1")) snprintf(ida, sizeof(ida), "\"id\":\"s%s\"", lv->inc[i].hid);
        if (!strcmp(lv->inc[i].id, "b2b2")) snprintf(idb, sizeof(idb), "\"id\":\"s%s\"", lv->inc[i].hid);
        if (!strcmp(lv->inc[i].id, "c3c3")) snprintf(idc, sizeof(idc), "\"id\":\"s%s\"", lv->inc[i].hid);
    }
    WT_ASSERT(ida[0] && idb[0] && idc[0]);
    WT_EQ(detail("bssid=" B55, MONO0, lv), 200);
    const char *bd = body();
    WT_HAS(bd, ida);
    WT_HAS(bd, idb);
    WT_LACKS(bd, idc);
    WT_EQ(w_count(bd, "\"type_name\":"), 2);
    WT_HAS(bd, "\"type_name\":\"KARMA_PROBE_FORGE\",\"sev\":2,\"confidence\":null,\"state\":\"open\"");
    WT_HAS(bd, "\"type_name\":\"KARMA_AP\",\"sev\":1,\"confidence\":35,\"state\":\"open\"");
    WT_HAS(bd, "\"observations\":4");
    WT_HAS(bd, "\"alerts_more\":false,\"alerts_held\":true}");
    /* The verdict arrived through the ingest too. */
    WT_HAS(bd, "\"hw\":{\"verdict\":\"suspected-pineapple-mk7\",\"signals\":\"pair\"");
    /* Local: checked, then out of scope, no row. */
    WT_EQ(detail("scope=local&bssid=" B55, MONO0, lv), 200);
    WT_HAS(body(), "\"out_of_scope\":true");
    WT_LACKS(body(), "\"alerts\"");
    web_live_destroy(lv);
    free(lv);
    free(f);
}

/* Parameters: bssid required, a canonical MAC, the only one; a refusal
 * is slothweb's word and never the value. No tables: 503. */
static void test_lure_detail_params(void) {
    fresh();
    WT_EQ(detail("", MONO0, NULL), 400);
    WT_HAS(body(), "missing_bssid");
    static const char *const BAD[] = {
        "bssid=02:11:22:33:44", "bssid=02:11:22:33:44:5g", "bssid=02-11-22-33-44-55",
        "bssid=02:11:22:33:44:55:66", "bssid=%3Cscript%3E",
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        WT_EQ(detail(BAD[i], MONO0, NULL), 400);
        WT_HAS(body(), "bad_bssid");
        WT_LACKS(body(), "script");
    }
    WT_EQ(detail("bssid=" B55 "&limit=1", MONO0, NULL), 400);
    WT_HAS(body(), "unknown_parameter");
    WT_EQ(detail("bssid=" B55 "&bssid=" B55, MONO0, NULL), 400);
    WT_EQ(detail("scope=local&bssid=nope", MONO0, NULL), 400);
    size_t len = 0;
    int st = 0;
    WT_EQ(web_lure_bssid_route(NULL, NULL, "bssid=" B55, T, MONO0, 0, g_out, sizeof(g_out), &len, &st), 0);
    WT_EQ(st, 503);
}

/* The worst-case answer fits behind its header: every change kept with
 * every string at its bound in octets the writer expands, the verdict,
 * the latency and the current row. */
static void test_lure_detail_worst_case_fits(void) {
    fresh();
    feed(HEALTH13);
    char ssid[256] = "", tool[400] = "", line[2048];
    for (int i = 0; i < 32; i++) strcat(ssid, "\\u0001");
    for (int i = 0; i < WEB_LURE_TOOL_MAX; i++) strcat(tool, "<");
    for (int i = 0; i < WEB_LURE_HIST; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"karma_suspect\",\"ts\":1099511627776,\"bssid\":\"" B55 "\","
                 "\"state\":\"live\",\"ssids\":1000000,\"ie_postures\":1000000,\"ie_collapsed\":1,"
                 "\"forged\":1000000,\"forge_stations\":1000000,\"pnl_best\":%d,\"lure_chain\":1,"
                 "\"score\":1000000,\"top_ssid\":\"%s\",\"tool\":\"%s\",\"last_seen\":1099511627776}",
                 999980 + i, ssid, tool);
        feed(line);
    }
    feed("{\"type\":\"alert\",\"ts\":1099511627776,\"key\":\"karma:" B55 "\",\"hw_verdict\":"
         "\"corroborated-0123456789012345678901234567890123\",\"hw_signals\":"
         "\"tool+stack+pair+oui+tool+stack+pair+oui+tool+st\"}");
    feed("{\"type\":\"beacon\",\"ts\":1099511627776,\"bssid\":\"" B55 "\",\"probe_lat\":{\"src\":\"tsft\","
         "\"n_dir\":1000000,\"med_dir_us\":10000000,\"p10_dir_us\":10000000,\"p90_dir_us\":10000000,"
         "\"min_dir_us\":10000000,\"n_wild\":1000000,\"med_wild_us\":10000000}}");
    WT_EQ(L.rejected + L.hw_rejected + L.lat_rejected, 0);
    static char out[65536 - WEB_LIVE_HDR_RESERVE];
    size_t len = 0;
    int st = 0;
    WT_EQ(web_lure_bssid_route(&L, NULL, "bssid=" B55, T, MONO0, 0, out, sizeof(out), &len, &st), 0);
    WT_EQ(st, 200);
    WT_ASSERT(len > 10000);
    WT_EQ(w_count(out, "\"ts_last\":"), WEB_LURE_HIST);
}

/* The page: the module, its drawer, its hooks in app.js and lure.js,
 * its words, the remote row's "-", and textContent only. */
static void no_sinks(const char *p, const char *from, const char *to) {
    const char *m = strstr(p, from);
    const char *e = m ? strstr(m, to) : NULL;
    WT_ASSERT(m && e);
    if (!m || !e) return;
    size_t n = (size_t)(e - m);
    char *mod = malloc(n + 1);
    WT_ASSERT(mod != NULL);
    if (!mod) return;
    memcpy(mod, m, n);
    mod[n] = '\0';
    WT_LACKS(mod, "innerHTML");
    WT_LACKS(mod, "outerHTML");
    WT_LACKS(mod, "insertAdjacentHTML");
    WT_LACKS(mod, "setAttribute");
    WT_LACKS(mod, "document.write");
    free(mod);
}

static void test_lure_detail_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "window.SlothKarma = {");
    WT_HAS(p, "<aside class=\"drawer\" id=\"kdrawer\" hidden aria-label=\"karma detail\">");
    WT_HAS(p, "id=\"kdr-body\"");
    WT_HAS(p, "<ol class=\"lst\" id=\"kdr-alerts\"></ol>");
    WT_HAS(p, "id=\"kdr-hist\"");
    WT_HAS(p, "<div class=\"sub\" id=\"dr-karma\" hidden></div>");
    WT_HAS(p, "  if (window.SlothKarma) SlothKarma.init({ getJSON: getJSON, errText: errText, keyColor: keyColor,\n"
              "    stamp: stamp, shortStamp: shortStamp, kvList: kvList, alertLink: alertLink });");
    WT_HAS(p, "      if (window.SlothKarma) SlothKarma.drawer(mac, fr);");
    WT_HAS(p, "    if (window.SlothKarma) SlothKarma.drawer(null);");
    WT_HAS(p, "    table(\"w-lure-karma\", KARMA_HEAD, (j && j.karma) || [], karmaCells, karmaFirst);");
    /* Another host's AP row: "-" whatever it carries. */
    WT_HAS(p, "    if (a.karma && !rem) SlothRf.bullet(km, a.karma.score, { max: 7, ranges: [3, 7], threshold: 3 },\n"
              "                                        \"karma \" + a.karma.score, \"warn\");\n"
              "    else km.appendChild(el(\"span\", \"d-dim\", \"-\"));");
    WT_HAS(p,
        "    // Another host's row: its export carries no lure data.\n"
        "    if (remote) {\n"
        "      box.appendChild(el(\"span\", \"k\", \"karma\"));\n"
        "      box.appendChild(el(\"span\", \"d-dim\", \" -\"));\n"
        "      box.hidden = false;\n"
        "      return;\n"
        "    }\n");
    WT_HAS(p,
        "  function stateText(j) {\n"
        "    if (!j) return \"not known\";\n"
        "    if (j.out_of_scope) return String(j.reason || \"\");\n"
        "    if (j.state === \"live\") return \"live: in sloth's KARMA table now\";\n"
        "    if (j.state === \"gone\") return \"gone: sloth retired the row at \" + stamp(j.gone_ts);\n"
        "    if (j.state === \"stale\") return \"stale: sloth has not refreshed the row for 11 min\";\n");
    WT_HAS(p,
        "  function hwText(hw) {\n"
        "    if (!hw) return \"-\";\n"
        "    if (typeof hw.verdict !== \"string\") return \"none on its newest KARMA_AP record\";\n");
    WT_HAS(p, "  function path(bssid) { return \"/api/lures/bssid?bssid=\" + encodeURIComponent(bssid); }");
    /* The alert row opens its page through alertLink (and so carries
     * its triage, frrs.js). */
    WT_HAS(p,
        "      var li = el(\"li\", null, alertText(a));\n"
        "      H.alertLink(li, String(a.id));\n");
    no_sinks(p, "// slothweb: one BSSID's KARMA detail", "window.SlothKarma = {");
    no_sinks(p, "// slothweb: the KARMA and key-harvest card", "window.SlothLure = {");
}

void run_lure_tests(void) {
    WT_RUN(test_lure_detail_history);
    WT_RUN(test_lure_detail_hw);
    WT_RUN(test_lure_detail_probe_lat);
    WT_RUN(test_lure_probe_lat_text_bound);
    WT_RUN(test_lure_detail_alerts);
    WT_RUN(test_lure_detail_params);
    WT_RUN(test_lure_detail_worst_case_fits);
    WT_RUN(test_lure_detail_page);
    WT_RUN(test_lure_reported);
    WT_RUN(test_lure_route);
    WT_RUN(test_lure_replace_and_gone);
    WT_RUN(test_lure_refuses);
    WT_RUN(test_lure_stale_and_bounds);
    WT_RUN(test_lure_worst_case_fits);
    WT_RUN(test_lure_scope);
    WT_RUN(test_lure_page);
    if (inited) { web_lure_destroy(&L); inited = 0; }
}
