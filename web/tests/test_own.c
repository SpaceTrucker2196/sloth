/* The operator's designated networks (web_own.h): sloth's `ownership`
 * record, in the shape src/jsonl.c writes it (the lines below are the
 * ones tests/test_ownership.c asserts sloth writes), kept by slothweb
 * and answered as yes, no or not known; and the page's half, the words
 * and marks, pinned whole out of the served page.
 *
 * Absence assertions, each seen red under the mutation named beside it
 * and restored. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_own.h"
#include "web_routes.h"
#include "wtest.h"

static web_own_t O;
static web_jrec_t R;

static void feed(const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_own_record(&O, &R, 1000);
}

static void feed_at(const char *line, long long ms) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_own_record(&O, &R, ms);
}

static int inited;

static void fresh(void) {
    if (inited) web_own_destroy(&O);
    WT_EQ(web_own_init(&O), 0);
    inited = 1;
    web_own_bind(&O);
}

static const char REC[] =
    "{\"type\":\"ownership\",\"ts\":1800000000,\"ssids\":2,\"ssid_0\":\"HomeNet\","
    "\"ssid_1\":\"a\\u0001b\",\"bssids\":1,\"bssid_0\":\"aa:bb:cc:dd:ee:0f\",\"known_macs\":2}";

/* Before any record, and with nothing bound, every answer is "not
 * known" (-1), never "no". Seen red with web_own_ssid() starting from
 * 0 instead of -1. */
static void test_own_not_known(void) {
    web_own_bind(NULL);
    WT_EQ(web_own_ssid("HomeNet", 7), -1);
    WT_EQ(web_own_bssid("aa:bb:cc:dd:ee:0f"), -1);
    WT_EQ(web_own_ssid_count(), -1);
    fresh();
    feed("{\"type\":\"sys_status\",\"ts\":1,\"seq\":1}");
    WT_EQ(web_own_ssid("HomeNet", 7), -1);
    WT_EQ(web_own_bssid("aa:bb:cc:dd:ee:0f"), -1);
    WT_EQ(web_own_ssid_count(), -1);
    WT_EQ((int)O.records, 0);
}

/* A record: its SSIDs octet for octet (case matters, a control byte
 * decoded from \u0001 matches its octet), its BSSIDs in either case. */
static void test_own_answers(void) {
    fresh();
    feed(REC);
    WT_EQ(O.seen, 1);
    WT_EQ(web_own_ssid_count(), 2);
    WT_EQ(web_own_ssid("HomeNet", 7), 1);
    WT_EQ(web_own_ssid("homenet", 7), 0);
    WT_EQ(web_own_ssid("HomeNet-5G", 10), 0);
    WT_EQ(web_own_ssid("HomeNe", 6), 0);               /* never a prefix */
    WT_EQ(web_own_ssid("a\x01" "b", 3), 1);
    WT_EQ(web_own_ssid("a?b", 3), 0);
    WT_EQ(web_own_ssid("", 0), 0);
    WT_EQ(web_own_bssid("aa:bb:cc:dd:ee:0f"), 1);
    WT_EQ(web_own_bssid("AA:BB:CC:DD:EE:0F"), 1);
    WT_EQ(web_own_bssid("aa:bb:cc:dd:ee:10"), 0);
    WT_EQ(web_own_bssid("not a mac"), 0);
    WT_EQ(O.known_macs, 2);
}

/* An empty roster is a record: "sloth designates none", answered no,
 * which a page tells from "not known". */
static void test_own_empty_roster(void) {
    fresh();
    feed("{\"type\":\"ownership\",\"ts\":1800000000,\"ssids\":0,\"bssids\":0,\"known_macs\":0}");
    WT_EQ(web_own_ssid_count(), 0);
    WT_EQ(web_own_ssid("HomeNet", 7), 0);
    WT_EQ(web_own_bssid("aa:bb:cc:dd:ee:0f"), 0);
}

/* Malformed or out of bounds: refused whole, the last good roster kept.
 * Seen red with parse()'s ssid_N presence test removed (the record with
 * a missing member replaced the roster) and with the known_macs bound
 * widened. */
static void test_own_malformed(void) {
    fresh();
    feed(REC);
    static const char *const BAD[] = {
        "{\"type\":\"ownership\",\"ts\":1,\"ssids\":17,\"bssids\":0,\"known_macs\":0}",
        "{\"type\":\"ownership\",\"ts\":1,\"ssids\":2,\"ssid_0\":\"X\",\"bssids\":0,\"known_macs\":0}",
        "{\"type\":\"ownership\",\"ts\":1,\"ssids\":1,\"ssid_0\":\"\",\"bssids\":0,\"known_macs\":0}",
        "{\"type\":\"ownership\",\"ts\":1,\"ssids\":1,\"ssid_0\":7,\"bssids\":0,\"known_macs\":0}",
        "{\"type\":\"ownership\",\"ts\":1,\"ssids\":0,\"bssids\":1,\"bssid_0\":\"aa-bb-cc-dd-ee-ff\",\"known_macs\":0}",
        "{\"type\":\"ownership\",\"ts\":1,\"ssids\":0,\"bssids\":17,\"known_macs\":0}",
        "{\"type\":\"ownership\",\"ts\":1,\"ssids\":0,\"bssids\":0,\"known_macs\":513}",
        "{\"type\":\"ownership\",\"ts\":1,\"ssids\":-1,\"bssids\":0,\"known_macs\":0}",
        "{\"type\":\"ownership\",\"ts\":1,\"ssids\":\"1\",\"bssids\":0,\"known_macs\":0}",
        "{\"type\":\"ownership\",\"ts\":1,\"bssids\":0,\"known_macs\":0}",
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) feed(BAD[i]);
    WT_EQ((int)O.rejected, (int)(sizeof(BAD) / sizeof(BAD[0])));
    WT_EQ(web_own_ssid_count(), 2);
    WT_EQ(web_own_ssid("HomeNet", 7), 1);
    WT_EQ(web_own_ssid("X", 1), 0);
    WT_EQ(web_own_bssid("aa:bb:cc:dd:ee:0f"), 1);
    WT_EQ(O.known_macs, 2);
    /* The next good one replaces it whole: a set, not a log. */
    feed("{\"type\":\"ownership\",\"ts\":1800000300,\"ssids\":1,\"ssid_0\":\"Office\",\"bssids\":0,\"known_macs\":0}");
    WT_EQ(web_own_ssid("HomeNet", 7), 0);
    WT_EQ(web_own_ssid("Office", 6), 1);
    WT_EQ(web_own_bssid("aa:bb:cc:dd:ee:0f"), 0);
}

/* A designation whose octets were not UTF-8 arrives as U+FFFD, three
 * octets each: past 32 it is counted and matches nothing, never a cut
 * prefix. Seen red (the 32-octet prefix matched) with the n > 32
 * branch made a truncation. */
static void test_own_not_utf8(void) {
    fresh();
    char line[512];
    char rep[11 * 6 + 1] = "";
    for (int i = 0; i < 11; i++) strcat(rep, "\\ufffd");
    snprintf(line, sizeof(line), "{\"type\":\"ownership\",\"ts\":1,\"ssids\":1,\"ssid_0\":\"%s\","
             "\"bssids\":0,\"known_macs\":0}", rep);
    feed(line);
    WT_EQ(web_own_ssid_count(), 1);
    char pre[33];
    for (int i = 0; i < 10; i++) memcpy(pre + 3 * i, "\xef\xbf\xbd", 3);
    pre[30] = '\xef'; pre[31] = '\xbf'; pre[32] = '\0';
    WT_EQ(web_own_ssid(pre, 32), 0);
}

/* The page's half, whole functions and lines. */
static void test_own_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  function designatedText(j) {\n"
              "    var n = j.designated_count;\n"
              "    if (j.designated === true) return \"yes: one of the \" + n + \" network\" + (n === 1 ? \"\" : \"s\") + \" sloth designates (--my-ssid)\";\n"
              "    if (j.designated === false)\n"
              "      return \"no: not among the \" + n + \" network\" + (n === 1 ? \"\" : \"s\") + \" sloth designates (--my-ssid)\";\n"
              "    return \"not known: sloth has not reported its designated networks\";\n"
              "  }\n");
    WT_HAS(p, "      [\"designated\", designatedText(j)]\n");
    WT_HAS(p, "      li.appendChild(macGo(b.bssid, false, b.channel));\n"
              "      if (b.designated === true) li.appendChild(H.el(\"span\", \"d-bright\", \"yours: --my-bssid\"));\n");
    WT_HAS(p, "  function designatedCaption(j) {\n"
              "    var n = j.designated_count;\n"
              "    if (!num(n)) return \"designated networks not known: sloth has not reported them\";\n"
              "    if (!n) return \"sloth designates no network (--my-ssid), so none is marked yours\";\n"
              "    var mine = (j.rows || []).filter(function (s) { return s.designated === true; }).length;\n"
              "    return \"yours: one of the \" + n + \" network\" + (n === 1 ? \"\" : \"s\") + \" sloth designates (--my-ssid), \" +\n"
              "           mine + \" of them asked for here\";\n"
              "  }\n");
    WT_HAS(p, "      c.appendChild(H.ssidSpan(String(s.ssid), s.ssid_k, s.ssid_np));\n"
              "      if (s.designated === true) c.appendChild(H.el(\"span\", \"d-bright\", \" yours\"));\n");
    WT_HAS(p, "                 designatedCaption(j),\n");
    WT_HAS(p, "    if (!rem && a.designated === true) ss.appendChild(el(\"span\", \"d-bright\", \" yours\"));\n");
    /* The old "cannot know" words are gone from both views. */
    WT_LACKS(p, "in neither sloth.db nor the stream");
}

/* #234: a live record naming the joined network is kept out of the
 * recent list under Monitor and marked "own" on the event stream (the
 * page drops it there); Hybrid keeps it; an alert about the network is
 * never marked (owner ruling 2026-11-19). Seen red with the ring's
 * Monitor skip removed. */
static void test_own_live(void) {
    fresh();
    web_live_t *l = calloc(1, sizeof(*l));
    WT_ASSERT(l != NULL);
    if (!l) return;
    web_live_init(l, "unix:/x");
    const long long t0 = 5000000;
    feed_at("{\"type\":\"wifi_sta\",\"ts\":1,\"mac\":\"0a:00:00:00:00:01\"}", t0);
    feed_at("{\"type\":\"wifi_ap\",\"ts\":1,\"bssid\":\"0a:00:00:00:00:01\",\"ssid\":\"HomeNet\"}", t0);
    static const char *const L[] = {
        "{\"type\":\"beacon\",\"ts\":2,\"bssid\":\"0a:00:00:00:00:01\",\"ssid\":\"HomeNet\"}",
        "{\"type\":\"probe_client\",\"ts\":2,\"mac\":\"02:11:22:33:44:55\",\"ssid\":\"HomeNet\"}",
        "{\"type\":\"beacon\",\"ts\":2,\"bssid\":\"0a:00:00:00:00:09\",\"ssid\":\"CafeFree\"}",
        "{\"type\":\"alert\",\"ts\":2,\"ty\":5,\"sev\":2,\"key\":\"EVIL_TWIN:HomeNet\","
        "\"bssid\":\"0a:00:00:00:00:01\",\"ssid\":\"HomeNet\",\"msg\":\"twin\"}",
    };
    for (size_t i = 0; i < sizeof(L) / sizeof(L[0]); i++) {
        WT_EQ(web_jl_parse(L[i], strlen(L[i]), &R), WEB_JL_OK);
        web_live_apply(l, &R, t0 + 1);
    }
    WT_EQ(l->ring[0].own, 1);
    WT_EQ(l->ring[1].own, 1);
    WT_EQ(l->ring[2].own, 0);
    WT_EQ(l->ring[3].own, 0);
    char ev[8192];
    WT_ASSERT(web_sse_record(ev, sizeof(ev), &l->ring[0]) > 0);
    WT_HAS(ev, "\"own\":true}");
    WT_ASSERT(web_sse_record(ev, sizeof(ev), &l->ring[2]) > 0);
    WT_LACKS(ev, "\"own\"");
    static char out[1 << 18];
    web_scope_ctx_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.scope = WEB_SCOPE_MONITOR;
    sc.given = 1;
    WT_ASSERT(web_live_json_scoped(l, &sc, out, sizeof(out), t0 + 2) > 0);
    WT_LACKS(out, "0a:00:00:00:00:01 ");
    WT_LACKS(out, "\"seq\":1,");
    WT_LACKS(out, "\"seq\":2,");
    WT_HAS(out, "\"seq\":3,");
    sc.scope = WEB_SCOPE_HYBRID;
    WT_ASSERT(web_live_json_scoped(l, &sc, out, sizeof(out), t0 + 2) > 0);
    WT_HAS(out, "\"seq\":1,");
    WT_HAS(out, "\"seq\":2,");
    /* No scope at all (web_live_json(), a NULL context): the joined
     * network's rows are there and nothing is dereferenced. Without
     * the "scoped &&" guard this call is the one that took the live
     * slothweb down (SIGSEGV in web_live_json_scoped(), 2026-11-19);
     * the test was not rerun against the unguarded line. */
    WT_ASSERT(web_live_json(l, out, sizeof(out), t0 + 2) > 0);
    WT_HAS(out, "\"seq\":1,");
    WT_HAS(out, "\"seq\":2,");
    web_live_destroy(l);
    free(l);
    web_own_bind(NULL);
}

void run_own_tests(void) {
    WT_RUN(test_own_not_known);
    WT_RUN(test_own_answers);
    WT_RUN(test_own_empty_roster);
    WT_RUN(test_own_malformed);
    WT_RUN(test_own_not_utf8);
    WT_RUN(test_own_live);
    WT_RUN(test_own_page);
    web_own_bind(NULL);
    if (inited) web_own_destroy(&O);
    inited = 0;
}
