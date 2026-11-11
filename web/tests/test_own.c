/* The operator's designated networks (web_own.h): sloth's `ownership`
 * record, in the shape src/jsonl.c writes it (the lines below are the
 * ones tests/test_ownership.c asserts sloth writes), kept by slothweb
 * and answered as yes, no or not known; and the page's half, the words
 * and marks, pinned whole out of the served page.
 *
 * Absence assertions, each seen red under the mutation named beside it
 * and restored. */
#include <stdio.h>
#include <string.h>

#include "web_assets.h"
#include "web_jsonl.h"
#include "web_own.h"
#include "wtest.h"

static web_own_t O;
static web_jrec_t R;

static void feed(const char *line) {
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_own_record(&O, &R, 1000);
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
    WT_HAS(p, "      li.appendChild(macGo(b.bssid, false));\n"
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
    WT_HAS(p, "    if (a.designated === true) ss.appendChild(el(\"span\", \"d-bright\", \" yours\"));\n");
    /* The old "cannot know" words are gone from both views. */
    WT_LACKS(p, "in neither sloth.db nor the stream");
}

void run_own_tests(void) {
    WT_RUN(test_own_not_known);
    WT_RUN(test_own_answers);
    WT_RUN(test_own_empty_roster);
    WT_RUN(test_own_malformed);
    WT_RUN(test_own_not_utf8);
    WT_RUN(test_own_page);
    web_own_bind(NULL);
    if (inited) web_own_destroy(&O);
    inited = 0;
}
