/* One SSID's detail (owner request 2026-11-11; web_ssidview.h):
 * /api/wifi/ssid through the route table over a sloth.db generated from
 * sloth's own DDL (sdb_gen.c) on the pinned clock, the `ssid=`
 * parameter's every shape (empty, not UTF-8, 32 octets, SQL-wildcard
 * looking), the read on a large file inside the request's budget, and
 * the page's half (web/ui/ssid.js) pinned by whole functions.
 *
 * Absence assertions, each seen red under the named mutation and
 * restored: the comments over test_ssid_detail(),
 * test_ssid_on_a_large_file() and test_page_ssid_detail() name them. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_assets.h"
#include "web_chain.h"
#include "web_jsonl.h"
#include "web_ssidview.h"
#include "web_routes.h"
#include "web_scope.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "wtest.h"
#include "wt_tmp.h"

#define T SDB_NOW
#define DY 86400LL

static char g_out[131072];

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

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

static int count(const char *s, const char *needle) {
    int n = 0;
    for (const char *h = strstr(s, needle); h; h = strstr(h + 1, needle)) n++;
    return n;
}

/* The parameter: one spelling an octet string, both ways. */
static void test_ssid_param(void) {
    static const struct { const char *octets; size_t n; const char *param; } OK[] = {
        { "", 0, "-" },
        { "HomeNet", 7, "SG9tZU5ldA" },
        { "Home%", 5, "SG9tZSU" },
        { "Home_et", 7, "SG9tZV9ldA" },
        { "caf\xe9\xff", 5, "Y2Fm6f8" },                     /* not UTF-8 */
        { "\xe2\x80\x8bx", 4, "4oCLeA" },                    /* a zero-width space */
        { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32,
          "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE" },
    };
    for (size_t i = 0; i < sizeof(OK) / sizeof(OK[0]); i++) {
        char out[WEB_SSID_OCTETS + 1], back[48];
        WT_EQ(web_ssid_param(OK[i].param, out), (int)OK[i].n);
        WT_ASSERT(!memcmp(out, OK[i].octets, OK[i].n + 1));
        web_ssid_param_of(OK[i].octets, OK[i].n, back);
        WT_ASSERT(!strcmp(back, OK[i].param));
    }
    WT_EQ((int)strlen(OK[6].param), 43);
    static const char *const BAD[] = {
        "", "A",                 /* one character carries no octet */
        "SG9tZ",                 /* five: the same */
        "SG9tZSV",               /* bits left over: not the one spelling */
        "AA",                    /* a NUL octet */
        "SG9t ZQ", "SG9t+ZQ", "SG9t/ZQ", "SG9tZQ==",   /* not base64url, no padding */
        "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", /* 33 octets */
        "--",
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        char out[WEB_SSID_OCTETS + 1];
        WT_EQ(web_ssid_param(BAD[i], out), -1);
    }
    char out[WEB_SSID_OCTETS + 1];
    WT_EQ(web_ssid_param(NULL, out), -1);
}

/* A decoder of this file's own, written from RFC 4648 section 5 by
 * position and not by the routine's accumulator: the octets of a
 * base64url text with no padding, -1 for anything web_ssid_param() is
 * documented to refuse (a character outside the alphabet, a length no
 * octet string encodes to, non-zero spare bits, a NUL octet, over 32
 * octets). "-" is the empty SSID and is not asked of it. */
static int ref_b64(const char *s, unsigned char *out) {
    size_t n = strlen(s);
    int v[64];
    if (n == 0 || n > 60 || n % 4 == 1) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        v[i] = c >= 'A' && c <= 'Z' ? c - 'A' : c >= 'a' && c <= 'z' ? c - 'a' + 26
             : c >= '0' && c <= '9' ? c - '0' + 52 : c == '-' ? 62 : c == '_' ? 63 : -1;
        if (v[i] < 0) return -1;
    }
    size_t no = n * 6 / 8;
    if (no > WEB_SSID_OCTETS) return -1;
    for (size_t k = 0; k < no; k++) {
        size_t q = k / 3 * 4;
        int b = k % 3 == 0 ? (v[q] << 2) | (v[q + 1] >> 4)
              : k % 3 == 1 ? ((v[q + 1] & 15) << 4) | (v[q + 2] >> 2)
                           : ((v[q + 2] & 3) << 6) | v[q + 3];
        if (!b) return -1;
        out[k] = (unsigned char)b;
    }
    int spare = n % 4 == 2 ? v[n - 1] & 15 : n % 4 == 3 ? v[n - 1] & 3 : 0;
    return spare ? -1 : (int)no;
}

/* The parameter under a few thousand generated texts, from a fixed
 * seed: every length from none to past the longest, the alphabet with
 * the characters next to it (+ / = % space, a byte over 0x7f), and
 * octet strings of every length with every byte value but NUL. Each
 * result is held to ref_b64() above, and the output goes into a block
 * of exactly WEB_SSID_OCTETS + 1 bytes so a write past it is the
 * sanitizer's to report. What it found on 2026-11-11: nothing. */
static void test_ssid_param_generated(void) {
    static const char ALPHA[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    static const char NEAR[] = "+/=% .~\x80\xff";
    uint32_t x = 0x51075ead;
    int asked = 0, agreed = 0, taken = 0;
    for (int it = 0; it < 6000; it++) {
        char in[64];
        x = x * 1664525u + 1013904223u;
        size_t n = (x >> 8) % 50;
        int dirty = (x >> 20) % 4 == 0;
        for (size_t i = 0; i < n; i++) {
            x = x * 1664525u + 1013904223u;
            in[i] = dirty && (x >> 28) == 0 ? NEAR[(x >> 12) % (sizeof(NEAR) - 1)]
                                            : ALPHA[(x >> 12) % 64];
        }
        in[n] = '\0';
        if (!strcmp(in, "-")) continue;
        char *out = malloc(WEB_SSID_OCTETS + 1);
        unsigned char want[64];
        WT_ASSERT(out != NULL);
        if (!out) return;
        int got = web_ssid_param(in, out), ref = ref_b64(in, want);
        if (got != ref) fprintf(stderr, "  \"%s\": got %d, want %d\n", in, got, ref);
        asked++;
        agreed += got == ref;
        if (got >= 0) {
            taken++;
            WT_ASSERT(got <= WEB_SSID_OCTETS && strlen(out) == (size_t)got);
            WT_ASSERT(ref < 0 || !memcmp(out, want, (size_t)got));
        }
        free(out);
    }
    WT_EQ(agreed, asked);
    WT_ASSERT(taken > 500);            /* the generator does reach the accepting side */
    /* Octets to text and back: every length, every byte value. */
    for (int it = 0; it < 2000; it++) {
        char oct[WEB_SSID_OCTETS + 8], text[48];
        x = x * 1664525u + 1013904223u;
        size_t n = 1 + (x >> 8) % (WEB_SSID_OCTETS + 4);
        for (size_t i = 0; i < n; i++) {
            x = x * 1664525u + 1013904223u;
            oct[i] = (char)(1 + (x >> 16) % 255);
        }
        web_ssid_param_of(oct, n, text);
        size_t kept = n > WEB_SSID_OCTETS ? WEB_SSID_OCTETS : n;
        WT_EQ((int)strlen(text), (int)((kept * 4 + 2) / 3));
        char *out = malloc(WEB_SSID_OCTETS + 1);
        WT_ASSERT(out != NULL);
        if (!out) return;
        WT_EQ(web_ssid_param(text, out), (int)kept);
        WT_ASSERT(!memcmp(out, oct, kept) && out[kept] == '\0');
        free(out);
    }
}

#ifndef WITH_SQLITE

/* Without SQLite there is no sloth.db: the route says so. */
static void test_route_without_sqlite(void) {
    web_health_t H;
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.m4 = &m4;
    WT_EQ(route(&H, "/api/wifi/ssid", "ssid=-"), 503);
    WT_HAS(body_of(g_out), "{\"error\":\"no_sloth_db\"");
}

#else


static char g_dir[TEST_TMP_MAX];
static char g_db[128];
static web_rollup_t ru;
static web_tsdb_t ts;
static web_slothdb_t sdb;
static web_chain_t C;
static web_m4_t m4;
static web_health_t H;

static void db_up(int seed) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-ssid-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char e2[64];
    WT_EQ(web_rollup_init(&ru, 64, 1, e2, sizeof(e2)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, NULL, 30, 256, NULL, NULL), 0);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    if (seed) WT_EQ(sdb_seed(g_db), 0);
    web_slothdb_init(&sdb, g_db, NULL);
    WT_EQ(web_chain_init(&C), 0);
    memset(&m4, 0, sizeof(m4));
    m4.tsdb = &ts;
    m4.sdb = &sdb;
    m4.chain = &C;
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.tsdb = &ts;
    H.m4 = &m4;
}

static void db_down(void) {
    web_chain_destroy(&C);
    web_slothdb_destroy(&sdb);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    unlink(g_db);
    rmdir(g_dir);
}

/* The acceptance scenario's HomeNet (sdb_gen.c: one station asking for
 * it and associated to aa:bb:cc:dd:ee:ff under that name) with APs
 * beside it: two beaconing HomeNet now, one that did and beacons Other
 * now, one each for the two names that would match HomeNet as a LIKE
 * pattern, one whose name is not UTF-8, one of 32 octets, two hidden. */
#define A32 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
static void ssid_seed(void) {
    static char sql[8192];
    snprintf(sql, sizeof(sql),
        "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,enc,akm,mfp,vendor,"
        "akm_bits,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:01','HomeNet',-50,6,'WPA3','PSK,SAE',1,'Acme',260,%lld,%lld),"
        " ('0a:00:00:00:00:02','HomeNet',-71,36,'WPA2','PSK',0,NULL,4,%lld,%lld),"
        " ('0a:00:00:00:00:03','Other',-60,1,'OPEN','',0,NULL,0,%lld,%lld),"
        " ('0a:00:00:00:00:04','Home%%',-61,1,'OPEN','',0,NULL,0,%lld,%lld),"
        " ('0a:00:00:00:00:05','Home_et',-62,1,'OPEN','',0,NULL,0,%lld,%lld),"
        " ('0a:00:00:00:00:06',CAST(x'636166e9ff' AS TEXT),-63,11,'WPA2','PSK',0,NULL,4,%lld,%lld),"
        " ('0a:00:00:00:00:07','" A32 "',-64,11,'WPA2','PSK',0,NULL,4,%lld,%lld),"
        " ('0a:00:00:00:00:08',NULL,-65,44,'WPA2','PSK',0,NULL,4,%lld,%lld),"
        " ('0a:00:00:00:00:09','',-66,48,'WPA2','PSK',0,NULL,4,%lld,%lld);"
        "INSERT INTO beacon_ap_ssids (bssid,ssid,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:01','HomeNet',%lld,%lld), ('0a:00:00:00:00:03','HomeNet',%lld,%lld),"
        " ('0a:00:00:00:00:03','Other',%lld,%lld);"
        "INSERT INTO karma_candidates (bssid,ssid_count,pnl_overlap,pnl_best,"
        "pnl_jaccard_ppm,ie_uniform,deauth_chain,score,top_ssid,first_seen,last_seen)"
        " VALUES ('0a:00:00:00:00:02',3,2,2,500000,1,1,5,'HomeNet',%lld,%lld);"
        "INSERT INTO assocs (bssid,sta_mac,ssid,sta_random,source,channel,signal_dbm,"
        "frame_count,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:01','00:03:93:00:00:03',NULL,0,1,6,-52,4,%lld,%lld),"
        " ('0a:00:00:00:00:04','00:03:93:00:00:03','Home%%',0,1,1,-52,4,%lld,%lld),"
        " ('0a:00:00:00:00:08','da:a1:19:00:00:04',NULL,1,1,44,-58,2,%lld,%lld);"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
        " ('da:a1:19:00:00:04','Home_et',%lld,%lld),"
        " ('da:a1:19:00:00:04',CAST(x'636166e9ff' AS TEXT),%lld,%lld);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,count) VALUES"
        " ('deauth:ff:ff:ff:ff:ff:ff@0a:00:00:00:00:01',%lld,%lld,7,2,'Deauth flood',40),"
        " ('saesplit:HomeNet:3d7880f113ad7b51',%lld,%lld,60,1,'SAE split on HomeNet',2),"
        " ('saesplit:Home%%:3c036ee149bd98d1',%lld,%lld,60,1,'SAE split on Home%%',1),"
        " ('wpslockout:0a:00:00:00:00:05',%lld,%lld,61,1,'WPS lockout',1),"
        " ('csa:0a:00:00:00:00:02',%lld,%lld,62,0,'CSA long ago',1);",
        T - 9 * DY, T - 60, T - 8 * DY, T - 120, T - 7 * DY, T - 180, T - DY, T - 200,
        T - DY, T - 210, T - 3600, T - 220, T - DY, T - 230, T - DY, T - 240, T - DY, T - 250,
        T - 9 * DY, T - 60, T - 7 * DY, T - 3 * DY, T - 3 * DY, T - 180,
        T - DY, T - 120,
        T - 2 * DY, T - 300, T - 2 * DY, T - 310, T - DY, T - 320,
        T - 5 * DY, T - 400, T - 4 * DY, T - 500,
        T - 3600, T - 600, T - 7200, T - 700, T - 7200, T - 710, T - 7200, T - 720,
        T - 41 * DY, T - 40 * DY);
    WT_EQ(sdb_exec(g_db, sql), 0);
}

static void twin(const char *real, const char *tw) {
    static web_jrec_t R;
    char line[512];
    snprintf(line, sizeof(line),
             "{\"type\":\"twin_episode\",\"ts\":%lld,\"ssid\":\"HomeNet\",\"real_bssid\":\"%s\","
             "\"twin_bssid\":\"%s\",\"enc\":\"WPA2\",\"real_rssi\":-70,\"twin_rssi\":-45,"
             "\"rssi_swing_dbm\":25,\"attack_in_progress\":1,\"attacker_oui\":0,"
             "\"hash_mismatch\":0,\"attributed\":1,\"confidence\":80}",
             T - 900, real, tw);
    WT_EQ(web_jl_parse(line, strlen(line), &R), WEB_JL_OK);
    web_chain_record(&C, &R);
}

/* The detail of one SSID: its BSSIDs now and once, each with its
 * posture, KARMA score and twin links; the stations associated and
 * asking; the alerts naming it; the strip.
 *
 * The absences, each seen red under its mutation and restored:
 *   - a name is compared with `=`, never as a pattern: SSID_IS's
 *     `b.ssid = ?1` made `b.ssid LIKE ?1` (Home% listed four BSSIDs,
 *     HomeNet's among them, and Home_et three);
 *   - an alert that names neither the SSID nor a BSSID of it is not
 *     listed: the key test made `instr(w.key, ?2) >= 0` (six alerts
 *     where two were, WPS lockout and Home%'s among them);
 *   - nor one older than the window: `w.last_seen >= ?3` made
 *     `?3 = ?3` (three alerts: the 40 day old CSA with them);
 *   - the key is a predicate and never in the answer: the statement's
 *     first column made `w.key` ("saesplit" and the key's hash in the
 *     body);
 *   - Local hears none of it: route_m5()'s branch for these routes
 *     forced to 0 (a Local answer carried the BSSIDs and the station). */
static void test_ssid_detail(void) {
    db_up(1);
    ssid_seed();
    twin("0a:00:00:00:00:01", "0a:00:00:00:00:02");
    web_rollup_add(&ru, WM_DEV_PRESENT, "0a:00:00:00:00:02", 1, T - 30);
    WT_EQ(route(&H, "/api/wifi/ssid", "ssid=SG9tZU5ldA"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"ssid\":\"HomeNet\",\"ssid_k\":");
    WT_HAS(b, "\"ssid_np\":false,\"hidden\":false,\"octets\":7,\"now\":1792627200,\"db\":\"open\",");
    WT_HAS(b, "\"designated\":null,\"first_seen\":1791849600,\"last_seen\":1792627140,\"bssids\":["
              "{\"bssid\":\"0a:00:00:00:00:01\",\"current\":true,\"vendor\":\"Acme\",\"channel\":6,"
              "\"enc\":\"WPA3\",\"akm\":\"PSK,SAE\",\"akm_names\":[\"PSK\",\"SAE\"],"
              "\"mfp_word\":\"capable\",\"signal\":-50,\"first_seen\":1791849600,"
              "\"last_seen\":1792627140,\"karma\":null,\"twins\":[{\"real\":\"0a:00:00:00:00:01\","
              "\"twin\":\"0a:00:00:00:00:02\",\"attributed\":true,\"tainted\":true,\"confidence\":80,");
    WT_HAS(b, "{\"bssid\":\"0a:00:00:00:00:02\",\"current\":true,\"vendor\":null,\"channel\":36,");
    WT_HAS(b, "\"karma\":{\"score\":5,\"ssid_count\":3},\"twins\":[{\"real\":");
    /* Once, and something else now: the times it beaconed this name. */
    WT_HAS(b, "{\"bssid\":\"0a:00:00:00:00:03\",\"current\":false,\"vendor\":null,\"channel\":1,"
              "\"enc\":\"OPEN\",\"akm\":null,\"akm_names\":[],\"mfp_word\":\"off\",\"signal\":-60,"
              "\"first_seen\":1792022400,\"last_seen\":1792368000,\"karma\":null,\"twins\":[]}");
    WT_HAS(b, "],\"bssids_total\":2,\"bssids_more\":false,");
    WT_EQ(count(b, "{\"bssid\":"), 3);
    /* Not its neighbours as a pattern would have them. */
    WT_LACKS(b, "0a:00:00:00:00:04");
    WT_LACKS(b, "0a:00:00:00:00:05");
    /* Associated: by the name the association carried (the scenario's)
     * and to a current BSSID (one with no name of its own). */
    WT_HAS(b, "\"assocs\":[{\"mac\":\"00:03:93:00:00:03\",\"random\":false,\"vendor\":null,"
              "\"bssid\":\"0a:00:00:00:00:01\",\"channel\":6,\"signal\":-52,");
    WT_HAS(b, "{\"mac\":\"da:a1:19:00:00:01\",\"random\":true,\"vendor\":null,"
              "\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"channel\":6,\"signal\":-50,");
    WT_HAS(b, "],\"assocs_total\":2,\"probers\":[{\"mac\":\"da:a1:19:00:00:01\",\"random\":true,"
              "\"vendor\":null,\"first_seen\":");
    WT_HAS(b, "],\"probers_total\":1,\"alerts\":[{\"title\":\"Deauth flood\",\"type\":7,\"sev\":2,"
              "\"count\":40,\"incidents\":1,\"id\":\"d");
    WT_HAS(b, "{\"title\":\"SAE split on HomeNet\",\"type\":60,\"sev\":1,\"count\":2,");
    WT_EQ(count(b, "{\"title\":"), 2);
    WT_LACKS(b, "SAE split on Home%");
    WT_LACKS(b, "WPS lockout");
    WT_LACKS(b, "CSA long ago");
    /* The key is a predicate: never in the answer. */
    WT_LACKS(b, "saesplit");
    WT_LACKS(b, "3d7880f113ad7b51");
    WT_HAS(b, "],\"alerts_more\":false,\"alerts_read\":true,\"alerts_reached\":null,"
              "\"alerts_days\":30,\"presence\":\"");
    /* The last cell but one (30 s back, the 10 min cell before now's):
     * the second BSSID's presence. */
    WT_HAS(b, "\"presence\":\"000000000000000000000000000000000002\",\"presence_from\":");
    WT_HAS(b, ",\"presence_bssids\":2}\n");

    /* The names a pattern would confuse: each its own. */
    WT_EQ(route(&H, "/api/wifi/ssid", "ssid=SG9tZSU"), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"ssid\":\"Home%\",");
    WT_HAS(b, "\"bssids\":[{\"bssid\":\"0a:00:00:00:00:04\",\"current\":true,");
    WT_EQ(count(b, "{\"bssid\":"), 1);
    WT_HAS(b, "\"bssids_total\":1,");
    WT_HAS(b, "\"assocs\":[{\"mac\":\"00:03:93:00:00:03\",");
    WT_HAS(b, "\"assocs_total\":1,\"probers\":[],\"probers_total\":0,\"alerts\":[{\"title\":"
              "\"SAE split on Home%\",");
    WT_EQ(count(b, "{\"title\":"), 1);
    WT_EQ(route(&H, "/api/wifi/ssid", "ssid=SG9tZV9ldA"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"bssids\":[{\"bssid\":\"0a:00:00:00:00:05\",");
    WT_EQ(count(b, "{\"bssid\":"), 1);
    WT_HAS(b, "\"probers\":[{\"mac\":\"da:a1:19:00:00:04\",");
    WT_HAS(b, "\"alerts\":[{\"title\":\"WPS lockout\",");

    /* Not UTF-8: the octets back as \xNN, flagged. */
    WT_EQ(route(&H, "/api/wifi/ssid", "ssid=Y2Fm6f8"), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"ssid\":\"caf\\\\xe9\\\\xff\",\"ssid_k\":");
    WT_HAS(b, "\"ssid_np\":true,\"hidden\":false,\"octets\":5,");
    WT_HAS(b, "\"bssids\":[{\"bssid\":\"0a:00:00:00:00:06\",");
    WT_HAS(b, "\"probers\":[{\"mac\":\"da:a1:19:00:00:04\",");
    /* 32 octets. */
    WT_EQ(route(&H, "/api/wifi/ssid", "ssid=QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"ssid\":\"" A32 "\",");
    WT_HAS(b, "\"octets\":32,");
    WT_HAS(b, "\"bssids\":[{\"bssid\":\"0a:00:00:00:00:07\",");
    /* Hidden: the BSSIDs with no name, NULL or empty; a wildcard probe
     * names none, so nobody asks for it. */
    WT_EQ(route(&H, "/api/wifi/ssid", "ssid=-"), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"ssid\":null,\"ssid_k\":0,\"ssid_np\":false,\"hidden\":true,\"octets\":0,");
    WT_HAS(b, "{\"bssid\":\"0a:00:00:00:00:08\",\"current\":true,");
    WT_HAS(b, "{\"bssid\":\"0a:00:00:00:00:09\",\"current\":true,");
    WT_EQ(count(b, "{\"bssid\":"), 2);
    WT_HAS(b, "\"assocs\":[{\"mac\":\"da:a1:19:00:00:04\",\"random\":true,\"vendor\":null,"
              "\"bssid\":\"0a:00:00:00:00:08\",");
    WT_HAS(b, "\"assocs_total\":1,\"probers\":[],\"probers_total\":0,\"alerts\":[],");
    /* A name nothing beacons: R5's empty answer, not an error. */
    WT_EQ(route(&H, "/api/wifi/ssid", "ssid=bm9ib2R5"), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"ssid\":\"nobody\",");
    WT_HAS(b, "\"first_seen\":null,\"last_seen\":null,\"bssids\":[],\"bssids_total\":0,"
              "\"bssids_more\":false,\"assocs\":[],\"assocs_total\":0,\"probers\":[],"
              "\"probers_total\":0,\"alerts\":[],");
    WT_HAS(b, "\"presence\":\"000000000000000000000000000000000000\",");

    static const char *const bad[][2] = {
        { "", "missing_ssid" }, { "ssid=A", "bad_ssid" }, { "ssid=SG9tZSV", "bad_ssid" },
        { "ssid=AA", "bad_ssid" }, { "ssid=Home%25", "bad_ssid" },
        { "ssid=-&q=1", "unknown_parameter" }, { "ssid=-&ssid=-", "repeated_parameter" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char want[64];
        WT_EQ(route(&H, "/api/wifi/ssid", bad[i][0]), 400);
        snprintf(want, sizeof(want), "{\"error\":\"%s\"}", bad[i][1]);
        WT_HAS(body_of(g_out), want);
    }
    /* Monitor's and Hybrid's; Local hears none of it, and a bad
     * parameter is still refused there. */
    WT_EQ(route(&H, "/api/wifi/ssid", "ssid=SG9tZU5ldA&scope=monitor"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"monitor\",\"ssid\":\"HomeNet\",");
    WT_HAS(body_of(g_out), "{\"bssid\":\"0a:00:00:00:00:01\",");
    {
        WT_EQ(route(&H, "/api/wifi/ssid", "ssid=SG9tZU5ldA&scope=local"), 200);
        WT_HAS(body_of(g_out), "{\"scope\":\"local\",\"out_of_scope\":true,\"reason\":\"an SSID");
        WT_HAS(body_of(g_out), "beacons and the probe requests asking for it are the passive "
                               "monitor radio");
        WT_LACKS(body_of(g_out), "0a:00:00:00:00:01");
        WT_LACKS(body_of(g_out), "da:a1:19:00:00:01");
    }
    WT_EQ(route(&H, "/api/wifi/ssid", "ssid=A&scope=local"), 400);
    db_down();
}

static long long mono_ms_t(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

#define BIG_ALERTS 600000
#define BIG_ASKERS 50000

/* A sloth.db with the alerts of the History view's large-file test
 * (test_history.c big_db(): 600,000 episodes, a twentieth of them in the
 * last 30 days) and one name 40 BSSIDs beacon, 5,000 stations are
 * associated to and 50,000 ask for: each list at its cap with the whole
 * count, inside the request's budget (scaled under the sanitizers, as
 * every timed read is). The alert walk is the cost (instr() over each
 * recent key, once a BSSID), so it is bounded by work: with 40 BSSIDs,
 * the newest 6,666 alert rows, and the answer says how far back that
 * reached. Seen red (the budget) with SSID_ALERT_WORK raised to
 * 48,000,000, which reads all 30,001. */
static void test_ssid_on_a_large_file(void) {
    db_up(0);
    static char sql[4096];
    snprintf(sql, sizeof(sql),
        "BEGIN;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < %d - 1)"
        " INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,count)"
        " SELECT 'g:' || i, f, f + i %% 900, i %% 90, i %% 3, 'PORT_SCAN', 1 FROM"
        " (SELECT i, CASE WHEN i < %d THEN %lld + (i * 37) %% %lld"
        "  ELSE %lld + (i * 37) %% %lld END AS f FROM n);"
        "CREATE TEMP TABLE c AS WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n"
        " WHERE i < %d - 1) SELECT i, printf('02:00:%%02x:%%02x:%%02x:%%02x', i / 16777216 %% 256,"
        " i / 65536 %% 256, i / 256 %% 256, i %% 256) AS mac, %lld - (i * 53) %% %lld AS l FROM n;"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) SELECT mac, 'carrier', l - 3600, l FROM c;"
        "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,first_seen,last_seen)"
        " SELECT printf('0a:00:00:01:%%02x:%%02x', i / 256, i %% 256), 'carrier', -70, 11,"
        " l - 3600, l FROM c WHERE i < 40;"
        "INSERT INTO assocs (bssid,sta_mac,ssid,first_seen,last_seen)"
        " SELECT '0a:00:00:01:00:00', mac, 'carrier', l - 3600, l FROM c WHERE i < 5000;"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,count) VALUES"
        " ('csa:0a:00:00:01:00:07',%lld,%lld,62,1,'CSA an hour ago',3);"
        "COMMIT;",
        BIG_ALERTS, BIG_ALERTS - BIG_ALERTS / 20,
        T - 400 * DY, 369 * DY, T - 30 * DY + 1000, 30 * DY - 2000,
        BIG_ASKERS, T - 60, 20 * DY, T - 7200, T - 3600);
    long long t0 = mono_ms_t();
    WT_EQ(sdb_exec(g_db, sql), 0);
    fprintf(stderr, "    generated %d alerts, %d askers in %lld ms\n", BIG_ALERTS, BIG_ASKERS,
            mono_ms_t() - t0);
    t0 = mono_ms_t();
    int st = route(&H, "/api/wifi/ssid", "ssid=Y2Fycmllcg");
    long long ms = mono_ms_t() - t0;
    const char *b = body_of(g_out);
    WT_EQ(st, 200);
    WT_ASSERT(ms < (long long)WEB_SDB_HTTP_MS * web_sdb_test_budget_scale);
    WT_HAS(b, "{\"ssid\":\"carrier\",");
    WT_EQ(count(b, "{\"bssid\":"), 40);
    WT_HAS(b, "\"bssids_total\":40,\"bssids_more\":false,");
    WT_HAS(b, "\"assocs_total\":5000,");
    WT_HAS(b, "\"probers_total\":50000,");
    WT_EQ(count(b, "{\"mac\":"), 2 * WEB_SSID_ITEMS);
    /* The newest are read first: the alert of an hour ago. */
    WT_HAS(b, "\"alerts\":[{\"title\":\"CSA an hour ago\",\"type\":62,\"sev\":1,\"count\":3,");
    WT_HAS(b, "],\"alerts_more\":false,\"alerts_read\":true,\"alerts_reached\":");
    const char *at = strstr(b, "\"alerts_reached\":");
    long long reached = at && at[17] != 'n' ? atoll(at + 17) : 0;
    fprintf(stderr, "    /api/wifi/ssid on it: %lld ms, %zu bytes (budget %d); alerts read back "
            "%lld days of %d\n", ms, strlen(b), WEB_SDB_HTTP_MS,
            reached ? (T - reached) / DY : (long long)WEB_SSID_ALERT_DAYS,
            WEB_SSID_ALERT_DAYS);
    /* 30,001 rows in the window, 6,666 read: not the whole of it. */
    WT_ASSERT(reached > T - 30 * DY && reached < T - 7200);
    t0 = mono_ms_t();
    WT_EQ(route(&H, "/api/wifi/ssid", "ssid=-"), 200);
    fprintf(stderr, "    the hidden SSID on it: %lld ms\n", mono_ms_t() - t0);
    WT_HAS(body_of(g_out), "\"bssids\":[],\"bssids_total\":0,");
    db_down();
}

#endif

/* ── the page ────────────────────────────────────────────────────────── */

/* web/ui/ssid.js and app.js's two hooks, each function whole (a pin of
 * one line misses a change to the lines around it). octets() and
 * param() are the page's half of web_ssid_param(): the suite has no
 * JavaScript engine, so they are held verbatim here and their vectors
 * are test_ssid_param()'s. */
static const char JS_OCTETS[] =
    "  function octets(disp) {\n"
    "    var s = String(disp), out = [], i = 0;\n"
    "    while (i < s.length) {\n"
    "      var c = s.charAt(i);\n"
    "      if (c === \"\\\\\" && s.charAt(i + 1) === \"\\\\\") { out.push(0x5c); i += 2; continue; }\n"
    "      if (c === \"\\\\\" && s.charAt(i + 1) === \"x\" && HEX2.test(s.substr(i + 2, 2))) {\n"
    "        out.push(parseInt(s.substr(i + 2, 2), 16));\n"
    "        i += 4;\n"
    "        continue;\n"
    "      }\n"
    "      var cp = s.codePointAt(i);\n"
    "      i += cp > 0xffff ? 2 : 1;\n"
    "      if (cp < 0x80) out.push(cp);\n"
    "      else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));\n"
    "      else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));\n"
    "      else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));\n"
    "    }\n"
    "    return out;\n"
    "  }\n"
    "";

static const char JS_PARAM[] =
    "  function param(disp) {\n"
    "    if (disp === null || disp === undefined || disp === \"\") return \"-\";\n"
    "    var o = octets(disp), out = \"\", acc = 0, bits = 0;\n"
    "    if (o.length > 32 || o.indexOf(0) >= 0) return null;\n"
    "    for (var i = 0; i < o.length; i++) {\n"
    "      acc = ((acc << 8) | o[i]) & 0xffff;\n"
    "      bits += 8;\n"
    "      while (bits >= 6) { bits -= 6; out += B64.charAt((acc >> bits) & 63); }\n"
    "    }\n"
    "    if (bits) out += B64.charAt((acc << (6 - bits)) & 63);\n"
    "    return out;\n"
    "  }\n"
    "";

static const char JS_LINK[] =
    "  function link(node, ssid) {\n"
    "    node.classList.add(\"go\", \"ssidgo\");\n"
    "    node.tabIndex = 0;\n"
    "    node.role = \"link\";\n"
    "    node.title = \"the detail of this SSID\";\n"
    "    node.addEventListener(\"click\", function (e) {\n"
    "      // Inside a row with a click of its own (a device row): only this.\n"
    "      e.stopPropagation();\n"
    "      open(ssid);\n"
    "    });\n"
    "    return node;\n"
    "  }\n"
    "";

static const char JS_MORE[] =
    "  function more(li, ssid) {\n"
    "    var b = H.el(\"button\", \"dt-reset ssidmore\", \"ssid\");\n"
    "    b.type = \"button\";\n"
    "    b.title = \"the detail of this SSID\";\n"
    "    b.addEventListener(\"click\", function () { open(ssid); });\n"
    "    li.appendChild(b);\n"
    "    return b;\n"
    "  }\n"
    "";

static const char JS_SPAN[] =
    "  function ssidSpan(ssid, k, np, plain) {\n"
    "    var n = ssidText(ssid, k, np);\n"
    "    return plain || !window.SlothSsid ? n : SlothSsid.link(n, ssid);\n"
    "  }\n"
    "";

static const char JS_HIDDEN[] =
    "  function ssidHidden(word) {\n"
    "    var n = el(\"span\", \"d-dim\", word);\n"
    "    return window.SlothSsid ? SlothSsid.link(n, null) : n;\n"
    "  }\n"
    "";

/* Every SSID the page writes goes through ssidSpan(), which makes it a
 * link to the detail: a click, or Enter or Space through the page's one
 * keydown handler (class go, tabIndex 0). The WiFi view's places: the AP
 * table's name and its history, the hidden word, the card's scan, the
 * channel mix's list (a button of its own beside the row's), and the
 * drawer's last SSID, PNL and associations. The request carries
 * param()'s spelling of the octets and nothing built from the display
 * form: seen red with the fetch made
 * "/api/wifi/ssid?ssid=" + encodeURIComponent(disp). An SSID is set with
 * textContent through the page's own span; the module's slice of the
 * page has no title, class or dataset taken from one: seen red with
 * `node.title = ssid;` put into link(). */
static void test_page_ssid_detail(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, JS_OCTETS);
    WT_HAS(p, JS_PARAM);
    WT_HAS(p, JS_LINK);
    WT_HAS(p, JS_MORE);
    WT_HAS(p, JS_SPAN);
    WT_HAS(p, JS_HIDDEN);
    WT_HAS(p, "  function ssidText(ssid, k, np) {\n    var sp = el(\"span\", \"\", ssid);\n");
    WT_HAS(p, "    H.getJSON(\"/api/wifi/ssid?ssid=\" + encodeURIComponent(p)).then(function (j) {\n");
    /* The hooks, where the WiFi view writes a name. */
    WT_HAS(p, "    ss.appendChild(a.ssid === null ? ssidHidden(\"(hidden)\") : "
              "ssidSpan(String(a.ssid), a.ssid_k, a.ssid_np));\n"
              "    if (window.SlothSubNotes && window.SlothSsid && a.ssid !== null)\n");
    WT_HAS(p, "        hist.appendChild(ssidSpan(String(x.ssid), x.ssid_k, x.ssid_np));");
    WT_HAS(p, "      ss.appendChild(a.ssid === null ? ssidHidden(\"(hidden)\") : "
              "ssidSpan(String(a.ssid), a.ssid_k, a.ssid_np));\n      row.appendChild(ss);");
    WT_HAS(p, ": ssidSpan(String(t.ssid), t.ssid_k, t.ssid_np, true));");
    WT_HAS(p, "      if (t.kind === \"ap\" && window.SlothSsid) SlothSsid.more(li, t.ssid === undefined "
              "? null : t.ssid);\n");
    WT_HAS(p, "function (x) { return ssidSpan(String(x.ssid), x.ssid_k, x.ssid_np); }, j.ssids_more);");
    WT_HAS(p, "function ssidVal(v, k, np) { return v === null || v === undefined ? null : "
              "ssidSpan(String(v), k, np); }");
    /* No name is written but through the two: no (hidden) span of the
     * old kind is left. */
    WT_LACKS(p, "el(\"span\", \"d-dim\", \"(hidden)\") : ssidSpan(");
    WT_HAS(p, "  if (window.SlothSsid) SlothSsid.init({ el: el, getJSON: getJSON, errText: errText, "
              "keyColor: keyColor,\n");
    /* The drawer and its includes, in their places. */
    static const char *const IDS[] = { "sdrawer", "sdr-name", "sdr-note", "sdr-close", "sdr-body",
                                       "sdr-strip", "sdr-strip-note", "sdr-lists" };
    for (size_t i = 0; i < sizeof(IDS) / sizeof(IDS[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), " id=\"%s\"", IDS[i]);
        WT_EQ(count(p, want), 1);
        snprintf(want, sizeof(want), "$(\"%s\")", IDS[i]);
        if (strcmp(IDS[i], "sdr-body") && strcmp(IDS[i], "sdr-name")) WT_HAS(p, want);
    }
    WT_HAS(p, "<aside class=\"drawer\" id=\"sdrawer\" hidden aria-label=\"ssid\">");
    const char *rcss = strstr(p, ".radar-stage { position: relative;"), *scss = strstr(p, ".ssidgo { cursor: pointer;");
    const char *rjs = strstr(p, "// slothweb: the Radar view"), *sjs = strstr(p, "// slothweb: one SSID's detail");
    const char *ini = strstr(p, "window.SlothSsid) SlothSsid.init(");
    WT_ASSERT(rcss && scss && rcss < scss);
    WT_ASSERT(rjs && sjs && ini && ini < rjs && rjs < sjs);
    /* The module's own slice of the page: what it does with a name. */
    const char *e = sjs ? strstr(sjs, "  window.SlothSsid = { init: init,") : NULL;
    WT_ASSERT(e != NULL);
    if (sjs && e) {
        size_t n = (size_t)(e - sjs);
        char *m = malloc(n + 1);
        WT_ASSERT(m != NULL);
        if (m) {
            memcpy(m, sjs, n);
            m[n] = '\0';
            WT_LACKS(m, "encodeURIComponent(disp)");
            WT_LACKS(m, "encodeURIComponent(ssid)");
            WT_LACKS(m, "\"?ssid=\" + disp");
            WT_LACKS(m, ".title = ssid");
            WT_LACKS(m, ".title = String(j.ssid");
            WT_LACKS(m, "className = ssid");
            WT_LACKS(m, "dataset.ssid = ssid");
            /* The states of R5, each in words. */
            WT_HAS(m, "\"none in sloth.db's beacon_aps\"");
            WT_HAS(m, "\"no association to it in sloth.db's assocs\"");
            WT_HAS(m, "j.hidden ? \"none: a wildcard probe names no network\" : "
                      "\"no station in sloth.db's pnl_ssids asks for it\"");
            WT_HAS(m, "j.alerts_read ? \"none in the last \" + j.alerts_days + \" d\" : "
                      "\"sloth.db's alerts could not be read\"");
            WT_HAS(m, "state: /^0*$/.test(String(j.presence)) ? \"no data\" : \"\" });");
            WT_HAS(m, "$(\"sdr-note\").textContent = \"nothing under this scope: \" + String(j.reason);");
            /* Its rows open what the page already has: the device
             * drawer and the alert's page. */
            WT_HAS(m, "b.addEventListener(\"click\", function () { H.openDrawer(String(mac)); });");
            WT_HAS(m, "H.alertLink(row, a.id);");
            WT_HAS(m, "document.addEventListener(\"keydown\", function (e) { if (e.key === \"Escape\") close(); });");
            free(m);
        }
    }
}

void run_ssidview_tests(void) {
    WT_RUN(test_ssid_param);
    WT_RUN(test_ssid_param_generated);
#ifndef WITH_SQLITE
    WT_RUN(test_route_without_sqlite);
#else
    WT_RUN(test_ssid_detail);
    WT_RUN(test_ssid_on_a_large_file);
#endif
    WT_RUN(test_page_ssid_detail);
}
