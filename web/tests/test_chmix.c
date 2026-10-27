/* The WiFi view's channel mix (web_chmix.h) and SSID display form
 * (web_ssid.h): the buckets and their bounds on a pinned clock, the
 * records that feed them through the strict decoder and the metric
 * derivation, /api/wifi/channels?mix=1 through the route table over
 * memory and (WITH_SQLITE) over slothweb.db with sloth.db naming the
 * APs, and every SSID a route sends in its display form. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../src/ip_color.h"
#include "sdb_gen.h"
#include "sloth.h"
#include "web_chmix.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_metrics.h"
#include "web_routes.h"
#ifdef WITH_SQLITE
#include <sqlite3.h>
#include "web_sqlbox.h"
#endif
#include "web_ssid.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "web_wifi.h"
#include "wtest.h"
#include "wt_tmp.h"

#define T SDB_NOW

static char g_out[65536];

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static int route(const web_health_t *h, const char *path, const char *query) {
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "%s", path);
    snprintf(rq.query, sizeof(rq.query), "%s", query);
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    if (web_route(&rq, h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    g_out[r.out_len] = '\0';
    return r.status;
}

static void mac_n(uint8_t mac[6], int n) {
    mac[0] = 0x02; mac[1] = 0xde; mac[2] = 0; mac[3] = 0;
    mac[4] = (uint8_t)(n >> 8); mac[5] = (uint8_t)n;
}

/* ── the display form ─────────────────────────────────────────────── */

static const char *esc(const char *s, size_t n, int *np) {
    static char out[512];
    web_ssid_escape(s, n, out, sizeof(out), np);
    return out;
}

/* Printable UTF-8 passes; an octet that starts no sequence, C0, DEL,
 * C1, U+FFFD, a bidi override, a zero width space, a private-use and a
 * noncharacter each become their octets as \xNN, flagged; a backslash
 * is doubled and not flagged, so the form reads back one way only. */
static void test_ssid_display_form(void) {
    int np = -1;
    WT_ASSERT(!strcmp(esc("Cafe", 4, &np), "Cafe")); WT_EQ(np, 0);
    WT_ASSERT(!strcmp(esc("caf\xc3\xa9 \xf0\x9f\xa6\xa5", 10, &np), "caf\xc3\xa9 \xf0\x9f\xa6\xa5"));
    WT_EQ(np, 0);
    WT_ASSERT(!strcmp(esc("a\\b", 3, &np), "a\\\\b")); WT_EQ(np, 0);
    WT_ASSERT(!strcmp(esc("\xff\xfe-x", 4, &np), "\\xff\\xfe-x")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("a\x01" "b", 3, &np), "a\\x01b")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("a\x7f", 2, &np), "a\\x7f")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("x\xc2\x85y", 4, &np), "x\\xc2\\x85y")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("\xef\xbf\xbd", 3, &np), "\\xef\\xbf\\xbd")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("ab\xe2\x80\xae" "cd", 7, &np), "ab\\xe2\\x80\\xaecd"));
    WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("a\xe2\x80\x8b" "b", 5, &np), "a\\xe2\\x80\\x8bb")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("\xee\x80\x80", 3, &np), "\\xee\\x80\\x80")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("\xef\xbf\xbe", 3, &np), "\\xef\\xbf\\xbe")); WT_EQ(np, 1);
    /* Default_Ignorable code points and blanks that draw as a space:
     * a Hangul filler, NBSP, the grapheme joiner, a variation selector,
     * a supplementary one, an em space, a Hangul choseong filler. Seen
     * red with printable() as it was before ignorable() and
     * blank_lookalike(). */
    WT_ASSERT(!strcmp(esc("home\xe3\x85\xa4", 7, &np), "home\\xe3\\x85\\xa4")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("home\xc2\xa0", 6, &np), "home\\xc2\\xa0")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("a\xcd\x8f" "b", 4, &np), "a\\xcd\\x8fb")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("a\xef\xb8\x8f", 4, &np), "a\\xef\\xb8\\x8f")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("a\xf3\xa0\x84\x80", 5, &np), "a\\xf3\\xa0\\x84\\x80"));
    WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("a\xe2\x80\x83" "b", 5, &np), "a\\xe2\\x80\\x83b")); WT_EQ(np, 1);
    WT_ASSERT(!strcmp(esc("\xe1\x85\x9f", 3, &np), "\\xe1\\x85\\x9f")); WT_EQ(np, 1);
    /* Hangul itself, and a CJK ideograph beside the ideographic space's
     * neighbours, are printable. */
    WT_ASSERT(!strcmp(esc("\xea\xb0\x80\xe4\xb8\x80", 6, &np), "\xea\xb0\x80\xe4\xb8\x80"));
    WT_EQ(np, 0);
    /* A truncated sequence: each octet on its own. */
    WT_ASSERT(!strcmp(esc("a\xe2\x80", 3, &np), "a\\xe2\\x80")); WT_EQ(np, 1);
    /* An overlong '/' is not a slash. */
    WT_ASSERT(!strcmp(esc("\xc0\xaf", 2, &np), "\\xc0\\xaf")); WT_EQ(np, 1);
    /* Cut before a whole escape when the room runs out. */
    char small[8];
    WT_EQ(web_ssid_escape("ab\xff\xff", 4, small, sizeof(small), &np), 6);
    WT_ASSERT(!strcmp(small, "ab\\xff"));
}

/* The colour is the TUI's (src/ip_color.c ip_color_index()) over the
 * octets themselves, also where they are not UTF-8 and the display form
 * differs from them. */
static void test_ssid_colour_is_the_tuis(void) {
    static const char *const S[] = {
        "Cafe", "attwifi", "caf\xe9", "\xff\xfe-demo", "x\xc2\x85y",
        "demo-\xff\xfe-legacy", "\xef\xbf\xbd", "a\\b", "",
    };
    int seen[8] = { 0 }, differ = 0;
    for (size_t i = 0; i < sizeof(S) / sizeof(S[0]); i++) {
        WT_EQ(web_ssid_color(S[i]), ip_color_index(S[i]));
        seen[web_ssid_color(S[i])] = 1;
        char d[256];
        web_ssid_escape(S[i], strlen(S[i]), d, sizeof(d), NULL);
        if (strcmp(d, S[i]) && web_ssid_color(d) != web_ssid_color(S[i])) differ++;
    }
    int distinct = 0;
    for (int i = 0; i < 8; i++) distinct += seen[i];
    WT_ASSERT(distinct >= 4);
    /* At least one case where hashing the display form would have given
     * another colour: the test can tell which is hashed. */
    WT_ASSERT(differ >= 1);
    WT_EQ(WEB_CH_SRC_HE_6GHZ, CH_SRC_HE_6GHZ);
}

/* ── the buckets ──────────────────────────────────────────────────── */

static web_chmix_t cm;
static web_mix_row_t g_rows[64];
static int g_nrows;

static int grab(void *ctx, const web_mix_row_t *r) {
    (void)ctx;
    if (g_nrows < 64) g_rows[g_nrows] = *r;
    g_nrows++;
    return 0;
}

static void ring(long long from, long long to) {
    g_nrows = 0;
    web_chmix_each_fine(&cm, from, to, grab, NULL);
}

/* Seven transmitters in one 10 s bucket: the five busiest are named,
 * frames first and then by MAC, the other two are "other", nothing is
 * lost from the total; the bucket closes when its interval has passed,
 * not before. The order seen red with by_frames() reversed. */
static void test_top_five_and_the_rest(void) {
    WT_EQ(web_chmix_init(&cm, 0), 0);
    uint8_t mac[6];
    static const int F[7] = { 3, 50, 7, 50, 1, 9, 20 };
    for (int i = 0; i < 7; i++) {
        mac_n(mac, i + 1);
        web_chmix_add(&cm, "6", mac, i == 1 ? WEB_TX_AP : WEB_TX_CLIENT, F[i], T + 1);
    }
    web_chmix_close_due(&cm, T + 9);
    ring(T - 100, T + 100);
    WT_EQ(g_nrows, 0);                          /* still open */
    web_chmix_close_due(&cm, T + 10);
    ring(T - 100, T + 100);
    WT_EQ(g_nrows, 1);
    const web_mix_row_t *r = &g_rows[0];
    WT_ASSERT(!strcmp(r->chan, "6"));
    WT_EQ(r->t, T);
    WT_EQ(r->n, 5);
    WT_EQ(r->tx[0].frames, 50); WT_EQ(r->tx[0].mac[5], 2);   /* ...:02 before ...:04 */
    WT_EQ(r->tx[0].kind, WEB_TX_AP);
    WT_EQ(r->tx[1].frames, 50); WT_EQ(r->tx[1].mac[5], 4);
    WT_EQ(r->tx[2].frames, 20);
    WT_EQ(r->tx[3].frames, 9);
    WT_EQ(r->tx[4].frames, 7);
    WT_EQ(r->other, 4);                         /* 3 + 1 */
    /* Without a store no minute or hour bucket is kept. */
    web_mix_row_t q[4];
    WT_EQ(web_chmix_take(&cm, q, 4), 0);
    web_chmix_destroy(&cm);
}

/* A scan of one-frame MACs past WEB_CHMIX_TRACK cannot push out the
 * busy transmitters already tracked, and a heavy one first heard after
 * the scan still takes a quiet one's place. Seen red with acc_add()
 * folding every untracked transmitter into "other". */
static void test_tracking_bound(void) {
    WT_EQ(web_chmix_init(&cm, 0), 0);
    uint8_t mac[6];
    mac_n(mac, 900);
    web_chmix_add(&cm, "11", mac, WEB_TX_AP, 40, T + 2);
    for (int i = 0; i < 200; i++) {
        mac_n(mac, 1000 + i);
        web_chmix_add(&cm, "11", mac, WEB_TX_CLIENT, 1, T + 2);
    }
    mac_n(mac, 901);
    web_chmix_add(&cm, "11", mac, WEB_TX_CLIENT, 30, T + 3);
    web_chmix_close_all(&cm);
    ring(T - 10, T + 10);
    WT_EQ(g_nrows, 1);
    WT_EQ(g_rows[0].tx[0].mac[4], 900 >> 8); WT_EQ(g_rows[0].tx[0].mac[5], 900 & 255);
    WT_EQ(g_rows[0].tx[1].mac[5], 901 & 255);
    WT_EQ(g_rows[0].tx[1].frames, 30);
    unsigned long long total = g_rows[0].other;
    for (int i = 0; i < g_rows[0].n; i++) total += g_rows[0].tx[i].frames;
    WT_EQ(total, 40 + 200 + 30);
    web_chmix_stats_t st;
    web_chmix_stats(&cm, &st);
    WT_ASSERT(st.folded > 0);
    web_chmix_destroy(&cm);
}

/* A heavy transmitter first heard half way through an hour, when the
 * bucket already tracks WEB_CHMIX_TRACK others that are each far ahead
 * of any one of its samples, still enters on what it has sent since
 * (its folded frames are remembered, not lost in "other") and is
 * named with exactly those frames; nothing is lost from the total.
 * Seen red with acc_add() comparing the newcomer's single sample with
 * the quietest one's running total. */
static void test_late_heavy_transmitter_enters(void) {
    WT_EQ(web_chmix_init(&cm, 1), 0);
    uint8_t mac[6];
    long long h0 = T - ((T % 3600) + 3600) % 3600;
    for (int s = 0; s < 360; s++) {
        long long now = h0 + s * 10;
        for (int i = 0; i < WEB_CHMIX_TRACK; i++) {
            mac_n(mac, 100 + i);
            web_chmix_add(&cm, "36", mac, WEB_TX_AP, 100, now);
        }
        if (s >= 180) {
            mac_n(mac, 999);
            web_chmix_add(&cm, "36", mac, WEB_TX_AP, 300, now);
        }
    }
    web_chmix_close_all(&cm);
    static web_mix_row_t q[256];
    size_t n = web_chmix_take(&cm, q, 256);
    int hours = 0;
    for (size_t k = 0; k < n; k++) {
        if (q[k].tier != WEB_TIER_HOUR) continue;
        hours++;
        WT_EQ(q[k].tx[0].mac[4], 999 >> 8);
        WT_EQ(q[k].tx[0].mac[5], 999 & 255);
        WT_EQ(q[k].tx[0].frames, 300 * 180);
        unsigned long long total = q[k].other;
        for (int i = 0; i < q[k].n; i++) total += q[k].tx[i].frames;
        WT_EQ(total, (unsigned long long)WEB_CHMIX_TRACK * 100 * 360 + 300 * 180);
    }
    WT_EQ(hours, 1);
    web_chmix_destroy(&cm);
}

/* The bounds: past WEB_CHMIX_CHANNELS channels the least recently heard
 * is closed and evicted; the ring overwrites its oldest row and counts
 * it; with a store the minute and hour buckets queue for it. */
static void test_channel_and_ring_bounds(void) {
    WT_EQ(web_chmix_init(&cm, 1), 0);
    uint8_t mac[6];
    mac_n(mac, 1);
    for (int c = 1; c <= WEB_CHMIX_CHANNELS + 1; c++) {
        char k[8];
        snprintf(k, sizeof(k), "%d", c);
        web_chmix_add(&cm, k, mac, WEB_TX_CLIENT, 2, T + c);
    }
    web_chmix_stats_t st;
    web_chmix_stats(&cm, &st);
    WT_EQ(st.channels, WEB_CHMIX_CHANNELS);
    WT_EQ(st.channel_evictions, 1UL);
    ring(T - 10, T + 1000);
    WT_EQ(g_nrows, 1);                          /* channel 1's, closed early */
    WT_ASSERT(!strcmp(g_rows[0].chan, "1"));
    web_mix_row_t q[8];
    WT_EQ(web_chmix_take(&cm, q, 8), 2);         /* its minute and hour too */
    WT_EQ(q[0].tier + q[1].tier, WEB_TIER_MINUTE + WEB_TIER_HOUR);
    web_chmix_destroy(&cm);

    WT_EQ(web_chmix_init(&cm, 0), 0);
    for (long long b = 0; b < WEB_CHMIX_RING + 3; b++)
        web_chmix_add(&cm, "6", mac, WEB_TX_CLIENT, 1, T + b * 10);
    web_chmix_close_all(&cm);
    web_chmix_stats(&cm, &st);
    WT_EQ(st.ring_rows, WEB_CHMIX_RING);
    WT_EQ(st.ring_overwritten, 3UL);
    WT_EQ(st.ring_oldest, T + 30);
    web_chmix_destroy(&cm);
}

/* ── the records ──────────────────────────────────────────────────── */

static web_rollup_t  ru;
static web_metrics_t mx;
static web_jrec_t    rec;
static long long     g_now;

static long long pinned(void *ctx) { (void)ctx; return g_now; }

static void line(const char *s) {
    int e = web_jl_parse(s, strlen(s), &rec);
    WT_EQ(e, WEB_JL_OK);
    if (e == WEB_JL_OK) web_metrics_record(&mx, &rec);
}

/* beacon and probe_client feed the mix with their frame-count deltas,
 * each on its record's channel: an AP by its bssid (on 6g37 when its
 * channel came from the HE 6 GHz element), a station by its mac; a
 * first sight is a baseline, as for the time series; the beacon names
 * its AP. A record with no channel adds nothing. An assoc record, in
 * the shape src/jsonl.c jsonl_emit_assocs() writes it, adds nothing
 * either: its frame_count is both ends' frames (web_chmix.h). Seen red
 * with the beacon's channel_source ignored (channel 37, not 6g37) and
 * with the assoc delta credited to its sta_mac as a client. */
static void test_records_feed_the_mix(void) {
    char err[64];
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&mx, &ru, pinned, NULL), 0);
    WT_EQ(web_chmix_init(&cm, 0), 0);
    web_metrics_set_mix(&mx, &cm);
    g_now = T;
    char l[512];
    for (int k = 0; k < 2; k++) {
        snprintf(l, sizeof(l), "{\"type\":\"beacon\",\"ts\":%lld,\"ssid\":\"demo\\ufffdx\","
                 "\"bssid\":\"02:DE:00:00:00:A1\",\"channel\":37,\"channel_source\":3,"
                 "\"frame_count\":%d}", T, 100 + k * 25);
        line(l);
        snprintf(l, sizeof(l), "{\"type\":\"probe_client\",\"ts\":%lld,"
                 "\"mac\":\"0a:de:00:00:00:23\",\"ssid\":\"\",\"channel\":6,"
                 "\"first_seen\":1,\"last_seen\":%lld,\"frame_count\":%d}", T, T, 10 + k * 4);
        line(l);
        snprintf(l, sizeof(l), "{\"type\":\"assoc\",\"ts\":%lld,\"bssid\":\"02:de:00:00:00:a1\","
                 "\"sta_mac\":\"02:de:00:00:00:10\",\"ssid\":\"x\",\"sta_random\":0,"
                 "\"source\":1,\"channel\":6,\"signal_dbm\":-51,\"first_seen\":1,"
                 "\"last_seen\":%lld,\"frame_count\":%d}", T, T, 3 + k * 6);
        line(l);
        snprintf(l, sizeof(l), "{\"type\":\"probe_client\",\"ts\":%lld,"
                 "\"mac\":\"0a:de:00:00:00:24\",\"ssid\":\"\",\"first_seen\":1,"
                 "\"last_seen\":%lld,\"frame_count\":%d}", T, T, 10 + k * 50);
        line(l);
    }
    web_chmix_close_all(&cm);
    ring(T - 10, T + 10);
    WT_EQ(g_nrows, 2);
    int saw6g = 0, saw6 = 0;
    for (int i = 0; i < g_nrows && i < 64; i++) {
        const web_mix_row_t *r = &g_rows[i];
        if (!strcmp(r->chan, "6g37")) {
            saw6g = 1;
            WT_EQ(r->n, 1);
            WT_EQ(r->tx[0].frames, 25);
            WT_EQ(r->tx[0].kind, WEB_TX_AP);
            WT_EQ(r->tx[0].mac[5], 0xa1);
        }
        if (!strcmp(r->chan, "6")) {
            saw6 = 1;
            WT_EQ(r->n, 1);                   /* the prober alone */
            WT_EQ(r->tx[0].frames, 4);
            WT_EQ(r->tx[0].mac[5], 0x23);
            WT_EQ(r->tx[0].kind, WEB_TX_CLIENT);
            WT_EQ(r->other, 0);
        }
    }
    WT_ASSERT(saw6g && saw6);
    uint8_t ap[6] = { 0x02, 0xde, 0, 0, 0, 0xa1 };
    char ssid[WEB_CHMIX_SSID_MAX + 1];
    WT_EQ(web_chmix_ssid(&cm, ap, ssid), 1);
    WT_ASSERT(!strcmp(ssid, "demo\xef\xbf\xbdx"));
    /* The stream's longest form, 32 octets each U+FFFD, is kept whole,
     * not cut to a prefix that would be shown and coloured as the name;
     * a longer one (not from sloth) is not kept. Seen red with the slot
     * cut to 32 bytes. */
    char big[WEB_CHMIX_SSID_MAX + 2];
    for (int i = 0; i < 32; i++) memcpy(big + i * 3, "\xef\xbf\xbd", 3);
    big[96] = '\0';
    WT_EQ((int)strlen(big), WEB_CHMIX_SSID_MAX);
    web_chmix_name(&cm, ap, big, T + 1);
    WT_EQ(web_chmix_ssid(&cm, ap, ssid), 1);
    WT_ASSERT(!strcmp(ssid, big));
    big[96] = 'x'; big[97] = '\0';
    uint8_t ap2[6] = { 0x02, 0xde, 0, 0, 0, 0xa2 };
    web_chmix_name(&cm, ap2, big, T + 1);
    WT_EQ(web_chmix_ssid(&cm, ap2, ssid), 0);
    web_chmix_destroy(&cm);
    web_metrics_destroy(&mx);
    web_rollup_destroy(&ru);
}

/* ── the route ────────────────────────────────────────────────────── */

static web_tsdb_t   ts;
static web_m4_t     m4;
static web_health_t H;

static void mem_up(int store_on) {
    char err[64];
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, NULL, 30, 256, NULL, NULL), 0);
    WT_EQ(web_chmix_init(&cm, store_on), 0);
    web_tsdb_set_mix(&ts, &cm);
    memset(&m4, 0, sizeof(m4));
    m4.tsdb = &ts;
    m4.oui = web_oui_builtin();
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.tsdb = &ts;
    H.m4 = &m4;
}

static void mem_down(void) {
    web_chmix_destroy(&cm);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
}

/* The index of id in the answer's tx list, or -1. */
static int tx_index(const char *b, const char *id) {
    const char *tx = strstr(b, "\"tx\":[");
    const char *end = tx ? strstr(tx, "],\"channels\":") : NULL;
    if (!tx || !end) return -1;
    char want[48];
    snprintf(want, sizeof(want), "{\"id\":\"%s\"", id);
    int i = 0;
    for (const char *p = tx + 6; p < end; p++) {
        if (!strncmp(p, want, strlen(want))) return i;
        if (!strncmp(p, "{\"id\":", 6)) i++;
    }
    return -1;
}

/* The cells of a channel's row, as written. */
static const char *row_of(const char *b, const char *key) {
    char want[48];
    snprintf(want, sizeof(want), "{\"key\":\"%s\",", key);
    return strstr(b, want);
}

/* The fine tier from memory: rows in band order, a cell the merge of
 * its buckets cut to the top five with the rest in "other", each
 * transmitter once in "tx" with its kind (an AP with the stream's name
 * in its display form, the replacement character escaped and flagged),
 * an empty cell null. Seen red with by_mix_band() comparing keys alone
 * (11 before 6) and with mix_tx_json() writing the SSID through
 * web_jw_str() (the U+FFFD raw). */
static void test_mix_route_from_memory(void) {
    mem_up(0);
    uint8_t mac[6];
    for (int i = 0; i < 7; i++) {
        mac_n(mac, i + 1);
        web_chmix_add(&cm, "6", mac, i ? WEB_TX_CLIENT : WEB_TX_AP, 20 - i, T - 60);
        web_chmix_add(&cm, "6", mac, i ? WEB_TX_CLIENT : WEB_TX_AP, 20 - i, T - 50);
    }
    mac_n(mac, 1);
    web_chmix_name(&cm, mac, "demo\xef\xbf\xbd", T - 60);
    mac_n(mac, 40);
    web_chmix_add(&cm, "11", mac, WEB_TX_CLIENT, 3, T - 600);
    web_chmix_add(&cm, "6g37", mac, WEB_TX_CLIENT, 2, T - 600);
    web_chmix_close_all(&cm);
    char q[200];
    snprintf(q, sizeof(q), "mix=1&from=%lld&to=%lld&cols=60", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/channels", q), 200);
    const char *b = body_of(g_out);
    char want[300];
    snprintf(want, sizeof(want), "{\"metric\":\"wifi.mix\",\"kind\":\"counter\","
             "\"unit\":\"frames\",\"tier\":\"fine\",\"step\":10,\"from\":%lld,\"to\":%lld,"
             "\"cols\":60,\"col_s\":60,\"top\":5,\"source\":\"memory\",", T - 3600, T);
    WT_HAS(b, want);
    WT_HAS(b, "\"total_keys\":3,");
    WT_HAS(b, "{\"id\":\"02:de:00:00:00:01\",\"kind\":\"ap\",\"vendor\":null,"
              "\"ssid\":\"demo\\\\xef\\\\xbf\\\\xbd\",\"ssid_k\":");
    WT_HAS(b, ",\"ssid_np\":true,\"ssid_src\":\"stream\"}");
    WT_LACKS(b, "\xef\xbf\xbd");
    WT_LACKS(b, "\\ufffd");
    WT_HAS(b, "{\"id\":\"02:de:00:00:00:05\",\"kind\":\"client\",\"vendor\":null}");
    const char *r6 = row_of(b, "6"), *r11 = row_of(b, "11"), *r37 = row_of(b, "6g37");
    WT_ASSERT(r6 && r11 && r37 && r6 < r11 && r11 < r37);
    WT_HAS(r6, "{\"key\":\"6\",\"band\":\"2.4\",\"total\":238,\"cells\":[");
    /* Column 59 holds both buckets: 2 x (20 + 19 + 18 + 17 + 16) named,
     * 2 x (15 + 14) the rest. */
    int i1 = tx_index(b, "02:de:00:00:00:01"), i5 = tx_index(b, "02:de:00:00:00:05");
    WT_ASSERT(i1 >= 0 && i5 >= 0);
    /* ...:07 is named in "tx" (the table has room for every one) but
     * not in this cell, whose five are busier. Seen red with the cell
     * keeping every tracked transmitter. */
    int i7 = tx_index(b, "02:de:00:00:00:07");
    WT_ASSERT(i7 >= 0);
    snprintf(want, sizeof(want), ",%d,28", i7);
    WT_LACKS(r6, want);
    snprintf(want, sizeof(want), "[238,58,%d,40,", i1);
    WT_HAS(r6, want);
    snprintf(want, sizeof(want), ",%d,32]]}", i5);
    WT_HAS(r6, want);
    WT_HAS(r6, "\"cells\":[null,");
    WT_HAS(b, "\"shown\":3,\"more\":false,\"folded\":false,\"read_cut\":false}");
    /* The refusals. */
    WT_EQ(route(&H, "/api/wifi/channels", "mix=2"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_mix\"}");
    WT_EQ(route(&H, "/api/wifi/channels", "mix=1&metric=ap_count"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"mix_takes_no_metric\"}");
    WT_EQ(route(&H, "/api/wifi/channels", "mix=1&cols=0"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_cols\"}");
    ts.mix = NULL;
    WT_EQ(route(&H, "/api/wifi/channels", "mix=1"), 503);
    WT_HAS(body_of(g_out), "{\"error\":\"no_channel_mix\"}");
    ts.mix = &cm;
    /* The plain grid is as it was. */
    WT_EQ(route(&H, "/api/wifi/channels", ""), 200);
    WT_LACKS(body_of(g_out), "wifi.mix");
    mem_down();
}

/* The worst answer still fits: 64 channels, every cell of 96 holding
 * five transmitters of ten-digit counts and a ten-digit rest, every AP
 * named with an SSID that escapes every octet. The answer stops at a
 * whole row with "more", never mid-row, and never overflows. */
static void test_mix_route_worst_case_fits(void) {
    mem_up(0);
    uint8_t mac[6];
    char name[33];
    memset(name, 0xff, 32);
    name[32] = '\0';
    int n = 0;
    for (int c = 0; c < WEB_CHMIX_CHANNELS; c++) {
        char k[8];
        snprintf(k, sizeof(k), "%d", c < 14 ? c + 1 : c + 22);
        for (int col = 0; col < 96; col++)
            for (int i = 0; i < 6; i++) {
                mac_n(mac, (n++ % 2000) + 1);
                web_chmix_add(&cm, k, mac, i % 2 ? WEB_TX_AP : WEB_TX_CLIENT,
                              3e9 + i, T - 3600 + col * 37 + 1);
                if (i % 2) web_chmix_name(&cm, mac, name, T);
            }
    }
    web_chmix_close_all(&cm);
    char q[160];
    snprintf(q, sizeof(q), "mix=1&from=%lld&to=%lld", T - 3600, T);
    WT_EQ(route(&H, "/api/wifi/channels", q), 200);
    const char *b = body_of(g_out);
    size_t bl = strlen(b);
    WT_ASSERT(bl > 0 && bl < sizeof(g_out) - WEB_LIVE_HDR_RESERVE);
    WT_ASSERT(bl > 2 && b[bl - 1] == '\n' && b[bl - 2] == '}');
    WT_HAS(b, "\"more\":true");
    WT_HAS(b, "\"folded\":true");
    WT_HAS(b, "]}],\"shown\":");
    WT_LACKS(b, "\"shown\":0,");
    mem_down();
}

/* /api/health says what the mix holds and dropped. */
static void test_mix_on_health(void) {
    mem_up(0);
    uint8_t mac[6];
    mac_n(mac, 1);
    web_chmix_add(&cm, "1", mac, WEB_TX_CLIENT, 5, T);
    WT_EQ(route(&H, "/api/health", ""), 200);
    WT_HAS(body_of(g_out), "\"chmix\":{\"channels\":1,\"samples\":1,\"ring_rows\":0,");
    mem_down();
}

/* ── the page ─────────────────────────────────────────────────────── */

#ifdef WITH_SQLITE

static char g_dir[TEST_TMP_MAX];
static web_store_t st;
static web_slothdb_t sdb;

/* The minute tier from slothweb.db, the APs named from sloth.db with
 * the octets sloth stored (not UTF-8 here): the display form escapes
 * them, and the colour is the TUI's over those octets, not over the
 * display form or the U+FFFD the stream would have carried. A BSSID
 * sloth.db does not know falls back to the stream's name. Seen red
 * with mix_tx_json() preferring the stream's name. */
static void test_mix_route_from_the_store(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-chmix-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char p[160], db[160], err[512];
    snprintf(p, sizeof(p), "%s/slothweb.db", g_dir);
    snprintf(db, sizeof(db), "%s/sloth.db", g_dir);
    WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    WT_EQ(sdb_make(db, db_schema_version(), 0), 0);
    WT_EQ(sdb_exec(db, "INSERT INTO beacon_aps (bssid,ssid,first_seen,last_seen)"
                       " VALUES ('02:de:00:00:00:01',"
                       " CAST(X'64656d6fff' AS TEXT),1,2)"), 0);
    web_slothdb_init(&sdb, db, NULL);
    mem_up(1);
    ts.store = &st;
    m4.sdb = &sdb;
    uint8_t mac[6];
    mac_n(mac, 1);
    web_chmix_name(&cm, mac, "streamname", T);
    uint8_t mac2[6];
    mac_n(mac2, 2);
    web_chmix_name(&cm, mac2, "only-on-the-stream", T);
    web_mix_row_t r[2];
    memset(r, 0, sizeof(r));
    snprintf(r[0].chan, sizeof(r[0].chan), "149");
    r[0].tier = WEB_TIER_MINUTE;
    r[0].t = T - 2 * 86400 + 120;
    r[0].n = 2;
    memcpy(r[0].tx[0].mac, mac, 6);
    r[0].tx[0].kind = WEB_TX_AP;
    r[0].tx[0].frames = 70;
    memcpy(r[0].tx[1].mac, mac2, 6);
    r[0].tx[1].kind = WEB_TX_AP;
    r[0].tx[1].frames = 20;
    r[0].other = 10;
    r[1] = r[0];
    r[1].tier = WEB_TIER_FINE;            /* never written */
    WT_EQ(web_store_mix_write(&st, r, 2), 0);
    char q[160];
    snprintf(q, sizeof(q), "mix=1&from=%lld&to=%lld&cols=24", T - 2 * 86400, T - 86400);
    WT_EQ(route(&H, "/api/wifi/channels", q), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"tier\":\"minute\",\"step\":60,");
    WT_HAS(b, "\"source\":\"store\",\"ring_from\":null,\"db\":\"open\",");
    char want[200];
    snprintf(want, sizeof(want), "{\"id\":\"02:de:00:00:00:01\",\"kind\":\"ap\","
             "\"vendor\":null,\"ssid\":\"demo\\\\xff\",\"ssid_k\":%d,"
             "\"ssid_np\":true,\"ssid_src\":\"sloth.db\"}", ip_color_index("demo\xff"));
    WT_HAS(b, want);
    WT_ASSERT(ip_color_index("demo\xff") != web_ssid_color("demo\\xff") ||
              ip_color_index("demo\xff") != web_ssid_color("demo\xef\xbf\xbd"));
    WT_HAS(b, "\"ssid\":\"only-on-the-stream\",\"ssid_k\":");
    WT_HAS(b, "\"ssid_src\":\"stream\"}");
    WT_LACKS(b, "streamname");
    WT_HAS(b, "{\"key\":\"149\",\"band\":\"5\",\"total\":100,\"cells\":[[100,10,0,70,1,20],");
    mem_down();
    web_slothdb_destroy(&sdb);
    web_store_close(&st);
    const char *files[] = { "sloth.db", "slothweb.db", "slothweb.db-wal",
                            "slothweb.db-shm", "sloth.db-wal", "sloth.db-shm" };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", g_dir, files[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

/* Every SSID a route reads from sloth.db goes out in its display form:
 * the AP table's SSID and history, the drawer's last SSID, PNL SSIDs
 * and associations, the History view's new APs and probe clients
 * (/api/sessions/new), and the SQL box's ssid and title columns
 * (web_sqlbox_run_db(), what /api/query runs); an alert title, which
 * sloth can write an SSID into, goes out in it on /api/history/alerts.
 * sloth stores high octets as they came (src/dot11_ie.c), so a raw 0xff
 * here would have reached the page as U+FFFD. Seen red with ap_json()
 * writing the SSID through jw_text_or_null(), with emit_new() writing
 * every label through it, with ssid_column() answering 0, and with
 * emit_alert() writing the title through it. */
static void test_every_db_ssid_is_escaped(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-ssid-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char db[160], p[160];
    snprintf(db, sizeof(db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(db, db_schema_version(), 0), 0);
    WT_EQ(sdb_exec(db,
        "INSERT INTO beacon_aps (bssid,ssid,channel,first_seen,last_seen) VALUES"
        " ('02:de:00:00:00:a7',CAST(X'64656d6fff2d78' AS TEXT),11,1,2);"
        "INSERT INTO beacon_ap_ssids (bssid,ssid,first_seen,last_seen) VALUES"
        " ('02:de:00:00:00:a7',CAST(X'64656d6fff2d78' AS TEXT),1,2),"
        " ('02:de:00:00:00:a7','plain',1,2);"
        "INSERT INTO devices (mac,last_ssid,is_ap,sources,first_seen,last_seen) VALUES"
        " ('02:de:00:00:00:10',CAST(X'64656d6fff2d78' AS TEXT),0,32,1,2);"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
        " ('02:de:00:00:00:10',CAST(X'78c28579' AS TEXT),1,2);"
        "INSERT INTO assocs (bssid,sta_mac,ssid,source,channel,first_seen,last_seen)"
        " VALUES ('02:de:00:00:00:a7','02:de:00:00:00:10',CAST(X'64656d6fff2d78' AS TEXT),"
        " 1,11,1,2);"
        "INSERT INTO sessions (id,started,ended,site_label) VALUES"
        " (1,0,1000,'a'),(2,1000000,NULL,'b');"
        "INSERT INTO beacon_aps (bssid,ssid,first_seen,last_seen) VALUES"
        " ('02:de:00:00:00:b1',CAST(X'6e6574ff' AS TEXT),2000000,2000001);"
        "INSERT INTO probe_clients (mac,ssid,first_seen,last_seen) VALUES"
        " ('02:de:00:00:00:c1',CAST(X'70ff71' AS TEXT),2000000,2000001);"), 0);
    char asql[400];
    snprintf(asql, sizeof(asql),
             "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,"
             "technique,match_ip,match_port,count) VALUES ('k',%lld,%lld,1,1,"
             "CAST(X'6576696ce280ae78' AS TEXT),'d','',NULL,NULL,1)", T - 100, T - 50);
    WT_EQ(sdb_exec(db, asql), 0);
    web_slothdb_init(&sdb, db, NULL);
    mem_up(0);
    m4.sdb = &sdb;
    WT_EQ(route(&H, "/api/wifi/aps", ""), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"ssid\":\"demo\\\\xff-x\",\"signal\"");
    WT_HAS(b, "{\"ssid\":\"demo\\\\xff-x\",\"first_seen\":1,\"last_seen\":2,"
              "\"ssid_k\":");
    WT_HAS(b, "{\"ssid\":\"plain\",\"first_seen\":1,\"last_seen\":2,\"ssid_k\":");
    char want[96];
    snprintf(want, sizeof(want), ",\"ssid_k\":%d,\"ssid_np\":true}",
             ip_color_index("demo\xff-x"));
    WT_HAS(b, want);
    WT_LACKS(b, "\\ufffd");
    WT_EQ(route(&H, "/api/device/02:de:00:00:00:10", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"ssid\":\"demo\\\\xff-x\",\"signal\"");
    WT_HAS(b, "{\"ssid\":\"x\\\\xc2\\\\x85y\",\"ssid_k\":");
    WT_HAS(b, "\"ssid\":\"demo\\\\xff-x\",\"source\":1,\"channel\":11,");
    WT_LACKS(b, "\\ufffd");
    WT_LACKS(b, "\\u0085");
    WT_EQ(route(&H, "/api/devices", ""), 200);
    WT_HAS(body_of(g_out), "\"ssid\":\"demo\\\\xff-x\",\"signal\"");
    WT_LACKS(body_of(g_out), "\\ufffd");
    /* History's new APs and probe clients. */
    WT_EQ(route(&H, "/api/sessions/new", "id=2"), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"ident\":\"02:de:00:00:00:b1\",\"label\":\"net\\\\xff\",");
    WT_HAS(b, "{\"ident\":\"02:de:00:00:00:c1\",\"label\":\"p\\\\xffq\",");
    WT_HAS(b, ",\"label_np\":true}");
    WT_LACKS(b, "\\ufffd");
    /* An alert title. */
    char hq[96];
    snprintf(hq, sizeof(hq), "from=%lld&to=%lld", T - 1000, T);
    WT_EQ(route(&H, "/api/history/alerts", hq), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"title\":\"evil\\\\xe2\\\\x80\\\\xaex\",");
    WT_LACKS(b, "\xe2\x80\xae");
    /* The SQL box. */
    sqlite3 *h = NULL;
    WT_EQ(sqlite3_open_v2(db, &h, SQLITE_OPEN_READONLY, NULL), SQLITE_OK);
    static char out[1 << 14];
    web_sqlbox_lim_t lim = { 1000, 100, sizeof(out) - 1024 };
    web_sqlbox_res_t res;
    static const char sq[] = "SELECT b.ssid AS ap_ssid, p.ssid, a.title FROM beacon_aps b,"
                             " probe_clients p, alerts a WHERE b.bssid='02:de:00:00:00:b1'";
    size_t ol = web_sqlbox_run_db(h, sq, strlen(sq), &lim, out, sizeof(out), &res);
    WT_ASSERT(ol > 0 && ol < sizeof(out));
    out[ol < sizeof(out) ? ol : sizeof(out) - 1] = '\0';
    WT_HAS(out, "[\"net\\\\xff\",\"p\\\\xffq\",\"evil\\\\xe2\\\\x80\\\\xaex\"]");
    WT_LACKS(out, "\\ufffd");
    WT_LACKS(out, "\xe2\x80\xae");
    sqlite3_close(h);
    mem_down();
    web_slothdb_destroy(&sdb);
    const char *files[] = { "sloth.db", "sloth.db-wal", "sloth.db-shm" };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", g_dir, files[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

#endif

/* The stream's SSIDs on the ticker are in their display form too. */
static void test_ticker_ssid_escaped(void) {
    web_live_t l;
    web_live_init(&l, "unix:/x");
    static web_jrec_t r2;
    const char *s = "{\"type\":\"beacon\",\"ts\":5,\"ssid\":\"evil\\u202ecod\\ufffd\"}";
    WT_EQ(web_jl_parse(s, strlen(s), &r2), WEB_JL_OK);
    web_live_apply(&l, &r2, 1000);
    web_live_rec_t recs[4];
    unsigned long long latest = 0;
    int n = web_live_recent_after(&l, 0, recs, 4, &latest);
    WT_EQ(n, 1);
    if (n == 1) {
        WT_ASSERT(!strcmp(recs[0].text, "evil\\xe2\\x80\\xaecod\\xef\\xbf\\xbd"));
    }
    web_live_destroy(&l);
}

/* An alert's title and detail, which sloth writes an SSID into as it
 * came (src/alerts/rules_twin.c), reach the alerts list and the ticker
 * in the display form: the stream's U+202E, U+FFFD and a Hangul filler
 * escaped, never raw. The detail is kept only for an audited type
 * (web_alertfmt.h), so the record names one; test_alert_detail_withheld
 * below has the other side. Seen red with alert_record() copying title
 * and detail as they were and, apart, with summarise() joining them
 * unescaped. */
static void test_alert_text_escaped(void) {
    web_live_t l;
    web_live_init(&l, "unix:/x");
    static web_jrec_t r2;
    char s[512];
    snprintf(s, sizeof(s),
             "{\"type\":\"alert.create\",\"ts\":5,\"incident_id\":\"i1\",\"sev\":1,"
             "\"ty\":%d,\"title\":\"Open setup AP home\xe3\x85\xa4\","
             "\"detail\":\"ssid=evil\xe2\x80\xae" "cod\\ufffd\"}",
             (int)ALERT_TYPE_EVIL_TWIN_PROXIMITY);
    WT_EQ(web_jl_parse(s, strlen(s), &r2), WEB_JL_OK);
    web_live_apply(&l, &r2, 1000);
    static char j[65536];
    size_t n = web_live_json(&l, j, sizeof(j), 1000);
    WT_ASSERT(n > 0);
    if (!n) j[0] = '\0';
    WT_HAS(j, "\"title\":\"Open setup AP home\\\\xe3\\\\x85\\\\xa4\"");
    WT_HAS(j, "\"detail\":\"ssid=evil\\\\xe2\\\\x80\\\\xaecod\\\\xef\\\\xbf\\\\xbd\"");
    WT_LACKS(j, "\xe2\x80\xae");
    WT_LACKS(j, "\xef\xbf\xbd");
    WT_LACKS(j, "\xe3\x85\xa4");
    web_live_rec_t recs[4];
    unsigned long long latest = 0;
    int k = web_live_recent_after(&l, 0, recs, 4, &latest);
    WT_EQ(k, 1);
    if (k == 1) {
        WT_ASSERT(!strcmp(recs[0].text, "Open setup AP home\\xe3\\x85\\xa4 "
                                        "ssid=evil\\xe2\\x80\\xaecod\\xef\\xbf\\xbd"));
        WT_ASSERT(!strstr(recs[0].text, "\xe2\x80\xae"));
    }
    web_live_destroy(&l);
}

/* The same record for a type whose detail is not audited
 * (OPEN_SETUP_AP): the title still in the display form, the detail
 * neither kept nor in the ticker, escaped or raw. Seen red with
 * alert_record() and summarise() escaping the detail before the gate. */
static void test_alert_detail_withheld(void) {
    web_live_t l;
    web_live_init(&l, "unix:/x");
    static web_jrec_t r2;
    char s[512];
    snprintf(s, sizeof(s),
             "{\"type\":\"alert.create\",\"ts\":5,\"incident_id\":\"i1\",\"sev\":1,"
             "\"ty\":%d,\"title\":\"Open setup AP home\xe3\x85\xa4\","
             "\"detail\":\"ssid=evil\xe2\x80\xae" "cod\\ufffd\"}",
             (int)ALERT_TYPE_OPEN_SETUP_AP);
    WT_EQ(web_jl_parse(s, strlen(s), &r2), WEB_JL_OK);
    web_live_apply(&l, &r2, 1000);
    static char j[65536];
    size_t n = web_live_json(&l, j, sizeof(j), 1000);
    WT_ASSERT(n > 0);
    if (!n) j[0] = '\0';
    WT_HAS(j, "\"title\":\"Open setup AP home\\\\xe3\\\\x85\\\\xa4\"");
    WT_HAS(j, "\"detail\":\"\"");
    WT_LACKS(j, "ssid=evil");
    web_live_rec_t recs[4];
    unsigned long long latest = 0;
    int k = web_live_recent_after(&l, 0, recs, 4, &latest);
    WT_EQ(k, 1);
    if (k == 1) {
        WT_ASSERT(!strcmp(recs[0].text, "Open setup AP home\\xe3\\x85\\xa4"));
        WT_ASSERT(!strstr(recs[0].text, "ssid"));
    }
    web_live_destroy(&l);
}

void run_chmix_tests(void) {
    WT_RUN(test_ssid_display_form);
    WT_RUN(test_ssid_colour_is_the_tuis);
    WT_RUN(test_top_five_and_the_rest);
    WT_RUN(test_tracking_bound);
    WT_RUN(test_late_heavy_transmitter_enters);
    WT_RUN(test_channel_and_ring_bounds);
    WT_RUN(test_records_feed_the_mix);
    WT_RUN(test_mix_route_from_memory);
    WT_RUN(test_mix_route_worst_case_fits);
    WT_RUN(test_mix_on_health);
    WT_RUN(test_ticker_ssid_escaped);
    WT_RUN(test_alert_text_escaped);
    WT_RUN(test_alert_detail_withheld);
#ifdef WITH_SQLITE
    WT_RUN(test_mix_route_from_the_store);
    WT_RUN(test_every_db_ssid_is_escaped);
#endif
}
