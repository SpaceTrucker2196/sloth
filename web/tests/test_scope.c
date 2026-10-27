/* The capture scope (web_scope.h, owner request 2026-10-26): the top
 * bar's Monitor / Hybrid / Local switch. The tables are held to the
 * files they classify (include/sloth_alerts.def, web_live.c's
 * POLL_TYPES, src/device_risk.c's weights, app.js's monitor-row types);
 * the parameter step is held to the shared parser's rules; and every
 * route is asked under each scope against one fixture that holds data of
 * both kinds and one MAC seen both ways, through the route table, so
 * each scope is seen to show its own data and none of the other's.
 * Hybrid is held to the answer without a scope byte for byte, the echo
 * aside.
 *
 * Every absence assertion here was seen red before it was trusted, by
 * the mutation named beside it, and the tree restored byte for byte. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_alertkb.h"
#include "web_anomaly.h"
#include "web_assets.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_metrics.h"
#include "web_routes.h"
#include "web_scope.h"
#include "web_series.h"
#include "web_slothdb.h"
#include "web_tsdb.h"
#include "wtest.h"

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 1 << 16, n = 0, r;
    char *b = malloc(cap + 1);
    while (b && (r = fread(b + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) {
            char *nb = realloc(b, cap * 2 + 1);
            if (!nb) { free(b); b = NULL; break; }
            b = nb;
            cap *= 2;
        }
    }
    fclose(f);
    if (b) b[n] = '\0';
    return b;
}

/* ── the tables ─────────────────────────────────────────────────────── */

/* Every row of include/sloth_alerts.def is classified, once, in order,
 * and only the two own-state kinds (tests/test_research_corpus.c's
 * list) are META. Seen red with CAPTIVE_PORTAL's row removed (the
 * names fell out of step from there) and with PROBE_FLOOD tagged META. */
static void test_alert_table_is_the_def(void) {
    char *def = slurp("include/sloth_alerts.def");
    WT_ASSERT(def != NULL);
    if (!def) return;
    int n = 0;
    for (char *p = def; p; ) {
        if (!strncmp(p, "X(", 2)) {
            const char *a = p + 2, *c = strchr(a, ',');
            WT_ASSERT(c != NULL);
            if (c && n < web_scope_alerts_n) {
                const char *nm = web_scope_alerts[n].name;
                int same = strlen(nm) == (size_t)(c - a) && !strncmp(nm, a, (size_t)(c - a));
                if (!same) fprintf(stderr, "    row %d is %s, the .def says %.*s\n",
                                   n, nm, (int)(c - a), a);
                WT_ASSERT(same);
            }
            n++;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    free(def);
    WT_EQ(n, web_scope_alerts_n);
    WT_EQ(web_akb_n, web_scope_alerts_n);
    int meta = 0;
    for (int i = 0; i < web_scope_alerts_n; i++) {
        int t = web_scope_alerts[i].tag;
        WT_ASSERT(t == WEB_SC_M || t == WEB_SC_META ||
                  t == (WEB_SC_L | WEB_SC_IPCAP));
        if (t == WEB_SC_META) {
            meta++;
            WT_ASSERT(!strcmp(web_scope_alerts[i].name, "NO_MONITOR_MODE") ||
                      !strcmp(web_scope_alerts[i].name, "BT_OWN_TRANSMIT"));
        }
        if (i < web_akb_n) WT_ASSERT(!strcmp(web_akb[i].name, web_scope_alerts[i].name));
    }
    WT_EQ(meta, 2);
    /* The rule's input, not its file: the overrides the survey named. */
    static const struct { const char *n; int tag; } O[] = {
        { "CAPTIVE_PORTAL", WEB_SC_L }, { "CAM_SETUP_OUI", WEB_SC_M },
        { "BEACONING", WEB_SC_L }, { "ATTACK_PATH", WEB_SC_L },
        { "WEAK_TLS", WEB_SC_L }, { "CAM_MDNS_SERVICE", WEB_SC_L },
        { "CAM_SSDP_DEVICE", WEB_SC_L }, { "ROGUE_RADIUS", WEB_SC_M },
        { "MY_NETWORK_RECON", WEB_SC_M }, { "BLE_WATCHLIST", WEB_SC_M },
        { "DEAUTH_FLOOD", WEB_SC_M }, { "PORT_SCAN", WEB_SC_L },
    };
    for (size_t k = 0; k < sizeof(O) / sizeof(O[0]); k++)
        for (int i = 0; i < web_scope_alerts_n; i++)
            if (!strcmp(web_scope_alerts[i].name, O[k].n))
                WT_EQ(web_scope_eff(web_scope_alert(i), 0), O[k].tag);
    WT_EQ(web_scope_alert(-1), 0);
    WT_EQ(web_scope_alert(web_scope_alerts_n), 0);
}

/* Every record type the poll thread writes (web_live.c's POLL_TYPES,
 * read from the source) and every type the capture thread writes has a
 * tag; app.js's monitor-row types are all Monitor's. Seen red with
 * "wifi_mld" removed from the table. */
static void test_record_types_are_classified(void) {
    char *src = slurp("web/src/web_live.c");
    WT_ASSERT(src != NULL);
    if (!src) return;
    const char *p = strstr(src, "POLL_TYPES[] = {");
    const char *e = p ? strstr(p, "NULL") : NULL;
    WT_ASSERT(p && e);
    int n = 0;
    for (const char *q = p; q && e && q < e; ) {
        const char *a = strchr(q, '"');
        if (!a || a > e) break;
        const char *b = strchr(a + 1, '"');
        char t[40];
        snprintf(t, sizeof(t), "%.*s", (int)(b - a - 1), a + 1);
        if (!web_scope_record(t)) fprintf(stderr, "    %s has no tag\n", t);
        WT_ASSERT(web_scope_record(t) != 0);
        n++;
        q = b + 1;
    }
    WT_ASSERT(n > 40);
    free(src);
    static const char *const cap[] = { "dns", "tls", "quic", "http", "ntp", "icmp",
                                       "cleartext_cred", "alert", "socket_gap" };
    for (size_t i = 0; i < sizeof(cap) / sizeof(cap[0]); i++)
        if (strcmp(cap[i], "alert")) WT_ASSERT(web_scope_record(cap[i]) != 0);
    char *js = slurp("web/ui/app.js");
    WT_ASSERT(js != NULL);
    if (!js) return;
    p = strstr(js, "var MON_TYPES = [");
    e = p ? strstr(p, "];") : NULL;
    WT_ASSERT(p && e);
    int m = 0;
    for (const char *q = p; q && e && q < e; ) {
        const char *a = strchr(q, '"');
        if (!a || a > e) break;
        const char *b = strchr(a + 1, '"');
        char t[40];
        snprintf(t, sizeof(t), "%.*s", (int)(b - a - 1), a + 1);
        WT_EQ(web_scope_record(t), WEB_SC_M);
        m++;
        q = b + 1;
    }
    WT_EQ(m, 15);
    free(js);
    /* By what heard them. */
    WT_EQ(web_scope_record("ble_device"), WEB_SC_M);
    WT_EQ(web_scope_record("wifi_sta"), WEB_SC_L);
    WT_EQ(web_scope_record("wifi_ap"), WEB_SC_L);
    WT_EQ(web_scope_record("arp"), WEB_SC_L | WEB_SC_IPCAP);
    WT_EQ(web_scope_record("sensor_health"), WEB_SC_META);
    WT_EQ(web_scope_record("iface"), WEB_SC_BYKEY);
    WT_EQ(web_scope_record("device"), WEB_SC_BYKEY);
    WT_EQ(web_scope_record("not_a_type_yet"), 0);
}

/* sloth's risk weights and buckets (src/device_risk.c), read from the
 * source, are the ones the scopes recompute with. Seen red with
 * ALERT_TAGGED's weight in web_scope.c set to 2. */
static void test_risk_weights_are_sloths(void) {
    char *src = slurp("src/device_risk.c");
    WT_ASSERT(src != NULL);
    if (!src) return;
    static const char *const BIT[6] = {
        "DEV_RISK_RANDOM_MAC;", "DEV_RISK_UNKNOWN_VENDOR;", "DEV_RISK_NO_HOSTNAME;",
        "DEV_RISK_PROBE_ONLY;", "DEV_RISK_CLEARTEXT_CRED;", "DEV_RISK_ALERT_TAGGED;",
    };
    for (int b = 0; b < 6; b++) {
        const char *p = strstr(src, BIT[b]);
        const char *s = p ? strstr(p, "score += ") : NULL;
        WT_ASSERT(s != NULL);
        if (!s) continue;
        int w = atoi(s + 9);
        /* The weight alone decides the level of a device with only it. */
        WT_EQ(web_scope_risk_level(1LL << b), w >= 5 ? 3 : w >= 3 ? 2 : w >= 1 ? 1 : 0);
    }
    WT_HAS(src, "if      (score >= 5) level = DEV_RISK_CRIT;");
    WT_HAS(src, "else if (score >= 3) level = DEV_RISK_HIGH;");
    WT_HAS(src, "else if (score >= 1) level = DEV_RISK_MED;");
    free(src);
    WT_EQ(web_scope_risk_level(0), 0);
    WT_EQ(web_scope_risk_level(1 | 2), 1);           /* 2: MED */
    WT_EQ(web_scope_risk_level(1 | 2 | 4), 2);       /* 3: HIGH */
    WT_EQ(web_scope_risk_level(16 | 1 | 2), 3);      /* 5: CRIT */
    /* What each scope sees of the signals. */
    WT_EQ(web_scope_risk_mask(WEB_SCOPE_MONITOR), 1 | 2 | 8);
    WT_EQ(web_scope_risk_mask(WEB_SCOPE_LOCAL), 1 | 2 | 4 | 16 | 32);
    WT_EQ(web_scope_risk_mask(WEB_SCOPE_HYBRID), 0x3f);
}

static void test_tags(void) {
    WT_EQ(web_scope_find("monitor"), WEB_SCOPE_MONITOR);
    WT_EQ(web_scope_find("hybrid"), WEB_SCOPE_HYBRID);
    WT_EQ(web_scope_find("local"), WEB_SCOPE_LOCAL);
    WT_EQ(web_scope_find("Monitor"), -1);
    WT_EQ(web_scope_find(""), -1);
    WT_ASSERT(!strcmp(web_scope_word(WEB_SCOPE_LOCAL), "local"));
    /* META passes every scope; 0 Hybrid only. */
    WT_ASSERT(web_scope_pass(WEB_SCOPE_MONITOR, WEB_SC_META));
    WT_ASSERT(web_scope_pass(WEB_SCOPE_LOCAL, WEB_SC_META));
    WT_ASSERT(!web_scope_pass(WEB_SCOPE_MONITOR, 0));
    WT_ASSERT(web_scope_pass(WEB_SCOPE_HYBRID, 0));
    WT_ASSERT(!web_scope_pass(WEB_SCOPE_LOCAL, WEB_SC_M));
    WT_ASSERT(!web_scope_pass(WEB_SCOPE_MONITOR, WEB_SC_L));
    /* The IP capture on a radio: its records are Monitor's. */
    WT_EQ(web_scope_eff(WEB_SC_L | WEB_SC_IPCAP, 0), WEB_SC_L);
    WT_EQ(web_scope_eff(WEB_SC_L | WEB_SC_IPCAP, 1), WEB_SC_M);
    WT_EQ(web_scope_eff(WEB_SC_L, 1), WEB_SC_L);       /* /proc stays Local */
    WT_ASSERT(web_scope_ip_on_radio(127, "eth0", "wlan0mon"));
    WT_ASSERT(!web_scope_ip_on_radio(1, "wlan0mon", "wlan0mon"));
    WT_ASSERT(web_scope_ip_on_radio(-1, "wlan0mon", "wlan0mon"));
    WT_ASSERT(!web_scope_ip_on_radio(-1, "eth0", "wlan0mon"));
    WT_ASSERT(!web_scope_ip_on_radio(-1, "", ""));
    /* A device by its sources and camera signals. */
    WT_EQ(web_scope_device(1, -1, ""), WEB_SC_L);           /* ARP */
    WT_EQ(web_scope_device(16, -1, ""), WEB_SC_M);          /* probe */
    WT_EQ(web_scope_device(1 | 16, -1, ""), WEB_SC_META);   /* both */
    WT_EQ(web_scope_device(32, -1, NULL), WEB_SC_L);        /* STA */
    WT_EQ(web_scope_device(64, 2, ""), WEB_SC_M);           /* setup SSID */
    WT_EQ(web_scope_device(64, 8, ""), WEB_SC_L);           /* SSDP */
    WT_EQ(web_scope_device(64, -1, ""), 0);                 /* unknown kind */
    WT_EQ(web_scope_device(0, -1, "10.0.0.1"), WEB_SC_L);   /* an address */
    /* Interfaces by the radios named. */
    web_scope_ctx_t c;
    memset(&c, 0, sizeof(c));
    WT_EQ(web_scope_iface("wlan0mon", &c), WEB_SC_L);
    web_scope_note_mon(&c, "wlan0mon");
    web_scope_note_mon(&c, "wlan0mon");
    web_scope_note_mon(&c, "");
    WT_EQ(c.nmon, 1);
    WT_EQ(web_scope_iface("wlan0mon", &c), WEB_SC_M);
    WT_EQ(web_scope_iface("eth0", &c), WEB_SC_L);
    WT_EQ(web_scope_metric_key(WM_IFACE_RX, "wlan0mon", &c), WEB_SC_M);
    WT_EQ(web_scope_metric_key(WM_IFACE_RX, "eth0", &c), WEB_SC_L);
    WT_EQ(web_scope_metric_key(WM_ALERTS_FIRED, "1", &c), WEB_SC_M);   /* DEAUTH_FLOOD */
    WT_EQ(web_scope_metric_key(WM_ALERTS_FIRED, "0", &c), WEB_SC_L);   /* PORT_SCAN */
    WT_EQ(web_scope_metric_key(WM_ALERTS_FIRED, "x", &c), 0);
    WT_EQ(web_scope_metric_key(WM_DNS_QUERIES, "10.0.0.1", &c), WEB_SC_L);
    WT_EQ(web_scope_metric_key(WM_WIFI_DEAUTH, "02:00:00:00:00:01", &c), WEB_SC_M);
    WT_EQ(web_scope_metric_key(WM_DEV_PRESENT, "02:00:00:00:00:01", &c), 0);
    WT_EQ(web_scope_metric_key(WM_DEV_PRESENT_MON, "02:00:00:00:00:01", &c), WEB_SC_M);
    WT_EQ(web_scope_metric_key(WM_DEV_PRESENT_LOC, "02:00:00:00:00:01", &c), WEB_SC_L);
    /* Every metric is either one scope's, by its key, or Hybrid's. */
    for (int m = 0; m < WM_COUNT; m++) {
        int t = web_scope_metric(m);
        WT_ASSERT(t == 0 || t == WEB_SC_M || t == WEB_SC_L || t == WEB_SC_BYKEY ||
                  t == (WEB_SC_L | WEB_SC_IPCAP));
    }
    int ty[128];
    int nm = web_scope_alert_types(WEB_SCOPE_MONITOR, 0, ty, 128);
    int nl = web_scope_alert_types(WEB_SCOPE_LOCAL, 0, ty, 128);
    int nh = web_scope_alert_types(WEB_SCOPE_HYBRID, 0, ty, 128);
    WT_EQ(nh, web_scope_alerts_n);
    WT_EQ(nm + nl, web_scope_alerts_n + 2);   /* the two own-state types twice */
    WT_EQ(web_scope_alert_types(WEB_SCOPE_LOCAL, 1, ty, 128), 2);  /* radio: META only */
}

/* The shared parser's scope step: the pair out, the rest byte for byte,
 * the value decoded as every parameter is, each refusal a word of ours.
 * The absence of scope in rest seen red with the scope branch disabled,
 * every segment copied to rest. */
static void test_take(void) {
    char rest[512], err[48];
    int s, g;
    WT_EQ(web_scope_take("", rest, sizeof(rest), &s, &g, err, sizeof(err)), 0);
    WT_EQ(s, WEB_SCOPE_HYBRID); WT_EQ(g, 0); WT_ASSERT(!strcmp(rest, ""));
    WT_EQ(web_scope_take("q=x&scope=monitor&limit=5", rest, sizeof(rest), &s, &g,
                         err, sizeof(err)), 0);
    WT_EQ(s, WEB_SCOPE_MONITOR); WT_EQ(g, 1);
    WT_ASSERT(!strcmp(rest, "q=x&limit=5"));
    WT_LACKS(rest, "scope");
    WT_EQ(web_scope_take("scope=l%6Fcal", rest, sizeof(rest), &s, &g, err, sizeof(err)), 0);
    WT_EQ(s, WEB_SCOPE_LOCAL); WT_ASSERT(!strcmp(rest, ""));
    WT_EQ(web_scope_take("scope=hybrid&q=a%20b", rest, sizeof(rest), &s, &g, err,
                         sizeof(err)), 0);
    WT_EQ(s, WEB_SCOPE_HYBRID); WT_EQ(g, 1); WT_ASSERT(!strcmp(rest, "q=a%20b"));
    /* Refusals. */
    static const struct { const char *q, *why; } R[] = {
        { "scope=wifi", "bad_scope" }, { "scope=MONITOR", "bad_scope" },
        { "scope=monitor&scope=local", "repeated_parameter" },
        { "scope=", "empty_value" }, { "scope", "bad_query" },
        { "q=1&&scope=local", "bad_query" }, { "scope=%zz", "bad_escape" },
        { "scope=local&", "bad_query" },
    };
    for (size_t i = 0; i < sizeof(R) / sizeof(R[0]); i++) {
        err[0] = '\0';
        WT_EQ(web_scope_take(R[i].q, rest, sizeof(rest), &s, &g, err, sizeof(err)), -1);
        if (strcmp(err, R[i].why)) fprintf(stderr, "    %s: %s\n", R[i].q, err);
        WT_ASSERT(!strcmp(err, R[i].why));
    }
    /* A name that only starts like it is the route's to refuse. */
    WT_EQ(web_scope_take("scopes=1", rest, sizeof(rest), &s, &g, err, sizeof(err)), 0);
    WT_ASSERT(!strcmp(rest, "scopes=1")); WT_EQ(g, 0);
}

/* ── the live stream ────────────────────────────────────────────────── */

static web_live_t g_live, g_live2;
static web_live_t *g_feed_to = &g_live;

static void feed(const char *line) {
    static web_jrec_t r;
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_live_apply(g_feed_to, &r, 100000);
}

/* A stream with both kinds: the radio's beacon and probe, the IP
 * capture's ARP and DNS, a pass of three devices (a probe-only one, an
 * ARP-only one, one seen both ways), an iface of each, and an alert of
 * each kind plus sloth's own state. */
static void live_up(web_live_t *l) {
    g_feed_to = l;
    web_live_init(l, "unix:/test.sock");
    web_live_sock_connected(l, 1000);
    feed("{\"type\":\"sensor_health\",\"ts\":99,\"capture_iface\":\"eth0\","
         "\"capture_open\":1,\"capture_running\":1,\"monitor_iface\":\"wlan0mon\","
         "\"monitor_open\":1,\"monitor_running\":1,\"capture_linktype\":1,"
         "\"monitor_only\":0}");
    feed("{\"type\":\"iface\",\"ts\":100,\"name\":\"eth0\",\"rx_rate\":10}");
    feed("{\"type\":\"iface\",\"ts\":100,\"name\":\"wlan0mon\",\"rx_rate\":20}");
    feed("{\"type\":\"device\",\"ts\":100,\"mac\":\"02:00:00:00:00:a1\",\"ip\":\"\","
         "\"sources\":16,\"last_seen\":100}");
    feed("{\"type\":\"device\",\"ts\":100,\"mac\":\"02:00:00:00:00:c1\","
         "\"ip\":\"10.0.2.20\",\"sources\":1,\"last_seen\":100}");
    feed("{\"type\":\"device\",\"ts\":100,\"mac\":\"02:00:00:00:00:b0\","
         "\"ip\":\"10.0.2.10\",\"sources\":17,\"last_seen\":100}");
    feed("{\"type\":\"beacon\",\"ts\":100,\"bssid\":\"02:00:00:00:00:a1\","
         "\"ssid\":\"RadioOnlyNet\"}");
    feed("{\"type\":\"dns\",\"ts\":101,\"src\":\"10.0.2.20\",\"qname\":"
         "\"wired-only.example\"}");
    feed("{\"type\":\"alert.create\",\"ts\":102,\"incident_id\":\"aa01\",\"sev\":2,"
         "\"ty\":1,\"key\":\"deauth:02:00:00:00:00:a1\",\"title\":\"Deauth flood"
         " RADIO\"}");
    feed("{\"type\":\"alert.create\",\"ts\":102,\"incident_id\":\"aa02\",\"sev\":1,"
         "\"ty\":0,\"key\":\"scan:10.0.2.20\",\"title\":\"Port scan WIRED\","
         "\"match_ip\":\"10.0.2.20\"}");
    feed("{\"type\":\"alert.create\",\"ts\":102,\"incident_id\":\"aa03\",\"sev\":0,"
         "\"ty\":26,\"key\":\"nomon\",\"title\":\"No monitor SELF\"}");
    /* The next batch publishes the pass. */
    feed("{\"type\":\"iface\",\"ts\":110,\"name\":\"eth0\",\"rx_rate\":10}");
    g_feed_to = &g_live;
}

static size_t live_json_of(web_live_t *l, int scope, char *out, size_t cap) {
    web_scope_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.scope = scope;
    c.given = 1;
    web_live_scope_ctx(l, &c);
    return web_live_json_scoped(l, &c, out, cap, 104000);
}

static size_t live_json(int scope, char *out, size_t cap) {
    return live_json_of(&g_live, scope, out, cap);
}

/* Each seen red: the device count with publish() leaving dev_count_m
 * at 0; RadioOnlyNet in Local with the recent loop's scope test
 * removed; "Port scan WIRED" in Monitor with the alerts loop's test
 * removed; the open counts with scope_sum() returning early; the
 * by-type tables with type_in_scope() returning 1. */
static void test_live_scoped(void) {
    static char b[65536];
    WT_ASSERT(live_json(WEB_SCOPE_MONITOR, b, sizeof(b)) > 0);
    WT_HAS(b, "\"devices\":2,");
    WT_HAS(b, "\"alerts_open\":{\"low\":1,\"warn\":0,\"crit\":1,");
    WT_HAS(b, "RadioOnlyNet");
    WT_HAS(b, "Deauth flood RADIO");
    WT_HAS(b, "No monitor SELF");
    WT_LACKS(b, "wired-only.example");
    WT_LACKS(b, "Port scan WIRED");
    WT_LACKS(b, "\"dns\":");
    WT_HAS(b, "\"scope_facts\":{\"ip_on_radio\":false,\"capture_linktype\":1,"
              "\"monitor_only\":false,\"monitor_ifaces\":[\"wlan0mon\"]}");
    WT_ASSERT(live_json(WEB_SCOPE_LOCAL, b, sizeof(b)) > 0);
    WT_HAS(b, "\"devices\":2,");
    WT_HAS(b, "\"alerts_open\":{\"low\":1,\"warn\":1,\"crit\":0,");
    WT_HAS(b, "wired-only.example");
    WT_HAS(b, "Port scan WIRED");
    WT_HAS(b, "No monitor SELF");
    WT_LACKS(b, "RadioOnlyNet");
    WT_LACKS(b, "Deauth flood RADIO");
    WT_LACKS(b, "\"beacon\":");
    /* Hybrid: everything, and the answer without a scope is as it was. */
    static char h0[65536];
    size_t n0 = web_live_json(&g_live, h0, sizeof(h0), 104000);
    WT_ASSERT(n0 > 0);
    WT_HAS(h0, "\"devices\":3,");
    WT_HAS(h0, "\"alerts_open\":{\"low\":1,\"warn\":1,\"crit\":1,");
    WT_HAS(h0, "RadioOnlyNet");
    WT_HAS(h0, "wired-only.example");
    WT_LACKS(h0, "scope_facts");
    WT_LACKS(h0, "\"sc\":");
    web_scope_ctx_t hc;
    memset(&hc, 0, sizeof(hc));
    WT_EQ(web_live_json_scoped(&g_live, &hc, b, sizeof(b), 104000), n0);
    WT_ASSERT(!memcmp(b, h0, n0));
    /* The pass's scope, for pass:latest. */
    WT_EQ(web_live_pass_tag(&g_live, "02:00:00:00:00:a1"), WEB_SC_M);
    WT_EQ(web_live_pass_tag(&g_live, "02:00:00:00:00:c1"), WEB_SC_L);
    WT_EQ(web_live_pass_tag(&g_live, "02:00:00:00:00:b0"), WEB_SC_META);
    WT_EQ(web_live_pass_tag(&g_live, "02:00:00:00:00:ff"), -1);
}

/* The IP capture on the monitor radio (capture_iface == monitor_iface
 * and no link type, as an older sloth says it): the DNS record that
 * comes after counts as Monitor's. Seen red with sensor_record() not
 * setting sc.radio. */
static void test_live_ip_on_radio(void) {
    live_up(&g_live2);
    g_feed_to = &g_live2;
    feed("{\"type\":\"sensor_health\",\"ts\":120,\"capture_iface\":\"wlan0mon\","
         "\"capture_open\":1,\"capture_running\":1,\"monitor_iface\":\"wlan0mon\","
         "\"monitor_open\":1,\"monitor_running\":1}");
    feed("{\"type\":\"dns\",\"ts\":121,\"src\":\"10.9.9.9\",\"qname\":\"off-the-air.example\"}");
    g_feed_to = &g_live;
    static char b[65536];
    WT_ASSERT(live_json_of(&g_live2, WEB_SCOPE_MONITOR, b, sizeof(b)) > 0);
    WT_HAS(b, "off-the-air.example");
    WT_HAS(b, "\"ip_on_radio\":true");
    WT_ASSERT(live_json_of(&g_live2, WEB_SCOPE_LOCAL, b, sizeof(b)) > 0);
    WT_LACKS(b, "off-the-air.example");
    /* The open incidents' IP-capture types follow the radio of now (a
     * record already in the ticker keeps the tag it came with): Local
     * keeps sloth's own state alone. */
    WT_HAS(b, "\"alerts_open\":{\"low\":1,\"warn\":0,\"crit\":0,");
    WT_ASSERT(live_json_of(&g_live2, WEB_SCOPE_MONITOR, b, sizeof(b)) > 0);
    WT_HAS(b, "\"alerts_open\":{\"low\":1,\"warn\":1,\"crit\":1,");
    web_live_destroy(&g_live2);
}

/* ── the routes ─────────────────────────────────────────────────────── */

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

/* The answer to path?q under scope=hybrid, its echo taken out, is the
 * answer to path?q byte for byte. */
static void same_as_hybrid(const web_health_t *h, const char *path, const char *q) {
    static char a[65536], b[65536];
    char q2[600];
    int s1 = route(h, path, q);
    snprintf(a, sizeof(a), "%s", body_of(g_out));
    snprintf(q2, sizeof(q2), "%s%sscope=hybrid", q, q[0] ? "&" : "");
    int s2 = route(h, path, q2);
    WT_EQ(s1, s2);
    const char *bb = body_of(g_out);
    const char *e = "\"scope\":\"hybrid\"";
    if (!strncmp(bb, "{", 1) && !strncmp(bb + 1, e, strlen(e))) {
        size_t k = strlen(e) + (bb[1 + strlen(e)] == ',' ? 1 : 0);
        snprintf(b, sizeof(b), "{%s", bb + 1 + k);
    } else {
        snprintf(b, sizeof(b), "%s", bb);
        fprintf(stderr, "    %s: no echo\n", path);
        WT_ASSERT(0);
    }
    if (strcmp(a, b)) fprintf(stderr, "    %s?%s differs under scope=hybrid\n", path, q);
    WT_ASSERT(!strcmp(a, b));
}

/* The router's step: a bad scope is a 400 of its own words before any
 * route runs; a good one is echoed first; a query without one is
 * routed as it came. The echo's absence without scope seen red with
 * route_scoped() run for every /api path and scope_echo() not asking
 * whether a scope was named. */
static void test_router(void) {
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.live = &g_live;
    h.now_ms = 104000;
    h.wall_s = 1000;
    WT_EQ(route(&h, "/api/live", "scope=bogus"), 400);
    WT_HAS(body_of(g_out), "{\"error\":\"bad_scope\"}");
    WT_LACKS(body_of(g_out), "bogus");
    WT_EQ(route(&h, "/api/live", "scope=monitor&scope=monitor"), 400);
    WT_HAS(body_of(g_out), "repeated_parameter");
    WT_EQ(route(&h, "/api/live", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "{\"scope\":\"monitor\",\"socket\":");
    WT_EQ(route(&h, "/api/live", ""), 200);
    WT_LACKS(body_of(g_out), "{\"scope\":");
    WT_LACKS(body_of(g_out), "scope_facts");
    same_as_hybrid(&h, "/api/live", "");
    /* A route's own refusal still comes after the scope's step. */
    WT_EQ(route(&h, "/api/series", "scope=local&metric=nope"), 503);  /* no tsdb */
    /* /api/health takes no scope; it is not a scoped view. */
    WT_EQ(route(&h, "/api/health", "scope=local"), 200);
    WT_LACKS(body_of(g_out), "\"scope\":\"local\"");
}

/* /api/metrics, /api/keys, /api/series under a scope: an interface by
 * its radio, the scopes' own presence series, the rest by the metric.
 * The keys' absences seen red with key_in() returning 1, the
 * catalogue's with metric_in() returning 1, the series' with its out_of
 * test disabled. */
static void test_series_scoped(void) {
    char err[64];
    web_rollup_t *ru = calloc(1, sizeof(*ru));
    web_tsdb_t *ts = calloc(1, sizeof(*ts));
    WT_ASSERT(ru && ts);
    if (!ru || !ts) { free(ru); free(ts); return; }
    WT_EQ(web_rollup_init(ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(ts, ru, NULL, 30, 256, NULL, NULL), 0);
    web_rollup_add(ru, WM_IFACE_RX, "eth0", 10, 1000);
    web_rollup_add(ru, WM_IFACE_RX, "wlan0mon", 20, 1000);
    web_rollup_add(ru, WM_DNS_QUERIES, "10.0.2.20", 1, 1000);
    web_rollup_add(ru, WM_WIFI_DEAUTH, "02:00:00:00:00:a1", 1, 1000);
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.live = &g_live;
    h.tsdb = ts;
    h.now_ms = 104000;
    h.wall_s = 1005;
    WT_EQ(route(&h, "/api/keys", "metric=iface.rx_rate&scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"key\":\"wlan0mon\"");
    WT_LACKS(body_of(g_out), "\"key\":\"eth0\"");
    WT_EQ(route(&h, "/api/keys", "metric=iface.rx_rate&scope=local"), 200);
    WT_HAS(body_of(g_out), "\"key\":\"eth0\"");
    WT_LACKS(body_of(g_out), "\"key\":\"wlan0mon\"");
    WT_EQ(route(&h, "/api/keys", "metric=dns.queries&scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"total\":0,\"keys\":[]");
    same_as_hybrid(&h, "/api/keys", "metric=iface.rx_rate");
    WT_EQ(route(&h, "/api/metrics", "scope=monitor"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"name\":\"wifi.deauth\"");
    WT_HAS(b, "{\"name\":\"iface.rx_rate\"");
    WT_HAS(b, "{\"name\":\"dev.present.monitor\"");
    WT_LACKS(b, "{\"name\":\"dns.queries\"");
    WT_LACKS(b, "{\"name\":\"dev.present\",");
    WT_LACKS(b, "{\"name\":\"dev.present.local\"");
    WT_EQ(route(&h, "/api/metrics", "scope=local"), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"name\":\"dns.queries\"");
    WT_HAS(b, "\"scope\":\"local\"");
    WT_LACKS(b, "{\"name\":\"wifi.deauth\"");
    same_as_hybrid(&h, "/api/metrics", "");
    WT_EQ(route(&h, "/api/series", "metric=iface.rx_rate&key=eth0&scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"points\":[],\"out_of_scope\":true}");
    WT_EQ(route(&h, "/api/series", "metric=iface.rx_rate&key=wlan0mon&scope=monitor"), 200);
    WT_LACKS(body_of(g_out), "out_of_scope");
    same_as_hybrid(&h, "/api/series", "metric=iface.rx_rate&key=eth0");
    web_tsdb_destroy(ts);
    web_rollup_destroy(ru);
    free(ts);
    free(ru);
}

static void episode(web_anomaly_t *an, long long id, const char *kind, int metric,
                    const char *key, const char *ev, long long now) {
    web_store_ep_t e;
    memset(&e, 0, sizeof(e));
    e.id = id;
    snprintf(e.kind, sizeof(e.kind), "%s", kind);
    e.metric = metric;
    snprintf(e.key, sizeof(e.key), "%s", key);
    e.state = WEB_EP_OPEN;
    e.score = e.peak = 60;
    snprintf(e.evidence, sizeof(e.evidence), "%s", ev);
    e.first_seen = now - 120;
    e.last_seen = now - 60;
    e.last_bucket = now - 120;
    web_anomaly_restore_episode(an, &e);
}

/* /api/anomalies under a scope: each episode by what it scored. A2 is
 * Monitor's, A5-A9 Local's, A10 both; A1 by its metric and key; A3 by
 * the scope's own presence of its MAC. Seen red with
 * web_anomaly_ep_tag()'s default case answering META (A6 stood under
 * Monitor) and with A3's presence test answering both (the probe-only
 * MAC's A3 stood under Local). */
static void test_anomalies_scoped(void) {
    char err[64];
    web_rollup_t *ru = calloc(1, sizeof(*ru));
    web_tsdb_t *ts = calloc(1, sizeof(*ts));
    web_baseline_t *bl = calloc(1, sizeof(*bl));
    web_anomaly_t *an = calloc(1, sizeof(*an));
    WT_ASSERT(ru && ts && bl && an);
    if (!ru || !ts || !bl || !an) { free(ru); free(ts); free(bl); free(an); return; }
    WT_EQ(web_rollup_init(ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(ts, ru, NULL, 30, 256, NULL, NULL), 0);
    WT_EQ(web_baseline_init(bl, 256), 0);
    web_anom_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.bl = bl;
    WT_EQ(web_anomaly_init(an, 32, &cfg), 0);
    const long long now = 1800000000;
    web_rollup_add(ru, WM_DEV_PRESENT_MON, "02:00:00:00:00:a1", 1, now);
    episode(an, 1, "A2", -1, "02:00:00:00:00:a1", "EV-NEW-PROBE", now);
    episode(an, 2, "A6", -1, "10.0.2.20", "EV-NAMES-WIRED", now);
    episode(an, 3, "A10", -1, "", "EV-SENSOR-SELF", now);
    episode(an, 4, "A1", WM_DNS_QUERIES, "10.0.2.20", "EV-DNS-RATE", now);
    episode(an, 5, "A1", WM_WIFI_DEAUTH, "02:00:00:00:00:a1", "EV-DEAUTH-RATE", now);
    episode(an, 6, "A3", WM_DEV_PRESENT, "02:00:00:00:00:a1", "EV-HOURS-RADIO", now);
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.live = &g_live;
    h.tsdb = ts;
    h.anomaly = an;
    h.now_ms = 104000;
    h.wall_s = now;
    WT_EQ(route(&h, "/api/anomalies", "scope=monitor"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "EV-NEW-PROBE");
    WT_HAS(b, "EV-SENSOR-SELF");
    WT_HAS(b, "EV-DEAUTH-RATE");
    WT_HAS(b, "EV-HOURS-RADIO");
    WT_LACKS(b, "EV-NAMES-WIRED");
    WT_LACKS(b, "EV-DNS-RATE");
    WT_EQ(route(&h, "/api/anomalies", "scope=local"), 200);
    b = body_of(g_out);
    WT_HAS(b, "EV-NAMES-WIRED");
    WT_HAS(b, "EV-DNS-RATE");
    WT_HAS(b, "EV-SENSOR-SELF");
    WT_LACKS(b, "EV-NEW-PROBE");
    WT_LACKS(b, "EV-DEAUTH-RATE");
    WT_LACKS(b, "EV-HOURS-RADIO");
    WT_EQ(route(&h, "/api/anomalies", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "EV-NEW-PROBE");
    WT_HAS(b, "EV-NAMES-WIRED");
    same_as_hybrid(&h, "/api/anomalies", "");
    /* The baseline of a series the scope does not hold reads unfed. Seen
     * red with route_baseline() reading it whatever the scope. */
    web_baseline_feed(bl, WM_DNS_QUERIES, "10.0.2.20", now - 3600, 4, 1);
    WT_EQ(route(&h, "/api/baseline", "metric=dns.queries&key=10.0.2.20&scope=local"), 200);
    WT_HAS(body_of(g_out), "\"fed\":true");
    WT_EQ(route(&h, "/api/baseline", "metric=dns.queries&key=10.0.2.20&scope=monitor"), 200);
    WT_HAS(body_of(g_out), "\"fed\":false");
    web_anomaly_destroy(an);
    web_baseline_destroy(bl);
    web_tsdb_destroy(ts);
    web_rollup_destroy(ru);
    free(an); free(bl); free(ts); free(ru);
}

/* The presence split: a probe is Monitor's, an ARP row Local's, a
 * device row by its sources. Seen red with presence() not adding the
 * Local split, and its absences with every record tagged both. */
static void test_presence_split(void) {
    char err[64];
    web_rollup_t *ru = calloc(1, sizeof(*ru));
    web_metrics_t *mx = calloc(1, sizeof(*mx));
    WT_ASSERT(ru && mx);
    if (!ru || !mx) { free(ru); free(mx); return; }
    WT_EQ(web_rollup_init(ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(mx, ru, NULL, NULL), 0);
    static const char *const L[] = {
        "{\"type\":\"probe_client\",\"ts\":5,\"mac\":\"02:00:00:00:00:a1\",\"last_seen\":5}",
        "{\"type\":\"arp\",\"ts\":5,\"mac\":\"02:00:00:00:00:c1\",\"ip\":\"10.0.2.20\","
        "\"last_seen\":5}",
        "{\"type\":\"device\",\"ts\":5,\"mac\":\"02:00:00:00:00:b0\",\"ip\":\"10.0.2.10\","
        "\"sources\":17,\"last_seen\":5}",
        "{\"type\":\"sensor\",\"ts\":5,\"kind\":\"wifi\",\"iface\":\"wlan1mon\"}",
    };
    for (size_t i = 0; i < sizeof(L) / sizeof(L[0]); i++) {
        static web_jrec_t r;
        WT_EQ(web_jl_parse(L[i], strlen(L[i]), &r), WEB_JL_OK);
        web_metrics_record(mx, &r);
    }
    WT_ASSERT(web_rollup_has(ru, WM_DEV_PRESENT_MON, "02:00:00:00:00:a1"));
    WT_ASSERT(!web_rollup_has(ru, WM_DEV_PRESENT_LOC, "02:00:00:00:00:a1"));
    WT_ASSERT(web_rollup_has(ru, WM_DEV_PRESENT_LOC, "02:00:00:00:00:c1"));
    WT_ASSERT(!web_rollup_has(ru, WM_DEV_PRESENT_MON, "02:00:00:00:00:c1"));
    WT_ASSERT(web_rollup_has(ru, WM_DEV_PRESENT_MON, "02:00:00:00:00:b0"));
    WT_ASSERT(web_rollup_has(ru, WM_DEV_PRESENT_LOC, "02:00:00:00:00:b0"));
    WT_ASSERT(web_rollup_has(ru, WM_DEV_PRESENT, "02:00:00:00:00:c1"));
    web_metrics_destroy(mx);
    web_rollup_destroy(ru);
    free(mx);
    free(ru);
}

#ifdef WITH_SQLITE

/* ── sloth.db ───────────────────────────────────────────────────────── *
 *
 *   B 02:00:00:00:00:b0 seen both ways: ARP and probes (sources 17),
 *     a DHCP name, a PNL SSID, a wifi_stas signal (-33, Local's) and a
 *     probe signal (-71, Monitor's) beside the merged -40; risk signals
 *     RANDOM_MAC | PROBE_ONLY | ALERT_TAGGED (CRIT in all, MED in
 *     Monitor, HIGH in Local); first seen by ARP 20 d ago, by probe 5 d.
 *   M 02:00:00:00:00:a1 the monitor radio's only: a beacon (sources 8).
 *   L 02:00:00:00:00:c1 the wire's only: ARP (sources 1).
 * Alerts: DEAUTH_FLOOD on M (Monitor's), PORT_SCAN on L's address
 * (Local's), NO_MONITOR_MODE (sloth's own, both). A beacon_aps row, an
 * SSH flow (Local's). */
static char g_dir[64], g_db[128];
static web_slothdb_t g_sdb;
static web_m4_t g_m4;
static web_health_t H;

static int sdb_up(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/slothweb-scope-XXXXXX");
    if (!mkdtemp(g_dir)) return -1;
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    if (sdb_make(g_db, db_schema_version(), 1) != 0) return -1;
    const long long N = SDB_NOW, D = 86400;
    char sql[8192];
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,ip,hostname,vendor,last_ssid,is_ap,signal_dbm,"
        "probe_count,sources,risk_signals,risk_level,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:b0','10.0.2.10','both-host','BothCo','BothNet',0,-40,4,"
        "17,41,3,%lld,%lld),"
        " ('02:00:00:00:00:a1',NULL,NULL,'RadioCo','RadioOnlyNet',1,-62,0,8,1,1,%lld,%lld),"
        " ('02:00:00:00:00:c1','10.0.2.20','wired-host','WireCo',NULL,0,NULL,0,1,1,1,"
        "%lld,%lld);"
        "INSERT INTO arp (ip,mac,iface,first_seen,last_seen) VALUES"
        " ('10.0.2.10','02:00:00:00:00:b0','eth0',%lld,%lld),"
        " ('10.0.2.20','02:00:00:00:00:c1','eth0',%lld,%lld);"
        "INSERT INTO dhcp_leases (ip,hostname,expire,first_seen,last_seen) VALUES"
        " ('10.0.2.10','both-dhcp',0,%lld,%lld);"
        "INSERT INTO probe_clients (mac,ssid,signal_dbm,channel,frame_count,"
        "presence,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:b0','BothNet',-71,6,10,0,%lld,%lld);"
        "INSERT INTO pnl_clients (mac,mac_random,probe_count,first_seen,last_seen)"
        " VALUES ('02:00:00:00:00:b0',1,4,%lld,%lld);"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:b0','PnlOnlyNet',%lld,%lld);"
        "INSERT INTO wifi_stas (mac,signal_dbm,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:b0',-33,%lld,%lld);"
        "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,enc,first_seen,last_seen)"
        " VALUES ('02:00:00:00:00:a1','RadioOnlyNet',-62,11,'WPA2',%lld,%lld);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,"
        "technique,match_ip,match_port,count) VALUES"
        " ('deauth:02:00:00:00:00:a1',%lld,%lld,1,2,'Deauth flood RADIO',NULL,'T1499',"
        "NULL,NULL,5),"
        " ('scan:10.0.2.20',%lld,%lld,0,1,'Port scan WIRED',NULL,'T1046','10.0.2.20',"
        "22,3),"
        " ('nomon',%lld,%lld,26,0,'No monitor SELF',NULL,'',NULL,NULL,1);"
        "INSERT INTO ssh_flows (src_ip,dst_ip,banner_count,first_seen,last_seen)"
        " VALUES ('10.0.2.20','10.0.2.10',4,%lld,%lld);"
        "INSERT INTO sessions (id,started,ended,site_label) VALUES"
        " (1,%lld,%lld,'one'), (2,%lld,NULL,'two');",
        N - 20 * D, N - 60, N - 3 * D, N - 120, N - 4 * D, N - 90,
        N - 20 * D, N - 3600, N - 4 * D, N - 90,
        N - 15 * D, N - 7200,
        N - 5 * D, N - 7000,
        N - 5 * D, N - 7000, N - 5 * D, N - 7000,
        N - 10 * D, N - 300,
        N - 3 * D, N - 120,
        N - 2 * D, N - 600, N - 2 * D, N - 500, N - D, N - 400,
        N - D, N - 200,
        N - 30 * D, N - 25 * D, N - 6 * D);
    if (sdb_exec(g_db, sql) != 0) return -1;
    web_sdb_fns_t f = { NULL, NULL, NULL, &g_live };
    web_slothdb_init(&g_sdb, g_db, &f);
    memset(&g_m4, 0, sizeof(g_m4));
    g_m4.sdb = &g_sdb;
    g_m4.oui = web_oui_builtin();
    memset(&H, 0, sizeof(H));
    H.wall_s = SDB_NOW;
    H.now_ms = 104000;
    H.live = &g_live;
    H.m4 = &g_m4;
    return 0;
}

static void sdb_down(void) {
    web_slothdb_destroy(&g_sdb);
    const char *files[] = { "sloth.db", "sloth.db-wal", "sloth.db-shm" };
    char p[192];
    for (size_t i = 0; i < 3; i++) {
        snprintf(p, sizeof(p), "%s/%s", g_dir, files[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

/* A device row of a /api/devices body, as text (up to its "ssid_meta"
 * or the next row). */
static void row_of(const char *b, const char *mac, char *out, size_t cap) {
    char want[40];
    snprintf(want, sizeof(want), "{\"mac\":\"%s\"", mac);
    const char *p = strstr(b, want);
    out[0] = '\0';
    if (!p) return;
    const char *e = strstr(p + 1, "{\"mac\":");
    size_t n = e ? (size_t)(e - p) : strlen(p);
    snprintf(out, cap, "%.*s", (int)(n < cap ? n : cap - 1), p);
}

/* Devices: each scope its own devices, the one seen both ways in both
 * with the scope's own columns. Seen red: the Monitor membership with
 * dcols()'s member predicate left out (L was listed); the address under
 * Monitor with c->ip "d.ip"; Monitor's signal with c->signal
 * "d.signal_dbm" (-40); Local's SSID with c->ssid "d.last_ssid"; the DHCP name
 * under Monitor with row_select()'s names test removed; the risk with
 * c->risk "d.risk_level". */
static void test_devices_scoped(void) {
    char row[4096];
    WT_EQ(route(&H, "/api/devices", "scope=monitor"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"scope\":\"monitor\",\"now\":");
    WT_HAS(b, "\"mac\":\"02:00:00:00:00:a1\"");
    WT_HAS(b, "\"mac\":\"02:00:00:00:00:b0\"");
    WT_LACKS(b, "02:00:00:00:00:c1");
    WT_LACKS(b, "10.0.2.");
    WT_LACKS(b, "both-host");
    WT_LACKS(b, "both-dhcp");
    WT_LACKS(b, "wired-host");
    row_of(b, "02:00:00:00:00:b0", row, sizeof(row));
    WT_HAS(row, "\"ip\":null");
    WT_HAS(row, "\"name\":null");
    WT_HAS(row, "\"ssid\":\"BothNet\"");
    WT_HAS(row, "\"signal\":-71");
    WT_HAS(row, "\"sources\":16");
    WT_HAS(row, "\"risk\":1,\"risk_signals\":9");
    WT_HAS(row, "\"first_seen\":1792195200");        /* the probe's 5 d */
    WT_EQ(route(&H, "/api/devices", "scope=local"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"mac\":\"02:00:00:00:00:c1\"");
    WT_HAS(b, "\"mac\":\"02:00:00:00:00:b0\"");
    WT_LACKS(b, "02:00:00:00:00:a1");
    WT_LACKS(b, "BothNet");
    WT_LACKS(b, "RadioOnlyNet");
    row_of(b, "02:00:00:00:00:b0", row, sizeof(row));
    WT_HAS(row, "\"ip\":\"10.0.2.10\"");
    WT_HAS(row, "\"name\":\"both-dhcp\"");
    WT_HAS(row, "\"ssid\":null");
    WT_HAS(row, "\"signal\":-33");
    WT_HAS(row, "\"sources\":1");
    WT_HAS(row, "\"risk\":2,\"risk_signals\":33");
    WT_HAS(row, "\"first_seen\":1790899200");        /* ARP's 20 d */
    /* Hybrid: sloth's own row. */
    WT_EQ(route(&H, "/api/devices", ""), 200);
    b = body_of(g_out);
    WT_HAS(b, "02:00:00:00:00:a1");
    WT_HAS(b, "02:00:00:00:00:c1");
    row_of(b, "02:00:00:00:00:b0", row, sizeof(row));
    WT_HAS(row, "\"signal\":-40");
    WT_HAS(row, "\"risk\":3,\"risk_signals\":41");
    same_as_hybrid(&H, "/api/devices", "");
    same_as_hybrid(&H, "/api/devices", "q=has%3Aip&sort=signal&dir=asc");
    /* The query language answers in the scope's columns: under Monitor
     * no address matches, and a sort on one is a sort on nothing. Seen
     * red with term() reading d.ip for the address (its free-text and
     * ip: cases). */
    WT_EQ(route(&H, "/api/devices", "scope=monitor&q=ip%3A10.0.2"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[]");
    WT_EQ(route(&H, "/api/devices", "scope=local&q=ip%3A10.0.2"), 200);
    WT_HAS(body_of(g_out), "\"count\":2");
    WT_EQ(route(&H, "/api/devices", "scope=local&q=ssid%3ABothNet"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[]");
    WT_EQ(route(&H, "/api/devices", "scope=monitor&q=ssid%3APnlOnly"), 200);
    WT_HAS(body_of(g_out), "\"count\":1");
    WT_EQ(route(&H, "/api/devices", "scope=monitor&q=src%3Aarp"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[]");
    WT_EQ(route(&H, "/api/devices", "scope=monitor&q=risk%3A%3E%3D2"), 200);
    WT_HAS(body_of(g_out), "\"rows\":[]");
    /* Every sort in both directions prepares under both scopes. */
    static const char *const S[] = { "last", "first", "mac", "risk", "vendor",
                                     "ip", "ssid", "signal", "sources" };
    for (size_t i = 0; i < 9; i++)
        for (int sc = 0; sc < 2; sc++)
            for (int d = 0; d < 3; d++) {
                char q[96];
                snprintf(q, sizeof(q), "scope=%s&sort=%s%s", sc ? "local" : "monitor",
                         S[i], d == 0 ? "" : d == 1 ? "&dir=asc" : "&dir=desc");
                WT_EQ(route(&H, "/api/devices", q), 200);
                WT_HAS(body_of(g_out), "\"count\":2");
            }
    /* pass:latest is the pass's devices of the scope, and pass_size the
     * pass's count of them (the devices tile's), 2 of 3 in each. Seen red
     * with pass_size left the whole pass's. */
    WT_EQ(route(&H, "/api/devices", "scope=monitor&q=pass%3Alatest"), 200);
    b = body_of(g_out);
    WT_HAS(b, "02:00:00:00:00:a1");
    WT_HAS(b, "02:00:00:00:00:b0");
    WT_LACKS(b, "02:00:00:00:00:c1");
    WT_HAS(b, "\"pass_size\":2,");
    WT_EQ(route(&H, "/api/devices", "scope=local&q=pass%3Alatest"), 200);
    WT_LACKS(body_of(g_out), "02:00:00:00:00:a1");
    WT_HAS(body_of(g_out), "\"pass_size\":2,");
    WT_EQ(route(&H, "/api/devices", "q=pass%3Alatest"), 200);
    WT_HAS(body_of(g_out), "\"pass_size\":3,");
}

/* One device, each list in its own scope. Seen red: the SSIDs under
 * Local with the !loc test on the ssids list removed; the ARP address
 * under Monitor with the !mon test on the ips list removed; M's
 * DEAUTH_FLOOD under Local with web_sdb_alerts()'s type list left out. */
static void test_device_scoped(void) {
    WT_EQ(route(&H, "/api/device/02%3A00%3A00%3A00%3A00%3Ab0", "scope=monitor"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"in_scope\":true");
    WT_HAS(b, "PnlOnlyNet");
    WT_HAS(b, "\"ips\":[]");
    WT_HAS(b, "\"names\":[]");
    WT_LACKS(b, "10.0.2.10");
    WT_LACKS(b, "both-dhcp");
    WT_EQ(route(&H, "/api/device/02%3A00%3A00%3A00%3A00%3Ab0", "scope=local"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"ssids\":[]");
    WT_HAS(b, "\"assocs\":[]");
    WT_HAS(b, "{\"addr\":\"10.0.2.10\"");
    WT_HAS(b, "both-dhcp");
    WT_LACKS(b, "PnlOnlyNet");
    WT_LACKS(b, "BothNet");
    /* A device the scope never heard: no record, said so. Seen red
     * with web_sdb_device()'s membership test disabled. */
    WT_EQ(route(&H, "/api/device/02%3A00%3A00%3A00%3A00%3Ac1", "scope=monitor"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"record\":null");
    WT_HAS(b, "\"in_scope\":false");
    WT_LACKS(b, "wired-host");
    /* Its alerts: Local's PORT_SCAN names L's address. */
    WT_EQ(route(&H, "/api/device/02%3A00%3A00%3A00%3A00%3Ac1", "scope=local"), 200);
    WT_HAS(body_of(g_out), "Port scan WIRED");
    WT_EQ(route(&H, "/api/device/02%3A00%3A00%3A00%3A00%3Aa1", "scope=local"), 200);
    WT_LACKS(body_of(g_out), "Deauth flood RADIO");
    WT_EQ(route(&H, "/api/device/02%3A00%3A00%3A00%3A00%3Aa1", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "Deauth flood RADIO");
    same_as_hybrid(&H, "/api/device/02%3A00%3A00%3A00%3A00%3Ab0", "");
    /* Lookup: under Monitor there are no addresses, nor the names
     * behind one. Seen red with the address kept under Monitor (the
     * route's !mon test before it is copied removed): its DHCP name was
     * listed. The !mon tests on the ARP reads stand behind that one;
     * with the address gone they cannot be isolated by this request. */
    WT_EQ(route(&H, "/api/lookup", "q=10.0.2.10&scope=monitor"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"ip_in_scope\":false");
    WT_HAS(b, "\"macs\":[]");
    WT_HAS(b, "\"names\":[]");
    WT_LACKS(b, "both-dhcp");
    WT_HAS(b, "\"device\":null");
    WT_EQ(route(&H, "/api/lookup", "q=10.0.2.10&scope=local"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"addr\":\"02:00:00:00:00:b0\"");
    WT_LACKS(b, "ip_in_scope");
    same_as_hybrid(&H, "/api/lookup", "q=10.0.2.10");
}

/* Alerts and History: each scope its own types, sloth's own state in
 * both; the WiFi view Monitor's alone, the flows Local's. Seen red:
 * PORT_SCAN under Monitor with window_rows()'s scope list left out;
 * DEAUTH_FLOOD in Local's History with alerts_between()'s list left
 * out; the AP under Local with route_m5()'s none_here test removed;
 * the stream's PORT_SCAN under Monitor with the route's incident filter
 * disabled. */
static void test_alerts_history_scoped(void) {
    WT_EQ(route(&H, "/api/alerts", "scope=monitor"), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "Deauth flood RADIO");
    WT_HAS(b, "No monitor SELF");
    WT_LACKS(b, "Port scan WIRED");
    WT_LACKS(b, "\"name\":\"PORT_SCAN\"");
    WT_EQ(route(&H, "/api/alerts", "scope=local"), 200);
    b = body_of(g_out);
    WT_HAS(b, "Port scan WIRED");
    WT_HAS(b, "No monitor SELF");
    WT_LACKS(b, "Deauth flood RADIO");
    WT_LACKS(b, "\"name\":\"DEAUTH_FLOOD\"");
    same_as_hybrid(&H, "/api/alerts", "");
    WT_EQ(route(&H, "/api/history/alerts", "scope=local&from=1791000000"), 200);
    b = body_of(g_out);
    WT_HAS(b, "Port scan WIRED");
    WT_LACKS(b, "Deauth flood RADIO");
    WT_EQ(route(&H, "/api/history/alerts", "scope=monitor&from=1791000000"), 200);
    WT_LACKS(body_of(g_out), "Port scan WIRED");
    same_as_hybrid(&H, "/api/history/alerts", "from=1791000000");
    WT_EQ(route(&H, "/api/history/devices", "scope=monitor&from=1791000000"), 200);
    b = body_of(g_out);
    WT_HAS(b, "02:00:00:00:00:a1");
    WT_LACKS(b, "02:00:00:00:00:c1");
    WT_EQ(route(&H, "/api/history/devices", "scope=local&from=1791000000"), 200);
    WT_LACKS(body_of(g_out), "02:00:00:00:00:a1");
    same_as_hybrid(&H, "/api/history/devices", "from=1791000000");
    /* The overview's counts: each scope's devices by its own first seen
     * and its alerts. B was first heard by probe 5 d ago, by ARP 20 d.
     * Seen red with web_sdb_overview()'s scoped read disabled. */
    WT_EQ(route(&H, "/api/history/overview", "scope=monitor&from=1791000000&cols=1"), 200);
    WT_HAS(body_of(g_out), "\"devices\":[2],\"alerts\":[2]");
    /* Local first heard B 20 d ago, before from: L alone. */
    WT_EQ(route(&H, "/api/history/overview", "scope=local&from=1791000000&cols=1"), 200);
    WT_HAS(body_of(g_out), "\"devices\":[1],\"alerts\":[2]");
    WT_EQ(route(&H, "/api/history/overview", "scope=monitor&from=1792200000&cols=1"), 200);
    WT_HAS(body_of(g_out), "\"devices\":[1],");          /* B's probe is 5 d old */
    /* Hybrid counts sloth's own first_seen: B's is 20 d. */
    WT_EQ(route(&H, "/api/history/overview", "from=1791000000&cols=1"), 200);
    WT_HAS(body_of(g_out), "\"devices\":[2],\"alerts\":[3]");
    /* --report's "new since the previous session": beacons and probes
     * are Monitor's; a device is new where the scope first heard it (B
     * by ARP 20 d ago, since the previous visit ended 25 d ago). Seen
     * red with new_since's Local test removed (the beacon listed under
     * Local) and its scoped device read disabled (L listed under
     * Monitor). */
    WT_EQ(route(&H, "/api/sessions/new", "id=2&scope=local"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"aps\":{\"rows\":[],\"total\":0,");
    WT_HAS(b, "\"probe_clients\":{\"rows\":[],\"total\":0,");
    WT_HAS(b, "02:00:00:00:00:c1");
    WT_HAS(b, "02:00:00:00:00:b0");
    WT_LACKS(b, "RadioOnlyNet");
    WT_LACKS(b, "\"ident\":\"02:00:00:00:00:a1\"");
    WT_EQ(route(&H, "/api/sessions/new", "id=2&scope=monitor"), 200);
    b = body_of(g_out);
    WT_HAS(b, "RadioOnlyNet");
    WT_HAS(b, "\"ident\":\"02:00:00:00:00:a1\"");
    WT_LACKS(b, "02:00:00:00:00:c1");
    WT_LACKS(b, "wired-host");
    same_as_hybrid(&H, "/api/sessions/new", "id=2");
    /* The WiFi view and the flows. */
    WT_EQ(route(&H, "/api/wifi/aps", "scope=local"), 200);
    b = body_of(g_out);
    WT_HAS(b, "{\"scope\":\"local\",\"out_of_scope\":true,\"reason\":");
    WT_LACKS(b, "RadioOnlyNet");
    WT_EQ(route(&H, "/api/wifi/aps", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "RadioOnlyNet");
    WT_EQ(route(&H, "/api/wifi/aps", "scope=local&sort=bogus"), 400);   /* still checked */
    WT_EQ(route(&H, "/api/flows", "scope=monitor&proto=ssh"), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"out_of_scope\":true");
    WT_LACKS(b, "10.0.2.20");
    WT_EQ(route(&H, "/api/flows", "scope=local&proto=ssh"), 200);
    WT_HAS(body_of(g_out), "10.0.2.20");
    WT_EQ(route(&H, "/api/history/flows", "scope=monitor&from=1791000000"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true");
    same_as_hybrid(&H, "/api/flows", "proto=ssh");
    same_as_hybrid(&H, "/api/wifi/aps", "");
}

#endif

/* The page: the switch, its legend and its state's homes (the address
 * and this browser), and every fetch carrying the scope. Seen red with
 * the ticker's scope test removed from app.js, getJSON() fetching the
 * bare path, and the Monitor radio's id renamed in index.html. */
static void test_page_carries_the_switch(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "id=\"scope\" role=\"radiogroup\"");
    WT_HAS(p, "id=\"sc-monitor\"");
    WT_HAS(p, "id=\"sc-hybrid\"");
    WT_HAS(p, "id=\"sc-local\"");
    WT_HAS(p, "id=\"scope-legend\"");
    WT_HAS(p, "var SCOPE_KEY = \"slothweb.scope\";");
    WT_HAS(p, "function scoped(path) {");
    WT_HAS(p, "return fetch(scoped(path), { cache: \"no-store\" })");
    WT_HAS(p, "fetch(scoped(\"/api/live\"), { cache: \"no-store\" })");
    WT_HAS(p, "if (!scopeKeeps(r.sc)) return;");
}

void run_scope_tests(void) {
    WT_RUN(test_alert_table_is_the_def);
    WT_RUN(test_record_types_are_classified);
    WT_RUN(test_risk_weights_are_sloths);
    WT_RUN(test_tags);
    WT_RUN(test_take);
    live_up(&g_live);
    WT_RUN(test_live_scoped);
    WT_RUN(test_live_ip_on_radio);
    WT_RUN(test_router);
    WT_RUN(test_series_scoped);
    WT_RUN(test_presence_split);
    WT_RUN(test_anomalies_scoped);
#ifdef WITH_SQLITE
    WT_EQ(sdb_up(), 0);
    WT_RUN(test_devices_scoped);
    WT_RUN(test_device_scoped);
    WT_RUN(test_alerts_history_scoped);
    sdb_down();
#endif
    WT_RUN(test_page_carries_the_switch);
    web_live_destroy(&g_live);
}
