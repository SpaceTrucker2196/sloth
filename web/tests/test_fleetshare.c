/* Fleet sharing: monitor data only (owner hard rule, 2026-11-12;
 * web/src/web_fleetshare.h). The alert-type classification held to
 * include/sloth_alerts.def and to the capture scope's tags
 * (web_scope.c), the importer's rule shape by shape, and which device
 * rows travel. The export and the store, end to end, are
 * web/tests/test_fleet.c's (test_export_monitor_only,
 * test_ingest_refuses_forbidden, test_purge_once). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_alertkb.h"
#include "web_fleetshare.h"
#include "web_jsonl.h"
#include "web_scope.h"
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

static int listed(const char *const *l, const char *name, size_t n) {
    int k = 0;
    for (int i = 0; l[i]; i++)
        if (strlen(l[i]) == n && !strncmp(l[i], name, n)) k++;
    return k;
}

/* Every row of include/sloth_alerts.def is on exactly one of the two
 * lists, and each list names only rows of it: a type sloth adds later
 * fails here until it is classified (and is withheld meanwhile, since
 * the export asks the allow-list only). A shareable type is one the
 * capture scope tags Monitor, or a GNSS rule (the host's own receiver,
 * passive reception); never one it tags Local. Seen red with
 * DEAUTH_FLOOD dropped from the allow-list ("on 0 lists") and with
 * PORT_SCAN added to it (on both lists, and Local). */
static void test_every_alert_type_is_classified(void) {
    char *def = slurp("include/sloth_alerts.def");
    WT_ASSERT(def != NULL);
    if (!def) return;
    int n = 0, share = 0, held = 0;
    for (char *p = def; p; ) {
        if (!strncmp(p, "X(", 2)) {
            const char *a = p + 2, *c = strchr(a, ',');
            WT_ASSERT(c != NULL);
            if (c) {
                size_t len = (size_t)(c - a);
                int s = listed(web_fleet_share_alerts, a, len);
                int w = listed(web_fleet_withheld_alerts, a, len);
                if (s + w != 1)
                    fprintf(stderr, "    %.*s is on %d lists\n", (int)len, a, s + w);
                WT_EQ(s + w, 1);
                share += s;
                held += w;
                char nm[64];
                snprintf(nm, sizeof(nm), "%.*s", (int)len, a);
                WT_EQ(web_fleet_alert_shareable(nm), s == 1);
                int ty = web_akb_find(nm);
                int tag = web_scope_alert(ty);
                if (s) {
                    WT_ASSERT(tag == WEB_SC_M || (tag == WEB_SC_META && !strncmp(nm, "GNSS_", 5)));
                    WT_ASSERT(!(tag & WEB_SC_L) || tag == WEB_SC_META);
                }
            }
            n++;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    free(def);
    int ns = 0, nw = 0;
    while (web_fleet_share_alerts[ns]) ns++;
    while (web_fleet_withheld_alerts[nw]) nw++;
    WT_EQ(share, ns);
    WT_EQ(held, nw);
    WT_EQ(n, ns + nw);
    WT_EQ(n, web_akb_n);
    WT_EQ(web_fleet_alert_shareable(NULL), 0);
    WT_EQ(web_fleet_alert_shareable(""), 0);
    WT_EQ(web_fleet_alert_shareable("NOT_A_TYPE"), 0);
    /* Heard on the air and judged against the operator's own networks
     * and roster: the radio's (the provenance rule). sloth's own state
     * is withheld though the scope tags it META. */
    WT_EQ(web_fleet_alert_shareable("MY_NETWORK_RECON"), 1);
    WT_EQ(web_fleet_alert_shareable("UNKNOWN_DEVICE"), 1);
    WT_EQ(web_fleet_alert_shareable("NO_MONITOR_MODE"), 0);
    WT_EQ(web_fleet_alert_shareable("CAPTIVE_PORTAL"), 0);
    WT_EQ(web_fleet_alert_shareable("CAM_SETUP_OUI"), 1);
}

static const char *refuses(const char *line, int attested) {
    static web_jrec_t r;
    if (web_jl_parse(line, strlen(line), &r) != WEB_JL_OK) return "unparsed";
    return web_fleet_share_refuses(web_jl_str(&r, "type"), &r, attested);
}

/* The importer's rule, shape by shape: own_net is taken (it travels
 * under the provenance rule, from an answer with or without the rule).
 * Seen red with own_net refused again. */
static void test_refuses(void) {
    WT_ASSERT(refuses("{\"type\":\"own_net\",\"ssid\":\"A\",\"bssid\":null}", 1) == NULL);
    WT_ASSERT(refuses("{\"type\":\"own_net\",\"ssid\":\"A\",\"bssid\":null}", 0) == NULL);
    WT_ASSERT(refuses("{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:01\"}", 1) == NULL);
    WT_ASSERT(refuses("{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:01\"}", 0) != NULL);
    WT_ASSERT(refuses("{\"type\":\"ap\",\"bssid\":\"02:00:00:00:00:01\"}", 0) != NULL);
    WT_ASSERT(refuses("{\"type\":\"probe\",\"mac\":\"02:00:00:00:00:01\"}", 0) != NULL);
    WT_ASSERT(refuses("{\"type\":\"ble\",\"addr\":\"02:00:00:00:00:01\"}", 0) == NULL);
    WT_ASSERT(refuses("{\"type\":\"aircraft\",\"hex\":\"a00001\"}", 0) == NULL);
    WT_ASSERT(refuses("{\"type\":\"gnss_event\",\"alert_type\":\"GNSS_JAMMING\"}", 0) == NULL);
    WT_ASSERT(refuses("{\"type\":\"alert\",\"alert_type\":\"DEAUTH_FLOOD\",\"ip\":null}", 0) == NULL);
    WT_ASSERT(refuses("{\"type\":\"alert\",\"alert_type\":\"DEAUTH_FLOOD\",\"ip\":\"10.0.0.1\"}", 1)
              != NULL);
    WT_ASSERT(refuses("{\"type\":\"alert\",\"alert_type\":\"PORT_SCAN\",\"ip\":null}", 1) != NULL);
    WT_ASSERT(refuses("{\"type\":\"alert\",\"alert_type\":null,\"ip\":null}", 1) != NULL);
    WT_ASSERT(refuses("{\"type\":\"alert\",\"alert_type\":\"FUTURE_TYPE\"}", 1) != NULL);
    WT_ASSERT(refuses("{\"type\":\"verdict\",\"alert_type\":\"DEAUTH_FLOOD\","
                      "\"addr\":\"0e:00:00:00:00:01\"}", 0) == NULL);
    WT_ASSERT(refuses("{\"type\":\"verdict\",\"alert_type\":\"DEAUTH_FLOOD\",\"addr\":null}", 0)
              == NULL);
    WT_ASSERT(refuses("{\"type\":\"verdict\",\"alert_type\":\"DEAUTH_FLOOD\","
                      "\"addr\":\"10.0.0.1\"}", 1) != NULL);
    WT_ASSERT(refuses("{\"type\":\"verdict\",\"alert_type\":\"SSH_BRUTE_FORCE\","
                      "\"addr\":\"0e:00:00:00:00:01\"}", 1) != NULL);
}

/* Which share_rule values attest: both cuts of the rule, nothing else. */
static void test_rule_words(void) {
    WT_EQ(web_fleet_share_rule_ok("monitor_only/2"), 1);
    WT_EQ(web_fleet_share_rule_ok("monitor_only"), 1);
    WT_EQ(web_fleet_share_rule_ok("monitor_only/3"), 0);
    WT_EQ(web_fleet_share_rule_ok(""), 0);
    WT_EQ(web_fleet_share_rule_ok(NULL), 0);
    WT_EQ(strcmp(WEB_FLEET_SHARE_RULE, "monitor_only/2"), 0);
}

/* A device row travels when the radio heard it, whatever the LAN knows
 * of it; not when only the LAN or the station dump knows it, when it
 * carries an address or a name, when it is the host's own or rostered
 * (DEV_RISK_SELF), or when it is one of the host's own radios. Seen red
 * with the sources, DEV_RISK_SELF and own-radio tests removed in turn
 * (the address and name test cannot be isolated through the export,
 * whose Monitor scope never reads either). */
static void test_share_dev(void) {
    char self[2][WEB_FLEET_MAC_SZ];
    snprintf(self[0], sizeof(self[0]), "02:00:5e:00:00:0a");
    snprintf(self[1], sizeof(self[1]), "02:00:5e:00:00:0b");
    web_sdb_dev_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.mac, sizeof(d.mac), "0e:00:00:00:00:99");
    d.sources = 16;                      /* a probe */
    WT_EQ(web_fleet_share_dev(&d, (const char (*)[WEB_FLEET_MAC_SZ])self, 2), 1);
    d.sources = 8;                       /* a beacon: the joined AP's too */
    WT_EQ(web_fleet_share_dev(&d, (const char (*)[WEB_FLEET_MAC_SZ])self, 2), 1);
    d.sources = 64;                      /* a camera sign on a beacon */
    WT_EQ(web_fleet_share_dev(&d, (const char (*)[WEB_FLEET_MAC_SZ])self, 2), 1);
    d.sources = 1 | 2 | 4 | 32;          /* ARP, DHCP, mDNS, the station dump */
    WT_EQ(web_fleet_share_dev(&d, (const char (*)[WEB_FLEET_MAC_SZ])self, 2), 0);
    d.sources = 16;
    d.risk_signals = 64;                 /* DEV_RISK_SELF */
    WT_EQ(web_fleet_share_dev(&d, (const char (*)[WEB_FLEET_MAC_SZ])self, 2), 0);
    d.risk_signals = 0;
    snprintf(d.ip, sizeof(d.ip), "192.168.7.20");
    WT_EQ(web_fleet_share_dev(&d, (const char (*)[WEB_FLEET_MAC_SZ])self, 2), 0);
    d.ip[0] = '\0';
    snprintf(d.hostname, sizeof(d.hostname), "laptop");
    WT_EQ(web_fleet_share_dev(&d, (const char (*)[WEB_FLEET_MAC_SZ])self, 2), 0);
    d.hostname[0] = '\0';
    snprintf(d.mac, sizeof(d.mac), "02:00:5E:00:00:0B");   /* an own radio, any case */
    WT_EQ(web_fleet_share_dev(&d, (const char (*)[WEB_FLEET_MAC_SZ])self, 2), 0);
    WT_EQ(web_fleet_share_dev(&d, (const char (*)[WEB_FLEET_MAC_SZ])self, 1), 1);
}

void run_fleetshare_tests(void) {
    WT_RUN(test_every_alert_type_is_classified);
    WT_RUN(test_refuses);
    WT_RUN(test_rule_words);
    WT_RUN(test_share_dev);
}
