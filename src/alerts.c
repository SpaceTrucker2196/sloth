#include <stdio.h>
#include <string.h>
#include <time.h>
#include "alerts.h"
#include "threat_intel.h"
#include "beacon_detect.h"
#include "jsonl.h"
#include "alert_pcap.h"
#include "dga.h"

/* Engine state: deduped alert ring.
 *
 * Each alerts_update() call walks the trigger sources (scan/deauth/dns_log
 * /conns), and for each condition produces a stable dedup key. Existing
 * alerts under that key get count++ and last_seen=now; new keys append.
 * On overflow the oldest entry (lowest last_seen) is evicted. */

static alert_t engine[MAX_ALERTS];
static int     engine_count;

/* ── Helpers ─────────────────────────────────────────────── */

static void mac_to_str(const uint8_t mac[6], char *out, int sz) {
    snprintf(out, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Find existing alert with this key; returns index or -1. */
static int find_by_key(const char *key) {
    for (int i = 0; i < engine_count; i++) {
        if (strcmp(engine[i].key, key) == 0) return i;
    }
    return -1;
}

/* Evict the oldest entry (lowest last_seen) and return its slot. */
static int evict_oldest(void) {
    int slot = 0;
    time_t oldest = engine[0].last_seen;
    for (int i = 1; i < engine_count; i++) {
        if (engine[i].last_seen < oldest) {
            oldest = engine[i].last_seen;
            slot   = i;
        }
    }
    return slot;
}

/* Either bumps an existing alert under `key`, or appends a fresh one.
 * `detail` may be regenerated each tick — we always overwrite it so the
 * latest observation wins. `match_ip`/`match_port` are set only on new
 * alerts (so the criteria represent the first time we saw this key). */
static void fire(alert_type_t type, alert_sev_t sev,
                 const char *title, const char *detail,
                 const char *key,
                 const char *match_ip, uint16_t match_port,
                 time_t now) {
    int idx = find_by_key(key);
    if (idx >= 0) {
        engine[idx].count++;
        engine[idx].last_seen = now;
        engine[idx].sev = sev;
        snprintf(engine[idx].detail, sizeof(engine[idx].detail), "%s", detail);
        return;
    }

    int slot;
    if (engine_count < MAX_ALERTS) {
        slot = engine_count++;
    } else {
        slot = evict_oldest();
    }
    alert_t *a = &engine[slot];
    memset(a, 0, sizeof(*a));
    a->type       = type;
    a->sev        = sev;
    a->count      = 1;
    a->first_seen = now;
    a->last_seen  = now;
    snprintf(a->title,  sizeof(a->title),  "%s", title);
    snprintf(a->detail, sizeof(a->detail), "%s", detail);
    snprintf(a->key,    sizeof(a->key),    "%s", key);
    if (match_ip && match_ip[0])
        snprintf(a->match_ip, sizeof(a->match_ip), "%s", match_ip);
    a->match_port = match_port;
    /* New alert keys are interesting enough to log. */
    jsonl_emit_alert(a);
}

/* ── Rules ───────────────────────────────────────────────── */

static void rule_port_scan(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->scan_count; i++) {
        const scan_entry_t *e = &s->scan_entries[i];
        if (!e->flagged) continue;
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "scan:%s", e->ip);
        snprintf(detail, sizeof(detail), "%s scanned %d distinct ports",
                 e->ip, e->port_count);
        fire(ALERT_TYPE_PORT_SCAN, ALERT_SEV_CRIT,
             "PORT_SCAN", detail, key, e->ip, 0, now);
    }
}

static void rule_deauth_flood(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->deauth_count; i++) {
        const deauth_event_t *e = &s->deauth_events[i];
        if (!e->flood) continue;
        char tgt[20];
        mac_to_str(e->dst, tgt, sizeof(tgt));
        char bss[20];
        mac_to_str(e->bssid, bss, sizeof(bss));
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "deauth:%s", tgt);
        snprintf(detail, sizeof(detail),
                 "target=%s bssid=%s reason=%u count=%d",
                 tgt, bss, e->reason, e->count);
        fire(ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_WARN,
             "DEAUTH_FLOOD", detail, key, NULL, 0, now);
    }
}

static void rule_nxdomain_burst(const sloth_state_t *s, time_t now) {
    /* Per-src NXDOMAIN counter over a sliding window. */
    typedef struct { char src[46]; int count; } bucket_t;
    bucket_t buckets[32];
    int      nb = 0;

    for (int i = 0; i < s->dns_log_count; i++) {
        const dns_log_entry_t *e = &s->dns_log[i];
        if (!e->is_resp) continue;
        if (strcmp(e->answer, "NXDOMAIN") != 0) continue;
        if (now - e->ts > ALERT_NXDOMAIN_WINDOW_S) continue;

        int found = -1;
        for (int j = 0; j < nb; j++) {
            if (strcmp(buckets[j].src, e->src) == 0) { found = j; break; }
        }
        if (found < 0) {
            if (nb >= (int)(sizeof(buckets) / sizeof(buckets[0]))) continue;
            snprintf(buckets[nb].src, sizeof(buckets[nb].src), "%s", e->src);
            buckets[nb].count = 1;
            nb++;
        } else {
            buckets[found].count++;
        }
    }

    for (int i = 0; i < nb; i++) {
        if (buckets[i].count < ALERT_NXDOMAIN_THRESH) continue;
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "nxdomain:%.45s", buckets[i].src);
        snprintf(detail, sizeof(detail),
                 "%.45s saw %d NXDOMAIN responses in %ds",
                 buckets[i].src, buckets[i].count,
                 ALERT_NXDOMAIN_WINDOW_S);
        fire(ALERT_TYPE_NXDOMAIN_BURST, ALERT_SEV_WARN,
             "NXDOMAIN_BURST", detail, key, buckets[i].src, 53, now);
    }
}

/* ARP spoof / poisoning: detect when the MAC bound to an IP in the
 * ARP table changes from what we previously observed. Same-MAC
 * re-observations are silent. Once we fire we update the recorded MAC
 * so the alert only repeats on subsequent (further) changes.
 *
 * History is a static module-local table sized to the largest ARP
 * table we can ever see. */
/* ARP-spoof rule history — file-scope so alerts_clear() can reset it. */
static struct {
    char    ip[46];
    uint8_t mac[6];
    time_t  last_seen;
} g_arp_hist[MAX_ARP_ENTRIES];
static int g_arp_hist_n = 0;

static void rule_arp_spoof(const sloth_state_t *s, time_t now) {

    for (int i = 0; i < s->arp_count; i++) {
        const arp_entry_t *a = &s->arp_entries[i];
        if (!a->ip[0]) continue;
        /* Skip multicast / broadcast / null MACs — kernel ARP cache
         * occasionally lists those. */
        if ((a->mac[0] & 0x01) != 0) continue;
        int all_zero = 1;
        for (int j = 0; j < 6; j++) if (a->mac[j]) { all_zero = 0; break; }
        if (all_zero) continue;

        int found = -1;
        for (int j = 0; j < g_arp_hist_n; j++)
            if (strcmp(g_arp_hist[j].ip, a->ip) == 0) { found = j; break; }

        if (found < 0) {
            if (g_arp_hist_n >= MAX_ARP_ENTRIES) continue;
            snprintf(g_arp_hist[g_arp_hist_n].ip, sizeof(g_arp_hist[g_arp_hist_n].ip), "%s", a->ip);
            memcpy(g_arp_hist[g_arp_hist_n].mac, a->mac, 6);
            g_arp_hist[g_arp_hist_n].last_seen = now;
            g_arp_hist_n++;
            continue;
        }
        if (memcmp(g_arp_hist[found].mac, a->mac, 6) != 0) {
            char old_mac[18], new_mac[18];
            snprintf(old_mac, sizeof(old_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     g_arp_hist[found].mac[0], g_arp_hist[found].mac[1], g_arp_hist[found].mac[2],
                     g_arp_hist[found].mac[3], g_arp_hist[found].mac[4], g_arp_hist[found].mac[5]);
            snprintf(new_mac, sizeof(new_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     a->mac[0], a->mac[1], a->mac[2],
                     a->mac[3], a->mac[4], a->mac[5]);
            char key[ALERT_KEY_LEN];
            char detail[ALERT_DETAIL_LEN];
            snprintf(key,    sizeof(key),    "arp:%s", a->ip);
            snprintf(detail, sizeof(detail),
                     "%s now claims MAC %s (was %s)",
                     a->ip, new_mac, old_mac);
            fire(ALERT_TYPE_ARP_SPOOF, ALERT_SEV_CRIT,
                 "ARP_SPOOF", detail, key, a->ip, 0, now);
            /* Update record to the new MAC so we don't keep re-firing
             * on the same observation. Subsequent flips will re-fire. */
            memcpy(g_arp_hist[found].mac, a->mac, 6);
        }
        g_arp_hist[found].last_seen = now;
    }
}

/* Rogue DHCP: more than one distinct DHCP server identifier observed
 * in recent OFFER / ACK / NAK traffic. The legitimate network has one
 * authoritative DHCP server; a second is almost always either an
 * attacker MITM or a misconfigured device handing out gateway-IPs
 * that bypass the legitimate gateway.
 *
 * Dedup key is the comma-joined sorted list of server IPs so two
 * different competing servers produce one persistent alert; a third
 * later joining triggers a new key. */
static void rule_rogue_dhcp(const sloth_state_t *s, time_t now) {
    /* Collect distinct server IPs from dhcp events. Bounded — DHCP
     * snoop holds at most MAX_DHCP_EVENTS entries. */
    char servers[16][46];
    int  n = 0;
    for (int i = 0; i < s->dhcp_event_count && n < 16; i++) {
        const dhcp_event_t *e = &s->dhcp_events[i];
        if (!e->server_ip[0]) continue;
        int dup = 0;
        for (int j = 0; j < n; j++)
            if (strcmp(servers[j], e->server_ip) == 0) { dup = 1; break; }
        if (!dup) snprintf(servers[n++], 46, "%s", e->server_ip);
    }
    if (n < 2) return;     /* one or zero servers — nothing to flag */

    /* Sort for a stable dedup key. */
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++)
            if (strcmp(servers[j], servers[best]) < 0) best = j;
        if (best != i) {
            char t[46];
            memcpy(t,            servers[i],    sizeof(t));
            memcpy(servers[i],   servers[best], sizeof(t));
            memcpy(servers[best], t,            sizeof(t));
        }
    }

    char key[ALERT_KEY_LEN];
    int  kpos = snprintf(key, sizeof(key), "rogue_dhcp:");
    for (int i = 0; i < n && kpos < (int)sizeof(key) - 1; i++)
        kpos += snprintf(key + kpos, sizeof(key) - (size_t)kpos,
                          "%s%s", i ? "," : "", servers[i]);

    char detail[ALERT_DETAIL_LEN];
    int  dpos = snprintf(detail, sizeof(detail),
                         "%d distinct DHCP servers on segment: ", n);
    for (int i = 0; i < n && dpos < (int)sizeof(detail) - 1; i++)
        dpos += snprintf(detail + dpos, sizeof(detail) - (size_t)dpos,
                          "%s%s", i ? ", " : "", servers[i]);

    /* match_ip = first server alphabetically — operator gets a concrete
     * pivot. */
    fire(ALERT_TYPE_ROGUE_DHCP, ALERT_SEV_CRIT,
         "ROGUE_DHCP", detail, key, servers[0], 67, now);
}

/* DGA: any qname whose leftmost label trips the dga_is_suspicious
 * heuristic — high Shannon entropy + consonant clusters + digit
 * density. Dedup key is the qname so repeated lookups against the
 * same domain only ever produce one alert. */
static void rule_dga_domain(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->dns_log_count; i++) {
        const dns_log_entry_t *e = &s->dns_log[i];
        if (!e->qname[0]) continue;
        if (!dga_is_suspicious(e->qname)) continue;

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "dga:%s", e->qname);
        snprintf(detail, sizeof(detail),
                 "%.30s queried %.30s (entropy %.2f bits/char)",
                 e->src[0] ? e->src : "?", e->qname,
                 dga_label_entropy(e->qname));
        fire(ALERT_TYPE_DGA_DOMAIN, ALERT_SEV_WARN,
             "DGA_DOMAIN", detail, key, e->src, 53, now);
    }
}

static void rule_threat_domain(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->dns_log_count; i++) {
        const dns_log_entry_t *e = &s->dns_log[i];
        if (!e->qname[0]) continue;
        const char *ioc = NULL;
        if (!ti_match_domain(e->qname, &ioc)) continue;

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "threat-d:%s", ioc);
        snprintf(detail, sizeof(detail),
                 "%.30s queried %.30s (IOC %.16s)",
                 e->src[0] ? e->src : "?", e->qname, ioc);
        fire(ALERT_TYPE_THREAT_DOMAIN, ALERT_SEV_CRIT,
             "THREAT_DOMAIN", detail, key, e->src, 53, now);
    }
}

static void rule_threat_ip(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];
        const char *ioc = NULL;
        if (!ti_match_ip(c->remote_addr, &ioc)) continue;

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "threat-i:%s", ioc);
        snprintf(detail, sizeof(detail),
                 "connection to %s:%u (IOC %s)",
                 c->remote_addr, c->remote_port, ioc);
        fire(ALERT_TYPE_THREAT_IP, ALERT_SEV_CRIT,
             "THREAT_IP", detail, key, c->remote_addr, c->remote_port, now);
    }
}

/* Closure used by bd_each to drive fire(). */
struct beacon_cb {
    time_t now;
};

static int beacon_cb_fire(const bd_track_t *t, void *ud) {
    if (!bd_is_strong(t->remote_ip, t->remote_port)) return 0;
    struct beacon_cb *bc = (struct beacon_cb *)ud;
    double mean = 0, jitter = 0;
    int n = bd_stats(t->remote_ip, t->remote_port, &mean, &jitter);

    char key[ALERT_KEY_LEN];
    char detail[ALERT_DETAIL_LEN];
    snprintf(key,    sizeof(key),    "beacon:%.39s:%u",
             t->remote_ip, (unsigned)t->remote_port);
    snprintf(detail, sizeof(detail),
             "%.39s:%u every %.0fs (jitter=%.1fs, n=%d)",
             t->remote_ip, (unsigned)t->remote_port, mean, jitter, n);
    fire(ALERT_TYPE_BEACONING, ALERT_SEV_WARN,
         "BEACONING", detail, key,
         t->remote_ip, t->remote_port, bc->now);
    return 0;
}

static void rule_beaconing(const sloth_state_t *s, time_t now) {
    (void)s;
    struct beacon_cb bc = { .now = now };
    bd_each(beacon_cb_fire, &bc);
}

/* ── Snapshot ────────────────────────────────────────────── */

/* Copy engine into s->alerts newest-first. */
static void snapshot(sloth_state_t *s) {
    /* selection sort by last_seen desc — engine_count <= MAX_ALERTS=128
       so O(n^2) is fine. */
    int order[MAX_ALERTS];
    for (int i = 0; i < engine_count; i++) order[i] = i;

    for (int i = 0; i < engine_count - 1; i++) {
        int max = i;
        for (int j = i + 1; j < engine_count; j++) {
            if (engine[order[j]].last_seen > engine[order[max]].last_seen)
                max = j;
        }
        int tmp = order[i]; order[i] = order[max]; order[max] = tmp;
    }

    for (int i = 0; i < engine_count; i++) {
        s->alerts[i] = engine[order[i]];
    }
    s->alert_count = engine_count;

    if (s->alert_sel >= s->alert_count)
        s->alert_sel = s->alert_count > 0 ? s->alert_count - 1 : 0;
    if (s->alert_sel < 0) s->alert_sel = 0;
}

/* For any engine entry that has match_ip set and hasn't yet had its
 * packets dumped, walk s->packets[] and write a per-alert pcap. */
static void dump_new_alert_pcaps(const sloth_state_t *s) {
    if (!alert_pcap_enabled()) return;
    for (int i = 0; i < engine_count; i++) {
        alert_t *a = &engine[i];
        if (a->pcap_dumped) continue;
        if (!a->match_ip[0]) continue;
        alert_pcap_dump(s, a, NULL, 0);
        a->pcap_dumped = 1;
    }
}

void alerts_update(sloth_state_t *s) {
    if (!s) return;
    time_t now = time(NULL);
    rule_port_scan(s, now);
    rule_deauth_flood(s, now);
    rule_nxdomain_burst(s, now);
    rule_threat_domain(s, now);
    rule_dga_domain(s, now);
    rule_arp_spoof(s, now);
    rule_rogue_dhcp(s, now);
    rule_threat_ip(s, now);
    rule_beaconing(s, now);
    dump_new_alert_pcaps(s);
    snapshot(s);
}

void alerts_clear(void) {
    engine_count = 0;
    memset(engine, 0, sizeof(engine));
    /* Reset per-rule history too so tests (and the user pressing 'c')
     * get a fully clean slate. */
    g_arp_hist_n = 0;
    memset(g_arp_hist, 0, sizeof(g_arp_hist));
}
