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

/* Weak TLS: client negotiated a deprecated TLS version (SSLv2, SSLv3,
 * TLS 1.0, TLS 1.1) as seen in the ClientHello. All three are formally
 * deprecated (RFC 8996); ClientHellos still offering them indicate
 * legacy embedded gear, an unsupported library version, or — less
 * commonly — a downgrade attempt. Dedup key includes both src and
 * version so the same client offering multiple weak versions surfaces
 * separately. */
static int tls_ver_is_weak(const char *v) {
    if (!v) return 0;
    return strcmp(v, "SSL 2.0") == 0 ||
           strcmp(v, "SSL 3.0") == 0 ||
           strcmp(v, "TLS 1.0") == 0 ||
           strcmp(v, "TLS 1.1") == 0;
}

static void rule_weak_tls(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->tls_log_count; i++) {
        const tls_log_entry_t *e = &s->tls_log[i];
        if (!tls_ver_is_weak(e->tls_ver)) continue;
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "weak_tls:%s:%s",
                 e->src, e->tls_ver);
        snprintf(detail, sizeof(detail),
                 "%.20s -> %.24s offered %s (deprecated)",
                 e->src[0]  ? e->src  : "?",
                 e->host[0] ? e->host : (e->dst[0] ? e->dst : "?"),
                 e->tls_ver);
        fire(ALERT_TYPE_WEAK_TLS, ALERT_SEV_WARN,
             "WEAK_TLS", detail, key, e->src, 443, now);
    }
}

/* HTTP attack-path: well-known injection / traversal / RCE / SQLi /
 * XSS signatures in the URI of an observed request. Substring match
 * against a small static table. Like the UA rule, this is high
 * confidence but not exhaustive — encoded variants or novel payloads
 * miss. */
static const struct {
    const char *needle;
    const char *label;
} g_attack_path_table[] = {
    { "../",           "path traversal"  },
    { "..%2f",         "path traversal"  },
    { "..%5c",         "path traversal"  },
    { "/etc/passwd",   "etc/passwd"      },
    { "/etc/shadow",   "etc/shadow"      },
    { "c:\\windows",   "windows path"    },
    { "<script",       "XSS"             },
    { "javascript:",   "XSS"             },
    { "%00",           "null byte"       },
    { "union+select",  "SQL injection"   },
    { "union%20select","SQL injection"   },
    { "'+or+'1",       "SQL injection"   },
    { "'+or+1=1",      "SQL injection"   },
    { "${jndi:",       "log4shell"       },
    { "cmd.exe",       "RCE"             },
    { "/bin/sh",       "RCE"             },
    { "/bin/bash",     "RCE"             },
    { "wget+http",     "RCE download"    },
    { "curl+http",     "RCE download"    },
    { ";nc+-",         "RCE listener"    },
};

static const char *attack_path_match(const char *path) {
    if (!path || !path[0]) return NULL;
    int n = (int)(sizeof(g_attack_path_table) / sizeof(g_attack_path_table[0]));
    for (int i = 0; i < n; i++) {
        const char *needle = g_attack_path_table[i].needle;
        size_t nlen = strlen(needle);
        for (const char *p = path; *p; p++) {
            size_t k = 0;
            while (k < nlen && p[k]) {
                char a = p[k], b = needle[k];
                if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
                if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
                if (a != b) break;
                k++;
            }
            if (k == nlen) return g_attack_path_table[i].label;
        }
    }
    return NULL;
}

static void rule_attack_path(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->http_log_count; i++) {
        const http_log_entry_t *e = &s->http_log[i];
        const char *label = attack_path_match(e->path);
        if (!label) continue;
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "path:%s:%s", e->src, label);
        snprintf(detail, sizeof(detail),
                 "%.20s -> %.20s %.30s [%.14s]",
                 e->src[0]  ? e->src  : "?",
                 e->host[0] ? e->host : "?",
                 e->path[0] ? e->path : "/",
                 label);
        fire(ALERT_TYPE_ATTACK_PATH, ALERT_SEV_CRIT,
             "ATTACK_PATH", detail, key, e->src, 80, now);
    }
}

/* Attack-tool User-Agent: substring match against a small table of
 * well-known offensive-tooling UAs in observed HTTP requests. The
 * tools often advertise themselves verbatim because operators don't
 * typically tune their UA; when they do, this rule misses, which is
 * fine — it's a high-confidence signal, not a complete coverage. */
static const struct {
    const char *needle;
    const char *label;
} g_attack_ua_table[] = {
    { "sqlmap",    "sqlmap"    },
    { "nmap",      "nmap"      },
    { "masscan",   "masscan"   },
    { "nuclei",    "nuclei"    },
    { "nikto",     "nikto"     },
    { "gobuster",  "gobuster"  },
    { "ffuf",      "ffuf"      },
    { "hydra",     "hydra"     },
    { "wpscan",    "wpscan"    },
    { "dirb",      "dirb"      },
    { "metasploit","metasploit"},
    { "ZAP",       "OWASP ZAP" },
    { "Burp",      "Burp Suite"},
    { "acunetix",  "Acunetix"  },
    { "nessus",    "Nessus"    },
    { "openvas",   "OpenVAS"   },
    { "skipfish",  "skipfish"  },
    { "wfuzz",     "wfuzz"     },
};

static const char *attack_tool_ua_match(const char *ua) {
    if (!ua || !ua[0]) return NULL;
    int n = (int)(sizeof(g_attack_ua_table) / sizeof(g_attack_ua_table[0]));
    for (int i = 0; i < n; i++) {
        const char *needle = g_attack_ua_table[i].needle;
        size_t nlen = strlen(needle);
        for (const char *p = ua; *p; p++) {
            /* case-insensitive substring */
            size_t k = 0;
            while (k < nlen && p[k]) {
                char a = p[k], b = needle[k];
                if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
                if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
                if (a != b) break;
                k++;
            }
            if (k == nlen) return g_attack_ua_table[i].label;
        }
    }
    return NULL;
}

static void rule_attack_tool_ua(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->http_log_count; i++) {
        const http_log_entry_t *e = &s->http_log[i];
        const char *label = attack_tool_ua_match(e->user_agent);
        if (!label) continue;
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "ua:%s:%s", e->src, label);
        snprintf(detail, sizeof(detail),
                 "%.24s -> %.24s [%.16s]",
                 e->src[0]  ? e->src  : "?",
                 e->host[0] ? e->host : "?",
                 label);
        fire(ALERT_TYPE_ATTACK_TOOL_UA, ALERT_SEV_CRIT,
             "ATTACK_TOOL_UA", detail, key, e->src, 80, now);
    }
}

/* Probe-request flood: single client MAC emitting probe requests at
 * an abnormally high rate. Operationally interesting because:
 *   - active recon tools (kismet, hcxdumptool, wifite) burst probes
 *   - misbehaving / stuck devices DoS themselves with probe loops
 *   - KARMA-baiting attackers may walk a PNL by probing each entry
 *
 * Threshold: >= 30 frames sustained over >= 5 seconds = >= 6 probes/s.
 * Normal clients emit 1-2 probes per scan cycle and pause between
 * scans, so 6+/s sustained is solidly anomalous. */
#define PROBE_FLOOD_FRAMES    30
#define PROBE_FLOOD_WINDOW_S  5

static void rule_probe_flood(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->probe_count; i++) {
        const probe_client_t *p = &s->probe_clients[i];
        if (p->frame_count < PROBE_FLOOD_FRAMES)        continue;
        long elapsed = (long)(p->last_seen - p->first_seen);
        if (elapsed < PROBE_FLOOD_WINDOW_S)             continue;
        /* rate >= PROBE_FLOOD_FRAMES / elapsed; we passed both gates
         * so by construction the rate is acceptable. Render the rate
         * for the operator. */
        double rate = (double)p->frame_count / (double)elapsed;
        char mac_buf[20];
        snprintf(mac_buf, sizeof(mac_buf),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 p->mac[0], p->mac[1], p->mac[2],
                 p->mac[3], p->mac[4], p->mac[5]);
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "probe_flood:%s", mac_buf);
        snprintf(detail, sizeof(detail),
                 "%s sent %d probes in %lds (%.1f/s) - active recon / stuck client",
                 mac_buf, p->frame_count, elapsed, rate);
        fire(ALERT_TYPE_PROBE_FLOOD, ALERT_SEV_WARN,
             "PROBE_FLOOD", detail, key, NULL, 0, now);
    }
}

/* DNS tunnel detection.
 *
 * dnscat2 / iodine / DNSExfiltrator-style tunnels encode payload data
 * in the leftmost labels of DNS queries to an attacker-controlled
 * parent domain, then receive responses via TXT/NULL records. The
 * resulting signal: a burst of unusually long subdomains pointed at
 * the same parent zone in a short window.
 *
 * Heuristic: group recent dns_log queries by 2-label parent. For each
 * parent count the total queries and how many of them carried a
 * leftmost label >= 30 chars. >= 8 long-subdomain hits over >= 15
 * total queries inside the alert window -> CRIT. */
#define DNS_TUNNEL_LABEL_THRESH 30
#define DNS_TUNNEL_LONG_HITS    8
#define DNS_TUNNEL_TOTAL_THRESH 15

static const char *parent_domain(const char *qname) {
    int last_dot = -1, second_last_dot = -1;
    for (int i = 0; qname[i]; i++) {
        if (qname[i] == '.') {
            second_last_dot = last_dot;
            last_dot = i;
        }
    }
    if (second_last_dot >= 0) return qname + second_last_dot + 1;
    return qname;
}

static int leftmost_label_len(const char *qname) {
    int n = 0;
    while (qname[n] && qname[n] != '.') n++;
    return n;
}

static void rule_dns_tunnel(const sloth_state_t *s, time_t now) {
    typedef struct {
        char parent[64];
        int  qcount;
        int  long_hits;
        char src[46];
    } bucket_t;
    bucket_t buckets[16];
    int      nb = 0;

    for (int i = 0; i < s->dns_log_count; i++) {
        const dns_log_entry_t *e = &s->dns_log[i];
        if (!e->qname[0]) continue;
        /* Queries only — responses don't reveal tunnel intent. */
        if (e->is_resp) continue;
        if (now - e->ts > ALERT_NXDOMAIN_WINDOW_S) continue;

        const char *par = parent_domain(e->qname);
        int found = -1;
        for (int j = 0; j < nb; j++)
            if (strcmp(buckets[j].parent, par) == 0) { found = j; break; }
        if (found < 0) {
            if (nb >= (int)(sizeof(buckets) / sizeof(buckets[0]))) continue;
            snprintf(buckets[nb].parent, sizeof(buckets[nb].parent),
                     "%s", par);
            snprintf(buckets[nb].src, sizeof(buckets[nb].src),
                     "%s", e->src);
            buckets[nb].qcount    = 0;
            buckets[nb].long_hits = 0;
            found = nb++;
        }
        buckets[found].qcount++;
        if (leftmost_label_len(e->qname) >= DNS_TUNNEL_LABEL_THRESH)
            buckets[found].long_hits++;
    }

    for (int i = 0; i < nb; i++) {
        if (buckets[i].qcount    < DNS_TUNNEL_TOTAL_THRESH) continue;
        if (buckets[i].long_hits < DNS_TUNNEL_LONG_HITS)    continue;
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "dns_tunnel:%.40s", buckets[i].parent);
        snprintf(detail, sizeof(detail),
                 "%d queries to %.20s, %d with subdomain >= %d chars",
                 buckets[i].qcount, buckets[i].parent,
                 buckets[i].long_hits, DNS_TUNNEL_LABEL_THRESH);
        fire(ALERT_TYPE_DNS_TUNNEL, ALERT_SEV_CRIT,
             "DNS_TUNNEL", detail, key, buckets[i].src, 53, now);
    }
}

/* KARMA / Pineapple-style rogue AP: a single BSSID emitting beacons
 * (or probe responses) for many distinct SSIDs. Legitimate APs pick
 * one ESSID and stick to it. Rogue tools (Wifi Pineapple's PineAP,
 * mana, hostapd-wpe) impersonate every SSID a victim probes for, so
 * one MAC ends up advertising 3, 5, 20 different network names.
 *
 * Threshold: >= 3 distinct SSIDs from one BSSID. False positives are
 * possible (some captive-portal gear cycles SSIDs) but the operator
 * almost always wants to look. */
#define KARMA_SSID_THRESH 3

static void rule_karma_ap(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (a->ssid_history_n < KARMA_SSID_THRESH) continue;

        char bssid_str[20];
        snprintf(bssid_str, sizeof(bssid_str),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 a->bssid[0], a->bssid[1], a->bssid[2],
                 a->bssid[3], a->bssid[4], a->bssid[5]);
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "karma:%s", bssid_str);
        snprintf(detail, sizeof(detail),
                 "BSSID %s emitted %d distinct SSIDs - Pineapple/KARMA candidate",
                 bssid_str, a->ssid_history_n);
        fire(ALERT_TYPE_KARMA_AP, ALERT_SEV_CRIT,
             "KARMA_AP", detail, key, NULL, 0, now);
    }
}

/* Evil-twin AP: same SSID broadcast under more than one BSSID, where
 * one of the BSSIDs has weak/no security (OPEN, WEP) and another has
 * strong security (WPA / WPA2 / WPA3). This is the classic credential
 * harvesting setup — a rogue AP impersonating the real network on an
 * open channel so victims joining the "right name" get MITM'd.
 *
 * Legitimate mesh / enterprise deployments where all BSSIDs share the
 * same security level produce no alert. */
static int enc_is_weak(const char *enc) {
    return strcmp(enc, "OPEN") == 0 || strcmp(enc, "WEP") == 0;
}
static int enc_is_strong(const char *enc) {
    return strcmp(enc, "WPA")  == 0 || strcmp(enc, "WPA2") == 0 ||
           strcmp(enc, "WPA3") == 0;
}

static void rule_evil_twin(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (!a->ssid[0]) continue;      /* hidden -> can't correlate */
        if (!enc_is_weak(a->enc)) continue;
        /* Find a sibling BSSID with same SSID + strong security. */
        for (int j = 0; j < s->beacon_count; j++) {
            if (i == j) continue;
            const beacon_ap_t *b = &s->beacon_aps[j];
            if (strcmp(a->ssid, b->ssid) != 0) continue;
            if (memcmp(a->bssid, b->bssid, 6) == 0) continue;
            if (!enc_is_strong(b->enc)) continue;

            char a_bssid[20], b_bssid[20];
            snprintf(a_bssid, sizeof(a_bssid),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     a->bssid[0], a->bssid[1], a->bssid[2],
                     a->bssid[3], a->bssid[4], a->bssid[5]);
            snprintf(b_bssid, sizeof(b_bssid),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     b->bssid[0], b->bssid[1], b->bssid[2],
                     b->bssid[3], b->bssid[4], b->bssid[5]);
            char key[ALERT_KEY_LEN];
            char detail[ALERT_DETAIL_LEN];
            snprintf(key,    sizeof(key),    "twin:%.40s", a->ssid);
            /* Detail buffer is ALERT_DETAIL_LEN; SSID truncated to keep
             * the suffix readable. enc strings are bounded at 9 chars
             * by the beacon_ap_t struct. */
            snprintf(detail, sizeof(detail),
                     "'%.16s' on %s[%.6s] AND %s[%.6s] - twin",
                     a->ssid, a_bssid, a->enc, b_bssid, b->enc);
            fire(ALERT_TYPE_EVIL_TWIN, ALERT_SEV_CRIT,
                 "EVIL_TWIN", detail, key, NULL, 0, now);
            break;   /* one alert per weak BSSID is enough */
        }
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
    rule_evil_twin(s, now);
    rule_karma_ap(s, now);
    rule_dns_tunnel(s, now);
    rule_probe_flood(s, now);
    rule_attack_tool_ua(s, now);
    rule_attack_path(s, now);
    rule_weak_tls(s, now);
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
