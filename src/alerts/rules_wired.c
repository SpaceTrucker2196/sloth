/* Rules over what sloth sees on the IP side: port scans, DNS (NXDOMAIN
 * bursts, tunnelling, DGA, threat-intel names), ARP and the rogue
 * DHCP/RA servers, the cleartext and brute-force protocol rules, TLS
 * and HTTP attack signatures, ICMP tunnelling, beaconing, and the two
 * camera findings whose evidence arrives over IP (WS-Discovery, cloud
 * SNI).
 *
 * Moved out of src/alerts.c unchanged (#118) bar linkage: each rule is
 * reached through g_alert_rules[], so it is no longer static. When a
 * rule runs is src/alerts/rules_table.c's business, not this file's. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "tune.h"   /* operator-tunable thresholds (#82) */
#include "sensor_health.h"
#include "stab.h"
#include "threat_intel.h"
#include "vendor_watchlist.h"
#include "beacon_detect.h"
#include "dga.h"
#include "alert_key.h"
#include "rules.h"
#include "engine_internal.h"

/* ── Rules ───────────────────────────────────────────────── */

void rule_port_scan(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->scan_count; i++) {
        const scan_entry_t *e = &s->scan_entries[i];
        if (!e->flagged) continue;
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "scan:%s", e->ip);
        snprintf(detail, sizeof(detail), "%s scanned %d distinct ports",
                 e->ip, e->port_count);
        /* LOW: reconnaissance, not an active attack. The scanner is
         * looking; the operator should know but not be paged. */
        fire(ALERT_TYPE_PORT_SCAN, ALERT_SEV_LOW,
             "PORT_SCAN", detail, key, e->ip, 0, now);
    }
}

void rule_nxdomain_burst(const sloth_state_t *s, time_t now) {
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
        /* LOW: bursts are often typos / autofill misses. DGA / DNS tunnel
         * gets its own dedicated WARN/CRIT detector below. */
        fire(ALERT_TYPE_NXDOMAIN_BURST, ALERT_SEV_LOW,
             "NXDOMAIN_BURST", detail, key, buckets[i].src, 53, now);
    }
}

/* ARP spoof / poisoning: detect when the MAC bound to an IP in the
 * ARP table changes from what we previously observed. Same-MAC
 * re-observations are silent. Once we fire we update the recorded MAC
 * so the alert only repeats on subsequent (further) changes.
 *
 * History is a bounded table sized to the largest ARP table we can
 * ever see, keyed by IP, STAB_OLDEST (#110). It used to refuse every
 * new IP forever once full, so after enough uptime on a busy segment
 * this rule was blind to new hosts and nothing said so. Now a new IP
 * evicts the least-recently-seen one and the loss is tallied as
 * evict_arp_hist. The consequence to know about: an IP whose row was
 * evicted and that later reappears has no recorded MAC to compare
 * against, so it is a fresh baseline and not a spoof even if its MAC
 * differs from the one it had. That window exists only while more than
 * MAX_ARP_ENTRIES distinct IPs are cycling through the kernel table,
 * which is also the case the refuse-forever rule handled worst. */
/* ARP-spoof rule history — file-scope so alerts_clear() can reset it. */
typedef struct {
    char    ip[46];
    uint8_t mac[6];
    time_t  last_seen;
} arp_hist_t;
static int arp_hist_eq(const void *row, const void *key) {
    return strcmp(((const arp_hist_t *)row)->ip, (const char *)key) == 0;
}
STAB_DECL(g_arp_hist, arp_hist_t, MAX_ARP_ENTRIES, last_seen, STAB_OLDEST,
          SH_EVICT_ARP_HIST, NULL, arp_hist_eq);

/* alerts_clear() resets the ARP baseline with the rest of the engine,
 * and the table is file-scope here, beside the one rule that reads it. */
void rules_wired_forget(void) {
    stab_clear(&g_arp_hist);
}

void rule_arp_spoof(const sloth_state_t *s, time_t now) {

    for (int i = 0; i < s->arp_count; i++) {
        const arp_entry_t *a = &s->arp_entries[i];
        if (!a->ip[0]) continue;
        /* Skip multicast / broadcast / null MACs — kernel ARP cache
         * occasionally lists those. */
        if ((a->mac[0] & 0x01) != 0) continue;
        int all_zero = 1;
        for (int j = 0; j < 6; j++) if (a->mac[j]) { all_zero = 0; break; }
        if (all_zero) continue;

        int created;
        arp_hist_t *h = stab_get(&g_arp_hist, a->ip, now, &created);
        if (created) {
            /* First observation, or an IP back from eviction: no prior
             * MAC exists, so record a baseline and say nothing. */
            snprintf(h->ip, sizeof(h->ip), "%s", a->ip);
            memcpy(h->mac, a->mac, 6);
            continue;
        }
        if (memcmp(h->mac, a->mac, 6) != 0) {
            char old_mac[18], new_mac[18];
            snprintf(old_mac, sizeof(old_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     h->mac[0], h->mac[1], h->mac[2],
                     h->mac[3], h->mac[4], h->mac[5]);
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
            memcpy(h->mac, a->mac, 6);
        }
        h->last_seen = now;
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

/* Every fresh cleartext_cred_t row is an alert — one per unique
 * (src, dst, protocol, username). Coalescing happens on the ring
 * side; here we just fan out to the alert engine so the alerts view
 * and cross-panel colouring pick them up. Severity WARN because a
 * cred on the wire is a policy failure but not a live intrusion. */
void rule_cleartext_cred(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->cleartext_cred_count; i++) {
        const cleartext_cred_t *r = &s->cleartext_creds[i];
        /* The username is whatever the client typed (#112): a remote
         * component, so two accounts sharing a long prefix stay two
         * exposures. protocol is one of the snoopers' own literals. */
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "cred");
        akey_ip(&k, r->src);
        akey_ip(&k, r->dst);
        akey_u(&k, (unsigned)r->dst_port);
        akey_tok(&k, r->protocol);
        akey_remote(&k, r->username, 32);
        if (!akey_end(&k)[0]) continue;
        snprintf(detail, sizeof(detail),
                 "%s user %.24s in the clear on %.20s%s -> %.24s:%u",
                 r->protocol,
                 r->username,
                 r->protocol,
                 r->password_observed ? " (password observed)" : "",
                 r->dst,
                 (unsigned)r->dst_port);
        fire(ALERT_TYPE_CLEARTEXT_CRED, ALERT_SEV_WARN,
             "CLEARTEXT_CRED", detail, key, r->src, r->dst_port, now);
    }
}

void rule_weak_tls(const sloth_state_t *s, time_t now) {
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

void rule_attack_path(const sloth_state_t *s, time_t now) {
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

void rule_attack_tool_ua(const sloth_state_t *s, time_t now) {
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
#define DNS_TUNNEL_LABEL_THRESH ((int)tune_val(TUNE_DNS_TUNNEL_LABEL_THRESH))
#define DNS_TUNNEL_LONG_HITS ((int)tune_val(TUNE_DNS_TUNNEL_LONG_HITS))
#define DNS_TUNNEL_TOTAL_THRESH ((int)tune_val(TUNE_DNS_TUNNEL_TOTAL_THRESH))

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

void rule_dns_tunnel(const sloth_state_t *s, time_t now) {
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

/* ICMP tunnel / covert channel: ptunnel, icmptunnel, and Loki smuggle a
 * TCP/data stream inside ICMP Echo payloads to slip past egress filters
 * that permit ping. The passive tell is sustained Echo Requests between
 * one src->dst pair carrying oversized payloads — interactive ping sends
 * a fixed small payload (56 B Linux, 32 B Windows) about once a second,
 * while a tunnel fills toward MTU at a high rate.
 *
 * Gate on payload size (> normal ping) AND volume (a burst from one
 * pair), so a stray large diagnostic ping doesn't trip it. Metadata
 * only — we read the ICMP length already captured, never the payload. */
#define ICMP_TUNNEL_MIN_PAYLOAD ((int)tune_val(TUNE_ICMP_TUNNEL_MIN_PAYLOAD))   /* bytes past the 8-byte echo header */
#define ICMP_TUNNEL_THRESHOLD ((int)tune_val(TUNE_ICMP_TUNNEL_THRESHOLD))    /* oversized echoes per pair per window */
#define ICMP_TUNNEL_WINDOW_S ((int)tune_val(TUNE_ICMP_TUNNEL_WINDOW_S))

void rule_icmp_tunnel(const sloth_state_t *s, time_t now) {
    typedef struct {
        char src[46];
        char dst[46];
        int  count;
        uint16_t min_len, max_len;
    } bucket_t;
    bucket_t buckets[16];
    int      nb = 0;

    for (int i = 0; i < s->icmp_log_count; i++) {
        const icmp_log_entry_t *e = &s->icmp_log[i];
        /* Echo Requests only (v4 type 8 / v6 128) — the request side
         * carries the outbound tunnel data; replies mirror it. */
        int is_echo_req = e->is_v6 ? (e->type == 128) : (e->type == 8);
        if (!is_echo_req) continue;
        if (e->payload_len < ICMP_TUNNEL_MIN_PAYLOAD) continue;
        if (now - e->ts > ICMP_TUNNEL_WINDOW_S) continue;

        int found = -1;
        for (int j = 0; j < nb; j++)
            if (strcmp(buckets[j].src, e->src) == 0 &&
                strcmp(buckets[j].dst, e->dst) == 0) { found = j; break; }
        if (found < 0) {
            if (nb >= (int)(sizeof(buckets) / sizeof(buckets[0]))) continue;
            snprintf(buckets[nb].src, sizeof(buckets[nb].src), "%s", e->src);
            snprintf(buckets[nb].dst, sizeof(buckets[nb].dst), "%s", e->dst);
            buckets[nb].count   = 1;
            buckets[nb].min_len = e->payload_len;
            buckets[nb].max_len = e->payload_len;
            nb++;
        } else {
            buckets[found].count++;
            if (e->payload_len < buckets[found].min_len) buckets[found].min_len = e->payload_len;
            if (e->payload_len > buckets[found].max_len) buckets[found].max_len = e->payload_len;
        }
    }

    for (int i = 0; i < nb; i++) {
        if (buckets[i].count < ICMP_TUNNEL_THRESHOLD) continue;

        char key[ALERT_KEY_LEN];
        snprintf(key, sizeof(key), "icmp-tunnel:%.39s->%.39s",
                 buckets[i].src, buckets[i].dst);
        char detail[ALERT_DETAIL_LEN];
        /* %.45s bounds each address at the longest an IPv6 literal can be,
         * so nothing real is ever truncated. The precision is what lets the
         * compiler bound the read: src/dst are always NUL-terminated (only
         * written via snprintf above, only read below nb), but that is not
         * provable at this call, so a bare %s is assumed to run on into the
         * rest of buckets[] — 1599 bytes of false-positive
         * -Wformat-truncation. Same idiom as the key build above (#58). */
        snprintf(detail, sizeof(detail),
                 "%.45s->%.45s: %d oversized echo reqs "
                 "(payload %u-%u B; ICMP covert channel)",
                 buckets[i].src, buckets[i].dst, buckets[i].count,
                 buckets[i].min_len, buckets[i].max_len);
        /* Portless — ICMP has no port; dst is the tunnel endpoint. */
        fire(ALERT_TYPE_ICMP_TUNNEL, ALERT_SEV_WARN,
             "ICMP_TUNNEL", detail, key, buckets[i].dst, 0, now);
    }
}

/* ── CAM_WS_DISCOVERY (#106 slice 1) ────────────────────────
 *
 * An ONVIF Network Video Transmitter — an IP camera — announces its
 * own presence over WS-Discovery multicast with no authentication:
 * anyone on the segment can enumerate every such camera without
 * sending a single probe of their own. sloth sends nothing either;
 * src/onvif_discovery.c only reads what the camera already
 * broadcast or answered to a Probe sloth happened to overhear.
 * Basis: OASIS WS-Discovery 1.1 (2009-07-01) + ONVIF Core
 * Specification, discovery — see
 * research/papers/ws-discovery-onvif.md. */
void rule_cam_ws_discovery(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->onvif_count; i++) {
        const onvif_device_t *d = &s->onvif_devices[i];
        if (!d->is_camera) continue;

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        /* Keyed by UUID when the device gave one (stable across a DHCP
         * lease change), falling back to IP otherwise — same fallback
         * ssdp_snoop.c's table uses for a message with no USN. */
        snprintf(key, sizeof(key), "cam-wsd:%s",
                 d->uuid[0] ? d->uuid : d->ip);
        snprintf(detail, sizeof(detail),
                 "ONVIF camera at %s announced itself over WS-Discovery"
                 " (%s)%s%s",
                 d->ip, d->kind,
                 d->xaddrs[0] ? ", service " : "",
                 d->xaddrs[0] ? d->xaddrs    : "");
        fire(ALERT_TYPE_CAM_WS_DISCOVERY, ALERT_SEV_WARN,
             "CAM_WS_DISCOVERY", detail, key, d->ip, 0, now);
    }
}

/* ── Surveillance-vendor cloud endpoint (#105, signal family B) ──
 *
 * A host on the monitored segment opened TLS to a body-cam or ALPR
 * platform's cloud. The SNI is already in state (tls_log_parse() in
 * src/tls_log.c put it there from a ClientHello sloth overheard), so
 * this rule adds no new capture surface at all — it is a watchlist
 * lookup over s->tls_log.
 *
 * Family B only: #105's OUI and SSID family (A) is out of scope until
 * the owner rules on passive reception of third-party street-side
 * devices under MISSION.md §2.4 (#145). An endpoint on a network the
 * operator already monitors needs no such ruling. The DNS half of
 * family B is rule_surv_dns below, over the same table.
 *
 * What the alert claims is narrower than #105's framing. The issue's
 * success criterion is "is there a Flock on my street right now"; a
 * TLS SNI cannot answer that. It can only say traffic on this segment
 * went to that vendor, and it cannot distinguish a docked camera
 * uploading from an analyst's browser tab on the vendor's portal — for
 * Flock it is almost always the latter, because the cameras uplink
 * over cellular and never touch a monitored LAN. The detail text says
 * so rather than implying a device was located.
 *
 * WARN, not CRIT: nothing here is an attack, and most hits are the
 * system working as designed. It is reported because an operator
 * generally wants to know their network carries surveillance-platform
 * traffic, not because someone did something wrong.
 *
 * Basis: the vendors' own network-requirement documents — see
 * research/papers/surveillance-vendor-endpoints.md. */
void rule_surv_cloud_sni(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->tls_log_count; i++) {
        const tls_log_entry_t *e = &s->tls_log[i];
        if (!e->host[0]) continue;
        const char *vendor = NULL, *family = NULL;
        if (!vendor_watchlist_match_domain(e->host, &vendor, &family))
            continue;

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        /* Keyed on vendor + LOCAL host. Not on the SNI, because a
         * vendor's upload tier hands out per-session hostnames and
         * keying on those makes one dock produce a fresh alert per
         * connection instead of one with a rising count.
         *
         * And not on the endpoint IP, which is what this shipped as.
         * Two reviewers measured the same two failures independently:
         *
         *   - Several of the operator's hosts talking to one vendor IP
         *     collapsed into a single alert that named only one of them.
         *     "Which of my hosts is uploading" is the question this rule
         *     exists to answer, so merging hosts answers the wrong one.
         *
         *   - Worse, the endpoint is chosen by the REMOTE side and
         *     nothing bounds how many it uses. 200 tls rows from ONE
         *     local host to one vendor domain across 200 destination
         *     addresses produced 127 incidents and filled the 128-slot
         *     engine (MAX_ALERTS), evicting real findings. Ordinary CDN
         *     rotation is enough to do that; no attacker is required.
         *
         * The local host bounds fan-out to the size of the segment,
         * which is the operator's own network and therefore theirs to
         * bound, and it is the axis a reader wants one row per. */
        snprintf(key, sizeof(key), "surv-sni:%s:%s", vendor,
                 e->src[0] ? e->src : "?");
        /* %.45s, not %.20s: 20 truncates an IPv6 literal mid-address
         * (measured: "2001:db8:85a3:8d3:13 -> ..."), and with match_ip
         * set to the endpoint below, the detail is the ONLY place the
         * local host appears at all. Truncating it there loses the
         * finding's subject. */
        snprintf(detail, sizeof(detail),
                 "%.45s -> %.40s: TLS to %s %s"
                 " (device upload or portal use, not distinguishable)",
                 e->src[0] ? e->src : "?", e->host, vendor, family);
        /* match_ip stays the endpoint, not the local host: a per-alert
         * pcap is most useful filtered to the conversation with the
         * vendor, and the local host's other traffic is not evidence
         * for this finding. Note the consequence, since it is not
         * obvious — the key names the local host and match_ip names the
         * remote one, so the two fields carry different ends of the
         * same conversation on purpose. */
        fire(ALERT_TYPE_SURV_CLOUD_SNI, ALERT_SEV_WARN,
             "SURV_CLOUD_SNI", detail, key, e->dst, 443, now);
    }
}

/* Surveillance-vendor lookup (#105 family B, second signal): a DNS
 * query from a host on the monitored segment names a domain in the
 * same embedded watchlist SURV_CLOUD_SNI reads. Same table, same
 * label-boundary suffix match, so the two rules can never disagree
 * about what is on the list.
 *
 * Why a second rule and not just the SNI one: the name reaches DNS in
 * cases where no ClientHello sloth can parse follows — a QUIC upload,
 * a ClientHello with ECH, a TLS session on a path sloth's capture does
 * not see. Verkada's own network page says its devices do not support
 * DNS over HTTPS, so for that vendor plaintext DNS is the one place
 * the name is guaranteed to cross the wire.
 *
 * Queries only (is_resp == 0). In a query, src is the host asking; in
 * a response it is the resolver, and keying on the resolver would fold
 * every client behind it into one alert — the merge the SNI rule's
 * re-key was made to stop.
 *
 * LOW, one tier under SURV_CLOUD_SNI's WARN, because a lookup is
 * weaker evidence than a session: link previews, prefetching browsers
 * and filtering resolvers all resolve names nobody then connects to.
 * The two rules corroborate each other when both fire for one host and
 * vendor; neither confirms a device. The detail says so.
 *
 * Basis: the vendors' own network-requirement documents — see
 * research/papers/surveillance-vendor-endpoints.md. */
void rule_surv_dns(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->dns_log_count; i++) {
        const dns_log_entry_t *e = &s->dns_log[i];
        if (e->is_resp || !e->qname[0]) continue;
        const char *vendor = NULL, *family = NULL;
        if (!vendor_watchlist_match_domain(e->qname, &vendor, &family))
            continue;

        /* Vendor + LOCAL host, the SNI rule's key and for its reasons:
         * not the qname, because a vendor hands out per-region and
         * per-session names (relay.prod-us-ohio., *.vstream.vnetcap.)
         * and one camera would otherwise be many alerts; and the local
         * host bounds fan-out to the operator's own segment. */
        char key[ALERT_KEY_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "surv-dns");
        akey_tok(&k, vendor);
        akey_ip(&k, e->src[0] ? e->src : "?");
        if (!akey_end(&k)[0]) continue;

        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "%.45s looked up %.63s: %s %s"
                 " (DNS lookup only; device or portal use not distinguishable)",
                 e->src[0] ? e->src : "?", e->qname, vendor, family);
        /* match_ip is the asking host and 53, the THREAT_DOMAIN shape:
         * a DNS query has no vendor endpoint to filter on, and the
         * per-alert pcap worth having is that host's DNS traffic. */
        fire(ALERT_TYPE_SURV_DNS, ALERT_SEV_LOW,
             "SURV_DNS", detail, key, e->src, 53, now);
    }
}

/* Rogue DHCP: more than one distinct DHCP server identifier observed
 * in recent OFFER / ACK / NAK traffic. The legitimate network has one
 * authoritative DHCP server; a second is almost always either an
 * attacker MITM or a misconfigured device handing out gateway-IPs
 * that bypass the legitimate gateway.
 *
 * Dedup key is the set of server IPs (order-independent, #112) so two
 * different competing servers produce one persistent alert; a third
 * later joining triggers a new key. */
void rule_rogue_dhcp(const sloth_state_t *s, time_t now) {
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

    /* The server set as a typed set component (#112): count plus the
     * hash of the sorted members. The comma-joined list it replaces
     * was cut at ALERT_KEY_LEN, so four or five IPv6 servers filled it
     * and two segments differing only in a later server were one
     * finding. The detail below still lists every server. */
    const char *members[16];
    for (int i = 0; i < n; i++) members[i] = servers[i];
    char key[ALERT_KEY_LEN];
    akey_t k;
    akey_begin(&k, key, sizeof(key), "rogue_dhcp");
    akey_set(&k, members, n);
    if (!akey_end(&k)[0]) return;

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

/* Rogue RA: more than one distinct IPv6 source advertising a non-zero
 * router lifetime. The IPv6 analogue of rogue DHCP — frameworks like
 * mitm6, Slaacers, and the Topera toolkit get default-router status
 * this way, then NAT/translate v4 traffic via the rogue path.
 *
 * Dedup key is the comma-joined sorted list of router source IPs so
 * the same competing pair stays as one persistent alert; a third
 * router joining mints a new key. */
void rule_rogue_ra(const sloth_state_t *s, time_t now) {
    char routers[8][46];
    int  n = 0;
    for (int i = 0; i < s->ndp_ra_count && n < 8; i++) {
        const ndp_ra_event_t *e = &s->ndp_ras[i];
        if (e->router_lifetime == 0) continue;  /* explicit non-router */
        if (!e->src_ip[0])           continue;
        int dup = 0;
        for (int j = 0; j < n; j++)
            if (strcmp(routers[j], e->src_ip) == 0) { dup = 1; break; }
        if (!dup) snprintf(routers[n++], 46, "%s", e->src_ip);
    }
    if (n < 2) return;

    /* Stable dedup key — alphabetical by IP. */
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++)
            if (strcmp(routers[j], routers[best]) < 0) best = j;
        if (best != i) {
            char t[46];
            memcpy(t,             routers[i],    sizeof(t));
            memcpy(routers[i],    routers[best], sizeof(t));
            memcpy(routers[best], t,             sizeof(t));
        }
    }

    char key[ALERT_KEY_LEN];
    int  kpos = snprintf(key, sizeof(key), "rogue_ra:");
    for (int i = 0; i < n && kpos < (int)sizeof(key) - 1; i++)
        kpos += snprintf(key + kpos, sizeof(key) - (size_t)kpos,
                          "%s%s", i ? "," : "", routers[i]);

    char detail[ALERT_DETAIL_LEN];
    int  dpos = snprintf(detail, sizeof(detail),
                         "%d distinct IPv6 routers on segment: ", n);
    for (int i = 0; i < n && dpos < (int)sizeof(detail) - 1; i++)
        dpos += snprintf(detail + dpos, sizeof(detail) - (size_t)dpos,
                          "%s%s", i ? ", " : "", routers[i]);

    fire(ALERT_TYPE_ROGUE_RA, ALERT_SEV_CRIT,
         "ROGUE_RA", detail, key, routers[0], 0, now);
}

/* SMB1 use: any flow observed speaking SMBv1 fires this alert.
 * SMBv1 has been deprecated by Microsoft since 2017 and disabled by
 * default on every modern Windows. EternalBlue (MS17-010) and the
 * WannaCry / NotPetya campaigns hit specifically the SMBv1 protocol.
 * One alert per (client, server, port) tuple so an operator can
 * pivot to the exact endpoint pair that needs remediation. */
void rule_smb1_use(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->smb_session_count; i++) {
        const smb_session_t *e = &s->smb_sessions[i];
        if (strcmp(e->dialect, "SMB1") != 0) continue;

        char key[ALERT_KEY_LEN];
        snprintf(key, sizeof(key), "smb1:%.39s>%.39s:%u",
                 e->client_ip, e->server_ip, (unsigned)e->server_port);
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "SMBv1 traffic %.39s -> %.39s:%u (count=%d). SMBv1 has been "
                 "deprecated since 2017 (EternalBlue / WannaCry); the "
                 "endpoint serving v1 should be patched or v1 disabled.",
                 e->client_ip, e->server_ip, (unsigned)e->server_port,
                 e->count);
        fire(ALERT_TYPE_SMB1_USE, ALERT_SEV_CRIT,
             "SMB1_USE", detail, key, e->server_ip, e->server_port, now);
    }
}

/* Kerberos pre-auth burst: ≥ KERB_PREAUTH_BURST_THRESHOLD failed
 * pre-auth attempts from a single source. Password-spray campaigns
 * iterate one password across many usernames and produce a clean
 * burst of KDC_ERR_PREAUTH_FAILED (24) responses. The threshold is
 * conservative — five failures from one workstation in any active
 * window is well outside normal user-mistypes-password territory. */
#define KERB_PREAUTH_BURST_THRESHOLD ((int)tune_val(TUNE_KERB_PREAUTH_BURST))

void rule_kerb_preauth_burst(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->kerb_event_count; i++) {
        const kerb_event_t *e = &s->kerb_events[i];
        if (e->preauth_failed_count < KERB_PREAUTH_BURST_THRESHOLD) continue;

        char key[ALERT_KEY_LEN];
        snprintf(key, sizeof(key), "kerb-burst:%.39s", e->src_ip);
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "%s: %d Kerberos pre-auth failures "
                 "(spray indicator; unknown-principal=%d, "
                 "preauth-required=%d)",
                 e->src_ip, e->preauth_failed_count,
                 e->principal_unknown_count,
                 e->preauth_required_count);
        fire(ALERT_TYPE_KERB_PREAUTH_BURST, ALERT_SEV_CRIT,
             "KERB_PREAUTH_BURST", detail, key, e->src_ip, 88, now);
    }
}

/* LDAP search flood: one source emitting ≥
 * LDAP_SEARCH_FLOOD_THRESHOLD LDAP SearchRequest messages across
 * the active aggregation window. Normal AD workstation logon
 * produces ~10–20 searches; BloodHound, ldapdomaindump, and the
 * impacket tooling routinely produce 100+ in seconds. The
 * threshold is conservative so misclassified bulk-membership
 * queries (a small AD admin tool sweeping the directory) won't
 * mass-fire — it catches the unmistakeable enumeration shape. */
#define LDAP_SEARCH_FLOOD_THRESHOLD ((int)tune_val(TUNE_LDAP_SEARCH_FLOOD))

void rule_ldap_search_flood(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->ldap_event_count; i++) {
        const ldap_event_t *e = &s->ldap_events[i];
        if (e->search_count < LDAP_SEARCH_FLOOD_THRESHOLD) continue;

        char key[ALERT_KEY_LEN];
        snprintf(key, sizeof(key), "ldap-flood:%.39s", e->src_ip);
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "%s: %d LDAP SearchRequest messages (AD enumeration "
                 "indicator; bind=%d, anon_bind=%d, referrals=%d)",
                 e->src_ip, e->search_count,
                 e->bind_count, e->bind_anon_count, e->search_ref_count);
        /* match_port = 389 — operators pivot to the cleartext LDAP
         * flow. (3268-flood deployments are rare; the alert still
         * fires, just with the standard port in the pivot.) */
        fire(ALERT_TYPE_LDAP_SEARCH_FLOOD, ALERT_SEV_CRIT,
             "LDAP_SEARCH_FLOOD", detail, key, e->src_ip, 389, now);
    }
}

/* BGP NOTIFICATION burst: three or more NOTIFICATION messages on
 * one peer-pair across the active aggregation window. In normal
 * operation NOTIFICATIONs are rare — they're sent only on session
 * teardown. A cluster of them on a peering segment means either
 * a flapping peer (operationally interesting) or a route-hijack
 * precursor (an attacker tearing down a legitimate session before
 * announcing competing prefixes). Either way it's worth surfacing.
 *
 * Dedup key includes both peers so each flapping pair gets its own
 * alert — operators pivot to the exact peer-pair that needs
 * investigation. */
#define BGP_NOTIFICATION_BURST_THRESHOLD ((int)tune_val(TUNE_BGP_NOTIFICATION_BURST))

void rule_bgp_notification_burst(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->bgp_session_count; i++) {
        const bgp_session_t *e = &s->bgp_sessions[i];
        if (e->notification_count < BGP_NOTIFICATION_BURST_THRESHOLD) continue;

        char key[ALERT_KEY_LEN];
        snprintf(key, sizeof(key), "bgp-notif:%.39s<>%.39s",
                 e->peer_a, e->peer_b);
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "%s <-> %s: %d BGP NOTIFICATION messages "
                 "(session-instability or hijack-precursor; "
                 "opens=%d updates=%d keepalives=%d)",
                 e->peer_a, e->peer_b, e->notification_count,
                 e->open_count, e->update_count, e->keepalive_count);
        fire(ALERT_TYPE_BGP_NOTIFICATION_BURST, ALERT_SEV_CRIT,
             "BGP_NOTIFICATION_BURST", detail, key,
             e->peer_a, 179, now);
    }
}

/* SSH brute force: ten or more SSH banner exchanges between one
 * client and one server. SSH brute-force tools (hydra, medusa,
 * ncrack) open many TCP connections per second and complete the
 * banner exchange each time before testing creds; a legitimate
 * user opens one and stays. The signal is the *connection*
 * cadence, not the encrypted auth payload — which we never see.
 *
 * Why 10: a normal user might re-connect a handful of times in a
 * session after network blips. Ten distinct banner exchanges to
 * the same server inside the active window is unambiguous
 * brute-force shape. fail2ban's default ban threshold is 5 with a
 * wider window; we're a bit higher to stay surprise-free. */
#define SSH_BRUTE_FORCE_THRESHOLD ((int)tune_val(TUNE_SSH_BRUTE_FORCE))

void rule_ssh_brute_force(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->ssh_flow_count; i++) {
        const ssh_flow_t *e = &s->ssh_flows[i];
        if (e->banner_count < SSH_BRUTE_FORCE_THRESHOLD) continue;

        char key[ALERT_KEY_LEN];
        snprintf(key, sizeof(key), "ssh-brute:%.39s->%.39s",
                 e->src_ip, e->dst_ip);
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "%s->%s: %d SSH banners (brute-force; %.30s)",
                 e->src_ip, e->dst_ip, e->banner_count,
                 e->server_banner[0] ? e->server_banner : "(none)");
        fire(ALERT_TYPE_SSH_BRUTE_FORCE, ALERT_SEV_CRIT,
             "SSH_BRUTE_FORCE", detail, key,
             e->src_ip, 22, now);
    }
}

/* RDP brute force: ten or more X.224 Connection Requests from
 * one client to one server. xfreerdp-loop, NLBrute, and Crowbar
 * all open a fresh TCP connection per credential attempt and
 * complete the TPKT/X.224 negotiation each time. A legitimate
 * user opens one and stays. The signal is the connection
 * cadence; the encrypted CredSSP/TLS payload underneath stays
 * opaque and we never need it.
 *
 * Why 10: matches the SSH threshold for the same reason —
 * generous enough for laptops behind NAT that re-connect a few
 * times after sleep/wake, well below what brute-force tools
 * produce in their first minute. */
#define RDP_BRUTE_FORCE_THRESHOLD ((int)tune_val(TUNE_RDP_BRUTE_FORCE))

void rule_rdp_brute_force(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->rdp_flow_count; i++) {
        const rdp_flow_t *e = &s->rdp_flows[i];
        if (e->connect_req_count < RDP_BRUTE_FORCE_THRESHOLD) continue;

        char key[ALERT_KEY_LEN];
        snprintf(key, sizeof(key), "rdp-brute:%.39s->%.39s",
                 e->src_ip, e->dst_ip);
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "%s->%s: %d RDP CRs (brute-force; user=%.20s)",
                 e->src_ip, e->dst_ip, e->connect_req_count,
                 e->last_cookie[0] ? e->last_cookie : "?");
        fire(ALERT_TYPE_RDP_BRUTE_FORCE, ALERT_SEV_CRIT,
             "RDP_BRUTE_FORCE", detail, key,
             e->src_ip, 3389, now);
    }
}

/* SNMP community brute: five or more distinct community strings
 * tried from one source against one destination. snmpwalk with a
 * wordlist (`-c` rotating) and metasploit's snmp_login both
 * iterate communities one packet at a time. Legitimate monitoring
 * uses one community string per (collector, agent) pair — usually
 * "public" for reads or a site-specific token. Seeing five
 * different communities in one window is the signature.
 *
 * Why 5: a normal monitoring host has exactly one community per
 * agent it queries. Even an operator typing the wrong string a
 * couple times stays well below 5. metasploit's default list
 * starts with public/private/cisco/community/admin — five hits
 * trips immediately. */
#define SNMP_COMMUNITY_BRUTE_THRESHOLD ((int)tune_val(TUNE_SNMP_COMMUNITY_BRUTE))

void rule_snmp_community_brute(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->snmp_flow_count; i++) {
        const snmp_flow_t *e = &s->snmp_flows[i];
        if (e->community_count < SNMP_COMMUNITY_BRUTE_THRESHOLD) continue;

        char key[ALERT_KEY_LEN];
        snprintf(key, sizeof(key), "snmp-brute:%.39s->%.39s",
                 e->src_ip, e->dst_ip);
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "%s->%s: %d SNMP communities tried (last=%.16s)",
                 e->src_ip, e->dst_ip, e->community_count,
                 e->last_community[0] ? e->last_community : "?");
        fire(ALERT_TYPE_SNMP_COMMUNITY_BRUTE, ALERT_SEV_CRIT,
             "SNMP_COMMUNITY_BRUTE", detail, key,
             e->src_ip, 161, now);
    }
}

/* MQTT broker brute force: ten or more CONNECT packets from one
 * client to one broker, OR five or more CONNACK failures on the
 * flow. CONNECTs are the brute-force shape; CONNACK failures are
 * the explicit "wrong creds" signal — quieter but more specific.
 * Either path trips the alert because the IoT broker side of the
 * problem is real: Mirai-class scanners hammer MQTT brokers with
 * the same wordlists they hammer SSH with.
 *
 * Why 10 / 5: matches the SSH brute threshold for CONNECT count
 * (same connection-cadence reasoning) and a tighter 5 for explicit
 * CONNACK failures — the broker telling us "wrong" five times is
 * stronger evidence than just connection volume. */
#define MQTT_BROKER_BRUTE_CONNECTS ((int)tune_val(TUNE_MQTT_BRUTE_CONNECTS))
#define MQTT_BROKER_BRUTE_FAILS ((int)tune_val(TUNE_MQTT_BRUTE_FAILS))

void rule_mqtt_broker_brute(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->mqtt_flow_count; i++) {
        const mqtt_flow_t *e = &s->mqtt_flows[i];
        int trip = (e->connect_count      >= MQTT_BROKER_BRUTE_CONNECTS)
                || (e->connack_fail_count >= MQTT_BROKER_BRUTE_FAILS);
        if (!trip) continue;

        char key[ALERT_KEY_LEN];
        snprintf(key, sizeof(key), "mqtt-brute:%.39s->%.39s",
                 e->src_ip, e->dst_ip);
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "%s->%s: %d CONNECTs / %d fails (user=%.16s)",
                 e->src_ip, e->dst_ip,
                 e->connect_count, e->connack_fail_count,
                 e->last_username[0] ? e->last_username : "?");
        fire(ALERT_TYPE_MQTT_BROKER_BRUTE, ALERT_SEV_CRIT,
             "MQTT_BROKER_BRUTE", detail, key,
             e->src_ip, 1883, now);
    }
}

/* DGA: any qname whose leftmost label trips the dga_is_suspicious
 * heuristic — high Shannon entropy + consonant clusters + digit
 * density. Dedup key is the qname so repeated lookups against the
 * same domain only ever produce one alert. */
void rule_dga_domain(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->dns_log_count; i++) {
        const dns_log_entry_t *e = &s->dns_log[i];
        if (!e->qname[0]) continue;
        if (!dga_is_suspicious(e->qname)) continue;

        /* The qname is chosen by whoever generated it — the point of a
         * DGA — so it is a remote component: readable prefix plus the
         * hash of the whole name (#112). */
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "dga");
        akey_remote(&k, e->qname, 40);
        if (!akey_end(&k)[0]) continue;
        snprintf(detail, sizeof(detail),
                 "%.30s queried %.30s (entropy %.2f bits/char)",
                 e->src[0] ? e->src : "?", e->qname,
                 dga_label_entropy(e->qname));
        fire(ALERT_TYPE_DGA_DOMAIN, ALERT_SEV_WARN,
             "DGA_DOMAIN", detail, key, e->src, 53, now);
    }
}

void rule_threat_domain(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->dns_log_count; i++) {
        const dns_log_entry_t *e = &s->dns_log[i];
        if (!e->qname[0]) continue;
        const char *ioc = NULL;
        if (!ti_match_domain(e->qname, &ioc)) continue;

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "threat-d:%s", ioc);
        /* "demo IOC", not "IOC": the embedded list is synthetic (RFC 5737
         * addresses, .testing/.example names) and the alert row is the
         * only place an operator ever learns that. A doc saying so does
         * not reach someone reading the Alerts view at 02:00. */
        snprintf(detail, sizeof(detail),
                 "%.30s queried %.30s (demo IOC %.16s)",
                 e->src[0] ? e->src : "?", e->qname, ioc);
        fire(ALERT_TYPE_THREAT_DOMAIN, ALERT_SEV_CRIT,
             "THREAT_DOMAIN", detail, key, e->src, 53, now);
    }
}

void rule_threat_ip(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];
        const char *ioc = NULL;
        if (!ti_match_ip(c->remote_addr, &ioc)) continue;

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "threat-i:%s", ioc);
        /* See rule_threat_domain: the list is demo data, and this string
         * is where the operator finds out. */
        snprintf(detail, sizeof(detail),
                 "connection to %s:%u (demo IOC %s)",
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
    int kind = bd_is_strong(t->remote_ip, t->remote_port);
    if (!kind) return 0;
    struct beacon_cb *bc = (struct beacon_cb *)ud;

    /* A typed address, not %.39s (#112): a 45-byte IPv4-mapped IPv6
     * literal was cut at 39, so two endpoints differing in their last
     * octet were one track's worth of findings. */
    char key[ALERT_KEY_LEN];
    char detail[ALERT_DETAIL_LEN];
    akey_t k;
    akey_begin(&k, key, sizeof(key), "beacon");
    akey_ip(&k, t->remote_ip);
    akey_u(&k, (unsigned)t->remote_port);
    if (!akey_end(&k)[0]) return 0;

    if (kind == 1) {
        /* v1 — classic low-jitter detector. */
        double mean = 0, jitter = 0;
        int n = bd_stats(t->remote_ip, t->remote_port, &mean, &jitter);
        snprintf(detail, sizeof(detail),
                 "%.39s:%u every %.0fs (jitter=%.1fs, n=%d)",
                 t->remote_ip, (unsigned)t->remote_port, mean, jitter, n);
    } else {
        /* v2 — gap concentration. Reports the median period and
         * the fraction of gaps within ±30% of it so an operator can
         * tell at a glance how confident the match is. */
        double period = 0, concentration = 0;
        int n = bd_autocorr_stats(t->remote_ip, t->remote_port,
                                  &period, &concentration);
        snprintf(detail, sizeof(detail),
                 "%.39s:%u every ~%.0fs jittered (concentration=%.2f, n=%d)",
                 t->remote_ip, (unsigned)t->remote_port,
                 period, concentration, n);
    }
    fire(ALERT_TYPE_BEACONING, ALERT_SEV_WARN,
         "BEACONING", detail, key,
         t->remote_ip, t->remote_port, bc->now);
    return 0;
}

void rule_beaconing(const sloth_state_t *s, time_t now) {
    (void)s;
    struct beacon_cb bc = { .now = now };
    bd_each(beacon_cb_fire, &bc);
}
