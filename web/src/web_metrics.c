#include "web_metrics.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "web_live.h"

/* ── keys ────────────────────────────────────────────────────────────── */

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int web_key_mac(const char *s, char *out) {
    if (!s || strlen(s) != 17) return -1;
    static const char hx[] = "0123456789abcdef";
    int all_zero = 1;
    for (int i = 0; i < 6; i++) {
        int a = hexval((unsigned char)s[i * 3]);
        int b = hexval((unsigned char)s[i * 3 + 1]);
        if (a < 0 || b < 0) return -1;
        if (i < 5 && s[i * 3 + 2] != ':') return -1;
        if (a || b) all_zero = 0;
        out[i * 3] = hx[a];
        out[i * 3 + 1] = hx[b];
        out[i * 3 + 2] = i < 5 ? ':' : '\0';
    }
    /* sloth writes "" for a row with no MAC; all zeros would be one. */
    return all_zero ? -1 : 0;
}

int web_key_ip(const char *s, char *out) {
    if (!s || !s[0] || strlen(s) > 45) return -1;
    unsigned char a[16];
    char tmp[INET6_ADDRSTRLEN];
    if (inet_pton(AF_INET, s, a) == 1) {
        if (!inet_ntop(AF_INET, a, tmp, sizeof(tmp))) return -1;
    } else if (inet_pton(AF_INET6, s, a) == 1) {
        if (!inet_ntop(AF_INET6, a, tmp, sizeof(tmp))) return -1;
    } else {
        return -1;
    }
    if (strlen(tmp) > WEB_KEY_MAX) return -1;
    memcpy(out, tmp, strlen(tmp) + 1);
    return 0;
}

/* Linux IFNAMSIZ is 16 with the NUL. */
int web_key_iface(const char *s, char *out) {
    if (!s) return -1;
    size_t n = strlen(s);
    if (n == 0 || n > 15) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '.' || c == ':' ||
              c == '@' || c == '-'))
            return -1;
    }
    memcpy(out, s, n + 1);
    return 0;
}

int web_key_channel(long long ch, const char *band, char *out) {
    if (ch < 1 || ch > 233) return -1;
    int six = band && !strcmp(band, "6 GHz");
    snprintf(out, WEB_KEY_MAX + 1, "%s%lld", six ? "6g" : "", ch);
    return 0;
}

static int all_digits(const char *s, size_t maxlen) {
    size_t n = strlen(s);
    if (n == 0 || n > maxlen) return 0;
    for (size_t i = 0; i < n; i++) if (s[i] < '0' || s[i] > '9') return 0;
    return s[0] != '0' || n == 1;
}

int web_key_channel_text(const char *s, char *out) {
    if (!s) return -1;
    const char *d = s;
    int six = 0;
    if (s[0] == '6' && s[1] == 'g') { six = 1; d = s + 2; }
    if (!all_digits(d, 3)) return -1;
    return web_key_channel(atoll(d), six ? "6 GHz" : "", out);
}

int web_key_alert_type(long long ty, char *out) {
    if (ty < 0 || ty > 9999) return -1;
    snprintf(out, WEB_KEY_MAX + 1, "%lld", ty);
    return 0;
}

int web_key_canon(int metric, const char *s, char *out) {
    if (metric < 0 || metric >= WM_COUNT || !s) return -1;
    const char *kk = web_metric_defs[metric].keykind;
    if (!kk[0]) {
        if (s[0]) return -1;
        out[0] = '\0';
        return 0;
    }
    if (!strcmp(kk, "mac"))     return web_key_mac(s, out);
    if (!strcmp(kk, "ip"))      return web_key_ip(s, out);
    if (!strcmp(kk, "iface"))   return web_key_iface(s, out);
    if (!strcmp(kk, "channel")) return web_key_channel_text(s, out);
    if (!strcmp(kk, "alert_type")) {
        if (!all_digits(s, 4)) return -1;
        return web_key_alert_type(atoll(s), out);
    }
    return -1;
}

/* ── high-water rows ─────────────────────────────────────────────────── */

static unsigned hw_hash(const char *s) {
    unsigned h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    return h;
}

/* A second, independent hash for the evicted-row filter. */
static unsigned hw_hash2(const char *s) {
    unsigned h = 5381;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        h = h * 33u + *p;
    return h ^ (h >> 15);
}

/* Into the current generation; a full one hands over to the other,
 * cleared first, so the ids it forgets are the oldest. */
static void gone_set(web_metrics_t *m, const char *id) {
    if (m->hw_gone_n >= WEB_HW_GONE_ROTATE) {
        m->hw_gone_cur ^= 1;
        memset(m->hw_gone[m->hw_gone_cur], 0, sizeof(m->hw_gone[0]));
        m->hw_gone_n = 0;
    }
    unsigned char *g = m->hw_gone[m->hw_gone_cur];
    unsigned a = hw_hash(id) % WEB_HW_GONE_BITS, b = hw_hash2(id) % WEB_HW_GONE_BITS;
    g[a / 8] |= (unsigned char)(1u << (a % 8));
    g[b / 8] |= (unsigned char)(1u << (b % 8));
    m->hw_gone_n++;
}

static int gone_maybe(const web_metrics_t *m, const char *id) {
    unsigned a = hw_hash(id) % WEB_HW_GONE_BITS, b = hw_hash2(id) % WEB_HW_GONE_BITS;
    for (int i = 0; i < 2; i++) {
        const unsigned char *g = m->hw_gone[i];
        if ((g[a / 8] >> (a % 8) & 1) && (g[b / 8] >> (b % 8) & 1)) return 1;
    }
    return 0;
}

static long long default_clock(void *ctx) {
    (void)ctx;
    return (long long)time(NULL);
}

int web_metrics_init(web_metrics_t *m, web_rollup_t *ru, web_clock_fn clock,
                     void *clock_ctx) {
    memset(m, 0, sizeof(*m));
    m->ru = ru;
    m->clock = clock ? clock : default_clock;
    m->clock_ctx = clock_ctx;
    m->hw_cap = WEB_HW_ROWS;
    m->hw_nhead = 1;
    while (m->hw_nhead < m->hw_cap * 2) m->hw_nhead <<= 1;
    m->hw = calloc((size_t)m->hw_cap, sizeof(*m->hw));
    m->hw_head = malloc((size_t)m->hw_nhead * sizeof(*m->hw_head));
    if (!m->hw || !m->hw_head) {
        web_metrics_destroy(m);
        return -1;
    }
    web_metrics_stream(m);
    return 0;
}

void web_metrics_destroy(web_metrics_t *m) {
    free(m->hw);
    free(m->hw_head);
    m->hw = NULL;
    m->hw_head = NULL;
}

void web_metrics_stream(web_metrics_t *m) {
    if (m->hw) {
        for (int i = 0; i < m->hw_cap; i++) m->hw[i].used = 0;
        for (int i = 0; i < m->hw_nhead; i++) m->hw_head[i] = -1;
    }
    m->hw_n = 0;
    memset(m->hw_gone, 0, sizeof(m->hw_gone));
    m->hw_gone_cur = 0;
    m->hw_gone_n = 0;
    m->have_first_ts = 0;
    m->first_ts = 0;
    m->in_iface = 0;
    m->batch_open = 0;
    m->taint = 0;
    m->probe_n = m->conns_n = 0;
}

void web_metrics_taint(web_metrics_t *m) { m->taint = 1; }

static void hw_unlink(web_metrics_t *m, int idx) {
    int *pp = &m->hw_head[hw_hash(m->hw[idx].id) & (unsigned)(m->hw_nhead - 1)];
    while (*pp >= 0 && *pp != idx) pp = &m->hw[*pp].next;
    if (*pp == idx) *pp = m->hw[idx].next;
}

/* The delta of a running total v for row id, floored at zero.
 * first_seen is the row's own, or -1 when the record has none. */
static double hw_delta(web_metrics_t *m, const char *id, long long v,
                       long long first_seen) {
    if (v < 0) v = 0;
    unsigned h = hw_hash(id) & (unsigned)(m->hw_nhead - 1);
    m->touch++;
    for (int i = m->hw_head[h]; i >= 0; i = m->hw[i].next) {
        web_hw_t *e = &m->hw[i];
        if (strcmp(e->id, id)) continue;
        long long d = v - e->v;
        e->v = v;
        e->touched = m->touch;
        return d > 0 ? (double)d : 0;
    }
    int slot = -1;
    if (m->hw_n < m->hw_cap) {
        for (int i = 0; i < m->hw_cap; i++) if (!m->hw[i].used) { slot = i; break; }
        m->hw_n++;
    } else {
        slot = 0;
        for (int i = 1; i < m->hw_cap; i++)
            if (m->hw[i].touched < m->hw[slot].touched) slot = i;
        hw_unlink(m, slot);
        gone_set(m, m->hw[slot].id);
        web_rollup_note_hw_eviction(m->ru);
    }
    web_hw_t *e = &m->hw[slot];
    e->used = 1;
    snprintf(e->id, sizeof(e->id), "%s", id);
    e->v = v;
    e->touched = m->touch;
    e->next = m->hw_head[h];
    m->hw_head[h] = slot;
    /* Born while we were listening: its whole total is new. Unless
     * this table evicted the row earlier on this connection: its total
     * up to then was already counted, so it is a baseline again. The
     * filter can only err towards a baseline (a born row whose id
     * collides with an evicted one loses its first total). */
    if (first_seen >= 0 && m->have_first_ts && first_seen >= m->first_ts &&
        !gone_maybe(m, id))
        return (double)v;
    return 0;
}

static void count(web_metrics_t *m, int metric, const char *key, double d,
                  long long now) {
    if (d > 0) web_rollup_add(m->ru, metric, key, d, now);
}

/* ── records ─────────────────────────────────────────────────────────── */

static void presence(web_metrics_t *m, const web_jrec_t *r, const char *field,
                     long long ts, long long now) {
    char k[WEB_KEY_MAX + 1];
    if (web_key_mac(web_jl_str(r, field), k) != 0) return;
    /* A table row is re-sent every pass for as long as sloth keeps it;
     * present means heard within the last fine bucket. */
    long long ls = web_jl_int(r, "last_seen", -1);
    if (ls >= 0 && ts >= 0 && ts - ls > WEB_FINE_S) return;
    web_rollup_add(m->ru, WM_DEV_PRESENT, k, 1, now);
}

static void batch_start(web_metrics_t *m, long long now) {
    if (m->batch_open && !m->taint) {
        web_rollup_add(m->ru, WM_WIFI_PROBE_CLIENTS, "", (double)m->probe_n, now);
        web_rollup_add(m->ru, WM_CONNS_TOTAL, "", (double)m->conns_n, now);
    }
    m->batch_open = 1;
    m->taint = 0;
    m->probe_n = m->conns_n = 0;
}

static void gauge(web_metrics_t *m, const web_jrec_t *r, const char *field,
                  int metric, const char *key, long long now) {
    double v;
    if (web_jl_num(r, field, &v)) web_rollup_add(m->ru, metric, key, v, now);
}

/* A flow row's running total, by its src and dst. */
static void flow(web_metrics_t *m, const web_jrec_t *r, const char *tag,
                 const char *srcf, const char *dstf, long long total,
                 int metric, long long now) {
    char src[WEB_KEY_MAX + 1], dst[WEB_KEY_MAX + 1], id[WEB_HW_ID_MAX + 1];
    if (web_key_ip(web_jl_str(r, srcf), src) != 0) return;
    if (web_key_ip(web_jl_str(r, dstf), dst) != 0) return;
    long long port = web_jl_int(r, "server_port", -1);
    snprintf(id, sizeof(id), "%s|%s|%s|%lld", tag, src, dst, port);
    count(m, metric, src,
          hw_delta(m, id, total, web_jl_int(r, "first_seen", -1)), now);
}

static long long sum_of(const web_jrec_t *r, const char *const *fields) {
    long long t = 0;
    for (int i = 0; fields[i]; i++) {
        long long v = web_jl_int(r, fields[i], 0);
        if (v > 0 && t < (1LL << 60)) t += v;
    }
    return t;
}

void web_metrics_record(web_metrics_t *m, const web_jrec_t *r) {
    const char *t = web_jl_str(r, "type");
    if (!t) return;
    long long now = m->clock(m->clock_ctx);
    long long ts = web_jl_int(r, "ts", -1);
    if (!m->have_first_ts && ts >= 0) {
        m->have_first_ts = 1;
        m->first_ts = ts;
    }
    if (!strcmp(t, "socket_gap")) { m->taint = 1; return; }

    if (!strcmp(t, "iface")) {
        if (!m->in_iface) batch_start(m, now);
        m->in_iface = 1;
    } else if (web_live_is_poll_type(t)) {
        m->in_iface = 0;
    }

    char k[WEB_KEY_MAX + 1], k2[WEB_KEY_MAX + 1], id[WEB_HW_ID_MAX + 1];

    presence(m, r, "mac", ts, now);
    presence(m, r, "sta_mac", ts, now);

    if (!strcmp(t, "iface")) {
        if (web_key_iface(web_jl_str(r, "name"), k) != 0) return;
        gauge(m, r, "rx_rate", WM_IFACE_RX, k, now);
        gauge(m, r, "tx_rate", WM_IFACE_TX, k, now);
    } else if (!strcmp(t, "top_host")) {
        if (web_key_ip(web_jl_str(r, "ip"), k) != 0) return;
        gauge(m, r, "rx_rate", WM_HOST_RX, k, now);
        gauge(m, r, "tx_rate", WM_HOST_TX, k, now);
        gauge(m, r, "conn_count", WM_HOST_CONNS, k, now);
    } else if (!strcmp(t, "probe_client")) {
        m->probe_n++;
        if (web_key_mac(web_jl_str(r, "mac"), k) != 0) return;
        snprintf(id, sizeof(id), "pc|%s", k);
        count(m, WM_DEV_FRAMES, k,
              hw_delta(m, id, web_jl_int(r, "frame_count", 0),
                       web_jl_int(r, "first_seen", -1)), now);
    } else if (!strcmp(t, "assoc")) {
        if (web_key_mac(web_jl_str(r, "sta_mac"), k) != 0) return;
        if (web_key_mac(web_jl_str(r, "bssid"), k2) != 0) return;
        snprintf(id, sizeof(id), "as|%s|%s", k2, k);
        count(m, WM_DEV_FRAMES, k,
              hw_delta(m, id, web_jl_int(r, "frame_count", 0),
                       web_jl_int(r, "first_seen", -1)), now);
    } else if (!strcmp(t, "seqnum_client")) {
        if (web_key_mac(web_jl_str(r, "mac"), k) != 0) return;
        snprintf(id, sizeof(id), "sq|%s", k);
        count(m, WM_DEV_FRAMES, k,
              hw_delta(m, id, web_jl_int(r, "frame_count", 0), -1), now);
    } else if (!strcmp(t, "dns")) {
        if (web_key_ip(web_jl_str(r, "src"), k) != 0) return;
        long long resp = web_jl_int(r, "is_resp", -1);
        const char *ans = web_jl_str(r, "answer");
        if (resp == 0) web_rollup_add(m->ru, WM_DNS_QUERIES, k, 1, now);
        else if (resp == 1 && ans && !strcmp(ans, "NXDOMAIN"))
            web_rollup_add(m->ru, WM_DNS_NXDOMAIN, k, 1, now);
    } else if (!strcmp(t, "tls")) {
        if (web_key_ip(web_jl_str(r, "src"), k) != 0) return;
        web_rollup_add(m->ru, WM_TLS_HANDSHAKES, k, 1, now);
    } else if (!strcmp(t, "http")) {
        /* A response carries status (#71); only requests count. */
        if (web_jl_get(r, "status")) return;
        if (web_key_ip(web_jl_str(r, "src"), k) != 0) return;
        web_rollup_add(m->ru, WM_HTTP_REQUESTS, k, 1, now);
    } else if (!strcmp(t, "alert")) {
        if (web_key_alert_type(web_jl_int(r, "ty", -1), k) != 0) return;
        web_rollup_add(m->ru, WM_ALERTS_FIRED, k, 1, now);
    } else if (!strcmp(t, "channel_summary")) {
        if (web_key_channel(web_jl_int(r, "channel", -1),
                            web_jl_str(r, "band"), k) != 0) return;
        gauge(m, r, "ap_count", WM_WIFI_AP_COUNT, k, now);
        snprintf(id, sizeof(id), "ch|%s", k);
        count(m, WM_WIFI_CTRL_TOTAL, k,
              hw_delta(m, id, web_jl_int(r, "ctrl_total", 0), -1), now);
    } else if (!strcmp(t, "deauth")) {
        char s[WEB_KEY_MAX + 1], d[WEB_KEY_MAX + 1];
        if (web_key_mac(web_jl_str(r, "bssid"), k) != 0) return;
        if (web_key_mac(web_jl_str(r, "src"), s) != 0) return;
        if (web_key_mac(web_jl_str(r, "dst"), d) != 0) return;
        snprintf(id, sizeof(id), "da|%s|%s|%s|%lld", s, d, k,
                 web_jl_int(r, "subtype", -1));
        count(m, WM_WIFI_DEAUTH, k,
              hw_delta(m, id, web_jl_int(r, "count", 0),
                       web_jl_int(r, "first_seen", -1)), now);
    } else if (!strcmp(t, "connections")) {
        m->conns_n++;
    } else if (!strcmp(t, "ssh_flow")) {
        flow(m, r, "ssh", "src_ip", "dst_ip", web_jl_int(r, "banner_count", 0),
             WM_FLOW_SSH, now);
    } else if (!strcmp(t, "rdp_flow")) {
        flow(m, r, "rdp", "src_ip", "dst_ip",
             web_jl_int(r, "connect_req_count", 0), WM_FLOW_RDP, now);
    } else if (!strcmp(t, "smb_session")) {
        flow(m, r, "smb", "client_ip", "server_ip", web_jl_int(r, "count", 0),
             WM_FLOW_SMB, now);
    } else if (!strcmp(t, "snmp_flow")) {
        static const char *const pdus[] = {
            "get_count", "getnext_count", "getbulk_count", "set_count",
            "response_count", "trap_count", NULL
        };
        flow(m, r, "snmp", "src_ip", "dst_ip", sum_of(r, pdus), WM_FLOW_SNMP,
             now);
    } else if (!strcmp(t, "mqtt_flow")) {
        static const char *const pk[] = {
            "connect_count", "subscribe_count", "publish_count", NULL
        };
        flow(m, r, "mqtt", "src_ip", "dst_ip", sum_of(r, pk), WM_FLOW_MQTT,
             now);
    }
}
