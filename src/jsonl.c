#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "jsonl.h"
#include "bandwidth.h"
#include "data_socket.h"

static FILE           *g_fp;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* True if either the file sink or the data-socket sink has a consumer.
 * Used by every jsonl_emit_* to skip the format work when nobody is
 * listening — running sloth without -o and without --data-socket should
 * not pay for JSON encoding it'll never deliver. */
static int any_sink(void) {
    return g_fp != NULL || data_socket_has_clients();
}

int jsonl_open(const char *path) {
    if (!path || !path[0]) return 0;
    pthread_mutex_lock(&g_mu);
    if (g_fp) { fclose(g_fp); g_fp = NULL; }
    g_fp = fopen(path, "a");
    int ok = g_fp != NULL;
    pthread_mutex_unlock(&g_mu);
    return ok;
}

void jsonl_close(void) {
    pthread_mutex_lock(&g_mu);
    if (g_fp) { fclose(g_fp); g_fp = NULL; }
    pthread_mutex_unlock(&g_mu);
}

int jsonl_is_open(void) {
    pthread_mutex_lock(&g_mu);
    int ok = g_fp != NULL;
    pthread_mutex_unlock(&g_mu);
    return ok;
}

/* Append RFC 8259-compatible escaping of `s` into `out` (size `sz`),
 * advancing *off. Truncates silently. Used by all emitters. */
static void json_escape(const char *s, char *out, int sz, int *off) {
    if (!s) s = "";
    for (; *s && *off + 6 < sz; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  out[(*off)++] = '\\'; out[(*off)++] = '"';  break;
            case '\\': out[(*off)++] = '\\'; out[(*off)++] = '\\'; break;
            case '\n': out[(*off)++] = '\\'; out[(*off)++] = 'n';  break;
            case '\r': out[(*off)++] = '\\'; out[(*off)++] = 'r';  break;
            case '\t': out[(*off)++] = '\\'; out[(*off)++] = 't';  break;
            default:
                if (c < 0x20) {
                    *off += snprintf(out + *off, (size_t)(sz - *off),
                                     "\\u%04x", c);
                } else {
                    out[(*off)++] = (char)c;
                }
        }
    }
    out[*off] = '\0';
}

/* Helper: write a complete JSON line to every active sink — the
 * configured file (if any) and every connected data-socket client.
 * Broadcast happens outside the file mutex; data_socket has its own. */
static void emit_line(const char *line) {
    pthread_mutex_lock(&g_mu);
    if (g_fp) {
        fputs(line, g_fp);
        fputc('\n', g_fp);
        fflush(g_fp);
    }
    pthread_mutex_unlock(&g_mu);
    data_socket_emit(line);
}

/* ── builder helpers ─────────────────────────────────────── */

/* 2048 is enough for the richest snapshot record (beacon with full
 * neighbor + ssid-history arrays); the event emitters all comfortably
 * fit in their original 1 KiB envelope. */
#define LINEBUF 2048

static void kv_str(char *buf, int sz, int *off, const char *key, const char *val) {
    *off += snprintf(buf + *off, (size_t)(sz - *off), ",\"%s\":\"", key);
    json_escape(val, buf, sz, off);
    *off += snprintf(buf + *off, (size_t)(sz - *off), "\"");
}

static void kv_int(char *buf, int sz, int *off, const char *key, long long val) {
    *off += snprintf(buf + *off, (size_t)(sz - *off),
                     ",\"%s\":%lld", key, val);
}

static void kv_double(char *buf, int sz, int *off, const char *key, double val) {
    *off += snprintf(buf + *off, (size_t)(sz - *off),
                     ",\"%s\":%.2f", key, val);
}

static void kv_mac(char *buf, int sz, int *off, const char *key,
                   const uint8_t mac[6]) {
    char m[20];
    snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    kv_str(buf, sz, off, key, m);
}

static void start_obj(char *buf, int sz, int *off, const char *type, time_t ts) {
    *off = snprintf(buf, (size_t)sz,
                    "{\"type\":\"%s\",\"ts\":%lld", type, (long long)ts);
}

static void end_obj(char *buf, int sz, int *off) {
    if (*off < sz - 1) buf[(*off)++] = '}';
    buf[*off] = '\0';
}

/* ── emitters ────────────────────────────────────────────── */

void jsonl_emit_dns(const dns_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "dns", e->ts);
    kv_str(buf, LINEBUF, &off, "src",    e->src);
    kv_str(buf, LINEBUF, &off, "qname",  e->qname);
    kv_str(buf, LINEBUF, &off, "qtype",  e->qtype);
    kv_str(buf, LINEBUF, &off, "answer", e->answer);
    kv_int(buf, LINEBUF, &off, "is_resp", e->is_resp ? 1 : 0);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_tls(const tls_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "tls", e->ts);
    kv_str(buf, LINEBUF, &off, "src",  e->src);
    kv_str(buf, LINEBUF, &off, "dst",  e->dst);
    kv_str(buf, LINEBUF, &off, "host", e->host);
    kv_str(buf, LINEBUF, &off, "ver",  e->tls_ver);
    kv_str(buf, LINEBUF, &off, "ja3",  e->ja3);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_quic(const quic_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "quic", e->ts);
    kv_str(buf, LINEBUF, &off, "src",  e->src);
    kv_str(buf, LINEBUF, &off, "dst",  e->dst);
    kv_str(buf, LINEBUF, &off, "host", e->host);
    kv_str(buf, LINEBUF, &off, "ver",  e->ver);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_http(const http_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "http", e->ts);
    kv_str(buf, LINEBUF, &off, "src",    e->src);
    kv_str(buf, LINEBUF, &off, "host",   e->host);
    kv_str(buf, LINEBUF, &off, "method", e->method);
    kv_str(buf, LINEBUF, &off, "path",   e->path);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_ntp(const ntp_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "ntp", e->ts);
    kv_str(buf, LINEBUF, &off, "src",  e->src);
    kv_str(buf, LINEBUF, &off, "dst",  e->dst);
    kv_str(buf, LINEBUF, &off, "mode", e->mode);
    kv_int(buf, LINEBUF, &off, "version", e->version);
    kv_int(buf, LINEBUF, &off, "stratum", e->stratum);
    kv_str(buf, LINEBUF, &off, "ref",  e->ref);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_icmp(const icmp_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "icmp", e->ts);
    kv_str(buf, LINEBUF, &off, "src", e->src);
    kv_str(buf, LINEBUF, &off, "dst", e->dst);
    kv_str(buf, LINEBUF, &off, "desc", e->desc);
    kv_int(buf, LINEBUF, &off, "ty",   e->type);
    kv_int(buf, LINEBUF, &off, "code", e->code);
    kv_int(buf, LINEBUF, &off, "seq",  e->seq);
    kv_int(buf, LINEBUF, &off, "v6",   e->is_v6 ? 1 : 0);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_alert(const alert_t *a) {
    if (!any_sink() || !a) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "alert", a->last_seen);
    kv_str(buf, LINEBUF, &off, "title",  a->title);
    kv_str(buf, LINEBUF, &off, "detail", a->detail);
    kv_str(buf, LINEBUF, &off, "key",    a->key);
    kv_int(buf, LINEBUF, &off, "sev",   (int)a->sev);
    kv_int(buf, LINEBUF, &off, "ty",    (int)a->type);
    kv_int(buf, LINEBUF, &off, "count", a->count);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

/* TCP states map to the Linux kernel's TCP_* enum (1=ESTABLISHED..11=CLOSING).
 * Same table the conns view uses; duplicated here to keep jsonl independent
 * of view code (one-way layering: views read state, emitters serialize it). */
static const char *jsonl_tcp_state_name(int st) {
    static const char *names[] = {
        "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
        "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE",
        "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"
    };
    if (st < 0 || st > 11) return "UNKNOWN";
    return names[st];
}

/* IPv6 literal addresses contain ':' (IPv4 dotted-quads never do). */
static int addr_is_v6(const char *a) { return strchr(a, ':') != NULL; }

static void fmt_endpoint(char *out, int sz, const char *addr, uint16_t port) {
    if (addr_is_v6(addr)) snprintf(out, (size_t)sz, "[%s]:%u", addr, port);
    else                  snprintf(out, (size_t)sz, "%s:%u",   addr, port);
}

static void fmt_bssid_lower(char out[20], const uint8_t b[6]) {
    snprintf(out, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
}

void jsonl_emit_twin_episodes(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->twin_episode_count; i++) {
        const twin_episode_t *e = &s->twin_episodes[i];
        char buf[LINEBUF]; int off = 0;
        char real_bssid[20], twin_bssid[20];
        fmt_bssid_lower(real_bssid, e->real_bssid);
        fmt_bssid_lower(twin_bssid, e->twin_bssid);
        start_obj(buf, LINEBUF, &off, "twin_episode", now);
        kv_str(buf, LINEBUF, &off, "ssid",                e->ssid);
        kv_str(buf, LINEBUF, &off, "real_bssid",          real_bssid);
        kv_str(buf, LINEBUF, &off, "twin_bssid",          twin_bssid);
        kv_str(buf, LINEBUF, &off, "enc",                 e->enc);
        kv_int(buf, LINEBUF, &off, "real_rssi",           (long long)e->real_rssi);
        kv_int(buf, LINEBUF, &off, "twin_rssi",           (long long)e->twin_rssi);
        kv_int(buf, LINEBUF, &off, "rssi_swing_dbm",      (long long)e->rssi_swing_dbm);
        kv_int(buf, LINEBUF, &off, "attack_in_progress",  e->attack_in_progress ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "attacker_oui",        e->attacker_oui       ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "hash_mismatch",       e->hash_mismatch      ? 1 : 0);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_connections(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];
        char  buf[LINEBUF]; int off = 0;
        char  src[64], dst[64];
        fmt_endpoint(src, sizeof(src), c->local_addr,  c->local_port);
        fmt_endpoint(dst, sizeof(dst), c->remote_addr, c->remote_port);

        start_obj(buf, LINEBUF, &off, "connections", now);
        kv_str(buf, LINEBUF, &off, "src",   src);
        kv_str(buf, LINEBUF, &off, "dst",   dst);
        kv_str(buf, LINEBUF, &off, "proto", c->proto == PROTO_TCP ? "tcp" : "udp");
        if (c->proto == PROTO_TCP) {
            kv_str(buf, LINEBUF, &off, "state", jsonl_tcp_state_name(c->state));
            if (c->rtt_us) {
                /* RTT formatted with one decimal — emit as raw number, not via kv_int. */
                off += snprintf(buf + off, (size_t)(LINEBUF - off),
                                ",\"rtt_ms\":%.1f", c->rtt_us / 1000.0);
            }
            kv_int(buf, LINEBUF, &off, "retx", (long long)c->retrans);
        }
        const conn_bw_t *bw = bw_lookup(s, c);
        kv_int(buf, LINEBUF, &off, "rx_bytes", bw ? (long long)bw->rx_bytes : 0);
        kv_int(buf, LINEBUF, &off, "tx_bytes", bw ? (long long)bw->tx_bytes : 0);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* ── Per-view snapshot emitters ──────────────────────────────
 *
 * One JSONL line per entry in each table. Cadence is the poll
 * loop (≈1 Hz); consumers rebuild the view from the latest
 * snapshot, keyed by an obvious natural identity field documented
 * in each emitter. Any-sink gating up front means the format work
 * is skipped entirely when nobody is listening. */

void jsonl_emit_ifaces(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->iface_count; i++) {
        const iface_stat_t *e = &s->ifaces[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "iface", now);
        kv_str(buf, LINEBUF, &off, "name",       e->name);
        kv_int(buf, LINEBUF, &off, "rx_bytes",   (long long)e->rx_bytes);
        kv_int(buf, LINEBUF, &off, "tx_bytes",   (long long)e->tx_bytes);
        kv_int(buf, LINEBUF, &off, "rx_packets", (long long)e->rx_packets);
        kv_int(buf, LINEBUF, &off, "tx_packets", (long long)e->tx_packets);
        kv_int(buf, LINEBUF, &off, "rx_errors",  (long long)e->rx_errors);
        kv_int(buf, LINEBUF, &off, "rx_drops",   (long long)e->rx_drops);
        kv_int(buf, LINEBUF, &off, "tx_errors",  (long long)e->tx_errors);
        kv_int(buf, LINEBUF, &off, "tx_drops",   (long long)e->tx_drops);
        kv_double(buf, LINEBUF, &off, "rx_rate", e->rx_rate);
        kv_double(buf, LINEBUF, &off, "tx_rate", e->tx_rate);
        kv_int(buf, LINEBUF, &off, "mtu",        (long long)e->mtu);
        kv_int(buf, LINEBUF, &off, "speed_mbps", (long long)e->speed_mbps);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_arp(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->arp_count; i++) {
        const arp_entry_t *e = &s->arp_entries[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "arp", now);
        kv_str(buf, LINEBUF, &off, "ip",    e->ip);
        kv_mac(buf, LINEBUF, &off, "mac",   e->mac);
        kv_str(buf, LINEBUF, &off, "iface", e->iface);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_dhcp_leases(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->dhcp_count; i++) {
        const dhcp_lease_t *e = &s->dhcp_leases[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "dhcp_lease", now);
        kv_str(buf, LINEBUF, &off, "ip",       e->ip);
        kv_str(buf, LINEBUF, &off, "hostname", e->hostname);
        kv_int(buf, LINEBUF, &off, "expire",   (long long)e->expire);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_wifi_aps(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->ap_count; i++) {
        const wifi_ap_t *e = &s->aps[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_ap", now);
        kv_str(buf, LINEBUF, &off, "ssid",       e->ssid);
        kv_str(buf, LINEBUF, &off, "bssid",      e->bssid);
        kv_int(buf, LINEBUF, &off, "signal_dbm", e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "channel",    e->channel);
        kv_str(buf, LINEBUF, &off, "enc",        e->enc);
        kv_int(buf, LINEBUF, &off, "status",     e->status);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_wifi_stas(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->wifi_sta_count; i++) {
        const wifi_sta_t *e = &s->wifi_stas[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_sta", now);
        kv_str(buf, LINEBUF, &off, "mac",            e->mac);
        kv_int(buf, LINEBUF, &off, "signal_dbm",     e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "tx_rate_kbps",   (long long)e->tx_rate_kbps);
        kv_int(buf, LINEBUF, &off, "rx_rate_kbps",   (long long)e->rx_rate_kbps);
        kv_int(buf, LINEBUF, &off, "connected_secs", (long long)e->connected_secs);
        kv_int(buf, LINEBUF, &off, "inactive_ms",    (long long)e->inactive_ms);
        kv_int(buf, LINEBUF, &off, "tx_bytes",       (long long)e->tx_bytes);
        kv_int(buf, LINEBUF, &off, "rx_bytes",       (long long)e->rx_bytes);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_top_hosts(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->top_host_count; i++) {
        const top_host_t *e = &s->top_hosts[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "top_host", now);
        kv_str(buf, LINEBUF, &off, "ip",         e->ip);
        kv_str(buf, LINEBUF, &off, "hostname",   e->hostname);
        kv_str(buf, LINEBUF, &off, "owner",      e->owner);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "conn_count", (long long)e->conn_count);
        kv_double(buf, LINEBUF, &off, "rx_rate", e->rx_rate);
        kv_double(buf, LINEBUF, &off, "tx_rate", e->tx_rate);
        kv_int(buf, LINEBUF, &off, "rx_bytes",   (long long)e->rx_bytes);
        kv_int(buf, LINEBUF, &off, "tx_bytes",   (long long)e->tx_bytes);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_devices(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->device_count; i++) {
        const device_t *e = &s->devices[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "device", now);
        kv_mac(buf, LINEBUF, &off, "mac",         e->mac);
        kv_str(buf, LINEBUF, &off, "ip",          e->ip);
        kv_str(buf, LINEBUF, &off, "hostname",    e->hostname);
        kv_str(buf, LINEBUF, &off, "vendor",      e->vendor);
        kv_str(buf, LINEBUF, &off, "last_ssid",   e->last_ssid);
        kv_int(buf, LINEBUF, &off, "is_ap",       e->is_ap ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "signal_dbm",  e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "probe_count", (long long)e->probe_count);
        kv_int(buf, LINEBUF, &off, "sources",     (long long)e->sources);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_beacons(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *e = &s->beacon_aps[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "beacon", now);
        kv_str(buf, LINEBUF, &off, "ssid",       e->ssid);
        kv_mac(buf, LINEBUF, &off, "bssid",      e->bssid);
        kv_int(buf, LINEBUF, &off, "signal_dbm", e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "channel",    e->channel);
        kv_str(buf, LINEBUF, &off, "enc",        e->enc);
        kv_int(buf, LINEBUF, &off, "beacon_ms",  (long long)e->beacon_ms);
        kv_str(buf, LINEBUF, &off, "pairwise",   e->pairwise);
        kv_str(buf, LINEBUF, &off, "group",      e->group);
        kv_str(buf, LINEBUF, &off, "akm",        e->akm);
        kv_int(buf, LINEBUF, &off, "mfp",        e->mfp);
        kv_str(buf, LINEBUF, &off, "vendor",     e->vendor);
        kv_int(buf, LINEBUF, &off, "has_wps",    e->has_wps ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "wps_state",  e->wps_state);
        kv_int(buf, LINEBUF, &off, "wps_locked", e->wps_locked);
        kv_str(buf, LINEBUF, &off, "phy",        e->phy);
        kv_int(buf, LINEBUF, &off, "revealed",   e->revealed ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "frame_count",(long long)e->frame_count);
        /* fp — flags + vendor-IE hash; OUI is the BSSID prefix, omit. */
        kv_int(buf, LINEBUF, &off, "fp_flags",       e->fp.flags);
        kv_int(buf, LINEBUF, &off, "vendor_ies_hash",(long long)e->fp.vendor_ies_hash);
        kv_int(buf, LINEBUF, &off, "rssi_min_60s", e->rssi_min_60s);
        kv_int(buf, LINEBUF, &off, "rssi_max_60s", e->rssi_max_60s);
        /* ssid_history as a JSON array — bounded by MAX_AP_SSID_HISTORY. */
        off += snprintf(buf + off, (size_t)(LINEBUF - off),
                        ",\"ssid_history\":[");
        for (int k = 0; k < e->ssid_history_n; k++) {
            off += snprintf(buf + off, (size_t)(LINEBUF - off),
                            "%s\"", k ? "," : "");
            json_escape(e->ssid_history[k], buf, LINEBUF, &off);
            off += snprintf(buf + off, (size_t)(LINEBUF - off), "\"");
        }
        off += snprintf(buf + off, (size_t)(LINEBUF - off), "]");
        /* neighbors[] — array of {bssid, channel, phy_type}. */
        off += snprintf(buf + off, (size_t)(LINEBUF - off),
                        ",\"neighbors\":[");
        for (int k = 0; k < e->neighbor_count; k++) {
            const ap_neighbor_t *n = &e->neighbors[k];
            char nb[20];
            snprintf(nb, sizeof(nb),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     n->bssid[0], n->bssid[1], n->bssid[2],
                     n->bssid[3], n->bssid[4], n->bssid[5]);
            off += snprintf(buf + off, (size_t)(LINEBUF - off),
                            "%s{\"bssid\":\"%s\",\"channel\":%d,\"phy_type\":%d}",
                            k ? "," : "", nb, n->channel, n->phy_type);
        }
        off += snprintf(buf + off, (size_t)(LINEBUF - off), "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_deauths(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->deauth_count; i++) {
        const deauth_event_t *e = &s->deauth_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "deauth", now);
        kv_mac(buf, LINEBUF, &off, "src",        e->src);
        kv_mac(buf, LINEBUF, &off, "dst",        e->dst);
        kv_mac(buf, LINEBUF, &off, "bssid",      e->bssid);
        kv_int(buf, LINEBUF, &off, "reason",     e->reason);
        kv_int(buf, LINEBUF, &off, "subtype",    e->subtype);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "count",      (long long)e->count);
        kv_int(buf, LINEBUF, &off, "flood",      e->flood ? 1 : 0);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_probe_clients(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->probe_count; i++) {
        const probe_client_t *e = &s->probe_clients[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "probe_client", now);
        kv_mac(buf, LINEBUF, &off, "mac",         e->mac);
        kv_str(buf, LINEBUF, &off, "ssid",        e->ssid);
        kv_int(buf, LINEBUF, &off, "signal_dbm",  e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "channel",     e->channel);
        kv_int(buf, LINEBUF, &off, "first_seen",  (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "frame_count", (long long)e->frame_count);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_pnl_clients(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->pnl_count; i++) {
        const pnl_client_t *e = &s->pnl_clients[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "pnl_client", now);
        kv_mac(buf, LINEBUF, &off, "mac",         e->mac);
        kv_int(buf, LINEBUF, &off, "mac_random",  e->mac_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "probe_count", (long long)e->probe_count);
        kv_str(buf, LINEBUF, &off, "os_fp",       e->os_fp);
        kv_str(buf, LINEBUF, &off, "phy",         e->phy);
        kv_int(buf, LINEBUF, &off, "first_seen",  (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        off += snprintf(buf + off, (size_t)(LINEBUF - off), ",\"ssids\":[");
        for (int k = 0; k < e->ssid_count; k++) {
            off += snprintf(buf + off, (size_t)(LINEBUF - off),
                            "%s\"", k ? "," : "");
            json_escape(e->ssids[k], buf, LINEBUF, &off);
            off += snprintf(buf + off, (size_t)(LINEBUF - off), "\"");
        }
        off += snprintf(buf + off, (size_t)(LINEBUF - off), "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_seqnum_clients(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->seqnum_count; i++) {
        const seqnum_client_t *e = &s->seqnum_clients[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "seqnum_client", now);
        kv_mac(buf, LINEBUF, &off, "mac",         e->mac);
        kv_int(buf, LINEBUF, &off, "mac_random",  e->mac_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "frame_count", (long long)e->frame_count);
        off += snprintf(buf + off, (size_t)(LINEBUF - off), ",\"hist\":[");
        for (int k = 0; k < e->hist_n; k++) {
            off += snprintf(buf + off, (size_t)(LINEBUF - off),
                            "%s%u", k ? "," : "", e->hist[k]);
        }
        off += snprintf(buf + off, (size_t)(LINEBUF - off), "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_seqnum_correlations(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->seqnum_correlation_count; i++) {
        const seqnum_correlation_t *e = &s->seqnum_correlations[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "seqnum_correlation", now);
        kv_mac(buf, LINEBUF, &off, "mac_a",        e->mac_a);
        kv_mac(buf, LINEBUF, &off, "mac_b",        e->mac_b);
        kv_int(buf, LINEBUF, &off, "mac_a_random", e->mac_a_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "mac_b_random", e->mac_b_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "gap",          e->gap);
        kv_int(buf, LINEBUF, &off, "dt_ms",        (long long)e->dt_ms);
        kv_int(buf, LINEBUF, &off, "a_count",      (long long)e->a_count);
        kv_int(buf, LINEBUF, &off, "b_count",      (long long)e->b_count);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_channels(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->channel_count; i++) {
        const channel_summary_t *e = &s->channels[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "channel_summary", now);
        kv_int(buf, LINEBUF, &off, "channel",     e->channel);
        kv_int(buf, LINEBUF, &off, "ap_count",    e->ap_count);
        kv_int(buf, LINEBUF, &off, "assoc_count", e->assoc_count);
        kv_int(buf, LINEBUF, &off, "best_signal", e->best_signal);
        kv_str(buf, LINEBUF, &off, "top_ssid",    e->top_ssid);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_assocs(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->assoc_count; i++) {
        const assoc_t *e = &s->assocs[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "assoc", now);
        kv_mac(buf, LINEBUF, &off, "bssid",       e->bssid);
        kv_mac(buf, LINEBUF, &off, "sta_mac",     e->sta_mac);
        kv_str(buf, LINEBUF, &off, "ssid",        e->ssid);
        kv_int(buf, LINEBUF, &off, "sta_random",  e->sta_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "source",      e->source);
        kv_int(buf, LINEBUF, &off, "channel",     e->channel);
        kv_int(buf, LINEBUF, &off, "signal_dbm",  e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "first_seen",  (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "frame_count", (long long)e->frame_count);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_eapol_events(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->eapol_count; i++) {
        const eapol_event_t *e = &s->eapol_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "eapol", now);
        kv_mac(buf, LINEBUF, &off, "bssid",      e->bssid);
        kv_mac(buf, LINEBUF, &off, "sta_mac",    e->sta_mac);
        kv_str(buf, LINEBUF, &off, "ssid",       e->ssid);
        kv_int(buf, LINEBUF, &off, "event_ts",   (long long)e->ts);
        kv_int(buf, LINEBUF, &off, "msg_num",    e->msg_num);
        kv_int(buf, LINEBUF, &off, "has_pmkid",  e->has_pmkid ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "handshake_complete",
                                                 e->handshake_complete ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "signal_dbm", e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "channel",    e->channel);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_mdns_services(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->mdns_count; i++) {
        const mdns_service_t *e = &s->mdns_services[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "mdns_service", now);
        kv_str(buf, LINEBUF, &off, "instance",  e->instance);
        kv_str(buf, LINEBUF, &off, "service",   e->service);
        kv_str(buf, LINEBUF, &off, "host",      e->host);
        kv_str(buf, LINEBUF, &off, "ip",        e->ip);
        kv_int(buf, LINEBUF, &off, "port",      e->port);
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_nbns_names(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->nbns_count; i++) {
        const nbns_name_t *e = &s->nbns_names[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "nbns_name", now);
        kv_str(buf, LINEBUF, &off, "name",      e->name);
        kv_str(buf, LINEBUF, &off, "ip",        e->ip);
        kv_int(buf, LINEBUF, &off, "suffix",    e->suffix);
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_ssdp_devices(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->ssdp_count; i++) {
        const ssdp_device_t *e = &s->ssdp_devices[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "ssdp_device", now);
        kv_str(buf, LINEBUF, &off, "ip",        e->ip);
        kv_str(buf, LINEBUF, &off, "kind",      e->type);  /* "type" is JSON-reserved-ish; rename */
        kv_str(buf, LINEBUF, &off, "usn",       e->usn);
        kv_str(buf, LINEBUF, &off, "location",  e->location);
        kv_str(buf, LINEBUF, &off, "nts",       e->nts);
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_scan_entries(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->scan_count; i++) {
        const scan_entry_t *e = &s->scan_entries[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "scan_entry", now);
        kv_str(buf, LINEBUF, &off, "ip",         e->ip);
        kv_int(buf, LINEBUF, &off, "port_count", e->port_count);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "flagged",    e->flagged ? 1 : 0);
        /* Distinct ports as a small array — bounded by MAX_SCAN_PORTS. */
        off += snprintf(buf + off, (size_t)(LINEBUF - off), ",\"ports\":[");
        for (int k = 0; k < e->port_count && k < MAX_SCAN_PORTS; k++) {
            off += snprintf(buf + off, (size_t)(LINEBUF - off),
                            "%s%u", k ? "," : "", e->ports[k]);
        }
        off += snprintf(buf + off, (size_t)(LINEBUF - off), "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_packets(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    /* Packet ring is sized at MAX_PACKETS; pkt_count is the number
     * of *written* slots, capped at MAX_PACKETS. We emit ALL currently
     * valid entries each tick — the ring's ordering doesn't matter for
     * the snapshot model. raw bytes are deliberately omitted (would
     * leak frame contents into log files); only the metadata ships. */
    int n = s->pkt_count < MAX_PACKETS ? s->pkt_count : MAX_PACKETS;
    for (int i = 0; i < n; i++) {
        const packet_info_t *e = &s->packets[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "packet", now);
        kv_int(buf, LINEBUF, &off, "ts_sec",   (long long)e->ts_sec);
        kv_int(buf, LINEBUF, &off, "ts_usec",  (long long)e->ts_usec);
        kv_str(buf, LINEBUF, &off, "src",      e->src);
        kv_str(buf, LINEBUF, &off, "dst",      e->dst);
        kv_int(buf, LINEBUF, &off, "src_port", e->src_port);
        kv_int(buf, LINEBUF, &off, "dst_port", e->dst_port);
        kv_int(buf, LINEBUF, &off, "proto",    e->proto);
        kv_int(buf, LINEBUF, &off, "len",      (long long)e->len);
        kv_str(buf, LINEBUF, &off, "info",     e->info);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_state_snapshots(const sloth_state_t *s) {
    /* Cheap gating — every emitter checks any_sink() too, but the
     * batch-level skip avoids the per-call setup when nobody's there. */
    if (!any_sink() || !s) return;
    jsonl_emit_ifaces            (s);
    jsonl_emit_arp               (s);
    jsonl_emit_dhcp_leases       (s);
    jsonl_emit_wifi_aps          (s);
    jsonl_emit_wifi_stas         (s);
    jsonl_emit_top_hosts         (s);
    jsonl_emit_devices           (s);
    jsonl_emit_beacons           (s);
    jsonl_emit_deauths           (s);
    jsonl_emit_probe_clients     (s);
    jsonl_emit_pnl_clients       (s);
    jsonl_emit_seqnum_clients    (s);
    jsonl_emit_seqnum_correlations(s);
    jsonl_emit_channels          (s);
    jsonl_emit_assocs            (s);
    jsonl_emit_eapol_events      (s);
    jsonl_emit_mdns_services     (s);
    jsonl_emit_nbns_names        (s);
    jsonl_emit_ssdp_devices      (s);
    jsonl_emit_scan_entries      (s);
    jsonl_emit_packets           (s);
}
