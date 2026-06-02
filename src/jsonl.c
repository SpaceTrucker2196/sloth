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

#define LINEBUF 1024

static void kv_str(char *buf, int sz, int *off, const char *key, const char *val) {
    *off += snprintf(buf + *off, (size_t)(sz - *off), ",\"%s\":\"", key);
    json_escape(val, buf, sz, off);
    *off += snprintf(buf + *off, (size_t)(sz - *off), "\"");
}

static void kv_int(char *buf, int sz, int *off, const char *key, long long val) {
    *off += snprintf(buf + *off, (size_t)(sz - *off),
                     ",\"%s\":%lld", key, val);
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
