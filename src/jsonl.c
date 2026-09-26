#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "jsonl.h"
#include "alerts.h"
#include "wired_attach.h"
#include "secure_file.h"
#include "beacon_snoop.h"
#include "captive_portal.h"
#include "sensors.h"
#include "bandwidth.h"
#include "data_socket.h"
#include "formatter.h"
#include "views/procs.h"
#include "sensor_health.h"
#include "capture/capture.h"
#include "alert_pcap.h"
#include "eapol_log.h"

static FILE           *g_fp;
/* Open refusal reason and write-failure count (#87), under g_mu. */
static sfile_fail_t    g_fail;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* True if either the file sink or the data-socket sink has a consumer.
 * Used by every jsonl_emit_* to skip the format work when nobody is
 * listening — running sloth without -o and without --data-socket should
 * not pay for JSON encoding it'll never deliver. */
static int any_sink(void) {
    return g_fp != NULL || data_socket_has_clients();
}

/* ── Change-only snapshot emission (issue #42) ───────────────
 * The entity-snapshot emitters (pnl_client, seqnum_client, …) run every
 * poll (~1 Hz) and re-serialise every row whether or not anything
 * changed. For a mostly idle population that is pure duplication — in
 * production ~45 % of log volume was unchanged seqnum_client / pnl_client
 * rows. Each row is reduced to a 64-bit signature of its semantic payload
 * (identity + observation fields, never the envelope ts) and looked up in
 * a small direct-mapped cache keyed by the row's natural identity. A row
 * is written only when it is new, its signature changed, or
 * JSONL_HEARTBEAT_SECS have elapsed since it was last emitted — so
 * long-lived idle entities still refresh periodically and windowed
 * consumers ("who was here 2–4 AM?") keep working.
 *
 * The cache is a pure optimisation: a hash collision can only cause an
 * extra (harmless) emit, never a wrongful suppression, because a slot is
 * consulted only when its stored identity matches exactly. */
#define JSONL_HEARTBEAT_SECS 300
#define JSONL_DEDUP_SLOTS    1024
#define JSONL_DEDUP_KEYLEN   16
#define FNV64_OFFSET         0xcbf29ce484222325ULL
#define FNV64_PRIME          0x100000001b3ULL

typedef struct {
    uint64_t sig;
    time_t   emit_ts;
    uint8_t  key[JSONL_DEDUP_KEYLEN];
    uint8_t  keylen;
    uint8_t  kind;
    uint8_t  used;
} jsonl_dedup_slot_t;

static jsonl_dedup_slot_t g_dedup[JSONL_DEDUP_SLOTS];

/* Snapshot event "kinds" — one per deduped emitter. */
enum { JD_PNL = 1, JD_SEQNUM, JD_SENSOR_HEALTH };

static uint64_t fnv1a(const void *data, size_t n, uint64_t h) {
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= FNV64_PRIME; }
    return h;
}

/* Clear the change cache so the next snapshot re-emits a full baseline.
 * Called when a sink is (re)opened and available to tests. */
void jsonl_dedup_reset(void) {
    memset(g_dedup, 0, sizeof(g_dedup));
}

/* Returns 1 if a row of this (kind,key) carrying signature `sig` should be
 * emitted now (new / changed / heartbeat elapsed), 0 to suppress an
 * unchanged duplicate. Records the decision. */
static int jsonl_changed(uint8_t kind, const void *key, size_t keylen,
                         uint64_t sig, time_t now) {
    if (keylen > JSONL_DEDUP_KEYLEN) keylen = JSONL_DEDUP_KEYLEN;
    uint64_t h = fnv1a(key, keylen, fnv1a(&kind, 1, FNV64_OFFSET));
    jsonl_dedup_slot_t *sl = &g_dedup[h % JSONL_DEDUP_SLOTS];
    int match = sl->used && sl->kind == kind && sl->keylen == (uint8_t)keylen
                && memcmp(sl->key, key, keylen) == 0;
    if (match && sl->sig == sig && (now - sl->emit_ts) < JSONL_HEARTBEAT_SECS)
        return 0;
    sl->used   = 1;
    sl->kind   = kind;
    sl->keylen = (uint8_t)keylen;
    memcpy(sl->key, key, keylen);
    sl->sig     = sig;
    sl->emit_ts = now;
    return 1;
}

int jsonl_open(const char *path) {
    if (!path || !path[0]) return 0;
    pthread_mutex_lock(&g_mu);
    if (g_fp) { fclose(g_fp); g_fp = NULL; }
    sfile_fail_reset(&g_fail);
    /* Append: the forensic log accumulates across runs. Created 0600;
     * an existing file must already be private (#87). */
    g_fp = sfile_fopen(AT_FDCWD, path, SFILE_APPEND,
                       g_fail.last, sizeof(g_fail.last));
    int ok = g_fp != NULL;
    pthread_mutex_unlock(&g_mu);
    if (ok) jsonl_dedup_reset();   /* fresh sink → full baseline snapshot */
    return ok;
}

const char *jsonl_error(void) { return g_fail.last; }

int jsonl_write_failures(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_fail.failures;
    pthread_mutex_unlock(&g_mu);
    return n;
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

/* Bounded append into `buf` (size `sz`) at *off. snprintf returns the
 * length it *would* have written, so a bare `off += snprintf(...)`
 * lets `off` pass the end; `sz - off` then wraps to a huge size_t and
 * the next write lands out of bounds. A hostile AP reaches that with
 * escape-heavy SSIDs. Clamp so *off never exceeds sz - 1 — the output
 * truncates, memory stays in bounds. Every builder write goes here. */
static void appendf(char *buf, int sz, int *off, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static void appendf(char *buf, int sz, int *off, const char *fmt, ...) {
    if (sz <= 0) return;
    if (*off < 0) *off = 0;
    if (*off >= sz - 1) { *off = sz - 1; buf[*off] = '\0'; return; }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, (size_t)(sz - *off), fmt, ap);
    va_end(ap);
    if (n < 0) { buf[*off] = '\0'; return; }
    *off += n;
    if (*off > sz - 1) *off = sz - 1;
}

/* Append RFC 8259-compatible escaping of `s` into `out` (size `sz`),
 * advancing *off. Truncates silently. Used by all emitters. */
static void json_escape(const char *s, char *out, int sz, int *off) {
    if (!s) s = "";
    if (*off > sz - 1) *off = sz - 1;
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
                    appendf(out, sz, off, "\\u%04x", c);
                } else {
                    out[(*off)++] = (char)c;
                }
        }
    }
    out[*off] = '\0';
}

/* Output buffer for the CEF/syslog transform. Sized for the richest
 * record (a worst-case LINEBUF line, defined below) re-escaped by the
 * CEF/syslog rules, plus the framing a syslog header + SD-element can
 * add. */
#define EMIT_XFORM_MAX 16384

/* Helper: write a complete record to every active sink — the
 * configured file (if any) and every connected data-socket client.
 * `line` is always JSONL (that's what the builders produce); we
 * translate to CEF / syslog at this single chokepoint when the
 * operator picked one of those formats via --out-format.
 *
 * Broadcast to the data socket happens outside the file mutex;
 * data_socket has its own lock. */
static void emit_line(const char *line) {
    char xform[EMIT_XFORM_MAX];
    const char *to_emit = line;
    if (formatter_get() != OUT_FMT_JSONL) {
        int n = formatter_transform(line, xform, (int)sizeof(xform));
        if (n < 0) return;   /* malformed input — silently drop */
        to_emit = xform;
    }
    pthread_mutex_lock(&g_mu);
    if (g_fp) {
        int bad = fputs(to_emit, g_fp) == EOF ||
                  fputc('\n', g_fp)    == EOF ||
                  fflush(g_fp)         != 0;
        if (bad || ferror(g_fp)) {
            char err[SFILE_ERR_MAX];
            snprintf(err, sizeof(err), "-o: write failed: %s", strerror(errno));
            sfile_fail(&g_fail, "jsonl", err);
            clearerr(g_fp);   /* keep trying: a full disk may drain */
        }
    }
    pthread_mutex_unlock(&g_mu);
    data_socket_emit(to_emit);
}

/* ── builder helpers ─────────────────────────────────────── */

/* Sized for the hostile worst case, not the typical one. Beacon and
 * PNL records carry attacker-chosen SSID / WPS strings that
 * json_escape can expand 6x (\u00XX): a beacon with every string
 * field full runs ~4.5 KiB, a PNL client with 16 probed SSIDs ~3.4
 * KiB. At the old 2048 a hostile AP overflowed the buffer. appendf
 * keeps any future overrun in bounds; this keeps it from truncating. */
#define LINEBUF 8192

static void kv_str(char *buf, int sz, int *off, const char *key, const char *val) {
    appendf(buf, sz, off, ",\"%s\":\"", key);
    json_escape(val, buf, sz, off);
    appendf(buf, sz, off, "\"");
}

static void kv_int(char *buf, int sz, int *off, const char *key, long long val) {
    appendf(buf, sz, off, ",\"%s\":%lld", key, val);
}

static void kv_double(char *buf, int sz, int *off, const char *key, double val) {
    appendf(buf, sz, off, ",\"%s\":%.2f", key, val);
}

static void kv_mac(char *buf, int sz, int *off, const char *key,
                   const uint8_t mac[6]) {
    char m[20];
    snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    kv_str(buf, sz, off, key, m);
}

static void start_obj(char *buf, int sz, int *off, const char *type, time_t ts) {
    *off = 0;
    appendf(buf, sz, off, "{\"type\":\"%s\",\"ts\":%lld", type, (long long)ts);
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
    if (e->ja4[0])
        kv_str(buf, LINEBUF, &off, "ja4",  e->ja4);
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
    if (e->ja4h[0])
        kv_str(buf, LINEBUF, &off, "ja4h", e->ja4h);
    /* Response side (#71), additive. body_complete is the field a
     * consumer must key on before comparing bytes: sloth does not
     * reassemble TCP, so "different" and "incomplete" are different
     * answers and only the first means anything. The body itself is
     * deliberately not emitted — it can be page content of any kind,
     * and the forensic value is in the status and the completeness. */
    if (e->is_response) {
        kv_int(buf, LINEBUF, &off, "status",         e->status);
        kv_int(buf, LINEBUF, &off, "content_length", e->content_length);
        kv_int(buf, LINEBUF, &off, "chunked",        e->chunked ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "body_complete",  e->body_complete ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "body_len",       e->resp_body_len);
    }
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
    kv_int(buf, LINEBUF, &off, "plen", e->payload_len);
    kv_int(buf, LINEBUF, &off, "v6",   e->is_v6 ? 1 : 0);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

/* The two AP-pair axes (#89 slice 3), additive per
 * docs/wiki/jsonl-schema.md and shared by the legacy `alert` record and
 * the `alert.*` lifecycle stream so a consumer never has to read both
 * families to get them.
 *
 * `ap_class` is omitted when UNKNOWN and on every rule that is not
 * about an AP pair — same rule as `confidence` and `inventory`, and for
 * the same reason: a field present on all 61 rules would assert
 * something about the 60 that never classified anything.
 *
 * `wired_attachment` is omitted when UNKNOWN, which today is always,
 * because nothing in-tree can see the wire. **Absence means "not
 * established", never "not attached"** — the schema doc says so
 * explicitly, and it is the one inference a consumer must not draw from
 * a missing field here. The `EVIL_TWIN` detail string carries a literal
 * `wired=?` for the human reading the alert. */
static void emit_pair_axes(char *buf, int *off, const alert_t *a) {
    if (a->ap_class != (uint8_t)TWIN_CLASS_UNKNOWN)
        kv_str(buf, LINEBUF, off, "ap_class",
               twin_class_label((twin_class_t)a->ap_class));
    if (a->wired_attach != (uint8_t)WIRED_ATTACH_UNKNOWN)
        kv_str(buf, LINEBUF, off, "wired_attachment",
               wired_attach_label((wired_attach_t)a->wired_attach));
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
    /* MITRE ATT&CK technique — omitted when empty so consumers don't
     * see a spurious "technique": "" for host-posture alerts like
     * NO_MONITOR_MODE. Schema is additive per docs/wiki/jsonl-schema.md. */
    if (a->technique[0])
        kv_str(buf, LINEBUF, &off, "technique", a->technique);
    /* Severity and confidence are separate axes (#89): `sev` is how bad
     * the finding is if true, `confidence` is how likely it is to be
     * true. Omitted when the rule reported none — most rules assert a
     * condition they observed directly and have nothing to qualify, and
     * emitting 0 would read as "certainly false". Additive per
     * docs/wiki/jsonl-schema.md. */
    if (a->confidence)
        kv_int(buf, LINEBUF, &off, "confidence", (int)a->confidence);
    /* Content hash of the approved inventory this finding consulted
     * (#89 slice 2), so a record in an archive names the exact file
     * that produced it — the human-readable `version` label cannot,
     * because two files may both claim one. Omitted when the rule
     * consulted no inventory: stamping every record would assert the
     * anchor backed findings it never touched. Additive per
     * docs/wiki/jsonl-schema.md. */
    if (a->inventory[0])
        kv_str(buf, LINEBUF, &off, "inventory", a->inventory);
    emit_pair_axes(buf, &off, a);
    /* Join key into the lifecycle stream (#98), additive. A consumer
     * that only knows `alert` sees exactly the record it always saw
     * plus one field it can ignore. */
    if (a->incident_id[0])
        kv_str(buf, LINEBUF, &off, "incident_id", a->incident_id);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_alert_event(const alert_t *a, const char *event, time_t ts,
                            int prev_sev, const char *reason) {
    if (!any_sink() || !a || !event) return;
    char  buf[LINEBUF]; int off = 0;
    char  event_id[ALERT_EVENT_ID_LEN];
    snprintf(event_id, sizeof(event_id), "%s-%04u",
             a->incident_id, a->event_seq % 10000u);

    start_obj(buf, LINEBUF, &off, event, ts);
    kv_str(buf, LINEBUF, &off, "event_id",    event_id);
    kv_str(buf, LINEBUF, &off, "incident_id", a->incident_id);
    kv_str(buf, LINEBUF, &off, "key",         a->key);
    kv_str(buf, LINEBUF, &off, "title",       a->title);
    kv_str(buf, LINEBUF, &off, "detail",      a->detail);
    kv_int(buf, LINEBUF, &off, "sev",   (int)a->sev);
    kv_int(buf, LINEBUF, &off, "ty",    (int)a->type);
    if (prev_sev >= 0)
        kv_int(buf, LINEBUF, &off, "prev_sev", prev_sev);
    kv_int(buf, LINEBUF, &off, "observations", a->observations);
    kv_int(buf, LINEBUF, &off, "evaluations",  a->evaluations);
    /* Same number as the legacy record's `count`, carried so a
     * lifecycle-only consumer never has to read both families. */
    kv_int(buf, LINEBUF, &off, "count",        a->count);
    kv_int(buf, LINEBUF, &off, "first_detected", (long long)a->first_detected);
    kv_int(buf, LINEBUF, &off, "last_evaluated", (long long)a->last_evaluated);
    kv_int(buf, LINEBUF, &off, "first_observed", (long long)a->first_observed);
    kv_int(buf, LINEBUF, &off, "last_observed",  (long long)a->last_observed);
    if (a->technique[0])
        kv_str(buf, LINEBUF, &off, "technique", a->technique);
    /* Same separate axis as the legacy record (#89) — a consumer paging
     * on severity can weight by how sure sloth is without a second
     * lookup. */
    if (a->confidence)
        kv_int(buf, LINEBUF, &off, "confidence", (int)a->confidence);
    /* Same field as the legacy record (#89 slice 2) — a lifecycle-only
     * consumer never has to read both families. */
    if (a->inventory[0])
        kv_str(buf, LINEBUF, &off, "inventory", a->inventory);
    emit_pair_axes(buf, &off, a);
    if (a->match_ip[0]) {
        kv_str(buf, LINEBUF, &off, "match_ip", a->match_ip);
        kv_int(buf, LINEBUF, &off, "match_port", (int)a->match_port);
        /* Per-export outcome (#92) — meaningless without a match_ip,
         * since that's the only case alert_pcap_dump() ever runs for.
         * pcap_path omitted until export actually writes a file;
         * pcap_write_failures omitted at 0 so a clean export doesn't
         * grow the line for nothing. */
        if (a->pcap_path[0])
            kv_str(buf, LINEBUF, &off, "pcap_path", a->pcap_path);
        if (a->pcap_write_failures)
            kv_int(buf, LINEBUF, &off, "pcap_write_failures",
                   a->pcap_write_failures);
    }
    if (reason && reason[0])
        kv_str(buf, LINEBUF, &off, "reason", reason);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_cleartext_cred(const cleartext_cred_t *r) {
    /* Never emit a password field, even NULL/empty. That's the whole
     * point of this event class — the exposure fact, not the secret. */
    if (!any_sink() || !r) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "cleartext_cred", r->ts);
    kv_str(buf, LINEBUF, &off, "src",       r->src);
    kv_str(buf, LINEBUF, &off, "dst",       r->dst);
    kv_int(buf, LINEBUF, &off, "dst_port",  (int)r->dst_port);
    kv_str(buf, LINEBUF, &off, "protocol",  r->protocol);
    kv_str(buf, LINEBUF, &off, "username",  r->username);
    kv_int(buf, LINEBUF, &off, "pw_observed", r->password_observed);
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
        /* Additive (#89). `attributed` 0 means `real_bssid`/`twin_bssid`
         * hold the pair in canonical BSSID order and nothing has
         * established which half is the impostor — a consumer must not
         * read `twin_bssid` as an accusation. RSSI used to decide this
         * and RSSI is not ownership. */
        kv_int(buf, LINEBUF, &off, "attributed",           e->attributed ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "confidence",           (long long)e->confidence);
        /* The two pair axes (#89 slice 3), same shape and same omission
         * rule as on the alert records. `wired_attachment` absent means
         * nothing that can see the wire has answered — not that the AP
         * is off the wire. */
        if (e->ap_class != (uint8_t)TWIN_CLASS_UNKNOWN)
            kv_str(buf, LINEBUF, &off, "ap_class",
                   twin_class_label((twin_class_t)e->ap_class));
        if (e->wired_attach != (uint8_t)WIRED_ATTACH_UNKNOWN)
            kv_str(buf, LINEBUF, &off, "wired_attachment",
                   wired_attach_label((wired_attach_t)e->wired_attach));
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
                appendf(buf, LINEBUF, &off, ",\"rtt_ms\":%.1f", c->rtt_us / 1000.0);
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
        kv_str(buf, LINEBUF, &off, "risk",         device_risk_label(e->risk_level));
        kv_int(buf, LINEBUF, &off, "risk_signals", (long long)e->risk_signals);
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
        /* Additive (#62): WPA_DG_* bits — the downgrade lanes this
         * AP advertises about itself. 0 for a clean posture. */
        kv_int(buf, LINEBUF, &off, "downgrade_flags", e->downgrade_flags);
        kv_int(buf, LINEBUF, &off, "akm_bits",   (long long)e->akm_bits);
        /* Additive (#66): what the BSS is actually operating on, as
         * distinct from what its radio can do. channel_source names
         * which IE supplied the primary channel, so a wrong one is
         * attributable — DS Param is absent on much 6 GHz gear. */
        kv_int(buf, LINEBUF, &off, "operating_width",  e->operating_width);
        kv_int(buf, LINEBUF, &off, "primary_channel",  e->primary_channel);
        kv_int(buf, LINEBUF, &off, "channel_source",   e->channel_source);
        kv_int(buf, LINEBUF, &off, "secondary_offset", e->secondary_offset);
        kv_str(buf, LINEBUF, &off, "vendor",     e->vendor);
        kv_int(buf, LINEBUF, &off, "has_wps",    e->has_wps ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "wps_state",  e->wps_state);
        kv_int(buf, LINEBUF, &off, "wps_locked", e->wps_locked);
        /* Additive (#82): Config Methods bitmap / Device Password ID.
         * 0 = not observed for both; 0x0004 on the latter means the AP
         * is advertising an active WPS Push-Button session right now.
         * Not sticky — reflects the most recent beacon only. */
        kv_int(buf, LINEBUF, &off, "wps_config_methods", e->wps_config_methods);
        kv_int(buf, LINEBUF, &off, "wps_device_pwd_id",  e->wps_device_pwd_id);
        /* Additive (#77): WPS Manufacturer / Model Name / Model Number /
         * Serial Number, when the beacon's WPS IE leaks them. "" when
         * absent, same convention as `vendor` above. */
        kv_str(buf, LINEBUF, &off, "wps_manufacturer", e->wps_manufacturer);
        kv_str(buf, LINEBUF, &off, "wps_model_name",    e->wps_model_name);
        kv_str(buf, LINEBUF, &off, "wps_model_number",  e->wps_model_number);
        kv_str(buf, LINEBUF, &off, "wps_serial",        e->wps_serial);
        kv_str(buf, LINEBUF, &off, "phy",        e->phy);
        kv_int(buf, LINEBUF, &off, "revealed",   e->revealed ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "frame_count",(long long)e->frame_count);
        /* fp — flags + vendor-IE hash; OUI is the BSSID prefix, omit. */
        kv_int(buf, LINEBUF, &off, "fp_flags",       e->fp.flags);
        kv_int(buf, LINEBUF, &off, "vendor_ies_hash",(long long)e->fp.vendor_ies_hash);
        /* Additive (#77): IE-ordering fingerprint; 0 = not decoded. */
        kv_int(buf, LINEBUF, &off, "ie_order_hash",  (long long)e->fp.ie_order_hash);
        kv_int(buf, LINEBUF, &off, "ie_order_count", e->fp.ie_order_count);
        /* Additive (#77): beacon TBTT jitter — stddev of the AP's own
         * medium-access deferral, in µs on the AP's clock. 0 samples
         * means the BSSID was heard once, or on the managed-mode path
         * that carries no timestamp; the sample count says which. */
        uint32_t tbtt_sd = 0;
        (void)beacon_tbtt_jitter(&e->tbtt, &tbtt_sd, NULL);
        kv_int(buf, LINEBUF, &off, "tbtt_jitter_us",      (long long)tbtt_sd);
        kv_int(buf, LINEBUF, &off, "tbtt_jitter_samples", (long long)e->tbtt.samples);
        kv_int(buf, LINEBUF, &off, "tbtt_jitter_resets",  (long long)e->tbtt.resets);
        kv_int(buf, LINEBUF, &off, "rssi_min_60s", e->rssi_min_60s);
        kv_int(buf, LINEBUF, &off, "rssi_max_60s", e->rssi_max_60s);
        /* QBSS Load — AP self-reported occupancy (omitted when the IE
         * was absent so consumers can tell "no data" from "0"). */
        if (e->has_qbss) {
            kv_int(buf, LINEBUF, &off, "qbss_stations",  e->qbss_stations);
            kv_int(buf, LINEBUF, &off, "qbss_chan_util", e->qbss_chan_util);
        }
        /* Malformed-IE counters — only when non-zero, so a clean AP's
         * record stays uncluttered (mgmt-frame fuzz detector, #33). */
        if (e->fuzz_ie_overruns || e->fuzz_oversize_ssid || e->fuzz_truncated_rsn) {
            kv_int(buf, LINEBUF, &off, "fuzz_ie_overruns",   e->fuzz_ie_overruns);
            kv_int(buf, LINEBUF, &off, "fuzz_oversize_ssid", e->fuzz_oversize_ssid);
            kv_int(buf, LINEBUF, &off, "fuzz_truncated_rsn", e->fuzz_truncated_rsn);
        }
        /* ssid_history as a JSON array — bounded by MAX_AP_SSID_HISTORY. */
        appendf(buf, LINEBUF, &off, ",\"ssid_history\":[");
        for (int k = 0; k < e->ssid_history_n; k++) {
            appendf(buf, LINEBUF, &off, "%s\"", k ? "," : "");
            json_escape(e->ssid_history[k], buf, LINEBUF, &off);
            appendf(buf, LINEBUF, &off, "\"");
        }
        appendf(buf, LINEBUF, &off, "]");
        /* neighbors[] — array of {bssid, channel, phy_type}. */
        appendf(buf, LINEBUF, &off, ",\"neighbors\":[");
        for (int k = 0; k < e->neighbor_count; k++) {
            const ap_neighbor_t *n = &e->neighbors[k];
            char nb[20];
            snprintf(nb, sizeof(nb),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     n->bssid[0], n->bssid[1], n->bssid[2],
                     n->bssid[3], n->bssid[4], n->bssid[5]);
            appendf(buf, LINEBUF, &off, "%s{\"bssid\":\"%s\",\"channel\":%d,\"phy_type\":%d}",
                            k ? "," : "", nb, n->channel, n->phy_type);
        }
        appendf(buf, LINEBUF, &off, "]");
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
        /* #88, additive: "reason" is 0 and meaningless unless
         * reason_valid; retries/protected/truncated are subsets of
         * count; flood_last is when the window threshold was last met
         * (0 = never). */
        kv_int(buf, LINEBUF, &off, "reason_valid", e->reason_valid ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "retries",      (long long)e->retries);
        kv_int(buf, LINEBUF, &off, "protected",    (long long)e->protected_count);
        kv_int(buf, LINEBUF, &off, "truncated",    (long long)e->truncated_count);
        kv_int(buf, LINEBUF, &off, "flood_last",   (long long)e->flood_last);
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
        /* #88, additive: probe-flood window evidence. */
        kv_int(buf, LINEBUF, &off, "flood",         e->flood ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "flood_last",    (long long)e->flood_last);
        kv_int(buf, LINEBUF, &off, "burst_frames",  (long long)e->burst_frames);
        kv_int(buf, LINEBUF, &off, "burst_span_ms", (long long)e->burst_span_ms);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_pnl_clients(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->pnl_count; i++) {
        const pnl_client_t *e = &s->pnl_clients[i];

        /* Suppress rows unchanged since last emit (issue #42). Signature
         * covers identity + every observation field serialised below,
         * excluding only the envelope ts. */
        uint64_t sig = fnv1a(&e->mac_random,  sizeof(e->mac_random),  FNV64_OFFSET);
        sig = fnv1a(&e->probe_count, sizeof(e->probe_count), sig);
        sig = fnv1a(e->os_fp, sizeof(e->os_fp), sig);
        sig = fnv1a(e->phy,   sizeof(e->phy),   sig);
        sig = fnv1a(&e->first_seen, sizeof(e->first_seen), sig);
        sig = fnv1a(&e->last_seen,  sizeof(e->last_seen),  sig);
        sig = fnv1a(&e->ssid_count, sizeof(e->ssid_count), sig);
        for (int k = 0; k < e->ssid_count; k++)
            sig = fnv1a(e->ssids[k], strlen(e->ssids[k]), sig);
        if (!jsonl_changed(JD_PNL, e->mac, sizeof(e->mac), sig, now)) continue;

        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "pnl_client", now);
        kv_mac(buf, LINEBUF, &off, "mac",         e->mac);
        kv_int(buf, LINEBUF, &off, "mac_random",  e->mac_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "probe_count", (long long)e->probe_count);
        kv_str(buf, LINEBUF, &off, "os_fp",       e->os_fp);
        kv_str(buf, LINEBUF, &off, "phy",         e->phy);
        /* Additive (#60): 1 when an association request corroborated
         * the tier, 0 when it is inferred from probes alone. A consumer
         * that ignores it sees exactly what it saw before. */
        kv_int(buf, LINEBUF, &off, "phy_confirmed", e->phy_confirmed ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "first_seen",  (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        appendf(buf, LINEBUF, &off, ",\"ssids\":[");
        for (int k = 0; k < e->ssid_count; k++) {
            appendf(buf, LINEBUF, &off, "%s\"", k ? "," : "");
            json_escape(e->ssids[k], buf, LINEBUF, &off);
            appendf(buf, LINEBUF, &off, "\"");
        }
        appendf(buf, LINEBUF, &off, "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_seqnum_clients(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->seqnum_count; i++) {
        const seqnum_client_t *e = &s->seqnum_clients[i];

        /* Suppress rows unchanged since last emit (issue #42). frame_count
         * and hist advance whenever the client is actively seen, so active
         * devices still emit each cycle; only idle repeats are dropped. */
        uint64_t sig = fnv1a(&e->mac_random,  sizeof(e->mac_random),  FNV64_OFFSET);
        sig = fnv1a(&e->last_seen,   sizeof(e->last_seen),   sig);
        sig = fnv1a(&e->frame_count, sizeof(e->frame_count), sig);
        sig = fnv1a(&e->hist_n,      sizeof(e->hist_n),      sig);
        sig = fnv1a(e->hist, (size_t)e->hist_n * sizeof(e->hist[0]), sig);
        if (!jsonl_changed(JD_SEQNUM, e->mac, sizeof(e->mac), sig, now)) continue;

        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "seqnum_client", now);
        kv_mac(buf, LINEBUF, &off, "mac",         e->mac);
        kv_int(buf, LINEBUF, &off, "mac_random",  e->mac_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "frame_count", (long long)e->frame_count);
        appendf(buf, LINEBUF, &off, ",\"hist\":[");
        for (int k = 0; k < e->hist_n; k++) {
            appendf(buf, LINEBUF, &off, "%s%u", k ? "," : "", e->hist[k]);
        }
        appendf(buf, LINEBUF, &off, "]");
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
        /* Additive (#94). A consumer that stored `gap` alone could not
         * tell a forward transition from a coincidence nearby, nor how
         * much evidence the pair rested on — so it had no way to avoid
         * treating every row as an identification. Existing fields keep
         * their meaning exactly; no rename, no removal, no schema bump. */
        kv_int(buf, LINEBUF, &off, "fwd_gap",      e->fwd_gap);
        kv_int(buf, LINEBUF, &off, "confidence",   e->confidence);
        kv_int(buf, LINEBUF, &off, "window_start", (long long)e->window_start);
        kv_int(buf, LINEBUF, &off, "window_end",   (long long)e->window_end);
        kv_int(buf, LINEBUF, &off, "a_hist_n",     e->a_hist_n);
        kv_int(buf, LINEBUF, &off, "b_hist_n",     e->b_hist_n);
        kv_int(buf, LINEBUF, &off, "a_is_earlier", e->a_is_earlier ? 1 : 0);
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
        /* Additive (#64): observed control-frame volume. The measured
         * half of channel occupancy, as distinct from the QBSS Load IE
         * an AP reports about itself. CTS and ACK carry no transmitter
         * address, so these are per-channel and cannot be finer. */
        kv_int(buf, LINEBUF, &off, "ctrl_total",    (long long)e->ctrl_total);
        kv_int(buf, LINEBUF, &off, "ctrl_rts",      (long long)e->ctrl_rts);
        kv_int(buf, LINEBUF, &off, "ctrl_cts",      (long long)e->ctrl_cts);
        kv_int(buf, LINEBUF, &off, "ctrl_ack",      (long long)e->ctrl_ack);
        kv_int(buf, LINEBUF, &off, "ctrl_blockack", (long long)e->ctrl_blockack);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* What clients asked for, and what they gave up asking for it (#60).
 * Emitted alongside `assoc` rather than folded into it: the ask and the
 * grant are separate observations, and a request exists even when no
 * association follows — which is exactly the case worth seeing. */
void jsonl_emit_assoc_reqs(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->assoc_req_count; i++) {
        const assoc_req_t *e = &s->assoc_reqs[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_assoc_req", now);
        kv_mac(buf, LINEBUF, &off, "bssid",           e->bssid);
        kv_mac(buf, LINEBUF, &off, "sta_mac",         e->sta);
        kv_str(buf, LINEBUF, &off, "requested_ssid",  e->requested_ssid);
        kv_int(buf, LINEBUF, &off, "is_reassoc",      e->is_reassoc ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "listen_interval", e->listen_interval);
        kv_int(buf, LINEBUF, &off, "capability_info", e->capability_info);
        kv_int(buf, LINEBUF, &off, "akm_bits",        (long long)e->akm_bits);
        kv_int(buf, LINEBUF, &off, "pairwise_bits",   (long long)e->pairwise_bits);
        kv_int(buf, LINEBUF, &off, "requested_mfp",   e->requested_mfp);
        kv_int(buf, LINEBUF, &off, "supported_rates", (long long)e->supported_rates);
        kv_str(buf, LINEBUF, &off, "phy",             e->phy);
        kv_int(buf, LINEBUF, &off, "vendor_ie_hash",  (long long)e->vendor_ie_hash);
        kv_int(buf, LINEBUF, &off, "downgrade_flags", e->downgrade_flags);
        kv_int(buf, LINEBUF, &off, "prev_akm_bits",   (long long)e->prev_akm_bits);
        kv_int(buf, LINEBUF, &off, "prev_mfp",        e->prev_mfp);
        kv_int(buf, LINEBUF, &off, "last_seen",       (long long)e->ts);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* 802.11v steering (#59). One record per (BSSID, STA) the AP has sent
 * a BTM Request to, forcing or not — a consumer correlating an alert
 * needs the ordinary steering around it to tell an attack from a
 * roaming policy. `imminent_count` is the subset the alert acts on. */
void jsonl_emit_btm_steers(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->btm_steer_count; i++) {
        const btm_steer_t *e = &s->btm_steers[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "btm_request", now);
        kv_mac(buf, LINEBUF, &off, "bssid",             e->bssid);
        kv_mac(buf, LINEBUF, &off, "sta_mac",           e->sta);
        kv_int(buf, LINEBUF, &off, "req_count",         e->req_count);
        kv_int(buf, LINEBUF, &off, "imminent_count",    e->imminent_count);
        kv_int(buf, LINEBUF, &off, "request_mode",      e->last_request_mode);
        kv_int(buf, LINEBUF, &off, "disassoc_timer",    e->last_disassoc_timer);
        kv_int(buf, LINEBUF, &off, "validity_interval", e->last_validity_interval);
        kv_int(buf, LINEBUF, &off, "candidate_count",   e->candidate_count);
        kv_int(buf, LINEBUF, &off, "candidates_truncated",
               e->candidates_truncated ? 1 : 0);
        for (int c = 0; c < e->candidate_count && c < MAX_AP_NEIGHBORS; c++) {
            char key[16];
            snprintf(key, sizeof(key), "candidate_%d", c);
            kv_mac(buf, LINEBUF, &off, key, e->candidates[c]);
        }
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* Channel-switch announcements (#63). Every announcement, legitimate
 * or not — a consumer judging one needs the ordinary DFS traffic around
 * it, and `ta` versus `bssid` is the forgery signal. */
void jsonl_emit_csa_events(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->csa_count; i++) {
        const sloth_csa_event_t *e = &s->csa_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_csa_event", now);
        kv_mac(buf, LINEBUF, &off, "bssid",        e->bssid);
        kv_mac(buf, LINEBUF, &off, "ta",           e->ta);
        kv_int(buf, LINEBUF, &off, "new_channel",  e->new_channel);
        kv_int(buf, LINEBUF, &off, "new_op_class", e->new_op_class);
        kv_int(buf, LINEBUF, &off, "switch_mode",  e->switch_mode);
        kv_int(buf, LINEBUF, &off, "switch_count", e->switch_count);
        kv_int(buf, LINEBUF, &off, "source",       e->source);
        kv_int(buf, LINEBUF, &off, "from_channel", e->from_channel);
        kv_int(buf, LINEBUF, &off, "ts",           (long long)e->ts);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* 802.11k survey activity (#61). Targeted and broadcast requests are
 * separate fields because only the first is the signal, and reports are
 * separate again — a reply is evidence a survey succeeded, not that one
 * was attempted. */
void jsonl_emit_rrm_pairs(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->rrm_pair_count; i++) {
        const sloth_rrm_pair_t *e = &s->rrm_pairs[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "rrm_beacon_request", now);
        kv_mac(buf, LINEBUF, &off, "bssid",          e->bssid);
        kv_mac(buf, LINEBUF, &off, "sta_mac",        e->sta);
        kv_int(buf, LINEBUF, &off, "targeted_reqs",  e->targeted_reqs);
        kv_int(buf, LINEBUF, &off, "broadcast_reqs", e->broadcast_reqs);
        kv_int(buf, LINEBUF, &off, "reports_seen",   e->reports_seen);
        kv_str(buf, LINEBUF, &off, "last_ssid",      e->last_ssid);
        kv_int(buf, LINEBUF, &off, "last_channel",   e->last_channel);
        kv_int(buf, LINEBUF, &off, "measurement_mode", e->last_mode);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* Wi-Fi 7 Multi-Link Devices (#67). One record per MLD, listing the
 * per-link addresses its radios use simultaneously — the mapping that
 * lets a consumer stop counting one handset as three devices. */
void jsonl_emit_mlds(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->mld_count; i++) {
        const sloth_mld_t *e = &s->mlds[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_mld", now);
        kv_mac(buf, LINEBUF, &off, "mld_mac",    e->mld_mac);
        kv_int(buf, LINEBUF, &off, "link_count", e->link_count);
        kv_int(buf, LINEBUF, &off, "links_truncated",
               e->links_truncated ? 1 : 0);
        for (int j = 0; j < e->link_count && j < SLOTH_MLD_MAX_LINKS; j++) {
            char key[16];
            snprintf(key, sizeof(key), "link_%d_mac", j);
            kv_mac(buf, LINEBUF, &off, key, e->link_mac[j]);
            snprintf(key, sizeof(key), "link_%d_id", j);
            kv_int(buf, LINEBUF, &off, key, e->link_id[j]);
        }
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* Captive-portal interception events (#69). One record per detection,
 * carrying which of the three independent signals fired — a consumer
 * correlating them wants to know whether the body, the DNS answer or
 * the TLS destination gave it away, because a portal evading one still
 * has to pass the others. */
void jsonl_emit_cp_events(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->cp_event_count; i++) {
        const cp_event_t *e = &s->cp_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "captive_portal_event", now);
        kv_str(buf, LINEBUF, &off, "host",     e->host);
        kv_str(buf, LINEBUF, &off, "src",      e->src);
        kv_int(buf, LINEBUF, &off, "kind",     e->kind);
        kv_str(buf, LINEBUF, &off, "kind_label", cp_kind_label(e->kind));
        kv_str(buf, LINEBUF, &off, "evidence", e->evidence);
        kv_int(buf, LINEBUF, &off, "ts",       (long long)e->ts);
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
        /* Added #97: handshake_complete on its own says "a candidate
         * message pair", which a consumer used to have to read as
         * "associated". These three keep the claims apart. */
        kv_int(buf, LINEBUF, &off, "handshake_progress",
                                                 e->handshake_progress);
        kv_int(buf, LINEBUF, &off, "replay_counter_ok",
                                                 e->replay_counter_ok ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "assoc_evidence",
                                                 e->assoc_evidence ? 1 : 0);
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
        appendf(buf, LINEBUF, &off, ",\"ports\":[");
        for (int k = 0; k < e->port_count && k < MAX_SCAN_PORTS; k++) {
            appendf(buf, LINEBUF, &off, "%s%u", k ? "," : "", e->ports[k]);
        }
        appendf(buf, LINEBUF, &off, "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_packets(sloth_state_t *s) {
    if (!s) return;
    /* A packet record is event-like: each captured frame must be emitted
     * exactly once, not re-serialised every refresh cycle (issue #20). We
     * track progress with a monotonic counter (pkt_total, bumped by the
     * capture thread on every write) and a per-consumer high-water mark
     * (pkt_jsonl_emitted). A monotonic pair — rather than comparing the
     * wrapping pkt_head — lets us tell "0 new" from "a whole ring turned
     * over since the last tick" and cap the emit to what's still resident.
     *
     * With no sink, advance the mark to the write head so a client that
     * connects later streams forward (tail -f) instead of getting a
     * backlog dump. */
    if (!any_sink()) { s->pkt_jsonl_emitted = s->pkt_total; return; }
    time_t now = time(NULL);
    uint64_t pending = s->pkt_total - s->pkt_jsonl_emitted;
    /* If more than a ring's worth arrived between ticks, the oldest were
     * overwritten and are unrecoverable — emit only the survivors. */
    if (pending > MAX_PACKETS) pending = MAX_PACKETS;
    uint64_t first = s->pkt_total - pending;   /* absolute index of oldest survivor */
    for (uint64_t k = first; k < s->pkt_total; k++) {
        const packet_info_t *e = &s->packets[k % MAX_PACKETS];
        /* raw bytes are deliberately omitted (would leak frame contents
         * into log files); only the metadata ships. */
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
    s->pkt_jsonl_emitted = s->pkt_total;
}

void jsonl_emit_processes(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    /* Procs view aggregates over s->conns; reuse the same aggregator
     * the view itself calls so the wire shape exactly matches what an
     * operator sees in [5]. Stack-allocated buffer (~6 KB at the
     * default MAX_PROCS). */
    proc_stat_t procs[MAX_PROCS];
    int n = procs_aggregate(s, procs, MAX_PROCS);
    for (int i = 0; i < n; i++) {
        const proc_stat_t *e = &procs[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "process", now);
        kv_int(buf, LINEBUF, &off, "pid",        e->pid);
        kv_str(buf, LINEBUF, &off, "proc",       e->proc);
        kv_int(buf, LINEBUF, &off, "ppid",       e->ppid);
        kv_int(buf, LINEBUF, &off, "depth",      e->depth);
        kv_int(buf, LINEBUF, &off, "conn_count", e->conn_count);
        kv_int(buf, LINEBUF, &off, "tcp_count",  e->tcp_count);
        kv_int(buf, LINEBUF, &off, "udp_count",  e->udp_count);
        kv_int(buf, LINEBUF, &off, "tx_bytes",   (long long)e->tx_bytes);
        kv_int(buf, LINEBUF, &off, "rx_bytes",   (long long)e->rx_bytes);
        kv_double(buf, LINEBUF, &off, "tx_rate", e->tx_rate);
        kv_double(buf, LINEBUF, &off, "rx_rate", e->rx_rate);
        appendf(buf, LINEBUF, &off, ",\"ports\":[");
        for (int k = 0; k < e->port_count; k++) {
            appendf(buf, LINEBUF, &off, "%s%u", k ? "," : "", e->ports[k]);
        }
        appendf(buf, LINEBUF, &off, "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_ndp_ras(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->ndp_ra_count; i++) {
        const ndp_ra_event_t *e = &s->ndp_ras[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "ndp_ra", now);
        kv_str(buf, LINEBUF, &off, "src_ip",          e->src_ip);
        if (e->has_src_mac) kv_mac(buf, LINEBUF, &off, "src_mac", e->src_mac);
        kv_int(buf, LINEBUF, &off, "cur_hop_limit",   e->cur_hop_limit);
        kv_int(buf, LINEBUF, &off, "flags",           e->flags);
        kv_int(buf, LINEBUF, &off, "router_lifetime", e->router_lifetime);
        kv_int(buf, LINEBUF, &off, "first_seen",      (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",       (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "count",           (long long)e->count);
        appendf(buf, LINEBUF, &off, ",\"prefixes\":[");
        for (int k = 0; k < e->prefix_count; k++) {
            appendf(buf, LINEBUF, &off, "%s\"", k ? "," : "");
            json_escape(e->prefixes[k], buf, LINEBUF, &off);
            appendf(buf, LINEBUF, &off, "\"");
        }
        appendf(buf, LINEBUF, &off, "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_smb_sessions(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->smb_session_count; i++) {
        const smb_session_t *e = &s->smb_sessions[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "smb_session", now);
        kv_str(buf, LINEBUF, &off, "client_ip",   e->client_ip);
        kv_str(buf, LINEBUF, &off, "server_ip",   e->server_ip);
        kv_int(buf, LINEBUF, &off, "server_port", e->server_port);
        kv_str(buf, LINEBUF, &off, "dialect",     e->dialect);
        kv_int(buf, LINEBUF, &off, "first_seen",  (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "count",       (long long)e->count);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_kerb_events(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->kerb_event_count; i++) {
        const kerb_event_t *e = &s->kerb_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "kerb_event", now);
        kv_str(buf, LINEBUF, &off, "src_ip",                  e->src_ip);
        kv_int(buf, LINEBUF, &off, "as_req_count",            e->as_req_count);
        kv_int(buf, LINEBUF, &off, "as_rep_count",            e->as_rep_count);
        kv_int(buf, LINEBUF, &off, "tgs_req_count",           e->tgs_req_count);
        kv_int(buf, LINEBUF, &off, "tgs_rep_count",           e->tgs_rep_count);
        kv_int(buf, LINEBUF, &off, "preauth_required_count",  e->preauth_required_count);
        kv_int(buf, LINEBUF, &off, "preauth_failed_count",    e->preauth_failed_count);
        kv_int(buf, LINEBUF, &off, "principal_unknown_count", e->principal_unknown_count);
        kv_int(buf, LINEBUF, &off, "error_other_count",       e->error_other_count);
        kv_int(buf, LINEBUF, &off, "first_seen",              (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",               (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_ldap_events(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->ldap_event_count; i++) {
        const ldap_event_t *e = &s->ldap_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "ldap_event", now);
        kv_str(buf, LINEBUF, &off, "src_ip",           e->src_ip);
        kv_int(buf, LINEBUF, &off, "bind_count",       e->bind_count);
        kv_int(buf, LINEBUF, &off, "bind_anon_count",  e->bind_anon_count);
        kv_int(buf, LINEBUF, &off, "search_count",     e->search_count);
        kv_int(buf, LINEBUF, &off, "search_ref_count", e->search_ref_count);
        kv_int(buf, LINEBUF, &off, "first_seen",       (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",        (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_bgp_sessions(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->bgp_session_count; i++) {
        const bgp_session_t *e = &s->bgp_sessions[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "bgp_session", now);
        kv_str(buf, LINEBUF, &off, "peer_a",             e->peer_a);
        kv_str(buf, LINEBUF, &off, "peer_b",             e->peer_b);
        kv_int(buf, LINEBUF, &off, "open_count",         e->open_count);
        kv_int(buf, LINEBUF, &off, "update_count",       e->update_count);
        kv_int(buf, LINEBUF, &off, "notification_count", e->notification_count);
        kv_int(buf, LINEBUF, &off, "keepalive_count",    e->keepalive_count);
        kv_int(buf, LINEBUF, &off, "first_seen",         (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",          (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_ssh_flows(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->ssh_flow_count; i++) {
        const ssh_flow_t *e = &s->ssh_flows[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "ssh_flow", now);
        kv_str(buf, LINEBUF, &off, "src_ip",         e->src_ip);
        kv_str(buf, LINEBUF, &off, "dst_ip",         e->dst_ip);
        kv_int(buf, LINEBUF, &off, "banner_count",   e->banner_count);
        kv_str(buf, LINEBUF, &off, "server_banner",  e->server_banner);
        kv_int(buf, LINEBUF, &off, "first_seen",     (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",      (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_rdp_flows(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->rdp_flow_count; i++) {
        const rdp_flow_t *e = &s->rdp_flows[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "rdp_flow", now);
        kv_str(buf, LINEBUF, &off, "src_ip",            e->src_ip);
        kv_str(buf, LINEBUF, &off, "dst_ip",            e->dst_ip);
        kv_int(buf, LINEBUF, &off, "connect_req_count", e->connect_req_count);
        kv_str(buf, LINEBUF, &off, "last_cookie",       e->last_cookie);
        kv_int(buf, LINEBUF, &off, "proto_mask",        (int)e->proto_mask);
        kv_int(buf, LINEBUF, &off, "first_seen",        (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",         (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_snmp_flows(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->snmp_flow_count; i++) {
        const snmp_flow_t *e = &s->snmp_flows[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "snmp_flow", now);
        kv_str(buf, LINEBUF, &off, "src_ip",          e->src_ip);
        kv_str(buf, LINEBUF, &off, "dst_ip",          e->dst_ip);
        kv_int(buf, LINEBUF, &off, "version",         e->version);
        kv_int(buf, LINEBUF, &off, "get_count",       e->get_count);
        kv_int(buf, LINEBUF, &off, "getnext_count",   e->getnext_count);
        kv_int(buf, LINEBUF, &off, "getbulk_count",   e->getbulk_count);
        kv_int(buf, LINEBUF, &off, "set_count",       e->set_count);
        kv_int(buf, LINEBUF, &off, "response_count",  e->response_count);
        kv_int(buf, LINEBUF, &off, "trap_count",      e->trap_count);
        kv_int(buf, LINEBUF, &off, "community_count", e->community_count);
        kv_str(buf, LINEBUF, &off, "last_community",  e->last_community);
        kv_int(buf, LINEBUF, &off, "first_seen",      (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",       (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_mqtt_flows(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->mqtt_flow_count; i++) {
        const mqtt_flow_t *e = &s->mqtt_flows[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "mqtt_flow", now);
        kv_str(buf, LINEBUF, &off, "src_ip",             e->src_ip);
        kv_str(buf, LINEBUF, &off, "dst_ip",             e->dst_ip);
        kv_int(buf, LINEBUF, &off, "connect_count",      e->connect_count);
        kv_int(buf, LINEBUF, &off, "connack_fail_count", e->connack_fail_count);
        kv_int(buf, LINEBUF, &off, "subscribe_count",    e->subscribe_count);
        kv_int(buf, LINEBUF, &off, "publish_count",      e->publish_count);
        kv_int(buf, LINEBUF, &off, "proto_level",        e->proto_level);
        kv_str(buf, LINEBUF, &off, "last_username",      e->last_username);
        kv_int(buf, LINEBUF, &off, "first_seen",         (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",          (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_sensors(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->sensor_count; i++) {
        const sensor_t *sn = &s->sensors[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "sensor", now);
        kv_str(buf, LINEBUF, &off, "kind",       sensor_kind_name(sn->kind));
        kv_str(buf, LINEBUF, &off, "state",      sensor_state_name(sn->state));
        kv_str(buf, LINEBUF, &off, "name",       sn->name);
        kv_str(buf, LINEBUF, &off, "iface",      sn->iface);
        kv_int(buf, LINEBUF, &off, "observed",   (long long)sn->observed);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)sn->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)sn->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* Multi-radio merged 802.11 world model (#21). One line per observed
 * entity, carrying observer metadata: how many radios saw it, which ones
 * (bitmask), the strongest signal heard and which radio heard it. */
void jsonl_emit_wifi_merged(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->wifi_merged.count; i++) {
        const wifi_merged_t *e = &s->wifi_merged.ents[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_merged", now);
        kv_mac(buf, LINEBUF, &off, "key",         e->key);
        kv_int(buf, LINEBUF, &off, "seen_by",     e->seen_by);
        kv_int(buf, LINEBUF, &off, "sensor_mask", e->sensor_mask);
        kv_int(buf, LINEBUF, &off, "best_rssi",   e->best_rssi);
        kv_int(buf, LINEBUF, &off, "best_sensor", e->best_sensor);
        kv_int(buf, LINEBUF, &off, "channel",     e->channel);
        kv_int(buf, LINEBUF, &off, "freq_mhz",    e->freq_mhz);
        kv_int(buf, LINEBUF, &off, "observations",(long long)e->observations);
        kv_int(buf, LINEBUF, &off, "first_seen",  (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* ── sensor_health (#91 slice 3) ─────────────────────────────
 *
 * One singleton record per tick, carrying what slices 1 and 2 collect.
 * Additive — a new record type; nothing existing is renamed or reshaped
 * (MISSION §4.3).
 *
 * Emitted through the same change-only cache as the entity snapshots,
 * but the signature is chosen carefully. `ps_recv` climbs on every tick
 * of a working sensor, so signing over it would mean a line per second
 * forever and the suppression would be decorative. The signature is
 * therefore the *qualitative* health — liveness, exit reasons, the
 * channel pair, retune failures — plus the cumulative drop/ifdrop
 * counters and the eviction tally, all of which moving is genuinely
 * news. A healthy sensor emits one line per JSONL_HEARTBEAT_SECS; a
 * degrading one emits the moment it degrades. */
static void health_kv(char *buf, int *off, const char *prefix,
                      const capture_health_t *h) {
    char key[40];
    snprintf(key, sizeof(key), "%s_open", prefix);
    kv_int(buf, LINEBUF, off, key, h->open);
    snprintf(key, sizeof(key), "%s_running", prefix);
    kv_int(buf, LINEBUF, off, key, h->running);
    snprintf(key, sizeof(key), "%s_exit", prefix);
    kv_str(buf, LINEBUF, off, key,
           capture_exit_name((capture_exit_t)h->exit_reason));
    snprintf(key, sizeof(key), "%s_exit_detail", prefix);
    kv_str(buf, LINEBUF, off, key, h->exit_detail);
    snprintf(key, sizeof(key), "%s_stats_valid", prefix);
    kv_int(buf, LINEBUF, off, key, h->stats_valid);
    snprintf(key, sizeof(key), "%s_recv", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->ps_recv);
    snprintf(key, sizeof(key), "%s_drop", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->ps_drop);
    snprintf(key, sizeof(key), "%s_ifdrop", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->ps_ifdrop);
    snprintf(key, sizeof(key), "%s_recv_delta", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->d_recv);
    snprintf(key, sizeof(key), "%s_drop_delta", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->d_drop);
    snprintf(key, sizeof(key), "%s_ifdrop_delta", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->d_ifdrop);
}

void jsonl_emit_sensor_health(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = time(NULL);

    /* chan_requested == 0 means the hopper has never ticked, which is not
     * a failure — only a request that was never confirmed is. */
    int chan_ok = s->chan_requested == 0 ||
                  s->chan_requested == s->chan_confirmed;

    uint64_t evict_total = sh_evict_total();

    /* Storage write failures (#92) — sensor_health is the sensor's own
     * self-report, and "I could not write the evidence I detected" is
     * exactly that kind of fact. Each sink already counted its own
     * failures (stderr-only, or a view header); this just gives a JSONL/
     * socket consumer the same visibility a console operator always had.
     * Read from each module's own accessor rather than from
     * s->eapol_export_failures — that field is synced by eapol_snapshot()
     * later in the same tick's poll loop, so reading it here would report
     * last tick's count instead of this one's. */
    int jsonl_fail  = jsonl_write_failures();
    int pcap_fail   = alert_pcap_failures();
    int eapol_fail  = eapol_export_failures();
    int storage_fail = jsonl_fail + pcap_fail + eapol_fail;

    /* See the note above on what is deliberately NOT in the signature. */
    struct {
        int      cap_open, cap_run, cap_exit;
        int      mon_open, mon_run, mon_exit;
        int      chan_req, chan_conf, retune_fail, chan_ok;
        uint64_t cap_drop, cap_ifdrop, mon_drop, mon_ifdrop, evicted;
        int      storage_fail;
    } sig;
    memset(&sig, 0, sizeof(sig));
    sig.cap_open    = s->cap_health.open;
    sig.cap_run     = s->cap_health.running;
    sig.cap_exit    = s->cap_health.exit_reason;
    sig.mon_open    = s->mon_health.open;
    sig.mon_run     = s->mon_health.running;
    sig.mon_exit    = s->mon_health.exit_reason;
    sig.chan_req    = s->chan_requested;
    sig.chan_conf   = s->chan_confirmed;
    sig.retune_fail = s->chan_retune_failures;
    sig.chan_ok     = chan_ok;
    sig.cap_drop    = s->cap_health.ps_drop;
    sig.cap_ifdrop  = s->cap_health.ps_ifdrop;
    sig.mon_drop    = s->mon_health.ps_drop;
    sig.mon_ifdrop  = s->mon_health.ps_ifdrop;
    sig.evicted     = evict_total;
    sig.storage_fail = storage_fail;

    /* Singleton: one fixed key, so the slot is this record's alone. */
    static const char health_key[] = "sensor";
    if (!jsonl_changed(JD_SENSOR_HEALTH, health_key, sizeof(health_key) - 1,
                       fnv1a(&sig, sizeof(sig), FNV64_OFFSET), now))
        return;

    char buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "sensor_health", now);
    kv_str(buf, LINEBUF, &off, "capture_iface",        s->pkt_iface);
    kv_str(buf, LINEBUF, &off, "monitor_iface",        s->probe_iface);
    kv_str(buf, LINEBUF, &off, "monitor_err",          s->probe_err);
    kv_int(buf, LINEBUF, &off, "chan_requested",       s->chan_requested);
    kv_int(buf, LINEBUF, &off, "chan_confirmed",       s->chan_confirmed);
    kv_int(buf, LINEBUF, &off, "chan_confirmed_ok",    chan_ok);
    kv_int(buf, LINEBUF, &off, "chan_retune_failures", s->chan_retune_failures);
    health_kv(buf, &off, "capture", &s->cap_health);
    health_kv(buf, &off, "monitor", &s->mon_health);
    kv_int(buf, LINEBUF, &off, "evictions", (long long)evict_total);
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++) {
        char key[40];
        snprintf(key, sizeof(key), "evict_%s", sh_evict_name((sh_evict_t)k));
        kv_int(buf, LINEBUF, &off, key,
               (long long)sh_evict_count((sh_evict_t)k));
    }
    kv_int(buf, LINEBUF, &off, "storage_failures",       storage_fail);
    kv_int(buf, LINEBUF, &off, "storage_jsonl_failures", jsonl_fail);
    kv_int(buf, LINEBUF, &off, "storage_pcap_failures",  pcap_fail);
    kv_int(buf, LINEBUF, &off, "storage_eapol_failures", eapol_fail);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_state_snapshots(sloth_state_t *s) {
    /* Cheap gating — every emitter checks any_sink() too, but the
     * batch-level skip avoids the per-call setup when nobody's there. */
    if (!any_sink() || !s) return;
    jsonl_emit_ifaces            (s);
    jsonl_emit_sensors           (s);
    jsonl_emit_wifi_merged       (s);
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
    jsonl_emit_assoc_reqs        (s);
    jsonl_emit_btm_steers        (s);
    jsonl_emit_csa_events        (s);
    jsonl_emit_rrm_pairs         (s);
    jsonl_emit_mlds              (s);
    jsonl_emit_cp_events         (s);
    jsonl_emit_eapol_events      (s);
    jsonl_emit_mdns_services     (s);
    jsonl_emit_nbns_names        (s);
    jsonl_emit_ssdp_devices      (s);
    jsonl_emit_scan_entries      (s);
    jsonl_emit_packets           (s);
    jsonl_emit_processes         (s);
    jsonl_emit_ndp_ras           (s);
    jsonl_emit_smb_sessions      (s);
    jsonl_emit_kerb_events       (s);
    jsonl_emit_ldap_events       (s);
    jsonl_emit_bgp_sessions      (s);
    jsonl_emit_ssh_flows         (s);
    jsonl_emit_rdp_flows         (s);
    jsonl_emit_snmp_flows        (s);
    jsonl_emit_mqtt_flows        (s);
    /* Last: the sensor's self-report about this tick, after every
     * observation in it has been emitted (#91 slice 3). */
    jsonl_emit_sensor_health     (s);
}
