#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "jsonl.h"
#include "jsonl_internal.h"
#include "gps.h"
#include "position_track.h"
#include "sloth_clock.h"
#include "netstr.h"
#include "tune.h"
#include "alerts.h"
#include "attack_hw.h"
#include "wired_attach.h"
#include "secure_file.h"
#include "sensors.h"
#include "data_socket.h"
#include "formatter.h"
#include "sensor_health.h"
#include "intel_pack.h"

/* The JSONL writer's core (#213): the sink, the change-only cache, the
 * line builders, and the records every daemon writes - alert, the
 * alert.* lifecycle, sensor, jsonl_emit_fields() - with the
 * sensor_health blocks they share. Nothing here names a capture module;
 * src/jsonl_internal.h says why that is the point of the file. */

static FILE           *g_fp;
/* Open refusal reason and write-failure count (#87), under g_mu. */
static sfile_fail_t    g_fail;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* True if either the file sink or the data-socket sink has a consumer.
 * Used by every jsonl_emit_* to skip the format work when nobody is
 * listening — running sloth without -o and without --data-socket should
 * not pay for JSON encoding it'll never deliver. */
int jsonl_any_sink(void) {
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
 * The cache is a pure optimisation: a collision can only cause an extra
 * emit, never a wrongful suppression, because a slot is consulted only
 * when its stored identity matches exactly. An extra emit is harmless
 * once; it is not harmless every tick. A direct-mapped table made two
 * live keys sharing a slot evict each other on every poll and both
 * re-emit forever (#101 review: 256 random BSSIDs gave ~64 extra lines
 * a tick). So the table is set-associative: a key hashes to a set of
 * JSONL_DEDUP_WAYS slots, a miss takes a free way or else the way least
 * recently looked up, and the table is sized well past every keyed
 * emitter combined (MAX_PNL_CLIENTS + MAX_SEQNUM_CLIENTS +
 * MAX_BEACON_APS + sensor_health = 641 keys over 4096 slots), so a set
 * holding more live keys than it has ways is not a load the sensor
 * reaches in practice. */
#define JSONL_HEARTBEAT_SECS 300
#define JSONL_DEDUP_WAYS     8
#define JSONL_DEDUP_SETS     512
#define JSONL_DEDUP_SLOTS    (JSONL_DEDUP_WAYS * JSONL_DEDUP_SETS)
#define JSONL_DEDUP_KEYLEN   16

typedef struct {
    uint64_t sig;
    time_t   emit_ts;
    time_t   seen_ts;    /* last lookup: the eviction order */
    uint8_t  key[JSONL_DEDUP_KEYLEN];
    uint8_t  keylen;
    uint8_t  kind;
    uint8_t  used;
} jsonl_dedup_slot_t;

static jsonl_dedup_slot_t g_dedup[JSONL_DEDUP_SLOTS];

uint64_t jsonl_fnv1a(const void *data, size_t n, uint64_t h) {
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
int jsonl_changed(uint8_t kind, const void *key, size_t keylen,
                  uint64_t sig, time_t now) {
    if (keylen > JSONL_DEDUP_KEYLEN) keylen = JSONL_DEDUP_KEYLEN;
    uint64_t h = fnv1a(key, keylen, fnv1a(&kind, 1, FNV64_OFFSET));
    jsonl_dedup_slot_t *set =
        &g_dedup[(size_t)(h % JSONL_DEDUP_SETS) * JSONL_DEDUP_WAYS];
    jsonl_dedup_slot_t *sl = NULL, *victim = NULL;
    for (int w = 0; w < JSONL_DEDUP_WAYS; w++) {
        jsonl_dedup_slot_t *c = &set[w];
        if (c->used && c->kind == kind && c->keylen == (uint8_t)keylen
            && memcmp(c->key, key, keylen) == 0) { sl = c; break; }
        if (!victim || (victim->used && (!c->used || c->seen_ts < victim->seen_ts)))
            victim = c;
    }
    if (sl) {
        sl->seen_ts = now;
        if (sl->sig == sig && (now - sl->emit_ts) < JSONL_HEARTBEAT_SECS)
            return 0;
    } else {
        sl = victim;
        sl->used   = 1;
        sl->kind   = kind;
        sl->keylen = (uint8_t)keylen;
        memcpy(sl->key, key, keylen);
        sl->seen_ts = now;
    }
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
void jsonl_appendf(char *buf, int sz, int *off, const char *fmt, ...) {
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
/* JSON string body (RFC 8259 §7). Output is always valid UTF-8 (#138):
 * the input is decoded per RFC 3629 (netstr_utf8_decode), and
 *   - each octet that does not start a well-formed sequence → \ufffd;
 *   - C0, DEL and C1 (U+0000..U+001F, U+007F..U+009F) → \u00YY — C1 is
 *     legal raw in JSON, but U+009B is CSI to a terminal that tails the
 *     log, so it leaves here as six ASCII octets;
 *   - U+2028 / U+2029 → \u2028 / \u2029 (raw, they end a line in
 *     JavaScript and some log viewers).
 * Every string that parsed before parses to the same value now; what
 * changes is that invalid input no longer reaches the consumer raw.
 * Worst case is still 6 output octets per input octet. */
void jsonl_escape(const char *s, char *out, int sz, int *off) {
    if (!s) s = "";
    if (*off > sz - 1) *off = sz - 1;
    const uint8_t *p = (const uint8_t *)s;
    size_t left = strlen(s);
    while (left > 0 && *off + 6 < sz) {
        uint32_t cp = 0;
        int len = netstr_utf8_decode(p, left, &cp);
        if (len == 0) {
            appendf(out, sz, off, "\\ufffd");
            p++; left--;
            continue;
        }
        switch (cp) {
            case '"':  out[(*off)++] = '\\'; out[(*off)++] = '"';  break;
            case '\\': out[(*off)++] = '\\'; out[(*off)++] = '\\'; break;
            case '\n': out[(*off)++] = '\\'; out[(*off)++] = 'n';  break;
            case '\r': out[(*off)++] = '\\'; out[(*off)++] = 'r';  break;
            case '\t': out[(*off)++] = '\\'; out[(*off)++] = 't';  break;
            default:
                if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)
                    || cp == 0x2028 || cp == 0x2029) {
                    appendf(out, sz, off, "\\u%04x", (unsigned)cp);
                } else {
                    memcpy(out + *off, p, (size_t)len);
                    *off += len;
                }
        }
        p += len; left -= (size_t)len;
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
void jsonl_emit_line(const char *line) {
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

void jsonl_kv_str(char *buf, int sz, int *off, const char *key, const char *val) {
    appendf(buf, sz, off, ",\"%s\":\"", key);
    json_escape(val, buf, sz, off);
    appendf(buf, sz, off, "\"");
}

void jsonl_kv_int(char *buf, int sz, int *off, const char *key, long long val) {
    appendf(buf, sz, off, ",\"%s\":%lld", key, val);
}

void jsonl_kv_double(char *buf, int sz, int *off, const char *key, double val) {
    appendf(buf, sz, off, ",\"%s\":%.2f", key, val);
}

void jsonl_kv_mac(char *buf, int sz, int *off, const char *key,
                  const uint8_t mac[6]) {
    char m[20];
    snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    kv_str(buf, sz, off, key, m);
}

void jsonl_start_obj(char *buf, int sz, int *off, const char *type, time_t ts) {
    *off = 0;
    appendf(buf, sz, off, "{\"type\":\"%s\",\"ts\":%lld", type, (long long)ts);
}

void jsonl_end_obj(char *buf, int sz, int *off) {
    if (*off < sz - 1) buf[(*off)++] = '}';
    buf[*off] = '\0';
}

/* ── alert records ───────────────────────────────────────── */

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

/* Tool-signature provenance (#90), additive, shared by both record
 * families for the same reason as the pair axes above.
 *
 * All four are omitted when no signature matched — present only on
 * findings a signature shaped, same rule as `inventory`. When present,
 * `validated` is always emitted, and as a JSON boolean rather than the
 * 0/1 ints elsewhere in the schema: it is the one field a consumer must
 * not read past, the issue asks for `validated: bool` by name, and a
 * `false` literal survives a naive `if record["validated"]` either way.
 * formatter.c's scanner already accepts true/false. */
static void emit_signature(char *buf, int *off, const alert_t *a) {
    if (!a->sig_id[0]) return;
    kv_str(buf, LINEBUF, off, "signature_id", a->sig_id);
    kv_str(buf, LINEBUF, off, "signature_version", a->sig_version);
    appendf(buf, LINEBUF, off, ",\"validated\":%s",
            a->sig_validated ? "true" : "false");
    kv_str(buf, LINEBUF, off, "signature_evidence", a->sig_evidence);
}

/* Attack-hardware verdict (#151), additive, both record families.
 * Omitted when there is none, like the signature fields above. */
static void emit_hw_verdict(char *buf, int *off, const alert_t *a) {
    char label[40], names[32];
    hw_verdict_format(a->hw_tier, a->hw_device, a->hw_signals,
                      label, sizeof(label), names, sizeof(names));
    if (!label[0]) return;
    kv_str(buf, LINEBUF, off, "hw_verdict", label);
    kv_str(buf, LINEBUF, off, "hw_signals", names);
}

/* Evidence-ring citations (#92), additive, shared by both record
 * families for the same reason as the signature fields above. Indexed
 * keys rather than a JSON array, matching the existing convention for a
 * small bounded list (jsonl_emit_btm_steers' candidate_N, jsonl_emit_mlds'
 * link_N_mac) so every record this file emits stays a flat object.
 *
 * Named `evidence_id_N` rather than reusing `event_id` — the lifecycle
 * event's own `event_id` field is a different, unrelated string
 * (`<incident_id>-<seq>`), and the two must not collide in one object.
 *
 * Omitted entirely when the detector cited nothing — most rules have
 * no frames to cite (docs/wiki/pcap-export.md lists the ones that do),
 * and a record with `evidence_count` but no ids (or the reverse) would
 * be a claim half made. */
static void emit_evidence(char *buf, int *off, const alert_t *a) {
    if (!a->evidence_id_count) return;
    kv_int(buf, LINEBUF, off, "evidence_count", a->evidence_id_count);
    for (int i = 0; i < a->evidence_id_count && i < ALERT_EVIDENCE_IDS; i++) {
        char key[24];
        snprintf(key, sizeof(key), "evidence_id_%d", i);
        kv_int(buf, LINEBUF, off, key, (long long)a->evidence_ids[i]);
    }
}

/* Where the sensor was as the incident opened (2026-10-27): one nested
 * `loc` object, omitted entirely when unstamped. Formatted by
 * gps_loc_json() without printf's %f, so the TUI's setlocale() cannot
 * put a decimal comma into it. Additive per docs/wiki/jsonl-schema.md. */
static void emit_loc(char *buf, int *off, const alert_t *a) {
    char lj[256];
    if (gps_loc_json(&a->loc, lj, sizeof(lj)) > 0)
        appendf(buf, LINEBUF, off, ",%s", lj);
}

/* The intel-pack snapshot (#231, #184 C6): which pack version and which
 * exact bytes the tables a finding consulted were generated from. One
 * object, version and hash together, so neither travels without the
 * other. On sensor_health always; on an alert only when its rule
 * consulted a table (alert_t.intel_pack), for the reason `inventory`
 * is omitted when no inventory was read. Both values are build
 * constants of a known alphabet (semver, lowercase hex). */
void jsonl_intel_pack(char *buf, int *off) {
    appendf(buf, LINEBUF, off, ",\"intel_pack\":{\"version\":\"%s\",\"hash\":\"%s\"}",
            intel_pack_version(), intel_pack_hash());
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
    if (a->intel_pack)
        jsonl_intel_pack(buf, &off);
    emit_pair_axes(buf, &off, a);
    emit_signature(buf, &off, a);
    emit_hw_verdict(buf, &off, a);
    emit_evidence(buf, &off, a);
    /* Join key into the lifecycle stream (#98), additive. A consumer
     * that only knows `alert` sees exactly the record it always saw
     * plus one field it can ignore. */
    if (a->incident_id[0])
        kv_str(buf, LINEBUF, &off, "incident_id", a->incident_id);
    emit_loc(buf, &off, a);
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
    /* Earlier incidents on this key (#112), additive and omitted at 0
     * like every other counter here. Bounded by the engine's LRU side
     * table, so it is a count of what sloth remembers, not a lifetime
     * total — see alert_t.reopen_count. */
    if (a->reopen_count)
        kv_int(buf, LINEBUF, &off, "reopen_count", (long long)a->reopen_count);
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
    if (a->intel_pack)
        jsonl_intel_pack(buf, &off);
    emit_pair_axes(buf, &off, a);
    emit_signature(buf, &off, a);
    emit_hw_verdict(buf, &off, a);
    emit_evidence(buf, &off, a);
    if (a->match_ip[0]) {
        kv_str(buf, LINEBUF, &off, "match_ip", a->match_ip);
        kv_int(buf, LINEBUF, &off, "match_port", (int)a->match_port);
    }
    if (a->match_ip[0] || a->evidence_id_count) {
        /* Per-export outcome (#92) — meaningful only for an alert one of
         * the two exporters can run for: a match_ip (alert_pcap_dump(),
         * --pcap-dir) or cited evidence-ring frames (the evidence export,
         * --collect-handshakes + --eapol-dir, slice 1). pcap_path omitted
         * until export actually writes a file; pcap_write_failures
         * omitted at 0 so a clean export doesn't grow the line for
         * nothing. Same two keys for both exporters, so a consumer has
         * one place to look for an incident's frames. */
        if (a->pcap_path[0])
            kv_str(buf, LINEBUF, &off, "pcap_path", a->pcap_path);
        if (a->pcap_write_failures)
            kv_int(buf, LINEBUF, &off, "pcap_write_failures",
                   a->pcap_write_failures);
    }
    emit_loc(buf, &off, a);
    if (reason && reason[0])
        kv_str(buf, LINEBUF, &off, "reason", reason);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

/* ── sensor registry ─────────────────────────────────────── */

void jsonl_emit_sensors(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
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

void jsonl_emit_fields(const char *type, time_t ts, const jsonl_field_t *f, int n) {
    if (!any_sink() || !type || !f) return;
    char buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, type, ts);
    for (int i = 0; i < n; i++) {
        if (f[i].kind == JSONL_F_STR) {
            kv_str(buf, LINEBUF, &off, f[i].key, f[i].s);
        } else if (f[i].kind == JSONL_F_INT) {
            kv_int(buf, LINEBUF, &off, f[i].key, f[i].i);
        } else {
            char num[32];
            gps_fmt_fixed(num, sizeof(num), f[i].d, f[i].dp);
            appendf(buf, LINEBUF, &off, ",\"%s\":%s", f[i].key, num);
        }
    }
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

/* ── sensor_health blocks (src/jsonl_internal.h) ─────────── */

void jsonl_sh_gnss_sig(const sloth_state_t *s, jsonl_sh_gnss_sig_t *o) {
    o->gps_configured = s->gps.configured;
    o->gps_state      = s->gps.state;
    o->gps_age_bucket = s->gps.fix_age_s < 0 ? -1
        : (s->gps.fix_age_s > tune_val(TUNE_GPS_MAX_FIX_AGE_S) ? 1 : 0);
    o->gps_bad_any    = (s->gps.bad_checksum + s->gps.parse_errors) > 0;
    o->gps_err_any    = s->gps.err[0] != '\0';
    o->loc_src        = s->gps.has_loc ? s->gps.loc_src : 0;
    o->loc_cell_lat   = s->gps.has_loc ? (int)floor(s->gps.loc_lat * 100.0) : 0;
    o->loc_cell_lon   = s->gps.has_loc ? (int)floor(s->gps.loc_lon * 100.0) : 0;
    /* The held band (gps.c take_tpv: hysteresis a quarter past each
     * edge), never the raw one: a 9600-baud offset hovering at 500 ms
     * otherwise re-signed this line TPV by TPV. */
    o->gnss_time_off_band = s->gps.has_time_off ? s->gps.time_off_band : -1;
    o->gnss_cn0_band      = gps_cn0_band(s->gps.cn0_mean);
    o->gnss_jam_band      = gps_jam_band(s->gps.jam);
}

void jsonl_sh_evictions(char *buf, int *off, uint64_t evict_total,
                        int storage_fail) {
    kv_int(buf, LINEBUF, off, "evictions", (long long)evict_total);
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++) {
        char key[40];
        snprintf(key, sizeof(key), "evict_%s", sh_evict_name((sh_evict_t)k));
        kv_int(buf, LINEBUF, off, key,
               (long long)sh_evict_count((sh_evict_t)k));
    }
    kv_int(buf, LINEBUF, off, "storage_failures",       storage_fail);
}

void jsonl_sh_process(char *buf, int *off, unsigned long long socket_refused,
                      int socket_clients, const char *libs) {
    /* A raised threshold can silence a detector, so a consumer must be
     * able to tell a quiet sensor from a detuned one (#82). Count plus
     * the knobs themselves: the count alone would not say which rule
     * went quiet. Empty string on a default run. */
    kv_int(buf, LINEBUF, off, "tuned_count", (long long)tune_non_default());
    {
        char tbuf[256];
        tune_format_non_default(tbuf, sizeof(tbuf));
        kv_str(buf, LINEBUF, off, "tuned", tbuf);
    }
    /* Data-socket hygiene (#135). Appended, so every earlier field keeps
     * its name and position. `socket_peer_refused` climbing is one peer
     * trying to take more than socket.max_per_peer slots — a consumer
     * misconfigured to reconnect without closing, or a local account
     * crowding the listener; `socket_clients` is the live occupancy of
     * the 16 slots, 0 when no --data-socket is configured. */
    kv_int(buf, LINEBUF, off, "socket_peer_refused", (long long)socket_refused);
    kv_int(buf, LINEBUF, off, "socket_clients",      socket_clients);
    /* Parse faults (#126). Appended, so every earlier field keeps its
     * name and position. Deliberately absent from `sig` above: under a
     * beacon-spam or mode-m fuzz run these climb on every frame, so
     * signing over them would turn this record into the per-tick
     * firehose the signature exists to prevent. They ride the 300 s
     * heartbeat and any other transition's line, the way `ps_recv` and
     * the flow-ring evictions do. A sibling tally, not more `evict_*`
     * fields: `evictions` is published as the exact sum of that
     * breakout and must stay so. */
    kv_int(buf, LINEBUF, off, "parse_faults",
           (long long)sh_parse_fault_total());
    for (int k = 0; k < SH_PF_KIND_COUNT; k++) {
        char key[48];
        snprintf(key, sizeof(key), "parse_fault_%s",
                 sh_parse_fault_name((sh_parse_fault_t)k));
        kv_int(buf, LINEBUF, off, key,
               (long long)sh_parse_fault_count((sh_parse_fault_t)k));
    }
    /* Process memory (#121). Appended after the parse-fault breakout, so
     * every earlier field keeps its name and position. Sampled HERE —
     * after jsonl_changed() has already decided this line goes out — so
     * the figures cannot reach `sig` by accident and a suppressed tick
     * pays for no /proc read. They are the definition of a value that
     * moves without news: rss and malloc drift on every tick of a
     * healthy sensor, fd_count steps on each socket client, so signing
     * over any of them would emit this record once a second. A leak
     * shows as a slope across heartbeats, which is what a 300 s cadence
     * is enough to see. -1 is "not measured" (sensor_health.h). */
    sh_mem_t mem;
    sh_mem_sample(&mem);
    kv_int(buf, LINEBUF, off, "rss_kb",            mem.rss_kb);
    kv_int(buf, LINEBUF, off, "rss_hwm_kb",        mem.rss_hwm_kb);
    kv_int(buf, LINEBUF, off, "sqlite_mem_kb",     mem.sqlite_mem_kb);
    kv_int(buf, LINEBUF, off, "sqlite_mem_hwm_kb", mem.sqlite_mem_hwm_kb);
    kv_int(buf, LINEBUF, off, "malloc_kb",         mem.malloc_kb);
    kv_int(buf, LINEBUF, off, "fd_count",          mem.fd_count);
    kv_int(buf, LINEBUF, off, "resolver_calls",    mem.resolver_calls);
    /* Loaded parser libraries (#142). Appended, so every earlier field
     * keeps its name and position. Outside `sig` on purpose: it is
     * fixed for the life of the process, so it could never be the
     * change worth a line — it rides every line instead, which is what
     * lets a consumer match any one record against a libpcap or sqlite
     * advisory without a second source. */
    kv_str(buf, LINEBUF, off, "libs", libs);
}

void jsonl_sh_gps(char *buf, int *off, const sloth_state_t *s) {
    /* --location / --gps (2026-10-27), ONLY while one of them is given,
     * so a run without either writes exactly what it wrote before. The
     * exact figures ride every line; the signature (jsonl_sh_gnss_sig())
     * carries their state and buckets. The position itself is not here:
     * it is on the alerts it stamps. gps_hdop is written without %f
     * (locale). Appended. */
    if (s->gps.configured) {
        const gps_health_t *g = &s->gps;
        char hd[24];
        gps_fmt_fixed(hd, sizeof(hd), g->hdop, 1);
        kv_str(buf, LINEBUF, off, "gps_state", gps_state_name(g->state));
        kv_str(buf, LINEBUF, off, "gps_src", g->src);
        kv_int(buf, LINEBUF, off, "gps_fix_age_s", g->fix_age_s);
        kv_int(buf, LINEBUF, off, "gps_quality", g->quality);
        kv_int(buf, LINEBUF, off, "gps_sats", g->sats);
        appendf(buf, LINEBUF, off, ",\"gps_hdop\":%s", hd);
        kv_int(buf, LINEBUF, off, "gps_sentences",    (long long)g->sentences);
        kv_int(buf, LINEBUF, off, "gps_bad_checksum", (long long)g->bad_checksum);
        kv_int(buf, LINEBUF, off, "gps_parse_errors", (long long)g->parse_errors);
        kv_int(buf, LINEBUF, off, "gps_reconnects",   (long long)g->reconnects);
        kv_int(buf, LINEBUF, off, "gps_positions_dropped",
               (long long)postrack_dropped());
        kv_str(buf, LINEBUF, off, "gps_err", g->err);
        /* GNSS observation (2026-11-02, docs/wiki/gnss.md): the sky's
         * summary and the receiver's clock, only with a --gps reader
         * (a --location run has no receiver). gnss_time_offset_ms is
         * present only once a TPV carried a parseable time. Appended. */
        if (g->has_gps) {
            char cn[24];
            gps_fmt_fixed(cn, sizeof(cn), g->cn0_mean, 1);
            kv_int(buf, LINEBUF, off, "gnss_sats_in_view", g->sats_in_view);
            kv_int(buf, LINEBUF, off, "gnss_sats_used", g->sats_used);
            appendf(buf, LINEBUF, off, ",\"gnss_cn0_mean\":%s", cn);
            if (g->has_time_off)
                kv_int(buf, LINEBUF, off, "gnss_time_offset_ms", g->time_off_ms);
            kv_int(buf, LINEBUF, off, "gnss_jam", g->jam);
        }
        /* Where the sensor is (2026-11-06, docs/wiki/location.md): the
         * stamp the alerts carry, here for a consumer with no alert to
         * read it from (slothweb's Radar centre). Only while a position
         * exists: a --gps run searching for its first fix writes none.
         * Five decimals as the alert stamp's are seven: a metre is
         * enough for a centre. Appended; no %f (locale). */
        if (g->has_loc) {
            char la[32], lo[32];
            gps_fmt_fixed(la, sizeof(la), g->loc_lat, 5);
            gps_fmt_fixed(lo, sizeof(lo), g->loc_lon, 5);
            appendf(buf, LINEBUF, off, ",\"loc_lat\":%s,\"loc_lon\":%s", la, lo);
            if (g->loc_has_alt) {
                char al[32];
                gps_fmt_fixed(al, sizeof(al), g->loc_alt_m, 1);
                appendf(buf, LINEBUF, off, ",\"loc_alt_m\":%s", al);
            }
            kv_str(buf, LINEBUF, off, "loc_src", gps_loc_src_name(g->loc_src));
        }
    }
}

void jsonl_sh_tail(char *buf, int *off, const char *daemon, int db_cap_mb) {
    /* The record stream's own contract version (ADR 0007, #185 item 3),
     * appended after the flag-gated blocks above so every earlier field
     * keeps its name and position — a version field is worth less than
     * the positional stability of the fields a consumer already reads.
     *
     * Outside `sig` for the reason `libs` is: a compile-time constant can
     * never be the change worth a line. It rides every line instead,
     * which is the point — a consumer holding one record can tell which
     * contract it was written under without a second source, and the
     * sensor that wrote it may be long gone. */
    /* --db's size ceiling, db.max_mb in MiB (JSONL 1.7.0, additive):
     * 0 unlimited, -1 with no database open. Its own member because
     * `tuned` names only a non-default value and is cut at 256 bytes,
     * so a consumer could not always tell the default from "not said";
     * slothweb draws it as the limit on sloth.db's size. Before
     * jsonl_version, which stays last. */
    /* Which daemon wrote the record (JSONL 1.9.0, #213, additive):
     * "wifi" or "rf". The sensor is two processes with a stream each
     * (ADR 0010) and both write this record; a consumer of both needs
     * to know whose it is without inferring it from which blocks are
     * there. Appended after the last block, ahead of the two members
     * that stay last. A constant, so outside `sig` like the version. */
    /* The intel-pack snapshot the build's tables came from (JSONL 2.6.0,
     * #231, additive): a constant, so outside `sig` like the version,
     * and before the members that stay last. Both daemons write it:
     * one tree, one snapshot. */
    jsonl_intel_pack(buf, off);
    kv_str(buf, LINEBUF, off, "daemon", daemon);
    kv_int(buf, LINEBUF, off, "db_max_mb", db_cap_mb);
    kv_str(buf, LINEBUF, off, "jsonl_version", SLOTH_JSONL_VERSION);
}
