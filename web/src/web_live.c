#include "web_live.h"

#include <stdio.h>
#include <string.h>

#include "web_ssid.h"

void web_live_init(web_live_t *l, const char *spec) {
    memset(l, 0, sizeof(*l));
    pthread_mutex_init(&l->mu, NULL);
    if (spec) web_utf8_copy(l->spec, WEB_LIVE_SPEC_MAX, spec);
    l->sock_state = spec ? WEB_SOCK_CONNECTING : WEB_SOCK_NONE;
    l->last_error_ms = -1;
    l->last_record_ms = -1;
    for (int i = 0; i < 8; i++) l->rate_sec[i] = -1;
}

void web_live_destroy(web_live_t *l) { pthread_mutex_destroy(&l->mu); }

const char *web_live_sock_word(int state) {
    switch (state) {
    case WEB_SOCK_CONNECTING: return "connecting";
    case WEB_SOCK_CONNECTED:  return "connected";
    case WEB_SOCK_RETRYING:   return "retrying";
    default:                  return "none";
    }
}

/* ── the socket ──────────────────────────────────────────────────────── */

/* A new connection is a new stream: whatever pass or batch was open on
 * the old one cannot be finished by the new one. */
static void reset_stream(web_live_t *l) {
    l->in_round = 0;
    l->round_taint = 0;
    l->pending_taint = 0;
    l->batch_open = 0;
    l->batch_saw_dev = 0;
    l->batch_taint = 0;
    l->last_iface = 0;
}

void web_live_sock_attempt(web_live_t *l, long long now_ms) {
    (void)now_ms;
    pthread_mutex_lock(&l->mu);
    l->attempts++;
    l->sock_state = WEB_SOCK_CONNECTING;
    pthread_mutex_unlock(&l->mu);
}

void web_live_sock_connected(web_live_t *l, long long now_ms) {
    pthread_mutex_lock(&l->mu);
    l->connects++;
    l->conn_gen++;
    l->sock_state = WEB_SOCK_CONNECTED;
    l->connected_ms = now_ms;
    l->retry_ms = 0;
    reset_stream(l);
    /* sloth sends no replay of incidents already open, and a resolve
     * missed while away would leave one open here forever. Starting
     * empty under-counts until they resolve or update; keeping them
     * could over-count for good. */
    l->ninc = 0;
    l->inc_overflow = 0;
    pthread_mutex_unlock(&l->mu);
}

void web_live_sock_failed(web_live_t *l, const char *err, int retry_ms,
                          long long now_ms) {
    pthread_mutex_lock(&l->mu);
    if (l->sock_state == WEB_SOCK_CONNECTED) l->closes++;
    else                                     l->failures++;
    l->sock_state = WEB_SOCK_RETRYING;
    l->retry_ms = retry_ms;
    web_utf8_copy(l->last_error, WEB_LIVE_ERR_MAX, err ? err : "");
    l->last_error_ms = now_ms;
    reset_stream(l);
    pthread_mutex_unlock(&l->mu);
}

void web_live_sock_bytes(web_live_t *l, size_t n) {
    pthread_mutex_lock(&l->mu);
    l->bytes += n;
    pthread_mutex_unlock(&l->mu);
}

/* ── records ─────────────────────────────────────────────────────────── */

static int type_ok(const char *t) {
    size_t n = strlen(t);
    if (n == 0 || n > WEB_LIVE_TYPE_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = t[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '.'))
            return 0;
    }
    return 1;
}

static void count_type(web_live_t *l, const char *t) {
    for (int i = 0; i < l->ntypes; i++)
        if (!strcmp(l->types[i].name, t)) { l->types[i].n++; return; }
    if (l->ntypes >= WEB_LIVE_TYPES) { l->types_other++; return; }
    web_live_type_t *e = &l->types[l->ntypes++];
    snprintf(e->name, sizeof(e->name), "%s", t);
    e->n = 1;
}

static void rate_tick(web_live_t *l, long long now_ms) {
    long long sec = now_ms / 1000;
    int i = (int)(sec % 8);
    if (l->rate_sec[i] != sec) { l->rate_sec[i] = sec; l->rate_n[i] = 0; }
    l->rate_n[i]++;
}

/* Something may be missing from the stream here: a socket_gap, or a
 * line that would not decode (it may have been a device record). */
static void taint(web_live_t *l) {
    if (l->in_round) l->round_taint = 1;
    else             l->pending_taint = 1;
    l->batch_taint = 1;
}

static void publish(web_live_t *l, long n, long long ts) {
    l->dev_known = 1;
    l->dev_count = n;
    l->dev_ts = ts;
    l->dev_gen = l->conn_gen;
    l->dev_rounds++;
}

static void close_round(web_live_t *l) {
    if (l->round_taint) l->dev_rounds_tainted++;
    else                publish(l, l->round_n, l->round_ts);
    l->in_round = 0;
    l->round_taint = 0;
}

/* The record types sloth's poll thread writes, from src/jsonl.c:
 * jsonl_emit_connections() and jsonl_emit_twin_episodes(), then every
 * emitter jsonl_emit_state_snapshots() calls, in that order. Only
 * these steer the device bookkeeping.
 *
 * The rest are passed over, and that is not an optimisation. dns, tls,
 * quic, http, ntp, icmp and cleartext_cred come from the libpcap
 * capture thread (src/capture/capture.c capture_thread() into the
 * *_log.c rings), through the same emit_line() as the poll thread's
 * snapshot but under no lock that spans a pass: data_socket_emit()
 * locks per line. So a DNS answer can land between two device rows,
 * and treating it as the end of the pass would publish half of it.
 * alert and alert.* are poll-thread (alerts_update() in src/poll.c,
 * before the snapshot) but steer nothing here, so they are passed over
 * too; so is any type sloth adds later, until it is listed. */
static const char *const POLL_TYPES[] = {
    "connections", "twin_episode",
    "iface", "sensor", "wifi_merged", "arp", "dhcp_lease", "wifi_ap",
    "wifi_sta", "top_host", "device", "beacon", "wifi_regulatory",
    "deauth", "probe_client", "pnl_client", "seqnum_client",
    "seqnum_correlation", "channel_summary", "assoc", "wifi_assoc_req",
    "btm_request", "wifi_csa_event", "rrm_beacon_request", "wifi_mld",
    "captive_portal_event", "eapol", "mdns_service", "nbns_name",
    "ssdp_device", "onvif_device", "scan_entry", "packet", "process",
    "ndp_ra", "smb_session", "kerb_event", "ldap_event", "bgp_session",
    "ssh_flow", "rdp_flow", "snmp_flow", "mqtt_flow", "ble_device",
    "ble_alert", "sensor_health", NULL
};

int web_live_is_poll_type(const char *t) {
    for (int i = 0; POLL_TYPES[i]; i++)
        if (!strcmp(POLL_TYPES[i], t)) return 1;
    return 0;
}

/* The device-count bookkeeping for one record of type t. */
static void devices_step(web_live_t *l, const char *t, long long ts) {
    if (!web_live_is_poll_type(t)) return;
    int is_dev = !strcmp(t, "device");
    int is_iface = !strcmp(t, "iface");
    if (!is_dev && l->in_round) close_round(l);
    if (is_iface && !l->last_iface) {
        /* A snapshot batch starts. The one before it had no device pass:
         * sloth's table was empty, so the TUI says 0 too. */
        if (l->batch_open && !l->batch_saw_dev && !l->batch_taint)
            publish(l, 0, ts);
        l->batch_open = 1;
        l->batch_saw_dev = 0;
        l->batch_taint = 0;
        /* Anything dropped before this point came before the batch. */
        l->pending_taint = 0;
    }
    l->last_iface = is_iface;
    if (is_dev) {
        if (!l->in_round) {
            l->in_round = 1;
            l->round_n = 0;
            l->round_ts = ts;
            l->round_taint = l->pending_taint;
            l->pending_taint = 0;
        }
        l->round_n++;
        l->batch_saw_dev = 1;
    }
}

#define SUMMARY_TMP 512
typedef char SUMMARY_TMP_FITS[WEB_LIVE_TEXT_MAX < SUMMARY_TMP - 1 ? 1 : -1];

static const char *const SUMMARY_KEYS[] = {
    "qname", "host", "ssid", "mac", "bssid", "sta_mac", "addr", "ip",
    "src", "src_ip", "hostname", "name", "instance", "dst", "dst_ip",
    "kind", "desc", NULL
};

/* A short line for the ticker, from the members a reader looks for
 * first. Only decoded strings go in; the output is escaped later. */
static void summarise(const web_jrec_t *r, int is_alert, char *out,
                      size_t cap) {
    char tmp[SUMMARY_TMP];
    size_t n = 0;
    tmp[0] = '\0';
    if (is_alert) {
        /* sloth writes an SSID into an alert's title and detail as it
         * came (src/alerts/rules_twin.c), so both go out in the display
         * form too (web_ssid.h). */
        const char *ti = web_jl_str(r, "title");
        const char *de = web_jl_str(r, "detail");
        char e1[SUMMARY_TMP / 2 - 1], e2[SUMMARY_TMP / 2 - 1];
        ti = ti ? ti : "";
        de = de ? de : "";
        web_ssid_escape(ti, strnlen(ti, SUMMARY_TMP), e1, sizeof(e1), NULL);
        web_ssid_escape(de, strnlen(de, SUMMARY_TMP), e2, sizeof(e2), NULL);
        snprintf(tmp, sizeof(tmp), "%s %s", e1, e2);
    } else {
        int used = 0;
        for (int k = 0; SUMMARY_KEYS[k] && used < 4; k++) {
            const char *v = web_jl_str(r, SUMMARY_KEYS[k]);
            if (!v || !*v) continue;
            /* An SSID in its display form (web_ssid.h), never raw. */
            char esc[WEB_SSID_IN_MAX * WEB_SSID_EXPAND + 1];
            if (!strcmp(SUMMARY_KEYS[k], "ssid")) {
                web_ssid_escape(v, strnlen(v, WEB_SSID_IN_MAX), esc, sizeof(esc),
                                NULL);
                v = esc;
            }
            int w = snprintf(tmp + n, sizeof(tmp) - n, "%s%s",
                             used ? "  " : "", v);
            if (w < 0 || (size_t)w >= sizeof(tmp) - n) break;
            n += (size_t)w;
            used++;
        }
    }
    /* tmp holds whole decoded strings, except that snprintf may have cut
     * the last one mid-sequence; it only does so with tmp full (511
     * bytes). web_utf8_copy() cuts on a code-point boundary at cap
     * (WEB_LIVE_TEXT_MAX, the only cap passed), far
     * short of that, so the ragged tail never reaches out. That holds
     * while cap stays under sizeof(tmp) - 1: SUMMARY_TMP_FITS fails the
     * build otherwise. */
    web_utf8_copy(out, cap, tmp);
}

static int sev_ok(long long s) { return s >= 0 && s <= 2; }

static int inc_find(const web_live_t *l, const char *id) {
    for (int i = 0; i < l->ninc; i++)
        if (!strcmp(l->inc[i].id, id)) return i;
    return -1;
}

/* An address as sloth writes one (inet_ntop), or nothing: 1 to
 * WEB_LIVE_IP_MAX bytes of [0-9A-Fa-f:.]. The page colours the address
 * an alert names (the TUI's alert-hot override, tui_alert_hot_set()),
 * and checks it again; anything else is not an address and is dropped,
 * not cut to fit. */
static int match_ip_ok(const char *s) {
    size_t n = s ? strlen(s) : 0;
    if (n == 0 || n > WEB_LIVE_IP_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
              c == ':' || c == '.'))
            return 0;
    }
    return 1;
}

static void alert_record(web_live_t *l, const web_jrec_t *r, const char *t,
                         long long ts) {
    const char *id = web_jl_str(r, "incident_id");
    long long sev = web_jl_int(r, "sev", -1);
    if (id && *id && strlen(id) <= WEB_LIVE_ID_MAX && sev_ok(sev)) {
        int k = inc_find(l, id);
        if (!strcmp(t, "alert.resolve")) {
            if (k >= 0) l->inc[k] = l->inc[--l->ninc];
        } else if (k >= 0) {
            l->inc[k].sev = (int)sev;
        } else if (l->ninc < WEB_LIVE_INCIDENTS) {
            /* An update or escalate for an incident opened before this
             * connection is still an open incident. */
            snprintf(l->inc[l->ninc].id, sizeof(l->inc[0].id), "%s", id);
            l->inc[l->ninc].sev = (int)sev;
            l->ninc++;
        } else {
            l->inc_overflow = 1;
        }
    }
    web_live_alert_t *a = &l->alerts[l->alert_next];
    l->alert_next = (l->alert_next + 1) % WEB_LIVE_ALERTS;
    if (l->alert_n < WEB_LIVE_ALERTS) l->alert_n++;
    memset(a, 0, sizeof(*a));
    a->ts = ts;
    a->sev = sev_ok(sev) ? (int)sev : -1;
    snprintf(a->type, sizeof(a->type), "%s", t);
    const char *ti = web_jl_str(r, "title");
    const char *de = web_jl_str(r, "detail");
    /* In the display form (web_ssid.h): sloth puts an SSID into both
     * as it came. Cut before a whole escape or code point. */
    ti = ti ? ti : "";
    de = de ? de : "";
    web_ssid_escape(ti, strnlen(ti, WEB_SSID_IN_MAX), a->title, sizeof(a->title), NULL);
    web_ssid_escape(de, strnlen(de, WEB_SSID_IN_MAX * 2), a->detail, sizeof(a->detail),
                    NULL);
    if (id) web_utf8_copy(a->incident, WEB_LIVE_ID_MAX, id);
    const char *ip = web_jl_str(r, "match_ip");
    if (match_ip_ok(ip)) snprintf(a->match_ip, sizeof(a->match_ip), "%s", ip);
}

static void sensor_record(web_live_t *l, const web_jrec_t *r, long long ts,
                          long long now_ms) {
    l->sh_seen = 1;
    l->sh_ms = now_ms;
    l->sh_ts = ts;
    l->cap_open    = web_jl_int(r, "capture_open", 0) != 0;
    l->cap_running = web_jl_int(r, "capture_running", 0) != 0;
    l->mon_open    = web_jl_int(r, "monitor_open", 0) != 0;
    l->mon_running = web_jl_int(r, "monitor_running", 0) != 0;
    l->scope_ne    = web_jl_int(r, "scope_not_enforced", 0) != 0;
    const char *s;
    s = web_jl_str(r, "capture_iface"); web_utf8_copy(l->cap_iface, WEB_LIVE_SH_STR, s ? s : "");
    s = web_jl_str(r, "monitor_iface"); web_utf8_copy(l->mon_iface, WEB_LIVE_SH_STR, s ? s : "");
    s = web_jl_str(r, "capture_exit");  web_utf8_copy(l->cap_exit,  WEB_LIVE_SH_STR, s ? s : "");
    s = web_jl_str(r, "monitor_exit");  web_utf8_copy(l->mon_exit,  WEB_LIVE_SH_STR, s ? s : "");
    s = web_jl_str(r, "scope");         web_utf8_copy(l->scope,     WEB_LIVE_SH_STR, s ? s : "");
}

void web_live_apply(web_live_t *l, const web_jrec_t *r, long long now_ms) {
    const char *t = web_jl_str(r, "type");
    long long ts = web_jl_int(r, "ts", 0);
    if (!t) return;    /* the decoder refuses such a line; belt and braces */
    pthread_mutex_lock(&l->mu);
    l->lines++;
    l->records++;
    l->last_record_ms = now_ms;
    rate_tick(l, now_ms);
    if (!type_ok(t)) {
        l->types_invalid++;
        /* Unknown, so it could have stood for anything, a device row
         * included. */
        taint(l);
        pthread_mutex_unlock(&l->mu);
        return;
    }
    count_type(l, t);

    if (!strcmp(t, "socket_gap")) {
        l->gaps++;
        long long d = web_jl_int(r, "dropped", 0);
        if (d > 0) l->gap_dropped += (unsigned long long)d;
        taint(l);
    } else {
        devices_step(l, t, ts);
    }

    int is_alert = !strncmp(t, "alert.", 6);
    if (is_alert) alert_record(l, r, t, ts);
    if (!strcmp(t, "sensor_health")) sensor_record(l, r, ts, now_ms);

    web_live_rec_t *e = &l->ring[l->seq % WEB_LIVE_RING];
    l->seq++;
    e->seq = l->seq;
    e->ts = ts;
    snprintf(e->type, sizeof(e->type), "%s", t);
    summarise(r, is_alert || !strcmp(t, "alert"), e->text, WEB_LIVE_TEXT_MAX);
    pthread_mutex_unlock(&l->mu);
}

void web_live_decode_error(web_live_t *l, int err, long long now_ms) {
    (void)now_ms;
    pthread_mutex_lock(&l->mu);
    l->lines++;
    l->decode_errors++;
    if (err > 0 && err < WEB_JL_ECOUNT) l->dec_by[err]++;
    taint(l);
    pthread_mutex_unlock(&l->mu);
}

void web_live_truncated(web_live_t *l) {
    pthread_mutex_lock(&l->mu);
    l->truncated++;
    l->decode_errors++;
    taint(l);
    pthread_mutex_unlock(&l->mu);
}

/* ── readers ─────────────────────────────────────────────────────────── */

static const char *sensor_word(const web_live_t *l, long long now_ms) {
    if (!l->sh_seen) return "unknown";
    if (now_ms - l->sh_ms > WEB_LIVE_SH_STALE_MS) return "stale";
    if ((l->cap_open && !l->cap_running) || (l->mon_open && !l->mon_running) ||
        l->scope_ne)
        return "degraded";
    if (!l->cap_open && !l->mon_open) return "not_observing";
    return "ok";
}

const char *web_live_sensor_word(web_live_t *l, long long now_ms) {
    pthread_mutex_lock(&l->mu);
    const char *w = sensor_word(l, now_ms);
    pthread_mutex_unlock(&l->mu);
    return w;
}

static long rate10(const web_live_t *l, long long now_ms) {
    /* The five whole seconds before this one. */
    long long sec = now_ms / 1000;
    unsigned long sum = 0;
    for (long long s = sec - 5; s < sec; s++) {
        int i = (int)(((s % 8) + 8) % 8);
        if (l->rate_sec[i] == s) sum += l->rate_n[i];
    }
    return (long)(sum * 2);    /* sum / 5 s, times ten */
}

static void summary_locked(const web_live_t *l, web_live_sum_t *s,
                           long long now_ms) {
    memset(s, 0, sizeof(*s));
    s->sock_state = l->sock_state;
    s->dev_known = l->dev_known;
    s->devices = l->dev_count;
    s->dev_stale = !l->dev_known || l->sock_state != WEB_SOCK_CONNECTED ||
                   l->dev_gen != l->conn_gen;
    for (int i = 0; i < l->ninc; i++) s->alerts[l->inc[i].sev]++;
    s->alerts_overflow = l->inc_overflow;
    s->rate10 = rate10(l, now_ms);
    s->records = l->records;
    s->sensor = sensor_word(l, now_ms);
    s->last_record_age_ms = l->last_record_ms < 0 ? -1
                          : now_ms - l->last_record_ms;
    if (l->sock_state == WEB_SOCK_CONNECTED) {
        long long from = l->connected_ms;
        if (l->last_record_ms > from) from = l->last_record_ms;
        s->silence_ms = now_ms - from;
    } else {
        s->silence_ms = -1;
    }
}

void web_live_summary(web_live_t *l, web_live_sum_t *s, long long now_ms) {
    pthread_mutex_lock(&l->mu);
    summary_locked(l, s, now_ms);
    pthread_mutex_unlock(&l->mu);
}

int web_live_recent_after(web_live_t *l, unsigned long long after,
                          web_live_rec_t *out, int max,
                          unsigned long long *latest) {
    pthread_mutex_lock(&l->mu);
    unsigned long long hi = l->seq;
    unsigned long long lo = after + 1;
    if (hi >= WEB_LIVE_RING && lo < hi - WEB_LIVE_RING + 1)
        lo = hi - WEB_LIVE_RING + 1;
    if (hi >= (unsigned long long)max && lo < hi - (unsigned long long)max + 1)
        lo = hi - (unsigned long long)max + 1;
    int n = 0;
    for (unsigned long long q = lo; q <= hi && q > 0 && n < max; q++)
        out[n++] = l->ring[(q - 1) % WEB_LIVE_RING];
    *latest = hi;
    pthread_mutex_unlock(&l->mu);
    return n;
}

static void jw_rate(web_jw_t *w, long r10) {
    char b[32];
    snprintf(b, sizeof(b), "%ld.%ld", r10 / 10, r10 % 10);
    web_jw_raw(w, b);
}

static void jw_age(web_jw_t *w, long long ms) {
    if (ms < 0) web_jw_raw(w, "null");
    else        web_jw_int(w, ms / 1000);
}

void web_live_health_members(web_live_t *l, web_jw_t *w, long long now_ms) {
    pthread_mutex_lock(&l->mu);
    web_jw_raw(w, ",\"socket\":");      web_jw_str(w, web_live_sock_word(l->sock_state));
    web_jw_raw(w, ",\"socket_spec\":"); web_jw_str(w, l->spec);
    web_jw_raw(w, ",\"last_record_age_s\":");
    jw_age(w, l->last_record_ms < 0 ? -1 : now_ms - l->last_record_ms);
    web_jw_raw(w, ",\"socket_attempts\":");  web_jw_int(w, (long long)l->attempts);
    web_jw_raw(w, ",\"socket_connects\":");  web_jw_int(w, (long long)l->connects);
    web_jw_raw(w, ",\"socket_reconnects\":");
    web_jw_int(w, l->connects ? (long long)l->connects - 1 : 0);
    web_jw_raw(w, ",\"socket_failures\":");  web_jw_int(w, (long long)l->failures);
    web_jw_raw(w, ",\"socket_closes\":");    web_jw_int(w, (long long)l->closes);
    web_jw_raw(w, ",\"socket_retry_ms\":");  web_jw_int(w, l->retry_ms);
    web_jw_raw(w, ",\"socket_last_error\":");
    if (l->last_error_ms < 0) web_jw_raw(w, "null");
    else                      web_jw_str(w, l->last_error);
    web_jw_raw(w, ",\"socket_last_error_age_s\":");
    jw_age(w, l->last_error_ms < 0 ? -1 : now_ms - l->last_error_ms);
    web_jw_raw(w, ",\"socket_bytes\":");     web_jw_int(w, (long long)l->bytes);
    web_jw_raw(w, ",\"socket_lines\":");     web_jw_int(w, (long long)l->lines);
    web_jw_raw(w, ",\"socket_records\":");   web_jw_int(w, (long long)l->records);
    web_jw_raw(w, ",\"socket_decode_errors\":");
    web_jw_int(w, (long long)l->decode_errors);
    web_jw_raw(w, ",\"socket_decode_by\":{");
    int first = 1;
    for (int e = 1; e < WEB_JL_ECOUNT; e++) {
        if (!first) web_jw_raw(w, ",");
        first = 0;
        web_jw_key(w, web_jl_error_name(e));
        web_jw_int(w, (long long)l->dec_by[e]);
    }
    web_jw_raw(w, ",\"truncated\":"); web_jw_int(w, (long long)l->truncated);
    web_jw_raw(w, "}");
    web_jw_raw(w, ",\"socket_gaps\":");         web_jw_int(w, (long long)l->gaps);
    web_jw_raw(w, ",\"socket_gap_dropped\":");  web_jw_int(w, (long long)l->gap_dropped);
    pthread_mutex_unlock(&l->mu);
}

size_t web_live_json(web_live_t *l, char *out, size_t cap, long long now_ms) {
    web_jw_t w;
    web_jw_init(&w, out, cap);
    pthread_mutex_lock(&l->mu);
    web_live_sum_t s;
    summary_locked(l, &s, now_ms);

    web_jw_raw(&w, "{\"socket\":"); web_jw_str(&w, web_live_sock_word(s.sock_state));
    web_jw_raw(&w, ",\"devices\":");
    if (s.dev_known) web_jw_int(&w, s.devices); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"devices_stale\":"); web_jw_raw(&w, s.dev_stale ? "true" : "false");
    web_jw_raw(&w, ",\"devices_ts\":");
    if (s.dev_known) web_jw_int(&w, l->dev_ts); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"device_passes\":"); web_jw_int(&w, (long long)l->dev_rounds);
    web_jw_raw(&w, ",\"device_passes_unpublished\":");
    web_jw_int(&w, (long long)l->dev_rounds_tainted);

    web_jw_raw(&w, ",\"alerts_open\":{\"low\":"); web_jw_int(&w, (long long)s.alerts[0]);
    web_jw_raw(&w, ",\"warn\":"); web_jw_int(&w, (long long)s.alerts[1]);
    web_jw_raw(&w, ",\"crit\":"); web_jw_int(&w, (long long)s.alerts[2]);
    web_jw_raw(&w, ",\"overflow\":"); web_jw_raw(&w, s.alerts_overflow ? "true" : "false");
    web_jw_raw(&w, "}");

    web_jw_raw(&w, ",\"records\":"); web_jw_int(&w, (long long)s.records);
    web_jw_raw(&w, ",\"records_s\":"); jw_rate(&w, s.rate10);
    web_jw_raw(&w, ",\"last_record_age_s\":"); jw_age(&w, s.last_record_age_ms);

    web_jw_raw(&w, ",\"types\":{");
    for (int i = 0; i < l->ntypes; i++) {
        if (i) web_jw_raw(&w, ",");
        web_jw_key(&w, l->types[i].name);
        web_jw_int(&w, (long long)l->types[i].n);
    }
    web_jw_raw(&w, "},\"types_other\":"); web_jw_int(&w, (long long)l->types_other);
    web_jw_raw(&w, ",\"types_invalid\":"); web_jw_int(&w, (long long)l->types_invalid);

    web_jw_raw(&w, ",\"sensor\":{\"state\":"); web_jw_str(&w, s.sensor);
    if (l->sh_seen) {
        web_jw_raw(&w, ",\"age_s\":"); web_jw_int(&w, (now_ms - l->sh_ms) / 1000);
        web_jw_raw(&w, ",\"ts\":"); web_jw_int(&w, l->sh_ts);
        web_jw_raw(&w, ",\"capture_iface\":"); web_jw_str(&w, l->cap_iface);
        web_jw_raw(&w, ",\"capture_open\":"); web_jw_int(&w, l->cap_open);
        web_jw_raw(&w, ",\"capture_running\":"); web_jw_int(&w, l->cap_running);
        web_jw_raw(&w, ",\"capture_exit\":"); web_jw_str(&w, l->cap_exit);
        web_jw_raw(&w, ",\"monitor_iface\":"); web_jw_str(&w, l->mon_iface);
        web_jw_raw(&w, ",\"monitor_open\":"); web_jw_int(&w, l->mon_open);
        web_jw_raw(&w, ",\"monitor_running\":"); web_jw_int(&w, l->mon_running);
        web_jw_raw(&w, ",\"monitor_exit\":"); web_jw_str(&w, l->mon_exit);
        web_jw_raw(&w, ",\"scope\":"); web_jw_str(&w, l->scope);
        web_jw_raw(&w, ",\"scope_not_enforced\":"); web_jw_int(&w, l->scope_ne);
    }
    web_jw_raw(&w, "}");

    /* Newest first, as the page lists them. */
    web_jw_raw(&w, ",\"alerts\":[");
    for (int k = 0; k < l->alert_n; k++) {
        int i = (l->alert_next - 1 - k + 2 * WEB_LIVE_ALERTS) % WEB_LIVE_ALERTS;
        const web_live_alert_t *a = &l->alerts[i];
        if (k) web_jw_raw(&w, ",");
        web_jw_raw(&w, "{\"ts\":"); web_jw_int(&w, a->ts);
        web_jw_raw(&w, ",\"type\":"); web_jw_str(&w, a->type);
        web_jw_raw(&w, ",\"sev\":");
        if (a->sev < 0) web_jw_raw(&w, "null"); else web_jw_int(&w, a->sev);
        web_jw_raw(&w, ",\"title\":"); web_jw_str(&w, a->title);
        web_jw_raw(&w, ",\"detail\":"); web_jw_str(&w, a->detail);
        web_jw_raw(&w, ",\"incident_id\":"); web_jw_str(&w, a->incident);
        web_jw_raw(&w, ",\"match_ip\":"); web_jw_str(&w, a->match_ip);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "]");

    /* Oldest first, as the ticker appends them. */
    web_jw_raw(&w, ",\"recent\":[");
    unsigned long long hi = l->seq;
    unsigned long long lo = hi > WEB_LIVE_RING ? hi - WEB_LIVE_RING + 1 : 1;
    for (unsigned long long q = lo; hi && q <= hi; q++) {
        const web_live_rec_t *e = &l->ring[(q - 1) % WEB_LIVE_RING];
        if (q != lo) web_jw_raw(&w, ",");
        web_jw_raw(&w, "{\"seq\":"); web_jw_int(&w, (long long)e->seq);
        web_jw_raw(&w, ",\"type\":"); web_jw_str(&w, e->type);
        web_jw_raw(&w, ",\"ts\":"); web_jw_int(&w, e->ts);
        web_jw_raw(&w, ",\"text\":"); web_jw_str(&w, e->text);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "]}\n");
    pthread_mutex_unlock(&l->mu);
    return w.overflow ? 0 : w.len;
}
