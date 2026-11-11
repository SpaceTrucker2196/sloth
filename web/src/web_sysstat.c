#include "web_sysstat.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#include "web_series.h"

/* Contract and bounds: web_sysstat.h. */

int web_sys_init(web_sys_t *y) {
    memset(y, 0, sizeof(*y));
    y->undervolt = -1;
    y->sensor_seq = y->hw_seq = -1;
    return pthread_mutex_init(&y->mu, NULL) == 0 ? 0 : -1;
}

void web_sys_destroy(web_sys_t *y) {
    pthread_mutex_destroy(&y->mu);
}

int web_key_sys(const char *s, char *out) {
    if (!s) return -1;
    size_t n = strlen(s);
    if (n == 0 || n > WEB_KEY_MAX) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        else if (c == '/') c = '.';
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '.' || c == '-'))
            return -1;
        out[i] = c;
    }
    out[n] = '\0';
    return 0;
}

void web_sys_keep(char *out, size_t cap, const char *s) {
    char tmp[160];
    if (!out || cap == 0) return;
    out[0] = '\0';
    if (!s) return;
    size_t budget = cap - 1, cost = 0, n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p && n < sizeof(tmp) - 1; p++) {
        unsigned c = *p;
        /* What web_jw_strn() writes for it: six for a control, DEL and
         * the markup characters; a non-ASCII byte is charged six too,
         * which covers a two-byte C1 control. */
        size_t k = (c < 0x20 || c >= 0x7f || c == '<' || c == '>' || c == '&' || c == '\'')
                   ? 6 : (c == '"' || c == '\\') ? 2 : 1;
        if (cost + k > budget) break;
        cost += k;
        tmp[n++] = (char)c;
    }
    /* The budget may have run out inside a UTF-8 sequence: drop the
     * incomplete one, so what is kept is still valid UTF-8. */
    size_t i = n;
    while (i > 0 && ((unsigned char)tmp[i - 1] & 0xC0) == 0x80) i--;
    if (i > 0 && (unsigned char)tmp[i - 1] >= 0xC0) {
        unsigned lead = (unsigned char)tmp[i - 1];
        size_t need = lead < 0xE0 ? 2 : lead < 0xF0 ? 3 : 4;
        if (n - (i - 1) < need) n = i - 1;
    }
    memcpy(out, tmp, n);
    out[n] = '\0';
}

/* ── record members, range-checked ───────────────────────────────── */

static int jnum(const web_jrec_t *r, const char *k, double lo, double hi, double *out) {
    double v;
    if (!web_jl_num(r, k, &v) || !isfinite(v) || v < lo || v > hi) return 0;
    *out = v;
    return 1;
}

static int jll(const web_jrec_t *r, const char *k, long long lo, long long hi, long long *out) {
    const web_jfield_t *f = web_jl_get(r, k);
    if (!f || f->kind != WEB_J_INT || f->i < lo || f->i > hi) return 0;
    *out = f->i;
    return 1;
}

static void jkeep(const web_jrec_t *r, const char *k, char *out, size_t cap) {
    web_sys_keep(out, cap, web_jl_str(r, k));
}

/* A short lower-case word ([a-z0-9_-]): a name, a kind, a state. */
static int word_ok(const char *s, size_t max) {
    if (!s || !s[0] || strlen(s) > max) return 0;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '_' || *s == '-'))
            return 0;
    return 1;
}

static void status_apply(web_sys_t *y, const web_jrec_t *r, long long ts, long long now_ms) {
    long long seq, v;
    if (!jll(r, "seq", 0, 0xffffffffLL, &seq)) { y->rejected++; return; }
    y->seen = 1;
    y->ts = ts;
    y->rx_ms = now_ms;
    y->seq = seq;
    y->interval_s = jll(r, "interval_s", 1, 86400, &v) ? (int)v : 60;
    y->has_cpu = jnum(r, "cpu_pct", 0, 100, &y->cpu_pct);
    if (!jnum(r, "cpu_iowait_pct", 0, 100, &y->iowait_pct)) y->iowait_pct = 0;
    jkeep(r, "cpu_band", y->cpu_band, sizeof(y->cpu_band));
    y->has_load = jnum(r, "load1", 0, 1e6, &y->load1) && jnum(r, "load5", 0, 1e6, &y->load5) &&
                  jnum(r, "load15", 0, 1e6, &y->load15);
    y->has_mem = jll(r, "mem_total_kb", 1, 1LL << 50, &y->mem_total_kb) &&
                 jll(r, "mem_avail_kb", 0, y->mem_total_kb, &y->mem_avail_kb);
    jkeep(r, "mem_band", y->mem_band, sizeof(y->mem_band));
    y->has_uptime = jll(r, "uptime_s", 0, 1LL << 40, &y->uptime_s);
    y->has_rss = jll(r, "rss_kb", 0, 1LL << 50, &y->rss_kb);
    y->has_disk = jll(r, "disk_total_mb", 1, 1LL << 50, &y->disk_total_mb) &&
                  jll(r, "disk_free_mb", 0, y->disk_total_mb, &y->disk_free_mb);
    jkeep(r, "disk_for", y->disk_for, sizeof(y->disk_for));
    jkeep(r, "disk_band", y->disk_band, sizeof(y->disk_band));
    y->has_temp = jnum(r, "temp_max_c", -100, 250, &y->temp_max_c);
    jkeep(r, "temp_max_id", y->temp_max_id, sizeof(y->temp_max_id));
    jkeep(r, "temp_band", y->temp_band, sizeof(y->temp_band));
    y->undervolt = jll(r, "undervolt", 0, 1, &v) ? (int)v : -1;
    /* The beacon memory (1.2.0): the four always-present members in
     * range, or none of it; reach and time left only beside the state
     * that gives them a meaning. */
    long long ov = 0, qu = 0;
    y->has_recall = jll(r, "beacon_recall_max", 1, 1 << 20, &y->recall_max) &&
                    jll(r, "beacon_recall_slots", 0, y->recall_max, &y->recall_slots) &&
                    jll(r, "beacon_recall_overflowed", 0, 1, &ov) &&
                    jll(r, "beacon_recall_quiet", 0, 1, &qu) && (!qu || ov);
    y->recall_overflowed = y->has_recall ? (int)ov : 0;
    y->recall_quiet = y->has_recall ? (int)qu : 0;
    if (!y->has_recall || !ov || !jll(r, "beacon_recall_reach_s", 0, 1LL << 40, &y->recall_reach_s))
        y->recall_reach_s = -1;
    if (!y->has_recall || !qu || !jll(r, "beacon_recall_quiet_s", 0, 86400, &y->recall_quiet_s))
        y->recall_quiet_s = -1;
    /* A batch that says it has no sensors (or receivers) is followed by
     * no row to replace the last batch's with, so they go here. */
    long long t = 0, vo = 0, po = 0, rc = 0;
    if (jll(r, "temps", 0, 1000, &t) && jll(r, "volts", 0, 1000, &vo) &&
        jll(r, "power", 0, 1000, &po) && t + vo + po == 0) {
        memset(y->sensors, 0, sizeof(y->sensors));
        y->sensor_seq = seq;
    }
    if (jll(r, "receivers", 0, 1000, &rc) && rc == 0) {
        memset(y->hw, 0, sizeof(y->hw));
        y->hw_seq = seq;
    }
}

static void sensor_apply(web_sys_t *y, const web_jrec_t *r) {
    const char *cls = web_jl_str(r, "class"), *id = web_jl_str(r, "id");
    long long seq, v;
    if (!cls || !id || !id[0] || !jll(r, "seq", 0, 0xffffffffLL, &seq) ||
        (strcmp(cls, "temp") && strcmp(cls, "volt") && strcmp(cls, "power"))) {
        y->rejected++;
        return;
    }
    if (seq != y->sensor_seq) {
        memset(y->sensors, 0, sizeof(y->sensors));
        y->sensor_seq = seq;
    }
    char kid[sizeof(y->sensors[0].id)];
    web_sys_keep(kid, sizeof(kid), id);
    web_sys_sensor_t *s = NULL;
    for (int i = 0; i < WEB_SYS_SENSORS; i++) {
        web_sys_sensor_t *c = &y->sensors[i];
        if (c->used && !strcmp(c->cls, cls) && !strcmp(c->id, kid)) { s = c; break; }
        if (!c->used && !s) s = c;
    }
    if (!s) { y->overflow++; return; }
    memset(s, 0, sizeof(*s));
    s->used = 1;
    snprintf(s->cls, sizeof(s->cls), "%s", cls);
    memcpy(s->id, kid, sizeof(kid));
    if (web_key_sys(id, s->key) != 0 || !strcmp(s->key, "hottest")) s->key[0] = '\0';
    jkeep(r, "label", s->label, sizeof(s->label));
    s->has_val = cls[0] == 't' ? jnum(r, "c", -100, 250, &s->val)
                               : jnum(r, "v", -100, 100, &s->val);
    s->alarm = jll(r, "alarm", 0, 1, &v) ? (int)v : -1;
    s->capacity = jll(r, "capacity", 0, 100, &v) ? (int)v : -1;
    jkeep(r, "status", s->status, sizeof(s->status));
}

static int state_ok(const char *s) {
    return s && (!strcmp(s, "ok") || !strcmp(s, "stale") || !strcmp(s, "down") ||
                 !strcmp(s, "not_configured"));
}

static void source_apply(web_sys_t *y, const web_jrec_t *r, long long ts, long long now_ms) {
    const char *name = web_jl_str(r, "name"), *state = web_jl_str(r, "state");
    if (!word_ok(name, sizeof(y->sources[0].name) - 1) || !state_ok(state)) {
        y->rejected++;
        return;
    }
    web_sys_source_t *s = NULL;
    for (int i = 0; i < WEB_SYS_SOURCES; i++) {
        web_sys_source_t *c = &y->sources[i];
        if (c->used && !strcmp(c->name, name)) { s = c; break; }
        if (!c->used && !s) s = c;
    }
    if (!s) { y->overflow++; return; }
    memset(s, 0, sizeof(*s));
    s->used = 1;
    s->ts = ts;
    s->rx_ms = now_ms;
    snprintf(s->name, sizeof(s->name), "%s", name);
    snprintf(s->state, sizeof(s->state), "%s", state);
    jkeep(r, "kind", s->kind, sizeof(s->kind));
    jkeep(r, "flag", s->flag, sizeof(s->flag));
    jkeep(r, "detail", s->detail, sizeof(s->detail));
    jkeep(r, "endpoint", s->endpoint, sizeof(s->endpoint));
    jkeep(r, "hw", s->hw, sizeof(s->hw));
    jkeep(r, "desc", s->desc, sizeof(s->desc));
    jkeep(r, "driver", s->driver, sizeof(s->driver));
    jkeep(r, "age_band", s->age_band, sizeof(s->age_band));
    jkeep(r, "unit", s->unit, sizeof(s->unit));
    s->has_age = jll(r, "age_s", -1, 1LL << 40, &s->age_s);
    s->has_count = jll(r, "count", 0, 1LL << 62, &s->count);
    if (!jll(r, "errors", 0, 1LL << 62, &s->errors)) s->errors = 0;
    s->has_rate = jnum(r, "rate", 0, 1e9, &s->rate);
    s->has_reconnects = jll(r, "reconnects", 0, 1LL << 62, &s->reconnects);
}

static void hw_apply(web_sys_t *y, const web_jrec_t *r) {
    const char *key = web_jl_str(r, "key");
    long long seq, v;
    if (!key || !key[0] || !jll(r, "seq", 0, 0xffffffffLL, &seq)) { y->rejected++; return; }
    if (seq != y->hw_seq) {
        memset(y->hw, 0, sizeof(y->hw));
        y->hw_seq = seq;
    }
    char kk[sizeof(y->hw[0].key)];
    web_sys_keep(kk, sizeof(kk), key);
    web_sys_hw_t *h = NULL;
    for (int i = 0; i < WEB_SYS_HW; i++) {
        web_sys_hw_t *c = &y->hw[i];
        if (c->used && !strcmp(c->key, kk)) { h = c; break; }
        if (!c->used && !h) h = c;
    }
    if (!h) { y->overflow++; return; }
    memset(h, 0, sizeof(*h));
    h->used = 1;
    memcpy(h->key, kk, sizeof(kk));
    jkeep(r, "kind", h->kind, sizeof(h->kind));
    jkeep(r, "bus", h->bus, sizeof(h->bus));
    jkeep(r, "id", h->id, sizeof(h->id));
    jkeep(r, "desc", h->desc, sizeof(h->desc));
    jkeep(r, "vendor", h->vendor, sizeof(h->vendor));
    jkeep(r, "product", h->product, sizeof(h->product));
    jkeep(r, "driver", h->driver, sizeof(h->driver));
    jkeep(r, "ifaces", h->ifaces, sizeof(h->ifaces));
    h->known = jll(r, "known", 0, 1, &v) ? (int)v : 0;
}

static int which(const char *t) {
    if (!t) return 0;
    if (!strcmp(t, "sys_status")) return 1;
    if (!strcmp(t, "sys_sensor")) return 2;
    if (!strcmp(t, "source_status")) return 3;
    if (!strcmp(t, "receiver_hw")) return 4;
    return 0;
}

void web_sys_record(web_sys_t *y, const web_jrec_t *r, long long now_ms) {
    int w = which(web_jl_str(r, "type"));
    if (!y || !w) return;
    long long ts = web_jl_int(r, "ts", 0);
    pthread_mutex_lock(&y->mu);
    y->records++;
    if (w == 1) status_apply(y, r, ts, now_ms);
    else if (w == 2) sensor_apply(y, r);
    else if (w == 3) source_apply(y, r, ts, now_ms);
    else hw_apply(y, r);
    pthread_mutex_unlock(&y->mu);
}

void web_sys_metrics(web_rollup_t *ru, const web_jrec_t *r, long long now_s) {
    int w = which(web_jl_str(r, "type"));
    char k[WEB_KEY_MAX + 1];
    double v, tot;
    long long i;
    if (!ru || !w) return;
    if (w == 1) {
        if (jnum(r, "cpu_pct", 0, 100, &v)) web_rollup_add(ru, WM_SYS_CPU, "", v, now_s);
        if (jnum(r, "mem_total_kb", 1, 1e15, &tot) && jnum(r, "mem_avail_kb", 0, tot, &v))
            web_rollup_add(ru, WM_SYS_MEM_USED, "", 100.0 - 100.0 * v / tot, now_s);
        if (jnum(r, "rss_kb", 0, 1e15, &v)) web_rollup_add(ru, WM_SYS_RSS, "", v, now_s);
        if (jnum(r, "temp_max_c", -100, 250, &v))
            web_rollup_add(ru, WM_SYS_TEMP, "hottest", v, now_s);
        if (jll(r, "undervolt", 0, 1, &i))
            web_rollup_add(ru, WM_SYS_UNDERVOLT, "", (double)i, now_s);
    } else if (w == 2) {
        const char *cls = web_jl_str(r, "class");
        if (!cls || web_key_sys(web_jl_str(r, "id"), k) != 0 || !strcmp(k, "hottest")) return;
        if (!strcmp(cls, "temp")) {
            if (jnum(r, "c", -100, 250, &v)) web_rollup_add(ru, WM_SYS_TEMP, k, v, now_s);
        } else if (!strcmp(cls, "volt") || !strcmp(cls, "power")) {
            if (jnum(r, "v", -100, 100, &v)) web_rollup_add(ru, WM_SYS_VOLT, k, v, now_s);
        }
    } else if (w == 3) {
        const char *name = web_jl_str(r, "name"), *state = web_jl_str(r, "state");
        if (!word_ok(name, 24) || !state_ok(state) || web_key_sys(name, k) != 0) return;
        /* A source nobody configured has no up or down to chart. */
        if (!strcmp(state, "not_configured")) return;
        web_rollup_add(ru, WM_SRC_UP, k, !strcmp(state, "ok") ? 1.0 : 0.0, now_s);
        if (jnum(r, "rate", 0, 1e9, &v)) web_rollup_add(ru, WM_SRC_RATE, k, v, now_s);
    }
}

/* ── /api/sys ────────────────────────────────────────────────────── */

static void jw_num(web_jw_t *w, int has, double v, int dp) {
    char t[40];
    if (!has || !isfinite(v)) { web_jw_raw(w, "null"); return; }
    snprintf(t, sizeof(t), "%.*f", dp, v);
    web_jw_raw(w, t);
}

static void jw_ll(web_jw_t *w, int has, long long v) {
    if (has) web_jw_int(w, v); else web_jw_raw(w, "null");
}

/* A string member, null when it is empty: "" from the stream is "not
 * said", and the page words that, not an empty cell. */
static void jw_strnull(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s); else web_jw_raw(w, "null");
}

int web_sys_route(web_sys_t *y, const char *query, long long now_s, long long now_ms,
                  char *body, size_t cap, size_t *len, int *status) {
    char err[48];
    if (web_params_parse(query, NULL, 0, err, sizeof(err)) != 0) {
        *status = 400;
        *len = web_series_error_json(err, body, cap);
        return *len ? 0 : -1;
    }
    if (!y) {
        *status = 503;
        *len = web_series_error_json("no_sys", body, cap);
        return *len ? 0 : -1;
    }
    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&y->mu);
    long long age = y->seen ? (now_ms - y->rx_ms) / 1000 : -1;
    if (age < 0 && y->seen) age = 0;
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    /* Not "scope": a scoped request's answer already has that member. */
    web_jw_raw(&w, ",\"scope_note\":\"every scope: sloth's own state\"");
    web_jw_raw(&w, ",\"seen\":"); web_jw_raw(&w, y->seen ? "true" : "false");
    web_jw_raw(&w, ",\"ts\":"); jw_ll(&w, y->seen, y->ts);
    web_jw_raw(&w, ",\"age_s\":"); jw_ll(&w, y->seen, age);
    web_jw_raw(&w, ",\"seq\":"); jw_ll(&w, y->seen, y->seq);
    web_jw_raw(&w, ",\"interval_s\":"); jw_ll(&w, y->seen, y->interval_s);
    web_jw_raw(&w, ",\"stale\":");
    web_jw_raw(&w, y->seen && age > (long long)WEB_SYS_STALE_INTERVALS * y->interval_s
                   ? "true" : "false");
    web_jw_raw(&w, ",\"system\":");
    if (!y->seen) {
        web_jw_raw(&w, "null");
    } else {
        web_jw_raw(&w, "{\"cpu_pct\":"); jw_num(&w, y->has_cpu, y->cpu_pct, 1);
        web_jw_raw(&w, ",\"cpu_iowait_pct\":"); jw_num(&w, y->has_cpu, y->iowait_pct, 1);
        web_jw_raw(&w, ",\"cpu_band\":"); jw_strnull(&w, y->cpu_band);
        web_jw_raw(&w, ",\"load1\":"); jw_num(&w, y->has_load, y->load1, 2);
        web_jw_raw(&w, ",\"load5\":"); jw_num(&w, y->has_load, y->load5, 2);
        web_jw_raw(&w, ",\"load15\":"); jw_num(&w, y->has_load, y->load15, 2);
        web_jw_raw(&w, ",\"mem_total_kb\":"); jw_ll(&w, y->has_mem, y->mem_total_kb);
        web_jw_raw(&w, ",\"mem_avail_kb\":"); jw_ll(&w, y->has_mem, y->mem_avail_kb);
        web_jw_raw(&w, ",\"mem_band\":"); jw_strnull(&w, y->has_mem ? y->mem_band : "");
        web_jw_raw(&w, ",\"uptime_s\":"); jw_ll(&w, y->has_uptime, y->uptime_s);
        web_jw_raw(&w, ",\"rss_kb\":"); jw_ll(&w, y->has_rss, y->rss_kb);
        web_jw_raw(&w, ",\"disk_for\":"); jw_strnull(&w, y->has_disk ? y->disk_for : "");
        web_jw_raw(&w, ",\"disk_free_mb\":"); jw_ll(&w, y->has_disk, y->disk_free_mb);
        web_jw_raw(&w, ",\"disk_total_mb\":"); jw_ll(&w, y->has_disk, y->disk_total_mb);
        web_jw_raw(&w, ",\"disk_band\":"); jw_strnull(&w, y->has_disk ? y->disk_band : "");
        web_jw_raw(&w, ",\"temp_max_c\":"); jw_num(&w, y->has_temp, y->temp_max_c, 1);
        web_jw_raw(&w, ",\"temp_max_id\":"); jw_strnull(&w, y->has_temp ? y->temp_max_id : "");
        web_jw_raw(&w, ",\"temp_band\":"); jw_strnull(&w, y->has_temp ? y->temp_band : "");
        web_jw_raw(&w, ",\"undervolt\":"); jw_ll(&w, y->undervolt >= 0, y->undervolt);
        web_jw_raw(&w, "}");
    }
    /* quiet_until is the sensor's own clock (the batch's ts plus the
     * time it said was left): a time to show, never compared with
     * slothweb's. */
    web_jw_raw(&w, ",\"beacon_recall\":");
    if (!y->seen || !y->has_recall) {
        web_jw_raw(&w, "null");
    } else {
        web_jw_raw(&w, "{\"slots\":"); web_jw_int(&w, y->recall_slots);
        web_jw_raw(&w, ",\"max\":"); web_jw_int(&w, y->recall_max);
        web_jw_raw(&w, ",\"overflowed\":"); web_jw_raw(&w, y->recall_overflowed ? "true" : "false");
        web_jw_raw(&w, ",\"reach_s\":"); jw_ll(&w, y->recall_reach_s >= 0, y->recall_reach_s);
        web_jw_raw(&w, ",\"quiet\":"); web_jw_raw(&w, y->recall_quiet ? "true" : "false");
        web_jw_raw(&w, ",\"quiet_s\":"); jw_ll(&w, y->recall_quiet_s >= 0, y->recall_quiet_s);
        web_jw_raw(&w, ",\"quiet_until\":");
        jw_ll(&w, y->recall_quiet_s >= 0, y->ts + y->recall_quiet_s);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, ",\"sensors\":[");
    for (int i = 0, n = 0; i < WEB_SYS_SENSORS; i++) {
        const web_sys_sensor_t *s = &y->sensors[i];
        if (!s->used) continue;
        web_jw_raw(&w, n++ ? ",{\"class\":" : "{\"class\":"); web_jw_str(&w, s->cls);
        web_jw_raw(&w, ",\"id\":"); web_jw_str(&w, s->id);
        web_jw_raw(&w, ",\"key\":"); jw_strnull(&w, s->key);
        web_jw_raw(&w, ",\"label\":"); jw_strnull(&w, s->label);
        web_jw_raw(&w, s->cls[0] == 't' ? ",\"c\":" : ",\"v\":");
        jw_num(&w, s->has_val, s->val, s->cls[0] == 't' ? 1 : 3);
        web_jw_raw(&w, ",\"alarm\":"); jw_ll(&w, s->alarm >= 0, s->alarm);
        web_jw_raw(&w, ",\"capacity\":"); jw_ll(&w, s->capacity >= 0, s->capacity);
        web_jw_raw(&w, ",\"status\":"); jw_strnull(&w, s->status);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"sources\":[");
    for (int i = 0, n = 0; i < WEB_SYS_SOURCES; i++) {
        const web_sys_source_t *s = &y->sources[i];
        if (!s->used) continue;
        long long ra = (now_ms - s->rx_ms) / 1000;
        web_jw_raw(&w, n++ ? ",{\"name\":" : "{\"name\":"); web_jw_str(&w, s->name);
        web_jw_raw(&w, ",\"kind\":"); jw_strnull(&w, s->kind);
        web_jw_raw(&w, ",\"flag\":"); jw_strnull(&w, s->flag);
        web_jw_raw(&w, ",\"state\":"); web_jw_str(&w, s->state);
        web_jw_raw(&w, ",\"detail\":"); jw_strnull(&w, s->detail);
        web_jw_raw(&w, ",\"endpoint\":"); jw_strnull(&w, s->endpoint);
        web_jw_raw(&w, ",\"hw\":"); jw_strnull(&w, s->hw);
        web_jw_raw(&w, ",\"desc\":"); jw_strnull(&w, s->desc);
        web_jw_raw(&w, ",\"driver\":"); jw_strnull(&w, s->driver);
        web_jw_raw(&w, ",\"age_s\":"); jw_ll(&w, s->has_age, s->age_s);
        web_jw_raw(&w, ",\"age_band\":"); jw_strnull(&w, s->age_band);
        web_jw_raw(&w, ",\"unit\":"); jw_strnull(&w, s->unit);
        web_jw_raw(&w, ",\"count\":"); jw_ll(&w, s->has_count, s->count);
        web_jw_raw(&w, ",\"rate\":"); jw_num(&w, s->has_rate, s->rate, 2);
        web_jw_raw(&w, ",\"errors\":"); jw_ll(&w, s->has_count, s->errors);
        web_jw_raw(&w, ",\"reconnects\":"); jw_ll(&w, s->has_reconnects, s->reconnects);
        web_jw_raw(&w, ",\"ts\":"); web_jw_int(&w, s->ts);
        web_jw_raw(&w, ",\"report_age_s\":"); web_jw_int(&w, ra < 0 ? 0 : ra);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"receivers\":[");
    for (int i = 0, n = 0; i < WEB_SYS_HW; i++) {
        const web_sys_hw_t *h = &y->hw[i];
        if (!h->used) continue;
        web_jw_raw(&w, n++ ? ",{\"key\":" : "{\"key\":"); web_jw_str(&w, h->key);
        web_jw_raw(&w, ",\"kind\":"); jw_strnull(&w, h->kind);
        web_jw_raw(&w, ",\"bus\":"); jw_strnull(&w, h->bus);
        web_jw_raw(&w, ",\"id\":"); jw_strnull(&w, h->id);
        web_jw_raw(&w, ",\"known\":"); web_jw_int(&w, h->known);
        web_jw_raw(&w, ",\"desc\":"); jw_strnull(&w, h->desc);
        web_jw_raw(&w, ",\"vendor\":"); jw_strnull(&w, h->vendor);
        web_jw_raw(&w, ",\"product\":"); jw_strnull(&w, h->product);
        web_jw_raw(&w, ",\"driver\":"); jw_strnull(&w, h->driver);
        web_jw_raw(&w, ",\"ifaces\":"); jw_strnull(&w, h->ifaces);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"records\":"); web_jw_int(&w, (long long)y->records);
    web_jw_raw(&w, ",\"rejected\":"); web_jw_int(&w, (long long)y->rejected);
    web_jw_raw(&w, ",\"overflow\":"); web_jw_int(&w, (long long)y->overflow);
    web_jw_raw(&w, "}");
    pthread_mutex_unlock(&y->mu);
    if (w.overflow) return -1;
    *status = 200;
    *len = w.len;
    return 0;
}
