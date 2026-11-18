#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "victron.h"

/* Contract in victron.h. Pure except the table at the bottom, one
 * mutex-guarded struct the reader feeds and the main thread polls. */

/* ── JSON cursor ──────────────────────────────────────────────────
 * The locale-free walk src/rtl433.c uses, with this file's own bounds
 * (that file says why the parsers are not folded into one). sloth-va
 * escapes `"`, `\` and every byte outside printable ASCII as \u00XX;
 * an escape is kept here as its second byte, which the string cleaning
 * below then refuses or drops - no field sloth keeps needs one. */

typedef struct { const char *p, *e; } jcur_t;

static void jws(jcur_t *c) {
    while (c->p < c->e && (*c->p == ' ' || *c->p == '\t' ||
                           *c->p == '\r' || *c->p == '\n'))
        c->p++;
}

static int jstr(jcur_t *c, char *out, size_t outsz) {
    size_t k = 0;
    if (c->p >= c->e || *c->p != '"') return -1;
    c->p++;
    while (c->p < c->e && *c->p != '"') {
        char ch = *c->p++;
        if (ch == '\\') {
            if (c->p >= c->e) return -1;
            ch = *c->p++;
        }
        if (out && k + 1 < outsz) out[k++] = ch;
    }
    if (c->p >= c->e) return -1;
    c->p++;
    if (out && outsz) out[k] = '\0';
    return 0;
}

static int jnum(jcur_t *c, double *out) {
    const char *s = c->p;
    int neg = 0, digits = 0;
    double v = 0.0, scale = 1.0;
    if (c->p < c->e && *c->p == '-') { neg = 1; c->p++; }
    while (c->p < c->e && *c->p >= '0' && *c->p <= '9') {
        v = v * 10.0 + (*c->p++ - '0');
        digits++;
    }
    if (c->p < c->e && *c->p == '.') {
        c->p++;
        while (c->p < c->e && *c->p >= '0' && *c->p <= '9') {
            scale /= 10.0;
            v += (*c->p++ - '0') * scale;
            digits++;
        }
    }
    if (!digits || digits > 40) { c->p = s; return -1; }
    if (c->p < c->e && (*c->p == 'e' || *c->p == 'E')) {
        int eneg = 0, ex = 0, ed = 0;
        c->p++;
        if (c->p < c->e && (*c->p == '+' || *c->p == '-')) eneg = *c->p++ == '-';
        while (c->p < c->e && *c->p >= '0' && *c->p <= '9') {
            if (ex < 1000) ex = ex * 10 + (*c->p - '0');
            c->p++;
            ed++;
        }
        if (!ed) return -1;
        if (ex > 400) ex = 400;
        while (ex-- > 0) v = eneg ? v / 10.0 : v * 10.0;
    }
    *out = neg ? -v : v;
    return 0;
}

static int jskip(jcur_t *c) {
    jws(c);
    if (c->p >= c->e) return -1;
    char ch = *c->p;
    if (ch == '"') return jstr(c, NULL, 0);
    if (ch == '{' || ch == '[') {
        int depth = 0;
        while (c->p < c->e) {
            ch = *c->p;
            if (ch == '"') { if (jstr(c, NULL, 0) != 0) return -1; continue; }
            if (ch == '{' || ch == '[') { if (++depth > 8) return -1; }
            else if (ch == '}' || ch == ']') {
                if (--depth == 0) { c->p++; return 0; }
            }
            c->p++;
        }
        return -1;
    }
    if (ch == '-' || (ch >= '0' && ch <= '9')) { double d; return jnum(c, &d); }
    static const char *const lits[] = { "true", "false", "null" };
    for (size_t i = 0; i < 3; i++) {
        size_t l = strlen(lits[i]);
        if ((size_t)(c->e - c->p) >= l && memcmp(c->p, lits[i], l) == 0) {
            c->p += l;
            return 0;
        }
    }
    return -1;
}

static int jnull(jcur_t *c) {
    if ((size_t)(c->e - c->p) >= 4 && memcmp(c->p, "null", 4) == 0) { c->p += 4; return 1; }
    return 0;
}

/* ── The allow-list ────────────────────────────────────────────────
 * What sloth-va writes (va_victron.c: the Instant Readout fields of the
 * battery-monitor, inverter and DC/DC records, and the 65970000 GATT
 * values),
 * each with a sanity bound wider than the field can carry, and the step
 * the change signature bands it to (0 = exact). */
static const struct {
    const char *name, *unit;
    double lo, hi, step;
} VALS[] = {
    { "voltage_v",     "V",   -400,  400,        0.1 },
    { "aux_voltage_v", "V",   -400,  400,        0.1 },
    { "mid_voltage_v", "V",      0,  700,        0.1 },
    { "input_v",       "V",      0,  700,        0.1 },
    { "output_v",      "V",   -400,  400,        0.1 },
    { "current_a",     "A", -10000, 10000,       1.0 },
    { "power_w",       "W", -200000, 200000,    10.0 },
    { "consumed_ah",   "Ah", -200000, 200000,    1.0 },
    { "soc_pct",       "%",      0,  100,        1.0 },
    { "ttg_min",       "min",    0,  65535,     10.0 },
    { "temperature_c", "C",   -100,  400,        1.0 },
    /* The inverter record's AC output (schema v16). */
    { "ac_voltage_v",  "V",      0,  400,        1.0 },
    { "ac_current_a",  "A",      0,  250,        0.5 },
    { "ac_apparent_va", "VA",    0,  65535,     10.0 },
    { "alarm_reason",  "",       0,  65535,      0 },
    { "aux_input",     "",       0,  3,          0 },
    { "device_state",  "",       0,  255,        0 },
    { "charger_error", "",       0,  255,        0 },
    { "off_reason",    "",       0,  4294967295.0, 0 },
};
#define NVALS ((int)(sizeof(VALS) / sizeof(VALS[0])))

static int val_index(const char *name) {
    for (int i = 0; i < NVALS; i++)
        if (!strcmp(VALS[i].name, name)) return i;
    return -1;
}

int victron_value_known(const char *name, const char **unit) {
    int i = name ? val_index(name) : -1;
    if (i < 0) return 0;
    if (unit) *unit = VALS[i].unit;
    return 1;
}

long long victron_value_band(const char *name, double v) {
    int i = name ? val_index(name) : -1;
    double step = i >= 0 ? VALS[i].step : 0;
    if (step <= 0) return (long long)floor(v + 0.5);
    return (long long)floor(v / step + 0.5);
}

/* Keep [A-Za-z0-9] and " -_.:/()+" only; a value that would become
 * empty, or carried anything else that was not dropped, is "". */
static void clean(char *s, size_t sz) {
    size_t k = 0;
    for (size_t i = 0; s[i] && k + 1 < sz; i++) {
        unsigned char ch = (unsigned char)s[i];
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') || strchr(" -_.:/()+", ch))
            s[k++] = (char)ch;
    }
    s[k] = '\0';
}

/* Bounded copy, always terminated; a longer string is cut. */
static void put(char *dst, size_t dsz, const char *v) {
    size_t n = strlen(v);
    if (n >= dsz) n = dsz - 1;
    memcpy(dst, v, n);
    dst[n] = '\0';
}

static int mac_ok(const char *m) {
    if (strlen(m) != 17) return 0;
    for (int i = 0; i < 17; i++) {
        char c = m[i];
        if (i % 3 == 2) { if (c != ':') return 0; }
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

/* sloth-va's service list (va_record_jsonl()): UUIDs joined by ','.
 * Kept lower-cased only when every byte is [0-9a-fA-F-,] and it fits;
 * otherwise "" - a list with anything else in it is not one sloth-va
 * wrote, and a cut list would name a UUID that was not there. */
static void services_take(const char *v, char *out, size_t outsz) {
    size_t n = strlen(v);
    out[0] = '\0';
    if (n == 0 || n >= outsz) return;
    for (size_t i = 0; i < n; i++) {
        char c = v[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F') || c == '-' || c == ','))
            return;
    }
    for (size_t i = 0; i < n; i++)
        out[i] = (char)((v[i] >= 'A' && v[i] <= 'F') ? v[i] + 32 : v[i]);
    out[n] = '\0';
}

static int reject(int *why, int code) {
    if (why) *why = code;
    return -1;
}

static int parse_values(jcur_t *c, victron_msg_t *m) {
    jws(c);
    if (c->p >= c->e || *c->p != '{') return -1;
    c->p++;
    jws(c);
    if (c->p < c->e && *c->p == '}') { c->p++; return 0; }
    for (;;) {
        char k[40];
        jws(c);
        if (jstr(c, k, sizeof(k)) != 0) return -1;
        jws(c);
        if (c->p >= c->e || *c->p != ':') return -1;
        c->p++;
        jws(c);
        size_t kl = strlen(k);
        int i = val_index(k);
        if (i >= 0 && c->p < c->e && (*c->p == '-' || (*c->p >= '0' && *c->p <= '9'))) {
            double d;
            if (jnum(c, &d) != 0) return -1;
            if (!isfinite(d) || d < VALS[i].lo || d > VALS[i].hi) {
                m->bad_values++;
            } else {
                int at = -1;
                for (int j = 0; j < m->nvals; j++)
                    if (!strcmp(m->vals[j].name, k)) at = j;
                if (at < 0 && m->nvals < VICTRON_MAX_VALS) at = m->nvals++;
                if (at >= 0) {
                    put(m->vals[at].name, sizeof(m->vals[at].name), VALS[i].name);
                    m->vals[at].v = d;
                }
            }
        } else {
            /* A derived name (`device_state_name`) is sloth-va's
             * rendering of a number kept above: skipped, not counted. */
            if (!(kl > 5 && !strcmp(k + kl - 5, "_name"))) m->other_keys++;
            if (jskip(c) != 0) return -1;
        }
        jws(c);
        if (c->p < c->e && *c->p == ',') { c->p++; continue; }
        if (c->p < c->e && *c->p == '}') { c->p++; return 0; }
        return -1;
    }
}

int victron_line_parse(const char *line, size_t n, victron_msg_t *m, int *why) {
    memset(m, 0, sizeof(*m));
    if (n > VICTRON_MAX_LINE) return reject(why, VICTRON_REJ_OVERSIZE);
    jcur_t c = { line, line + n };
    jws(&c);
    if (c.p >= c.e) return 0;
    if (*c.p != '{') return reject(why, VICTRON_REJ_NOT_OBJECT);
    c.p++;
    int is_victron = 0, source_ok = 0;
    jws(&c);
    if (c.p < c.e && *c.p == '}') { c.p++; goto close; }
    for (;;) {
        char k[32];
        jws(&c);
        if (jstr(&c, k, sizeof(k)) != 0) return reject(why, VICTRON_REJ_MALFORMED);
        jws(&c);
        if (c.p >= c.e || *c.p != ':') return reject(why, VICTRON_REJ_MALFORMED);
        c.p++;
        jws(&c);
        char sv[64];
        if (!strcmp(k, "values")) {
            if (parse_values(&c, m) != 0) return reject(why, VICTRON_REJ_MALFORMED);
        } else if (!strcmp(k, "rssi") && c.p < c.e && (*c.p == '-' || (*c.p >= '0' && *c.p <= '9'))) {
            double d;
            if (jnum(&c, &d) != 0) return reject(why, VICTRON_REJ_MALFORMED);
            if (isfinite(d) && d >= -127 && d <= 20) { m->has_rssi = 1; m->rssi = (int)d; }
            else m->bad_values++;
        } else if (!strcmp(k, "services") && c.p < c.e && *c.p == '"') {
            /* Read one byte past the cap, so an over-long list is seen
             * as over-long rather than cut to fit. */
            char big[VICTRON_SERVICES_MAX + 2];
            if (jstr(&c, big, sizeof(big)) != 0) return reject(why, VICTRON_REJ_MALFORMED);
            services_take(big, m->services, sizeof(m->services));
        } else if ((!strcmp(k, "type") || !strcmp(k, "source") || !strcmp(k, "mac") ||
                    !strcmp(k, "serial") || !strcmp(k, "model") || !strcmp(k, "record") ||
                    !strcmp(k, "session")) && c.p < c.e && *c.p == '"') {
            if (jstr(&c, sv, sizeof(sv)) != 0) return reject(why, VICTRON_REJ_MALFORMED);
            if (!strcmp(k, "type")) is_victron = !strcmp(sv, "victron");
            else if (!strcmp(k, "source")) {
                source_ok = !strcmp(sv, "readout") || !strcmp(sv, "gatt");
                m->gatt = !strcmp(sv, "gatt");
            } else if (!strcmp(k, "mac")) {
                if (mac_ok(sv)) {
                    for (int i = 0; i < 17; i++)
                        m->mac[i] = (char)((sv[i] >= 'A' && sv[i] <= 'F') ? sv[i] + 32 : sv[i]);
                    m->mac[17] = '\0';
                }
            } else {
                clean(sv, sizeof(sv));
                char *dst = !strcmp(k, "serial") ? m->serial : !strcmp(k, "model") ? m->model
                          : !strcmp(k, "record") ? m->record : m->session;
                size_t dsz = !strcmp(k, "serial") ? sizeof(m->serial) : !strcmp(k, "model")
                          ? sizeof(m->model) : !strcmp(k, "record") ? sizeof(m->record)
                          : sizeof(m->session);
                put(dst, dsz, sv);
            }
        } else if (jnull(&c)) {
            /* "serial":null and the like: absent. */
        } else if (jskip(&c) != 0) {
            return reject(why, VICTRON_REJ_MALFORMED);
        }
        jws(&c);
        if (c.p < c.e && *c.p == ',') { c.p++; continue; }
        if (c.p < c.e && *c.p == '}') { c.p++; break; }
        return reject(why, VICTRON_REJ_MALFORMED);
    }
close:
    jws(&c);
    if (c.p != c.e) return reject(why, VICTRON_REJ_NOT_OBJECT);
    if (!is_victron || !source_ok) return reject(why, VICTRON_REJ_NOT_VICTRON);
    if (!m->mac[0]) return reject(why, VICTRON_REJ_NO_MAC);
    return 1;
}

const char *victron_reject_name(int why) {
    switch (why) {
    case VICTRON_REJ_OVERSIZE:    return "oversize";
    case VICTRON_REJ_NOT_OBJECT:  return "not_object";
    case VICTRON_REJ_MALFORMED:   return "malformed";
    case VICTRON_REJ_NOT_VICTRON: return "not_victron";
    case VICTRON_REJ_NO_MAC:      return "no_mac";
    default:                      return "";
    }
}

int victron_spec_parse(const char *spec, char *path, size_t pathsz,
                       char *err, size_t errsz) {
    const char *p = spec;
    if (!spec || !*spec) {
        if (err && errsz) snprintf(err, errsz, "empty SPEC");
        return -1;
    }
    if (strncmp(spec, "file://", 7) == 0) {
        p = spec + 7;
        if (*p != '/') {
            if (err && errsz) snprintf(err, errsz, "file:// takes a local absolute path (file:///path)");
            return -1;
        }
    } else if (strstr(spec, "://")) {
        if (err && errsz) snprintf(err, errsz, "unsupported scheme: want an absolute path "
                                               "or file:///path to sloth-va's victron.jsonl");
        return -1;
    } else if (*spec != '/') {
        if (err && errsz) snprintf(err, errsz, "want an absolute path");
        return -1;
    }
    size_t l = strlen(p);
    if (l < 2 || p[l - 1] == '/') {
        if (err && errsz) snprintf(err, errsz, "want a file, not a directory");
        return -1;
    }
    if (!path || l >= pathsz) {
        if (err && errsz) snprintf(err, errsz, "path too long");
        return -1;
    }
    memcpy(path, p, l + 1);
    return 0;
}

/* ── The signature ─────────────────────────────────────────────── */

static uint64_t mix64(uint64_t h, long long v) {
    h ^= (uint64_t)v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h * 0x100000001b3ULL;
}

static uint64_t mix_str(uint64_t h, const char *s) {
    for (; *s; s++) h = mix64(h, (unsigned char)*s);
    return mix64(h, 0);
}

uint64_t victron_device_sig(const victron_device_t *d) {
    uint64_t h = 0xcbf29ce484222325ULL;
    if (!d) return h;
    h = mix_str(h, d->mac);
    h = mix64(h, (long long)d->first_seen);
    h = mix_str(h, d->serial);
    h = mix_str(h, d->model);
    h = mix_str(h, d->record);
    h = mix_str(h, d->session);
    h = mix_str(h, d->services);
    h = mix64(h, d->vals_gatt);
    /* Values in allow-list order, so the order records arrived in does
     * not move the signature. */
    for (int i = 0; i < NVALS; i++) {
        int at = -1;
        for (int j = 0; j < d->nvals; j++)
            if (!strcmp(d->vals[j].name, VALS[i].name)) at = j;
        h = mix64(h, at >= 0);
        h = mix64(h, at >= 0 ? victron_value_band(VALS[i].name, d->vals[at].v) : -1000000);
    }
    return h;
}

/* ── The table ─────────────────────────────────────────────────── */

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static struct {
    int      configured;
    char     label[48];
    char     err[96];
    int      missing, ever_read;
    time_t   last_read, last_rec;
    uint64_t bytes, lines, records, bad, bad_values, other_keys, table_full;
    uint64_t rej[VICTRON_REJ_COUNT];
    uint64_t truncations, rotations, read_errors;
    victron_device_t dev[VICTRON_MAX_DEVICES];
    int      ndev;
} g;

static victron_device_t g_snap[VICTRON_MAX_DEVICES];

void victron_set_source(const char *label) {
    pthread_mutex_lock(&g_mu);
    g.configured = 1;
    snprintf(g.label, sizeof(g.label), "%s", label ? label : "");
    pthread_mutex_unlock(&g_mu);
}

/* Caller holds g_mu. Sticky merge. */
static void merge(victron_device_t *d, const victron_msg_t *m, time_t wall) {
    d->last_seen = wall;
    if (m->serial[0]) put(d->serial, sizeof(d->serial), m->serial);
    if (m->model[0])  put(d->model, sizeof(d->model), m->model);
    if (m->record[0]) put(d->record, sizeof(d->record), m->record);
    if (m->has_rssi)  { d->has_rssi = 1; d->rssi = m->rssi; }
    if (m->gatt) {
        d->sessions++;
        d->last_gatt = wall;
        if (m->session[0]) put(d->session, sizeof(d->session), m->session);
        /* The list belongs to the session that wrote it: a session that
         * names none (sloth-va lists them only when it found no
         * supported service) clears the last one. */
        put(d->services, sizeof(d->services), m->services);
    } else {
        d->last_readout = wall;
    }
    if (m->nvals > 0) { d->readings++; d->vals_gatt = m->gatt; }
    for (int i = 0; i < m->nvals; i++) {
        int at = -1;
        for (int j = 0; j < d->nvals; j++)
            if (!strcmp(d->vals[j].name, m->vals[i].name)) at = j;
        if (at < 0 && d->nvals < VICTRON_MAX_VALS) at = d->nvals++;
        if (at >= 0) d->vals[at] = m->vals[i];
    }
}

int victron_feed_line(const char *line, size_t n, time_t wall) {
    victron_msg_t m;
    int why = VICTRON_REJ_MALFORMED;
    int r = victron_line_parse(line, n, &m, &why);
    size_t b = 0;
    while (b < n && (line[b] == ' ' || line[b] == '\t' || line[b] == '\r')) b++;
    pthread_mutex_lock(&g_mu);
    if (b < n) g.lines++;
    if (r < 0) {
        g.bad++;
        if (why >= 0 && why < VICTRON_REJ_COUNT) g.rej[why]++;
    } else if (r == 1) {
        g.records++;
        g.bad_values += m.bad_values;
        g.other_keys += m.other_keys;
        if (wall > g.last_rec) g.last_rec = wall;
        victron_device_t *d = NULL;
        for (int i = 0; i < g.ndev; i++)
            if (!strcmp(g.dev[i].mac, m.mac)) d = &g.dev[i];
        if (!d && g.ndev < VICTRON_MAX_DEVICES) {
            d = &g.dev[g.ndev++];
            memset(d, 0, sizeof(*d));
            put(d->mac, sizeof(d->mac), m.mac);
            d->first_seen = wall;
        }
        if (d) merge(d, &m, wall);
        else   g.table_full++;
    }
    pthread_mutex_unlock(&g_mu);
    return r;
}

void victron_note_read(time_t wall, uint64_t bytes, int rotated, int truncated) {
    pthread_mutex_lock(&g_mu);
    g.ever_read = 1;
    g.missing = 0;
    g.err[0] = '\0';
    g.last_read = wall;
    g.bytes += bytes;
    if (rotated) g.rotations++;
    if (truncated) g.truncations++;
    pthread_mutex_unlock(&g_mu);
}

void victron_note_missing(void) {
    pthread_mutex_lock(&g_mu);
    g.missing = 1;
    g.err[0] = '\0';
    pthread_mutex_unlock(&g_mu);
}

void victron_note_read_error(const char *err) {
    pthread_mutex_lock(&g_mu);
    g.read_errors++;
    g.missing = 0;
    snprintf(g.err, sizeof(g.err), "%s", err ? err : "error");
    pthread_mutex_unlock(&g_mu);
}

void victron_note_bad_line(void) {
    pthread_mutex_lock(&g_mu);
    g.lines++;
    g.bad++;
    g.rej[VICTRON_REJ_OVERSIZE]++;
    pthread_mutex_unlock(&g_mu);
}

void victron_health_poll(sloth_state_t *s, time_t wall) {
    if (!s) return;
    (void)wall;
    victron_health_t *h = &s->victron;
    memset(h, 0, sizeof(*h));
    pthread_mutex_lock(&g_mu);
    h->configured = g.configured;
    h->missing = g.missing;
    snprintf(h->src, sizeof(h->src), "%s", g.label);
    snprintf(h->err, sizeof(h->err), "%s", g.err);
    h->last_read = g.last_read;
    h->last_rec = g.last_rec;
    h->bytes = g.bytes;
    h->lines = g.lines;
    h->records = g.records;
    h->bad_lines = g.bad;
    for (int i = 0; i < VICTRON_REJ_COUNT; i++) h->rej[i] = g.rej[i];
    h->bad_values = g.bad_values;
    h->other_keys = g.other_keys;
    h->table_full = g.table_full;
    h->truncations = g.truncations;
    h->rotations = g.rotations;
    h->read_errors = g.read_errors;
    if (!g.configured)                  h->state = VICTRON_NONE;
    else if (g.err[0])                  h->state = VICTRON_ERROR;
    else if (!g.ever_read || g.missing) h->state = VICTRON_WAITING;
    else                                h->state = VICTRON_LIVE;
    int n = g.ndev;
    memcpy(g_snap, g.dev, sizeof(g.dev[0]) * (size_t)n);
    pthread_mutex_unlock(&g_mu);
    h->devices = n;
    s->victron_rows = g_snap;
    s->victron_count = n;
}

void victron_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(&g, 0, sizeof(g));
    pthread_mutex_unlock(&g_mu);
}

const char *victron_state_name(int state) {
    switch (state) {
    case VICTRON_WAITING: return "waiting";
    case VICTRON_LIVE:    return "live";
    case VICTRON_ERROR:   return "error";
    default:              return "none";
    }
}
