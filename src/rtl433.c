#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "rtl433.h"
#include "sensor_health.h"
#include "stab.h"

/* Contract in rtl433.h. Pure except the table at the bottom, one
 * mutex-guarded struct the reader feeds and the main thread polls. */

/* ── JSON cursor ──────────────────────────────────────────────────
 * The same locale-free walk src/adsb.c and src/gps.c use (strtod
 * honours LC_NUMERIC, and the TUI calls setlocale), kept separate for
 * the reason the comment on adsb.c's copy gives: neither parser's
 * limits are the other's. An aircraft.json is one document of many
 * objects and a gpsd report is a stream of them; this is one object
 * per line, bounded at RTL433_MAX_LINE, with its own key and value
 * caps. Folding the three into one reader would change two shipped
 * parsers' limits and is a refactor, not this slice. */

typedef struct { const char *p, *e; } jcur_t;

static void jws(jcur_t *c) {
    while (c->p < c->e && (*c->p == ' ' || *c->p == '\t' ||
                           *c->p == '\r' || *c->p == '\n'))
        c->p++;
}

/* A string into out (truncated; an escape kept as its second byte -
 * output_file.c escapes only `"`, `\`, CR, LF and TAB, so there is no
 * \u to decode and the second byte is the character). *full is 0 when
 * it did not fit. */
static int jstr(jcur_t *c, char *out, size_t outsz, int *full) {
    size_t k = 0;
    int fit = 1;
    if (c->p >= c->e || *c->p != '"') return -1;
    c->p++;
    while (c->p < c->e && *c->p != '"') {
        char ch = *c->p++;
        if (ch == '\\') {
            if (c->p >= c->e) return -1;
            ch = *c->p++;
        }
        if (out && k + 1 < outsz) out[k++] = ch;
        else fit = 0;
    }
    if (c->p >= c->e) return -1;
    c->p++;
    if (out && outsz) out[k] = '\0';
    if (full) *full = fit;
    return 0;
}

/* RFC 8259 number, locale-free. */
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

/* Skip one value; containers by depth, strings honoured. A decoder may
 * put an object or an array under a key (output_file.c prints an
 * embedded JSON object verbatim when a string value is one), so a
 * nested value is a value to step over, not a malformed line. */
static int jskip(jcur_t *c) {
    jws(c);
    if (c->p >= c->e) return -1;
    char ch = *c->p;
    if (ch == '"') return jstr(c, NULL, 0, NULL);
    if (ch == '{' || ch == '[') {
        int depth = 0;
        while (c->p < c->e) {
            ch = *c->p;
            if (ch == '"') { if (jstr(c, NULL, 0, NULL) != 0) return -1; continue; }
            if (ch == '{' || ch == '[') { if (++depth > 16) return -1; }
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

/* ── Field validation ──────────────────────────────────────────── */

static int finite_in(double d, double lo, double hi) {
    return isfinite(d) && d >= lo && d <= hi;
}

/* Printable ASCII only, and nothing a JSON writer would have had to
 * escape. output_file.c escapes `"`, `\`, CR, LF and TAB and leaves
 * every other control byte raw, so a field that reaches a terminal or
 * another JSON document has to be checked here rather than trusted for
 * having been quoted (the CWE-150 lesson of #77). 1 when `s` is wholly
 * printable and at most `max` bytes. */
static int clean_str(const char *s, size_t max) {
    size_t n = 0;
    for (; s[n]; n++) {
        unsigned char c = (unsigned char)s[n];
        if (n >= max) return 0;
        if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') return 0;
    }
    return n > 0;
}

/* A validated value into its field; the caller checked that it fits. */
static void put(char *dst, size_t dstsz, const char *v) {
    size_t l = strlen(v);
    if (l >= dstsz) l = dstsz - 1;
    memcpy(dst, v, l);
    dst[l] = '\0';
}

/* An `id` or `channel` given as a JSON number: an integer, as written.
 * DATA_FORMAT.md allows either a number or (rarely) a string for both,
 * and the table's key is text, so a number becomes its own decimal
 * spelling - never a rounded one. 0 on success. */
static int whole_to_str(double d, char *dst, size_t dstsz) {
    if (!isfinite(d) || d != floor(d) || fabs(d) > 1e15) return -1;
    int n = snprintf(dst, dstsz, "%lld", (long long)d);
    return (n > 0 && (size_t)n < dstsz) ? 0 : -1;
}

/* DATA_FORMAT.md names exactly these three for `mic`; anything else is
 * not a message integrity check sloth knows how to report. */
static int mic_ok(const char *s) {
    return !strcmp(s, "CRC") || !strcmp(s, "CHECKSUM") || !strcmp(s, "PARITY");
}

/* r_api.c writes exactly these three for `mod`. */
static int mod_ok(const char *s) {
    return !strcmp(s, "ASK") || !strcmp(s, "FSK") || !strcmp(s, "LoRa");
}

/* Keys recognised and deliberately not stored (rtl433.h). `time` is on
 * every line `-M time` is asked for, so counting it as an unknown key
 * would bury the signal the counter exists to carry. */
static int skipped_key(const char *k) {
    return !strcmp(k, "time");
}

/* ── One line ──────────────────────────────────────────────────── */

#define RTL433_KEY_MAX 24   /* a longer key is on no list anyway */
#define RTL433_VAL_MAX 40   /* a longer string value fits no field here */

static int reject(int *why, int code) {
    if (why) *why = code;
    return -1;
}

int rtl433_line_parse(const char *line, size_t n, rtl433_msg_t *out, int *why) {
    if (!line || !out) return reject(why, RTL433_REJ_MALFORMED);
    memset(out, 0, sizeof(*out));
    out->protocol = -1;
    if (n && line[n - 1] == '\r') n--;
    size_t b = 0;
    while (b < n && (line[b] == ' ' || line[b] == '\t' || line[b] == '\r')) b++;
    if (b == n) return 0;                            /* blank */
    if (n > RTL433_MAX_LINE) return reject(why, RTL433_REJ_OVERSIZE);

    jcur_t c = { line, line + n };
    jws(&c);
    if (c.p >= c.e || *c.p != '{') return reject(why, RTL433_REJ_NOT_OBJECT);
    c.p++;
    jws(&c);
    int have_model = 0, have_id = 0;
    if (c.p < c.e && *c.p == '}') { c.p++; goto done; }
    for (;;) {
        char key[RTL433_KEY_MAX];
        int full;
        jws(&c);
        if (jstr(&c, key, sizeof(key), &full) != 0)
            return reject(why, RTL433_REJ_MALFORMED);
        if (!full) key[0] = '\0';   /* a long key is no key of ours */
        jws(&c);
        if (c.p >= c.e || *c.p != ':') return reject(why, RTL433_REJ_MALFORMED);
        c.p++;
        jws(&c);
        if (c.p >= c.e) return reject(why, RTL433_REJ_MALFORMED);
        int known = 1;
        if (*c.p == '"') {
            char v[RTL433_VAL_MAX];
            if (jstr(&c, v, sizeof(v), &full) != 0)
                return reject(why, RTL433_REJ_MALFORMED);
            if (!full) v[0] = '\0';
            if (!strcmp(key, "model")) {
                if (clean_str(v, RTL433_MODEL_MAX)) {
                    put(out->model, sizeof(out->model), v);
                    have_model = 1;
                } else out->bad_values++;
            } else if (!strcmp(key, "id")) {
                if (clean_str(v, RTL433_ID_MAX)) {
                    put(out->id, sizeof(out->id), v);
                    have_id = 1;
                } else out->bad_values++;
            } else if (!strcmp(key, "type")) {
                if (clean_str(v, RTL433_TYPE_MAX)) put(out->type, sizeof(out->type), v);
                else out->bad_values++;
            } else if (!strcmp(key, "subtype")) {
                if (clean_str(v, RTL433_TYPE_MAX)) put(out->subtype, sizeof(out->subtype), v);
                else out->bad_values++;
            } else if (!strcmp(key, "channel")) {
                if (clean_str(v, RTL433_ID_MAX)) put(out->channel, sizeof(out->channel), v);
                else out->bad_values++;
            } else if (!strcmp(key, "mic")) {
                if (mic_ok(v)) put(out->mic, sizeof(out->mic), v);
                else out->bad_values++;
            } else if (!strcmp(key, "mod")) {
                if (mod_ok(v)) put(out->mod, sizeof(out->mod), v);
                else out->bad_values++;
            } else if (!skipped_key(key)) {
                known = 0;
            }
        } else if (*c.p == '-' || (*c.p >= '0' && *c.p <= '9')) {
            double d;
            if (jnum(&c, &d) != 0) return reject(why, RTL433_REJ_MALFORMED);
            if (!strcmp(key, "id")) {
                if (whole_to_str(d, out->id, sizeof(out->id)) == 0) have_id = 1;
                else out->bad_values++;
            } else if (!strcmp(key, "channel")) {
                if (whole_to_str(d, out->channel, sizeof(out->channel)) != 0)
                    out->bad_values++;
            } else if (!strcmp(key, "protocol")) {
                if (finite_in(d, 0, 65535) && d == floor(d)) out->protocol = (int)d;
                else out->bad_values++;
            } else if (!strcmp(key, "freq") || !strcmp(key, "freq1")) {
                /* One field for both: r_api.c's ASK / LoRa branch writes
                 * `freq` and its FSK branch `freq1`, and the chain is
                 * exclusive. Up to 6 GHz covers every SoapySDR front end
                 * rtl_433 drives, not only the 433 MHz ISM band. */
                if (finite_in(d, 0.001, 6000)) { out->freq_mhz = d; out->has_freq = 1; }
                else out->bad_values++;
            } else if (!strcmp(key, "freq2")) {
                if (finite_in(d, 0.001, 6000)) { out->freq2_mhz = d; out->has_freq2 = 1; }
                else out->bad_values++;
            } else if (!strcmp(key, "rssi")) {
                if (finite_in(d, -200, 200)) { out->rssi_db = d; out->has_rssi = 1; }
                else out->bad_values++;
            } else if (!strcmp(key, "snr")) {
                if (finite_in(d, -200, 200)) { out->snr_db = d; out->has_snr = 1; }
                else out->bad_values++;
            } else if (!strcmp(key, "noise")) {
                if (finite_in(d, -200, 200)) { out->noise_db = d; out->has_noise = 1; }
                else out->bad_values++;
            } else if (!strcmp(key, "battery_ok")) {
                if (finite_in(d, 0, 1)) { out->battery_ok = d; out->has_battery = 1; }
                else out->bad_values++;
            } else if (!strcmp(key, "temperature_C") ||
                       !strcmp(key, "temperature_F")) {
                /* Absolute zero to a figure no ISM sensor reaches: the
                 * bound refuses a value that cannot be a reading, and
                 * the unit is the key's, never converted. */
                if (finite_in(d, -273.15, 1000)) {
                    out->temp = d;
                    out->temp_unit = key[12] == 'C' ? RTL433_TEMP_C : RTL433_TEMP_F;
                    out->has_temp = 1;
                } else out->bad_values++;
            } else if (!strcmp(key, "humidity")) {
                if (finite_in(d, 0, 100)) { out->humidity = d; out->has_humidity = 1; }
                else out->bad_values++;
            } else if (!strcmp(key, "pressure_kPa") || !strcmp(key, "pressure_hPa") ||
                       !strcmp(key, "pressure_psi") || !strcmp(key, "pressure_PSI")) {
                /* DATA_FORMAT.md documents hPa and psi; the TPMS decoders
                 * write `pressure_kPa` (src/devices/tpms_citroen.c,
                 * tpms_renault.c) and `pressure_PSI` (tpms_toyota.c),
                 * both of which follow its `<Type>_<Unit>` rule. All
                 * four are kept, each in its own unit. */
                if (finite_in(d, 0, 1000000)) {
                    out->pressure = d;
                    out->pres_unit = key[9] == 'k' ? RTL433_PRES_KPA
                                   : key[9] == 'h' ? RTL433_PRES_HPA
                                                   : RTL433_PRES_PSI;
                    out->has_pressure = 1;
                } else out->bad_values++;
            } else if (!skipped_key(key)) {
                known = 0;
            }
        } else {
            /* null, a boolean, or a nested array / object: stepped over
             * by depth. A key sloth stores that arrives as one of those
             * is the key's value being a shape this parser has no field
             * for, so it counts as an unknown key rather than a fault. */
            if (jskip(&c) != 0) return reject(why, RTL433_REJ_MALFORMED);
            if (!skipped_key(key)) known = 0;
        }
        if (!known && out->other_keys < 0xffffu) out->other_keys++;
        jws(&c);
        if (c.p >= c.e) return reject(why, RTL433_REJ_MALFORMED);
        if (*c.p == ',') { c.p++; continue; }
        if (*c.p == '}') { c.p++; break; }
        return reject(why, RTL433_REJ_MALFORMED);
    }
done:
    jws(&c);
    /* Trailing bytes after the object: not one object per line. */
    if (c.p != c.e) return reject(why, RTL433_REJ_NOT_OBJECT);
    if (!have_model) return reject(why, RTL433_REJ_NO_MODEL);
    if (!have_id)    return reject(why, RTL433_REJ_NO_ID);
    return 1;
}

const char *rtl433_reject_name(int why) {
    switch (why) {
    case RTL433_REJ_OVERSIZE:   return "oversize";
    case RTL433_REJ_NOT_OBJECT: return "not_object";
    case RTL433_REJ_MALFORMED:  return "malformed";
    case RTL433_REJ_NO_MODEL:   return "no_model";
    case RTL433_REJ_NO_ID:      return "no_id";
    default:                    return "";
    }
}

const char *rtl433_temp_unit_name(int unit) {
    switch (unit) {
    case RTL433_TEMP_C: return "C";
    case RTL433_TEMP_F: return "F";
    default:            return "";
    }
}

const char *rtl433_pres_unit_name(int unit) {
    switch (unit) {
    case RTL433_PRES_KPA: return "kPa";
    case RTL433_PRES_HPA: return "hPa";
    case RTL433_PRES_PSI: return "psi";
    default:              return "";
    }
}

/* ── The --rtl433 SPEC ─────────────────────────────────────────── */

int rtl433_spec_parse(const char *spec, char *path, size_t pathsz,
                      char *err, size_t errsz) {
    const char *p = spec;
    if (!spec || !*spec) {
        if (err && errsz) snprintf(err, errsz, "empty SPEC");
        return -1;
    }
    if (strncmp(spec, "file://", 7) == 0) {
        p = spec + 7;
        if (*p != '/') {
            if (err && errsz)
                snprintf(err, errsz, "file:// takes a local absolute path "
                         "(file:///path), not a host");
            return -1;
        }
    } else if (strstr(spec, "://")) {
        if (err && errsz)
            snprintf(err, errsz, "unsupported scheme: want an absolute path "
                     "or file:///path to rtl_433's JSON event log (-F json)");
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

/* ── The bands and the signature ───────────────────────────────── */

int rtl433_rssi_band(double rssi_db) {
    return (int)floor(rssi_db / (double)RTL433_RSSI_STEP_DB);
}

int rtl433_freq_band(double freq_mhz) {
    return (int)floor(freq_mhz);
}

static uint64_t mix64(uint64_t h, long long v) {
    h ^= (uint64_t)v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h * 0x100000001b3ULL;
}

static uint64_t mix_str(uint64_t h, const char *s) {
    for (; *s; s++) h = mix64(h, (unsigned char)*s);
    return mix64(h, 0);
}

/* A value and its presence, the value as its band. The absent case gets
 * a sentinel rather than 0, so "no temperature" and "0 degrees" are not
 * the same signature. */
static uint64_t mix_band(uint64_t h, int has, long long band) {
    h = mix64(h, has);
    return mix64(h, has ? band : -1000000);
}

static long long round_ll(double d) {
    return (long long)(d < 0 ? d - 0.5 : d + 0.5);
}

uint64_t rtl433_device_sig(const rtl433_device_t *d) {
    uint64_t h = 0xcbf29ce484222325ULL;
    if (!d) return h;
    h = mix_str(h, d->model);
    h = mix_str(h, d->id);
    h = mix64(h, (long long)d->first_seen);
    h = mix_str(h, d->type);
    h = mix_str(h, d->subtype);
    h = mix_str(h, d->channel);
    h = mix_str(h, d->mic);
    h = mix_str(h, d->mod);
    h = mix64(h, d->protocol);
    h = mix_band(h, d->has_rssi, rtl433_rssi_band(d->rssi_db));
    h = mix_band(h, d->has_freq, rtl433_freq_band(d->freq_mhz));
    h = mix64(h, d->has_freq2);        /* present or not, never its band */
    h = mix64(h, d->has_snr);
    h = mix64(h, d->has_noise);
    h = mix_band(h, d->has_battery, round_ll(d->battery_ok * 10.0));
    h = mix64(h, d->temp_unit);
    h = mix_band(h, d->has_temp, round_ll(d->temp));
    h = mix_band(h, d->has_humidity, round_ll(d->humidity));
    h = mix64(h, d->pres_unit);
    h = mix_band(h, d->has_pressure, round_ll(d->pressure));
    return h;
}

/* ── The table ─────────────────────────────────────────────────── */

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

typedef struct { const char *model, *id; } rtl433_key_t;

static int dev_key_eq(const void *row, const void *key) {
    const rtl433_device_t *d = (const rtl433_device_t *)row;
    const rtl433_key_t    *k = (const rtl433_key_t *)key;
    return strcmp(d->model, k->model) == 0 && strcmp(d->id, k->id) == 0;
}

/* STAB_OLDEST: a (model, id) pair is whatever is on the air, so a spray
 * of invented ones churns the table and is tallied, and can never make
 * sloth allocate or go deaf to a new device for the rest of the run. */
STAB_DECL(g_devs, rtl433_device_t, RTL433_MAX_DEVICES, last_seen,
          STAB_OLDEST, SH_EVICT_RTL433, NULL, dev_key_eq);

static struct {
    int      configured;
    char     label[48];
    char     err[96];
    int      missing;
    int      ever_read;
    time_t   last_read, last_msg;
    uint64_t bytes, lines, msgs, bad, bad_values, other_keys, evicted;
    uint64_t rej[RTL433_REJ_COUNT];
    uint64_t truncations, rotations, read_errors;
} g;

/* The poll's copy, which the sloth_state_t pointer names. Main thread
 * only. */
static rtl433_device_t g_snap[RTL433_MAX_DEVICES];

void rtl433_set_source(const char *label) {
    pthread_mutex_lock(&g_mu);
    g.configured = 1;
    snprintf(g.label, sizeof(g.label), "%s", label ? label : "");
    pthread_mutex_unlock(&g_mu);
}

/* Caller holds g_mu. Sticky: a value is replaced only by a line that
 * carries one. */
static void merge(rtl433_device_t *d, const rtl433_msg_t *m, time_t wall) {
    d->msgs++;
    d->last_seen = wall;
    d->other_keys += m->other_keys;
    if (m->type[0])    put(d->type, sizeof(d->type), m->type);
    if (m->subtype[0]) put(d->subtype, sizeof(d->subtype), m->subtype);
    if (m->channel[0]) put(d->channel, sizeof(d->channel), m->channel);
    if (m->mic[0])     put(d->mic, sizeof(d->mic), m->mic);
    if (m->mod[0])     put(d->mod, sizeof(d->mod), m->mod);
    if (m->protocol >= 0) d->protocol = m->protocol;
    if (m->has_freq)   { d->freq_mhz = m->freq_mhz;   d->has_freq = 1; }
    if (m->has_freq2)  { d->freq2_mhz = m->freq2_mhz; d->has_freq2 = 1; }
    if (m->has_rssi)   { d->rssi_db = m->rssi_db;     d->has_rssi = 1; }
    if (m->has_snr)    { d->snr_db = m->snr_db;       d->has_snr = 1; }
    if (m->has_noise)  { d->noise_db = m->noise_db;   d->has_noise = 1; }
    if (m->has_battery) { d->battery_ok = m->battery_ok; d->has_battery = 1; }
    if (m->has_temp) {
        d->temp = m->temp; d->temp_unit = m->temp_unit; d->has_temp = 1;
    }
    if (m->has_humidity) { d->humidity = m->humidity; d->has_humidity = 1; }
    if (m->has_pressure) {
        d->pressure = m->pressure; d->pres_unit = m->pres_unit;
        d->has_pressure = 1;
    }
}

void rtl433_feed_msg(const rtl433_msg_t *m, time_t wall) {
    if (!m || !m->model[0] || !m->id[0]) return;
    rtl433_key_t k = { m->model, m->id };
    pthread_mutex_lock(&g_mu);
    g.msgs++;
    g.bad_values += m->bad_values;
    g.other_keys += m->other_keys;
    if (wall > g.last_msg) g.last_msg = wall;
    int created;
    int was = stab_count(&g_devs);
    rtl433_device_t *d = stab_get(&g_devs, &k, wall, &created);
    if (d) {
        if (created) {
            /* The table was already full, so this row displaced one:
             * stab_get() has tallied it under SH_EVICT_RTL433 and the
             * count did not grow. Mirrored here for sensor_health,
             * which reports per source, not per process. */
            if (was == RTL433_MAX_DEVICES) g.evicted++;
            put(d->model, sizeof(d->model), m->model);
            put(d->id, sizeof(d->id), m->id);
            d->first_seen = wall;
            d->protocol = -1;
        }
        merge(d, m, wall);
    }
    pthread_mutex_unlock(&g_mu);
}

int rtl433_feed_line(const char *line, size_t n, time_t wall) {
    rtl433_msg_t m;
    int why = RTL433_REJ_MALFORMED;
    int r = rtl433_line_parse(line, n, &m, &why);
    size_t b = 0;
    while (b < n && (line[b] == ' ' || line[b] == '\t' || line[b] == '\r')) b++;
    pthread_mutex_lock(&g_mu);
    if (b < n) g.lines++;
    if (r < 0) {
        g.bad++;
        if (why >= 0 && why < RTL433_REJ_COUNT) g.rej[why]++;
        /* A refused line's own tallies still count: the operator wants
         * to know the decoder is writing fields sloth does not keep
         * whether or not that line could be keyed. */
        g.bad_values += m.bad_values;
        g.other_keys += m.other_keys;
    }
    pthread_mutex_unlock(&g_mu);
    if (r == 1) rtl433_feed_msg(&m, wall);
    return r;
}

void rtl433_note_read(time_t wall, uint64_t bytes, int rotated, int truncated) {
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

void rtl433_note_missing(void) {
    pthread_mutex_lock(&g_mu);
    g.missing = 1;
    g.err[0] = '\0';
    pthread_mutex_unlock(&g_mu);
}

void rtl433_note_read_error(const char *err) {
    pthread_mutex_lock(&g_mu);
    g.read_errors++;
    g.missing = 0;
    snprintf(g.err, sizeof(g.err), "%s", err ? err : "error");
    pthread_mutex_unlock(&g_mu);
}

void rtl433_note_bad_line(void) {
    pthread_mutex_lock(&g_mu);
    g.lines++;
    g.bad++;
    g.rej[RTL433_REJ_OVERSIZE]++;
    pthread_mutex_unlock(&g_mu);
}

void rtl433_health_poll(sloth_state_t *s, time_t wall) {
    if (!s) return;
    (void)wall;
    rtl433_health_t *h = &s->rtl433;
    memset(h, 0, sizeof(*h));
    int n;
    pthread_mutex_lock(&g_mu);
    h->configured = g.configured;
    h->missing = g.missing;
    snprintf(h->src, sizeof(h->src), "%s", g.label);
    snprintf(h->err, sizeof(h->err), "%s", g.err);
    h->last_read = g.last_read;
    h->last_msg = g.last_msg;
    h->bytes = g.bytes;
    h->lines = g.lines;
    h->msgs = g.msgs;
    h->bad_lines = g.bad;
    for (int i = 0; i < RTL433_REJ_COUNT; i++) h->rej[i] = g.rej[i];
    h->bad_values = g.bad_values;
    h->other_keys = g.other_keys;
    h->evicted = g.evicted;
    h->truncations = g.truncations;
    h->rotations = g.rotations;
    h->read_errors = g.read_errors;
    if (!g.configured)                  h->state = RTL433_NONE;
    else if (g.err[0])                  h->state = RTL433_ERROR;
    else if (!g.ever_read || g.missing) h->state = RTL433_WAITING;
    else                                h->state = RTL433_LIVE;
    n = stab_snapshot(&g_devs, g_snap, RTL433_MAX_DEVICES);
    pthread_mutex_unlock(&g_mu);
    h->devices = n;
    s->rtl433_rows = g_snap;
    s->rtl433_count = n;
}

void rtl433_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(&g, 0, sizeof(g));
    stab_clear(&g_devs);
    pthread_mutex_unlock(&g_mu);
}

const char *rtl433_state_name(int state) {
    switch (state) {
    case RTL433_WAITING: return "waiting";
    case RTL433_LIVE:    return "live";
    case RTL433_ERROR:   return "error";
    default:             return "none";
    }
}
