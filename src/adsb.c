#include <arpa/inet.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "adsb.h"

/* Contract in adsb.h. Pure except the table at the bottom, one
 * mutex-guarded struct the reader feeds and the main thread polls. */

/* ── JSON cursor ──────────────────────────────────────────────────
 * The same locale-free walk src/gps.c uses for gpsd's objects (strtod
 * honours LC_NUMERIC, and the TUI calls setlocale), kept separate so
 * neither parser's limits are the other's: an aircraft.json is one
 * document of many objects, not one line. */

typedef struct { const char *p, *e; } jcur_t;

static void jws(jcur_t *c) {
    while (c->p < c->e && (*c->p == ' ' || *c->p == '\t' ||
                           *c->p == '\r' || *c->p == '\n'))
        c->p++;
}

/* A string into out (truncated; an escape kept as its second byte: the
 * values read here are ASCII). *full is 0 when it did not fit. */
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
        } else if ((unsigned char)ch < 0x20) {
            return -1;
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

/* Skip one value; containers by depth, strings honoured. */
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
            if (ch == '{' || ch == '[') { if (++depth > 32) return -1; }
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

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int adsb_hex_parse(const char *s, uint32_t *icao, int *non_icao) {
    if (!s) return -1;
    int ni = 0;
    if (*s == '~') { ni = 1; s++; }
    uint32_t v = 0;
    for (int i = 0; i < 6; i++) {
        int h = hexv(s[i]);
        if (h < 0) return -1;
        v = (v << 4) | (uint32_t)h;
    }
    if (s[6] != '\0') return -1;
    if (icao) *icao = v;
    if (non_icao) *non_icao = ni;
    return 0;
}

static const char *const k_emerg[] = {
    "none", "general", "lifeguard", "minfuel", "nordo", "unlawful",
    "downed", "reserved"
};

const char *adsb_emergency_name(int e) {
    return (e >= 0 && e < (int)(sizeof(k_emerg) / sizeof(k_emerg[0])))
           ? k_emerg[e] : "";
}

static int emerg_parse(const char *s) {
    for (int i = 0; i < (int)(sizeof(k_emerg) / sizeof(k_emerg[0])); i++)
        if (strcmp(s, k_emerg[i]) == 0) return i;
    return ADSB_EMERG_ABSENT;
}

static int squawk_ok(const char *s) {
    for (int i = 0; i < 4; i++) if (s[i] < '0' || s[i] > '7') return 0;
    return s[4] == '\0';
}

static int category_ok(const char *s) {
    return s[0] >= 'A' && s[0] <= 'D' && s[1] >= '0' && s[1] <= '7' && s[2] == '\0';
}

/* type: lower-case letters and '_' (adsb_icao, tisb_trackfile, ...). */
static int type_ok(const char *s) {
    if (!*s) return 0;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || *s == '_')) return 0;
    return 1;
}

/* flight: printable ASCII, trailing spaces trimmed. readsb's charset is
 * A-Z, 0-9 and space, but a registration from a database could carry a
 * '-'; a quote or backslash is refused (kv_str escapes, but nothing a
 * decoder writes needs one). All spaces is absent. */
static int flight_fix(char *s) {
    size_t n = strlen(s);
    while (n > 0 && s[n - 1] == ' ') s[--n] = '\0';
    if (n == 0) return 0;
    for (size_t i = 0; i < n; i++)
        if (s[i] < 0x20 || s[i] > 0x7e || s[i] == '"' || s[i] == '\\') return 0;
    return 1;
}

static int finite_in(double d, double lo, double hi) {
    return isfinite(d) && d >= lo && d <= hi;
}

/* A validated value into its field; the caller checked it fits. */
static void put(char *dst, size_t dstsz, const char *v) {
    size_t l = strlen(v);
    if (l >= dstsz) l = dstsz - 1;
    memcpy(dst, v, l);
    dst[l] = '\0';
}

static int32_t round_i32(double d) {
    return (int32_t)(d < 0 ? d - 0.5 : d + 0.5);
}

/* ── One aircraft object ───────────────────────────────────────── *
 * 1 kept, 0 refused (no or bad hex), -1 malformed JSON. */
static int parse_aircraft(jcur_t *c, adsb_aircraft_t *a) {
    memset(a, 0, sizeof(*a));
    a->emergency = ADSB_EMERG_ABSENT;
    int have_hex = 0, have_lat = 0, have_lon = 0;
    double lat = 0, lon = 0;
    if (c->p >= c->e || *c->p != '{') return -1;
    c->p++;
    jws(c);
    if (c->p < c->e && *c->p == '}') { c->p++; return 0; }
    for (;;) {
        char key[24];
        int full;
        jws(c);
        if (jstr(c, key, sizeof(key), &full) != 0) return -1;
        if (!full) key[0] = '\0';   /* a long key is no key of ours */
        jws(c);
        if (c->p >= c->e || *c->p != ':') return -1;
        c->p++;
        jws(c);
        if (c->p >= c->e) return -1;
        if (*c->p == '"') {
            char v[24];
            if (jstr(c, v, sizeof(v), &full) != 0) return -1;
            if (!full) v[0] = '\0';
            if (strcmp(key, "hex") == 0) {
                int ni;
                if (adsb_hex_parse(v, &a->icao, &ni) == 0) {
                    a->non_icao = (uint8_t)ni;
                    have_hex = 1;
                }
            } else if (strcmp(key, "type") == 0) {
                if (strlen(v) < sizeof(a->type) && type_ok(v))
                    put(a->type, sizeof(a->type), v);
            } else if (strcmp(key, "flight") == 0) {
                if (strlen(v) <= 8 && flight_fix(v))
                    put(a->flight, sizeof(a->flight), v);
            } else if (strcmp(key, "squawk") == 0) {
                if (squawk_ok(v)) put(a->squawk, sizeof(a->squawk), v);
            } else if (strcmp(key, "category") == 0) {
                if (category_ok(v)) put(a->category, sizeof(a->category), v);
            } else if (strcmp(key, "emergency") == 0) {
                a->emergency = (int8_t)emerg_parse(v);
            } else if (strcmp(key, "alt_baro") == 0 && strcmp(v, "ground") == 0) {
                a->on_ground = 1;
                a->has_alt_baro = 0;
            }
        } else if (*c->p == '-' || (*c->p >= '0' && *c->p <= '9')) {
            double d;
            if (jnum(c, &d) != 0) return -1;
            if (strcmp(key, "alt_baro") == 0) {
                if (finite_in(d, -2000, 100000)) {
                    a->alt_baro = round_i32(d); a->has_alt_baro = 1; a->on_ground = 0;
                }
            } else if (strcmp(key, "alt_geom") == 0) {
                if (finite_in(d, -2000, 100000)) { a->alt_geom = round_i32(d); a->has_alt_geom = 1; }
            } else if (strcmp(key, "gs") == 0) {
                if (finite_in(d, 0, 4000)) { a->gs = d; a->has_gs = 1; }
            } else if (strcmp(key, "track") == 0) {
                if (finite_in(d, 0, 360)) { a->track = d; a->has_track = 1; }
            } else if (strcmp(key, "baro_rate") == 0) {
                if (finite_in(d, -60000, 60000)) { a->baro_rate = round_i32(d); a->has_baro_rate = 1; }
            } else if (strcmp(key, "geom_rate") == 0) {
                if (finite_in(d, -60000, 60000)) { a->geom_rate = round_i32(d); a->has_geom_rate = 1; }
            } else if (strcmp(key, "lat") == 0) {
                lat = d; have_lat = 1;
            } else if (strcmp(key, "lon") == 0) {
                lon = d; have_lon = 1;
            } else if (strcmp(key, "rssi") == 0) {
                if (finite_in(d, -200, 10)) { a->rssi = d; a->has_rssi = 1; }
            } else if (strcmp(key, "seen") == 0) {
                if (finite_in(d, 0, 1e6)) { a->seen = d; a->has_seen = 1; }
            } else if (strcmp(key, "seen_pos") == 0) {
                if (finite_in(d, 0, 1e6)) { a->seen_pos = d; a->has_seen_pos = 1; }
            } else if (strcmp(key, "messages") == 0) {
                if (finite_in(d, 0, 9e15)) { a->messages = (uint64_t)d; a->has_messages = 1; }
            }
        } else {
            /* null, a boolean, or a nested array / object (mlat, tisb,
             * nav_modes, acas_ra, lastPosition): skipped by depth. */
            if (jskip(c) != 0) return -1;
        }
        jws(c);
        if (c->p >= c->e) return -1;
        if (*c->p == ',') { c->p++; continue; }
        if (*c->p == '}') { c->p++; break; }
        return -1;
    }
    if (have_lat && have_lon && finite_in(lat, -90, 90) && finite_in(lon, -180, 180)) {
        a->lat = lat; a->lon = lon; a->has_pos = 1;
    }
    return have_hex ? 1 : 0;
}

static int parse_list(jcur_t *c, adsb_doc_t *out) {
    if (c->p >= c->e || *c->p != '[') return -1;
    c->p++;
    jws(c);
    if (c->p < c->e && *c->p == ']') { c->p++; return 0; }
    for (;;) {
        jws(c);
        if (c->p < c->e && *c->p == '{') {
            /* Parsed in place in the next free slot; once the list is
             * full, into a scratch row that is only counted. */
            adsb_aircraft_t scratch;
            adsb_aircraft_t *a = out->n < ADSB_MAX_AIRCRAFT ? &out->ac[out->n] : &scratch;
            int r = parse_aircraft(c, a);
            if (r < 0) return -1;
            if (r == 0) out->bad++;
            else if (out->n < ADSB_MAX_AIRCRAFT) out->n++;
            else out->overflow++;
        } else {
            if (jskip(c) != 0) return -1;
            out->bad++;
        }
        jws(c);
        if (c->p >= c->e) return -1;
        if (*c->p == ',') { c->p++; continue; }
        if (*c->p == ']') { c->p++; return 0; }
        return -1;
    }
}

int adsb_doc_parse(const char *buf, size_t n, adsb_doc_t *out) {
    if (!buf || !out || n > ADSB_MAX_DOC) return -1;
    out->has_now = out->has_messages = 0;
    out->now = 0;
    out->messages = 0;
    out->n = out->overflow = out->bad = 0;
    jcur_t c = { buf, buf + n };
    jws(&c);
    if (c.p >= c.e || *c.p != '{') return -1;
    c.p++;
    jws(&c);
    if (c.p < c.e && *c.p == '}') { c.p++; goto done; }
    for (;;) {
        char key[24];
        int full;
        jws(&c);
        if (jstr(&c, key, sizeof(key), &full) != 0) return -1;
        if (!full) key[0] = '\0';
        jws(&c);
        if (c.p >= c.e || *c.p != ':') return -1;
        c.p++;
        jws(&c);
        if (c.p >= c.e) return -1;
        if (strcmp(key, "aircraft") == 0 && *c.p == '[') {
            if (parse_list(&c, out) != 0) return -1;
        } else if (*c.p == '-' || (*c.p >= '0' && *c.p <= '9')) {
            double d;
            if (jnum(&c, &d) != 0) return -1;
            if (strcmp(key, "now") == 0 && finite_in(d, 0, 1e11)) {
                out->now = d; out->has_now = 1;
            } else if (strcmp(key, "messages") == 0 && finite_in(d, 0, 9e15)) {
                out->messages = (uint64_t)d; out->has_messages = 1;
            }
        } else {
            if (jskip(&c) != 0) return -1;
        }
        jws(&c);
        if (c.p >= c.e) return -1;
        if (*c.p == ',') { c.p++; continue; }
        if (*c.p == '}') { c.p++; break; }
        return -1;
    }
done:
    jws(&c);
    return c.p == c.e ? 0 : -1;
}

/* ── The --adsb SPEC ───────────────────────────────────────────── */

static int set_err(char *err, size_t errsz, const char *msg) {
    if (err && errsz) snprintf(err, errsz, "%s", msg);
    return -1;
}

/* 1..65535 in decimal, nothing else. */
static int port_parse(const char *s, int *out) {
    long v = 0;
    if (!*s) return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10 + (*s - '0');
        if (v > 65535) return -1;
    }
    if (v < 1) return -1;
    *out = (int)v;
    return 0;
}

/* sbs://[HOST[:PORT]]: HOST numeric, IPv6 in brackets, loopback only. */
static int sbs_spec_parse(const char *h, adsb_spec_t *out, char *err, size_t errsz) {
    static const char bad[] = "sbs:// wants a numeric loopback HOST "
                              "(127.0.0.1, [::1]) and PORT 1..65535";
    char host[64];
    const char *portp = NULL;
    int v6 = 0;
    if (*h == '\0' || *h == ':') {
        snprintf(host, sizeof(host), "127.0.0.1");
        if (*h == ':') portp = h + 1;
    } else if (*h == '[') {
        const char *rb = strchr(h, ']');
        if (!rb || rb == h + 1 || (size_t)(rb - h - 1) >= sizeof(host))
            return set_err(err, errsz, bad);
        memcpy(host, h + 1, (size_t)(rb - h - 1));
        host[rb - h - 1] = '\0';
        if (rb[1] == ':') portp = rb + 2;
        else if (rb[1] != '\0') return set_err(err, errsz, bad);
        v6 = 1;
    } else {
        const char *colon = strchr(h, ':');
        size_t hl = colon ? (size_t)(colon - h) : strlen(h);
        if (hl == 0 || hl >= sizeof(host)) return set_err(err, errsz, bad);
        memcpy(host, h, hl);
        host[hl] = '\0';
        if (colon) portp = colon + 1;
    }
    int port = ADSB_SBS_DEFAULT_PORT;
    if (portp && port_parse(portp, &port) != 0) return set_err(err, errsz, bad);
    int loop;
    if (v6) {
        struct in6_addr a6;
        if (inet_pton(AF_INET6, host, &a6) != 1) return set_err(err, errsz, bad);
        loop = IN6_IS_ADDR_LOOPBACK(&a6);
    } else {
        struct in_addr a4;
        if (inet_pton(AF_INET, host, &a4) != 1) return set_err(err, errsz, bad);
        loop = (ntohl(a4.s_addr) >> 24) == 127;
    }
    if (!loop) {
        if (err && errsz)
            snprintf(err, errsz, "sbs:// reads a decoder on this host: %s is "
                     "not loopback (127.0.0.0/8, [::1])", host);
        return -1;
    }
    out->kind = ADSB_SPEC_SBS;
    snprintf(out->host, sizeof(out->host), "%s", host);
    out->port = port;
    return 0;
}

int adsb_spec_parse(const char *spec, adsb_spec_t *out,
                    char *err, size_t errsz) {
    const char *p = spec;
    if (!out) return set_err(err, errsz, "no output");
    memset(out, 0, sizeof(*out));
    if (!spec || !*spec) return set_err(err, errsz, "empty SPEC");
    if (strncmp(spec, "sbs://", 6) == 0)
        return sbs_spec_parse(spec + 6, out, err, errsz);
    if (strncmp(spec, "beast://", 8) == 0)
        return set_err(err, errsz, "beast:// input is not yet supported: give "
                       "the decoder's aircraft.json path (e.g. "
                       "/run/readsb/aircraft.json) or its SBS output "
                       "(sbs://127.0.0.1:30003)");
    if (strncmp(spec, "file://", 7) == 0) {
        p = spec + 7;
        if (*p != '/')
            return set_err(err, errsz, "file:// takes a local absolute path "
                           "(file:///path), not a host");
    } else if (strstr(spec, "://")) {
        return set_err(err, errsz, "unsupported scheme: want an absolute path "
                       "or file:///path to aircraft.json, or sbs://HOST:PORT");
    } else if (*spec != '/') {
        return set_err(err, errsz, "want an absolute path");
    }
    size_t l = strlen(p);
    if (l < 2 || p[l - 1] == '/')
        return set_err(err, errsz, "want a file, not a directory");
    if (l >= sizeof(out->path)) return set_err(err, errsz, "path too long");
    memcpy(out->path, p, l + 1);
    out->kind = ADSB_SPEC_FILE;
    return 0;
}

void adsb_spec_label(const adsb_spec_t *sp, char *out, size_t outsz) {
    if (!out || !outsz) return;
    if (!sp) { out[0] = '\0'; return; }
    if (sp->kind == ADSB_SPEC_SBS)
        snprintf(out, outsz, strchr(sp->host, ':') ? "sbs:[%s]:%d" : "sbs:%s:%d",
                 sp->host, sp->port);
    else
        snprintf(out, outsz, "file:%.200s", sp->path);
}

/* ── SBS / BaseStation lines ───────────────────────────────────── */

#define SBS_MIN_FIELDS 22
#define SBS_MAX_FIELDS 24

typedef struct { const char *p; size_t n; } sbs_field_t;

/* A whole field as a number: jnum over it, every byte consumed. 0, or
 * -1 for an empty or non-numeric field. */
static int field_num(sbs_field_t f, double *out) {
    if (f.n == 0) return -1;
    jcur_t c = { f.p, f.p + f.n };
    if (jnum(&c, out) != 0 || c.p != c.e) return -1;
    return 0;
}

/* An integer field with readsb's optional trailing 'H' (GNSS). 1 with
 * *geom set, 0 for an empty field, -1 malformed. */
static int field_alt(sbs_field_t f, double *out, int *geom) {
    *geom = 0;
    if (f.n == 0) return 0;
    if (f.p[f.n - 1] == 'H') { *geom = 1; f.n--; }
    return field_num(f, out) == 0 ? 1 : -1;
}

static int field_is(sbs_field_t f, const char *lit) {
    size_t l = strlen(lit);
    return f.n == l && memcmp(f.p, lit, l) == 0;
}

/* Exactly `n` decimal digits at p. */
static int digits(const char *p, int n, int *out) {
    int v = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return -1;
        v = v * 10 + (p[i] - '0');
    }
    *out = v;
    return 0;
}

/* Days since 1970-01-01 of a proleptic Gregorian date (Howard
 * Hinnant's days_from_civil); timegm() is not C99. */
static int64_t days_from_civil(int y, int m, int d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const int64_t yoe = y - era * 400;
    const int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* "YYYY/MM/DD" + "HH:MM:SS[.mmm]" (UTC) -> unix ms. 0 for both empty
 * (no time), 1 parsed, -1 malformed. */
static int field_time(sbs_field_t d, sbs_field_t t, int64_t *ms) {
    if (d.n == 0 && t.n == 0) return 0;
    int y = 0, mo = 0, dd = 0, h = 0, mi = 0, se = 0, frac = 0;
    if (d.n != 10 || d.p[4] != '/' || d.p[7] != '/' ||
        digits(d.p, 4, &y) || digits(d.p + 5, 2, &mo) || digits(d.p + 8, 2, &dd))
        return -1;
    if (t.n < 8 || t.p[2] != ':' || t.p[5] != ':' ||
        digits(t.p, 2, &h) || digits(t.p + 3, 2, &mi) || digits(t.p + 6, 2, &se))
        return -1;
    if (t.n > 8) {
        /* readsb writes exactly three; one to three are taken as ms. */
        int fl = (int)t.n - 9;
        if (t.p[8] != '.' || fl < 1 || fl > 3 || digits(t.p + 9, fl, &frac))
            return -1;
        for (int i = fl; i < 3; i++) frac *= 10;
    }
    if (y < 1970 || mo < 1 || mo > 12 || dd < 1 || dd > 31 ||
        h > 23 || mi > 59 || se > 60)
        return -1;
    *ms = ((days_from_civil(y, mo, dd) * 86400 + h * 3600 + mi * 60 + se) * 1000) + frac;
    return 1;
}

int adsb_sbs_parse(const char *line, size_t n, adsb_sbs_msg_t *out) {
    if (!line || !out) return -1;
    if (n > 0 && line[n - 1] == '\r') n--;
    memset(out, 0, sizeof(*out));
    adsb_aircraft_t *a = &out->ac;
    a->emergency = ADSB_EMERG_ABSENT;
    if (n == 0) return 0;                          /* readsb's heartbeat */
    if (n > ADSB_SBS_MAX_LINE) return -1;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)line[i] < 0x20 || (unsigned char)line[i] > 0x7e) return -1;

    sbs_field_t f[SBS_MAX_FIELDS] = {{ NULL, 0 }};
    int nf = 0;
    const char *p = line, *e = line + n;
    for (;;) {
        const char *c = memchr(p, ',', (size_t)(e - p));
        const char *end = c ? c : e;
        if (nf == SBS_MAX_FIELDS) return -1;
        f[nf].p = p;
        f[nf].n = (size_t)(end - p);
        nf++;
        if (!c) break;
        p = c + 1;
    }
    /* The other BaseStation records carry no aircraft state readsb
     * would send; they are not errors. */
    static const char *const others[] = { "SEL", "ID", "AIR", "STA", "CLK" };
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); i++)
        if (field_is(f[0], others[i])) return 0;
    if (!field_is(f[0], "MSG") || nf < SBS_MIN_FIELDS) return -1;
    if (f[1].n != 1 || f[1].p[0] < '1' || f[1].p[0] > '8') return -1;
    out->type = f[1].p[0] - '0';

    char tmp[16];
    int ni;
    if (f[4].n >= sizeof(tmp)) return -1;
    memcpy(tmp, f[4].p, f[4].n);
    tmp[f[4].n] = '\0';
    if (adsb_hex_parse(tmp, &a->icao, &ni) != 0) return -1;
    a->non_icao = (uint8_t)ni;

    int64_t ms = 0;
    int tr = field_time(f[6], f[7], &ms);
    if (tr < 0) return -1;
    if (tr > 0) { out->has_time = 1; out->time_ms = ms; }

    /* 10 callsign: at most 8 characters before trimming. */
    if (f[10].n > 0 && f[10].n <= 8) {
        memcpy(tmp, f[10].p, f[10].n);
        tmp[f[10].n] = '\0';
        if (flight_fix(tmp)) put(a->flight, sizeof(a->flight), tmp);
    }

    double d = 0;
    int geom = 0, r;
    /* 21 on ground: -1 is "ground", as alt_baro's string is; a
     * barometric altitude on the same line is then not kept. */
    int ground = field_is(f[21], "-1");
    if (ground) a->on_ground = 1;
    /* 11 altitude */
    if ((r = field_alt(f[11], &d, &geom)) < 0) return -1;
    if (r > 0 && finite_in(d, -2000, 100000)) {
        if (geom) { a->alt_geom = round_i32(d); a->has_alt_geom = 1; }
        else if (!ground) { a->alt_baro = round_i32(d); a->has_alt_baro = 1; }
    }
    /* 12 ground speed, 13 track */
    if (f[12].n) {
        if (field_num(f[12], &d) != 0) return -1;
        if (finite_in(d, 0, 4000)) { a->gs = d; a->has_gs = 1; }
    }
    if (f[13].n) {
        if (field_num(f[13], &d) != 0) return -1;
        if (finite_in(d, 0, 360)) { a->track = d; a->has_track = 1; }
    }
    /* 14 / 15 position, only as a pair */
    if (f[14].n || f[15].n) {
        double lat = 0, lon = 0;
        if (field_num(f[14], &lat) != 0 || field_num(f[15], &lon) != 0) return -1;
        if (finite_in(lat, -90, 90) && finite_in(lon, -180, 180)) {
            a->lat = lat; a->lon = lon; a->has_pos = 1;
        }
    }
    /* 16 vertical rate */
    if ((r = field_alt(f[16], &d, &geom)) < 0) return -1;
    if (r > 0 && finite_in(d, -60000, 60000)) {
        if (geom) { a->geom_rate = round_i32(d); a->has_geom_rate = 1; }
        else      { a->baro_rate = round_i32(d); a->has_baro_rate = 1; }
    }
    /* 17 squawk */
    if (f[17].n == 4) {
        memcpy(tmp, f[17].p, 4);
        tmp[4] = '\0';
        if (squawk_ok(tmp)) put(a->squawk, sizeof(a->squawk), tmp);
    }
    /* 22 RSSI, 23 category: readsb --sbs-extra-fields only. */
    if (nf > 22 && f[22].n) {
        if (field_num(f[22], &d) != 0) return -1;
        if (finite_in(d, -200, 10)) { a->rssi = d; a->has_rssi = 1; }
    }
    if (nf > 23 && f[23].n == 2) {
        memcpy(tmp, f[23].p, 2);
        tmp[2] = '\0';
        if (category_ok(tmp)) put(a->category, sizeof(a->category), tmp);
    }
    return 1;
}

void adsb_sbs_lines_init(adsb_sbs_lines_t *l) {
    if (!l) return;
    l->len = 0;
    l->overlong = 0;
}

static void sbs_line(adsb_sbs_lines_t *l, int64_t wall_ms, uint64_t mono_ms) {
    int r = adsb_sbs_parse(l->buf, l->len, &l->msg);
    if (r > 0)       adsb_feed_sbs(&l->msg, wall_ms, mono_ms);
    else if (r == 0) adsb_note_sbs_alive(wall_ms, mono_ms);
    else             adsb_note_parse_error("malformed SBS line");
}

void adsb_sbs_lines_feed(adsb_sbs_lines_t *l, const uint8_t *data, size_t n,
                         int64_t wall_ms, uint64_t mono_ms) {
    if (!l || !data) return;
    for (size_t i = 0; i < n; i++) {
        char ch = (char)data[i];
        if (ch == '\n') {
            if (!l->overlong) sbs_line(l, wall_ms, mono_ms);
            l->len = 0;
            l->overlong = 0;
            continue;
        }
        if (l->overlong) continue;
        /* +1: a trailing '\r' rides along and is stripped by the parse. */
        if (l->len >= ADSB_SBS_MAX_LINE + 1) {
            l->overlong = 1;
            l->len = 0;
            adsb_note_parse_error("SBS line over 512 bytes");
            continue;
        }
        l->buf[l->len++] = ch;
    }
}

/* ── Bands and the signature ───────────────────────────────────── */

int adsb_alt_band(int on_ground, int has_alt, int alt_ft) {
    if (on_ground) return -2;
    if (!has_alt) return -1;
    if (alt_ft < 9750)   /* below -250 ft (a field under sea level) is band 0 */
        return alt_ft + 250 < 0 ? 0 : (alt_ft + 250) / 1000;
    return 10 + (alt_ft - 9750) / 4000;
}

/* The lowest altitude in band b (b >= 1). */
static int band_floor(int b) {
    return b <= 10 ? b * 1000 - 250 : 9750 + (b - 10) * 4000;
}

int adsb_alt_band_held(int held, int on_ground, int has_alt, int alt_ft) {
    int raw = adsb_alt_band(on_ground, has_alt, alt_ft);
    /* Ground, unknown, or a first band: no edge to hold against. */
    if (held < 0 || raw < 0 || held == INT16_MIN) return raw;
    if (raw > held)
        return alt_ft >= band_floor(held + 1) + ADSB_ALT_HYST_FT ? raw : held;
    if (raw < held)
        return alt_ft < band_floor(held) - ADSB_ALT_HYST_FT ? raw : held;
    return held;
}

static int cell_of(double deg) { return (int)floor(deg * 10.0); }

/* Hold the row's cell unless the position left it by the margin. */
static void cell_hold(adsb_aircraft_t *r) {
    if (!r->has_pos) return;
    int clat = cell_of(r->lat), clon = cell_of(r->lon);
    if (r->has_cell && (clat != r->cell_lat || clon != r->cell_lon)) {
        double lo_lat = r->cell_lat / 10.0 - ADSB_CELL_HYST_DEG;
        double hi_lat = (r->cell_lat + 1) / 10.0 + ADSB_CELL_HYST_DEG;
        double lo_lon = r->cell_lon / 10.0 - ADSB_CELL_HYST_DEG;
        double hi_lon = (r->cell_lon + 1) / 10.0 + ADSB_CELL_HYST_DEG;
        if (r->lat >= lo_lat && r->lat < hi_lat &&
            r->lon >= lo_lon && r->lon < hi_lon)
            return;
    }
    r->cell_lat = (int16_t)clat;
    r->cell_lon = (int16_t)clon;
    r->has_cell = 1;
}

static uint64_t mix64(uint64_t h, long long v) {
    h ^= (uint64_t)v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h * 0x100000001b3ULL;
}

static uint64_t mix_str(uint64_t h, const char *s) {
    for (; *s; s++) h = mix64(h, (unsigned char)*s);
    return mix64(h, 0);
}

uint64_t adsb_row_sig(const adsb_aircraft_t *a) {
    uint64_t h = 0xcbf29ce484222325ULL;
    if (!a) return h;
    h = mix64(h, (long long)a->icao);
    h = mix64(h, a->non_icao);
    h = mix64(h, (long long)a->first_seen);
    h = mix64(h, a->alt_band);
    h = mix64(h, a->has_cell ? a->cell_lat : -10000);
    h = mix64(h, a->has_cell ? a->cell_lon : -10000);
    h = mix64(h, a->has_pos);
    h = mix64(h, a->emergency);
    h = mix_str(h, a->squawk);
    h = mix_str(h, a->flight);
    h = mix_str(h, a->category);
    return h;
}

/* ── The table ─────────────────────────────────────────────────── */

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct {
    int             configured;
    int             sbs;            /* the source is an SBS stream */
    char            label[48];
    char            err[96];
    int             ever_doc;
    double          stamp;          /* the decoder's clock as last seen */
    int             ever_advance;
    uint64_t        advance_mono;   /* when it last moved forward */
    time_t          last_read;
    double          decoder_now;
    uint64_t        messages;
    uint64_t        reads, read_errors, parse_errors, overflow, bad, expired;
    int             n;
    adsb_aircraft_t rows[ADSB_MAX_AIRCRAFT];
} g;

/* The poll's copies, which s->adsb_rows / adsb_gone point at. Main
 * thread only. */
static adsb_aircraft_t g_snap[ADSB_MAX_AIRCRAFT];
static adsb_aircraft_t g_gone[ADSB_MAX_AIRCRAFT];

void adsb_set_source(const char *label) {
    pthread_mutex_lock(&g_mu);
    g.configured = 1;
    snprintf(g.label, sizeof(g.label), "%s", label ? label : "");
    pthread_mutex_unlock(&g_mu);
}

void adsb_set_source_sbs(const char *label) {
    adsb_set_source(label);
    pthread_mutex_lock(&g_mu);
    g.sbs = 1;
    pthread_mutex_unlock(&g_mu);
}

static adsb_aircraft_t *row_find(uint32_t icao, int non_icao) {
    for (int i = 0; i < g.n; i++)
        if (g.rows[i].icao == icao && g.rows[i].non_icao == non_icao)
            return &g.rows[i];
    return NULL;
}

static time_t ago(time_t wall, double secs) {
    return wall - (time_t)secs;
}

/* Sticky merge: what the document carries overwrites, what it omits
 * stays. The decoder's own validity windows already decide when a
 * field stops being current; a key flickering out of one document is
 * not news. */
static void merge(adsb_aircraft_t *r, const adsb_aircraft_t *a, time_t wall,
                  uint64_t mono_ms) {
    if (a->type[0])     memcpy(r->type, a->type, sizeof(r->type));
    if (a->flight[0])   memcpy(r->flight, a->flight, sizeof(r->flight));
    if (a->squawk[0])   memcpy(r->squawk, a->squawk, sizeof(r->squawk));
    if (a->category[0]) memcpy(r->category, a->category, sizeof(r->category));
    if (a->emergency != ADSB_EMERG_ABSENT) r->emergency = a->emergency;
    if (a->on_ground)   { r->on_ground = 1; r->has_alt_baro = 0; }
    if (a->has_alt_baro){ r->on_ground = 0; r->has_alt_baro = 1; r->alt_baro = a->alt_baro; }
    if (a->has_alt_geom){ r->has_alt_geom = 1; r->alt_geom = a->alt_geom; }
    if (a->has_gs)      { r->has_gs = 1; r->gs = a->gs; }
    if (a->has_track)   { r->has_track = 1; r->track = a->track; }
    if (a->has_baro_rate){ r->has_baro_rate = 1; r->baro_rate = a->baro_rate; }
    if (a->has_geom_rate){ r->has_geom_rate = 1; r->geom_rate = a->geom_rate; }
    if (a->has_rssi)    { r->has_rssi = 1; r->rssi = a->rssi; }
    if (a->has_messages){ r->has_messages = 1; r->messages = a->messages; }
    if (a->has_pos) {
        r->has_pos = 1; r->lat = a->lat; r->lon = a->lon;
        r->has_seen_pos = a->has_seen_pos;
        r->seen_pos = a->seen_pos;
        r->pos_ts = ago(wall, a->has_seen_pos ? a->seen_pos : 0);
    }
    double seen = a->has_seen ? a->seen : 0;
    r->has_seen = a->has_seen;
    r->seen = a->seen;
    r->last_seen = ago(wall, seen);
    uint64_t back = (uint64_t)(seen * 1000.0);
    r->last_mono_ms = mono_ms > back ? mono_ms - back : 0;
    /* Altitude band: the barometric altitude, else the geometric one. */
    int has_alt = r->has_alt_baro || r->has_alt_geom;
    int alt = r->has_alt_baro ? r->alt_baro : r->alt_geom;
    r->alt_band = (int16_t)adsb_alt_band_held(r->alt_band, r->on_ground, has_alt, alt);
    cell_hold(r);
}

void adsb_feed_doc(const adsb_doc_t *d, double stamp, time_t wall,
                   uint64_t mono_ms) {
    if (!d) return;
    pthread_mutex_lock(&g_mu);
    double clk = d->has_now ? d->now : stamp;
    if (!g.ever_doc) {
        /* The first document has shown no advance yet. The decoder is
         * local, so its clock is the host's: one already more than
         * ADSB_STALE_S behind was left by a decoder that stopped before
         * sloth started, and its aircraft were heard then, not now. */
        g.stamp = clk;
        if ((double)wall - clk <= (double)ADSB_STALE_S) {
            g.ever_advance = 1;
            g.advance_mono = mono_ms;
        }
    } else if (clk > g.stamp) {
        g.stamp = clk;
        g.ever_advance = 1;
        g.advance_mono = mono_ms;
    }
    g.ever_doc = 1;
    g.err[0] = '\0';
    g.last_read = wall;
    g.reads++;
    g.decoder_now = d->has_now ? d->now : 0;
    if (d->has_messages) g.messages = d->messages;
    g.overflow += (uint64_t)d->overflow;
    g.bad += (uint64_t)d->bad;
    for (int i = 0; g.ever_advance && i < d->n && i < ADSB_MAX_AIRCRAFT; i++) {
        const adsb_aircraft_t *a = &d->ac[i];
        adsb_aircraft_t *r = row_find(a->icao, a->non_icao);
        if (!r) {
            if (g.n >= ADSB_MAX_AIRCRAFT) { g.overflow++; continue; }
            r = &g.rows[g.n++];
            memset(r, 0, sizeof(*r));
            r->icao = a->icao;
            r->non_icao = a->non_icao;
            r->emergency = ADSB_EMERG_ABSENT;
            r->alt_band = INT16_MIN;
            r->first_seen = wall;
        }
        merge(r, a, wall, mono_ms);
    }
    pthread_mutex_unlock(&g_mu);
}

/* Under g_mu: an SBS line arrived. A stream has no document clock: the
 * line itself, heartbeat included, is the decoder showing it runs. */
static void sbs_alive(time_t wall, uint64_t mono_ms) {
    g.ever_doc = 1;
    g.ever_advance = 1;
    g.advance_mono = mono_ms;
    g.last_read = wall;
    g.err[0] = '\0';
}

void adsb_note_sbs_alive(int64_t wall_ms, uint64_t mono_ms) {
    pthread_mutex_lock(&g_mu);
    sbs_alive((time_t)(wall_ms / 1000), mono_ms);
    pthread_mutex_unlock(&g_mu);
}

void adsb_note_connected(void) {
    pthread_mutex_lock(&g_mu);
    g.err[0] = '\0';
    pthread_mutex_unlock(&g_mu);
}

void adsb_feed_sbs(const adsb_sbs_msg_t *m, int64_t wall_ms, uint64_t mono_ms) {
    if (!m) return;
    time_t wall = (time_t)(wall_ms / 1000);
    adsb_aircraft_t a = m->ac;
    /* seen as aircraft.json has it: seconds before the read that the
     * decoder heard the message. The decoder's clock is the host's (the
     * source is loopback); a line stamped ahead of the read is 0. */
    double seen = 0;
    if (m->has_time && wall_ms > m->time_ms) {
        seen = (double)(wall_ms - m->time_ms) / 1000.0;
        if (seen > 1e6) seen = 1e6;
    }
    a.has_seen = 1;
    a.seen = seen;
    if (a.has_pos) { a.has_seen_pos = 1; a.seen_pos = seen; }
    pthread_mutex_lock(&g_mu);
    sbs_alive(wall, mono_ms);
    g.reads++;
    g.messages++;
    adsb_aircraft_t *r = row_find(a.icao, a.non_icao);
    if (!r) {
        if (g.n >= ADSB_MAX_AIRCRAFT) {
            g.overflow++;
            pthread_mutex_unlock(&g_mu);
            return;
        }
        r = &g.rows[g.n++];
        memset(r, 0, sizeof(*r));
        r->icao = a.icao;
        r->non_icao = a.non_icao;
        r->emergency = ADSB_EMERG_ABSENT;
        r->alt_band = INT16_MIN;
        r->first_seen = wall;
    }
    /* No per-aircraft count in SBS: the lines received for it. */
    a.has_messages = 1;
    a.messages = r->messages + 1;
    merge(r, &a, wall, mono_ms);
    pthread_mutex_unlock(&g_mu);
}

static void note_err(const char *err, uint64_t *tally) {
    pthread_mutex_lock(&g_mu);
    (*tally)++;
    snprintf(g.err, sizeof(g.err), "%s", err ? err : "error");
    pthread_mutex_unlock(&g_mu);
}

void adsb_note_read_error(const char *err)  { note_err(err, &g.read_errors); }
void adsb_note_parse_error(const char *err) { note_err(err, &g.parse_errors); }

void adsb_health_poll(sloth_state_t *s, time_t wall, uint64_t mono_ms) {
    if (!s) return;
    (void)wall;
    adsb_health_t *h = &s->adsb;
    memset(h, 0, sizeof(*h));
    int ngone = 0;
    pthread_mutex_lock(&g_mu);
    /* Expire first, so the copy below never carries a row this poll
     * also reports gone. Order is not kept: the table is a set. */
    for (int i = 0; i < g.n; ) {
        adsb_aircraft_t *r = &g.rows[i];
        if (mono_ms >= r->last_mono_ms &&
            mono_ms - r->last_mono_ms >= (uint64_t)ADSB_EXPIRE_S * 1000u) {
            g_gone[ngone++] = *r;
            g.expired++;
            g.rows[i] = g.rows[--g.n];
            continue;
        }
        i++;
    }
    h->configured = g.configured;
    snprintf(h->src, sizeof(h->src), "%s", g.label);
    snprintf(h->err, sizeof(h->err), "%s", g.err);
    h->last_read = g.last_read;
    h->decoder_now = g.decoder_now;
    h->messages = g.messages;
    h->reads = g.reads;
    h->read_errors = g.read_errors;
    h->parse_errors = g.parse_errors;
    h->overflow = g.overflow;
    h->bad_entries = g.bad;
    h->expired = g.expired;
    h->aircraft = g.n;
    h->age_s = -1;
    h->fresh_bucket = -1;
    if (g.ever_advance) {
        uint64_t age = mono_ms > g.advance_mono ? mono_ms - g.advance_mono : 0;
        h->age_s = (int)(age / 1000u > 0x7fffffff ? 0x7fffffff : age / 1000u);
        h->fresh_bucket = h->age_s <= (g.sbs ? ADSB_SBS_STALE_S : ADSB_STALE_S) ? 0 : 1;
    } else if (g.ever_doc) {
        h->fresh_bucket = 1;   /* stale at first sight: no advance seen */
    }
    if (!g.configured)          h->state = ADSB_NONE;
    else if (g.err[0])          h->state = ADSB_ERROR;
    else if (h->fresh_bucket < 0) h->state = ADSB_WAITING;
    else if (h->fresh_bucket == 0) h->state = ADSB_LIVE;
    else                        h->state = ADSB_STALE;
    memcpy(g_snap, g.rows, sizeof(g.rows[0]) * (size_t)g.n);
    s->adsb_count = g.n;
    pthread_mutex_unlock(&g_mu);
    s->adsb_rows = g_snap;
    s->adsb_gone = g_gone;
    s->adsb_gone_count = ngone;
}

void adsb_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(&g, 0, sizeof(g));
    pthread_mutex_unlock(&g_mu);
}

const char *adsb_state_name(int state) {
    switch (state) {
    case ADSB_WAITING: return "waiting";
    case ADSB_LIVE:    return "live";
    case ADSB_STALE:   return "stale";
    case ADSB_ERROR:   return "error";
    default:           return "none";
    }
}
