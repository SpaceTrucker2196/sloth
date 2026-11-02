#include <arpa/inet.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "gps.h"
#include "tune.h"

/* Contract in gps.h. Everything here is pure except the arbitration
 * state at the bottom, which is one mutex-guarded struct the reader
 * worker feeds and the main thread reads. */

/* ── Locale-free numbers ──────────────────────────────────────────
 * strtod() honours LC_NUMERIC, and a sensor started under a locale with
 * a decimal comma would read "4807.038" as 4807. Both wire formats are
 * defined with a '.', so the digit walk is written out. */

/* [-]digits[.digits] over exactly s[0..n). 0 on success. `allow_sign`
 * admits a leading '-' (altitude, a fixed --location); NMEA position
 * fields never carry one. */
static int parse_dec(const char *s, size_t n, int allow_sign, double *out) {
    size_t i = 0;
    int neg = 0, digits = 0;
    double v = 0.0, scale = 1.0;
    if (n == 0) return -1;
    if (allow_sign && (s[0] == '-' || s[0] == '+')) { neg = s[0] == '-'; i++; }
    for (; i < n && s[i] >= '0' && s[i] <= '9'; i++, digits++)
        v = v * 10.0 + (s[i] - '0');
    if (i < n && s[i] == '.') {
        for (i++; i < n && s[i] >= '0' && s[i] <= '9'; i++, digits++) {
            scale /= 10.0;
            v += (s[i] - '0') * scale;
        }
    }
    if (i != n || digits == 0 || digits > 24) return -1;
    *out = neg ? -v : v;
    return 0;
}

static int parse_uint(const char *s, size_t n, long *out) {
    long v = 0;
    if (n == 0 || n > 9) return -1;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return 0;
}

/* ── NMEA 0183 ─────────────────────────────────────────────────── */

void nmea_fix_init(nmea_fix_t *f) {
    memset(f, 0, sizeof(*f));
    f->quality = -1;
    f->sats = -1;
    f->utc_hms = -1;
    f->utc_dmy = -1;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Strip a trailing CR/LF; the length that is left. */
static size_t trim_eol(const char *line, size_t n) {
    while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == '\n')) n--;
    return n;
}

int nmea_checksum_ok(const char *line, size_t n) {
    if (!line) return 0;
    n = trim_eol(line, n);
    /* "$" + at least one byte + "*hh" */
    if (n < 5 || line[0] != '$' || line[n - 3] != '*') return 0;
    int hi = hexval(line[n - 2]), lo = hexval(line[n - 1]);
    if (hi < 0 || lo < 0) return 0;
    unsigned x = 0;
    for (size_t i = 1; i < n - 3; i++) {
        if (line[i] == '*' || line[i] == '$') return 0;
        x ^= (unsigned char)line[i];
    }
    return x == (unsigned)(hi * 16 + lo);
}

#define NMEA_MAX_FIELDS 24

typedef struct { const char *p; size_t n; } fld_t;

/* "ddmm.mmmm" (deg_digits 2) / "dddmm.mmmm" (3) and a hemisphere.
 * 0 with *out in signed degrees; -1 when it does not parse or lands
 * outside the range. */
static int parse_coord(fld_t v, fld_t hemi, int deg_digits, double *out) {
    if (v.n < (size_t)deg_digits + 2 || hemi.n != 1) return -1;
    long deg;
    double min;
    if (parse_uint(v.p, (size_t)deg_digits, &deg) != 0) return -1;
    if (parse_dec(v.p + deg_digits, v.n - (size_t)deg_digits, 0, &min) != 0)
        return -1;
    /* The minutes' integer part is exactly two digits. */
    if (v.n < (size_t)deg_digits + 2 ||
        v.p[deg_digits] < '0' || v.p[deg_digits] > '9' ||
        v.p[deg_digits + 1] < '0' || v.p[deg_digits + 1] > '9' ||
        (v.n > (size_t)deg_digits + 2 && v.p[deg_digits + 2] != '.'))
        return -1;
    if (min >= 60.0) return -1;
    double d = (double)deg + min / 60.0;
    char h = hemi.p[0];
    if (deg_digits == 2) {
        if (h != 'N' && h != 'S') return -1;
        if (d > 90.0) return -1;
        if (h == 'S') d = -d;
    } else {
        if (h != 'E' && h != 'W') return -1;
        if (d > 180.0) return -1;
        if (h == 'W') d = -d;
    }
    *out = d;
    return 0;
}

/* The integer part of "hhmmss[.ss]" / "ddmmyy"; -1 when absent or bad. */
static long parse_hms(fld_t v) {
    size_t k = 0;
    while (k < v.n && v.p[k] != '.') k++;
    long x;
    if (k != 6 || parse_uint(v.p, k, &x) != 0) return -1;
    return x;
}

int nmea_parse(const char *line, size_t n, nmea_fix_t *f) {
    if (!line || !f) return -1;
    size_t raw = n;
    if (raw > NMEA_MAX_LINE) return -1;
    if (!nmea_checksum_ok(line, n)) return -1;
    n = trim_eol(line, n) - 3;         /* drop "*hh" */
    const char *body = line + 1;
    size_t blen = n - 1;

    fld_t fl[NMEA_MAX_FIELDS] = {{0}};
    int nf = 0;
    size_t start = 0;
    for (size_t i = 0; i <= blen; i++) {
        if (i == blen || body[i] == ',') {
            if (nf == NMEA_MAX_FIELDS) return -1;
            fl[nf].p = body + start;
            fl[nf].n = i - start;
            nf++;
            start = i + 1;
        }
    }
    /* Address: two-letter talker + three-letter type. A proprietary
     * "$P..." sentence has no talker and is someone else's business. */
    if (fl[0].n != 5 || fl[0].p[0] == 'P') return 0;
    const char *type = fl[0].p + 2;

    /* Merge into a copy so a malformed sentence changes nothing. */
    nmea_fix_t t = *f;
    t.pos_new = 0;
    if (memcmp(type, "GGA", 3) == 0) {
        if (nf < 10) return -1;
        long q = 0;
        if (fl[6].n && parse_uint(fl[6].p, fl[6].n, &q) != 0) return -1;
        if (q > 9) return -1;
        t.quality = (int)q;
        long hms = parse_hms(fl[1]);
        if (hms >= 0) t.utc_hms = hms;
        if (fl[7].n) {
            long sats;
            if (parse_uint(fl[7].p, fl[7].n, &sats) != 0 || sats > 99) return -1;
            t.sats = (int)sats;
        }
        if (fl[8].n) {
            double h;
            if (parse_dec(fl[8].p, fl[8].n, 0, &h) != 0) return -1;
            t.has_hdop = 1;
            t.hdop = h;
        }
        if (q == 0 || fl[2].n == 0 || fl[4].n == 0) {
            t.valid_lat_lon = 0;
            t.has_alt = 0;
        } else {
            double lat, lon;
            if (parse_coord(fl[2], fl[3], 2, &lat) != 0 ||
                parse_coord(fl[4], fl[5], 3, &lon) != 0)
                return -1;
            t.lat = lat;
            t.lon = lon;
            t.valid_lat_lon = 1;
            t.pos_new = 1;
            t.has_alt = 0;
            if (fl[9].n) {
                double alt;
                if (parse_dec(fl[9].p, fl[9].n, 1, &alt) != 0) return -1;
                t.alt_m = alt;
                t.has_alt = 1;
            }
        }
    } else if (memcmp(type, "RMC", 3) == 0) {
        if (nf < 10) return -1;
        if (fl[2].n != 1 || (fl[2].p[0] != 'A' && fl[2].p[0] != 'V'))
            return -1;
        t.rmc_status = fl[2].p[0];
        long hms = parse_hms(fl[1]);
        if (hms >= 0) t.utc_hms = hms;
        long dmy = parse_hms(fl[9]);
        if (dmy >= 0) t.utc_dmy = dmy;
        if (t.rmc_status == 'V' || fl[3].n == 0 || fl[5].n == 0) {
            t.valid_lat_lon = 0;
        } else {
            double lat, lon;
            if (parse_coord(fl[3], fl[4], 2, &lat) != 0 ||
                parse_coord(fl[5], fl[6], 3, &lon) != 0)
                return -1;
            t.lat = lat;
            t.lon = lon;
            t.valid_lat_lon = 1;
            t.pos_new = 1;
        }
    } else if (memcmp(type, "GSA", 3) == 0) {
        if (nf < 18) return -1;
        long mode = 0;
        if (fl[2].n != 1 || parse_uint(fl[2].p, 1, &mode) != 0 ||
            mode < 1 || mode > 3)
            return -1;
        t.gsa_mode = (int)mode;
        if (fl[16].n) {
            double h;
            if (parse_dec(fl[16].p, fl[16].n, 0, &h) != 0) return -1;
            t.has_hdop = 1;
            t.hdop = h;
        }
        if (mode == 1) t.valid_lat_lon = 0;
    } else {
        return 0;
    }
    *f = t;
    return 1;
}

int nmea_fix_usable(const nmea_fix_t *f) {
    if (!f || !f->valid_lat_lon) return 0;
    if (f->quality >= 0) return f->quality >= 1 && f->quality <= 5;
    return f->rmc_status == 'A' || f->gsa_mode >= 2;
}

double nmea_acc_m(double hdop) { return hdop * 5.0; }

/* ── gpsd JSON ─────────────────────────────────────────────────── */

typedef struct { const char *p, *e; } jcur_t;

static void jws(jcur_t *c) {
    while (c->p < c->e && (*c->p == ' ' || *c->p == '\t' ||
                           *c->p == '\r' || *c->p == '\n'))
        c->p++;
}

/* A JSON string at c->p into out (truncated, escapes kept as their
 * second byte: gpsd's keys and the values read here are ASCII). */
static int jstr(jcur_t *c, char *out, size_t outsz) {
    size_t k = 0;
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
    }
    if (c->p >= c->e) return -1;
    c->p++;
    if (out && outsz) out[k] = '\0';
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

/* Skip one value of any type; nested containers by depth, strings
 * honoured so a bracket inside one does not count. */
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

int gpsd_json_parse(const char *line, size_t n, gpsd_msg_t *out) {
    if (!line || !out || n > GPSD_MAX_LINE) return -1;
    memset(out, 0, sizeof(*out));
    out->mode = -1;
    jcur_t c = { line, line + n };
    jws(&c);
    if (c.p >= c.e || *c.p != '{') return -1;
    c.p++;
    char cls[32] = "";
    int have_msl = 0, have_hae = 0;
    double msl = 0, hae = 0;
    jws(&c);
    if (c.p < c.e && *c.p == '}') { c.p++; goto done; }
    for (;;) {
        char key[24];
        jws(&c);
        if (jstr(&c, key, sizeof(key)) != 0) return -1;
        jws(&c);
        if (c.p >= c.e || *c.p != ':') return -1;
        c.p++;
        jws(&c);
        if (c.p >= c.e) return -1;
        if (*c.p == '"') {
            char val[32];
            if (jstr(&c, val, sizeof(val)) != 0) return -1;
            if (strcmp(key, "class") == 0) snprintf(cls, sizeof(cls), "%s", val);
            else if (strcmp(key, "time") == 0)
                snprintf(out->time, sizeof(out->time), "%s", val);
        } else if (*c.p == '-' || (*c.p >= '0' && *c.p <= '9')) {
            double d;
            if (jnum(&c, &d) != 0) return -1;
            if      (strcmp(key, "mode") == 0)   out->mode = (d >= 0 && d <= 3) ? (int)d : 0;
            else if (strcmp(key, "lat") == 0)    { out->lat = d; out->has_lat = 1; }
            else if (strcmp(key, "lon") == 0)    { out->lon = d; out->has_lon = 1; }
            else if (strcmp(key, "altMSL") == 0) { msl = d; have_msl = 1; }
            else if (strcmp(key, "altHAE") == 0) { hae = d; have_hae = 1; }
            else if (strcmp(key, "alt") == 0 && !have_hae) { hae = d; have_hae = 1; }
            else if (strcmp(key, "eph") == 0)    { out->eph = d; out->has_eph = 1; }
            else if (strcmp(key, "epx") == 0)    { out->epx = d; out->has_epx = 1; }
            else if (strcmp(key, "epy") == 0)    { out->epy = d; out->has_epy = 1; }
            else if (strcmp(key, "hdop") == 0)   { out->hdop = d; out->has_hdop = 1; }
            else if (strcmp(key, "uSat") == 0 && d >= 0 && d < 1000)
                                                 { out->usat = (int)d; out->has_usat = 1; }
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
    if (c.p != c.e) return -1;
    if (have_msl) { out->alt_m = msl; out->has_alt = 1; }
    else if (have_hae) { out->alt_m = hae; out->has_alt = 1; }
    if (strcmp(cls, "TPV") == 0)     { out->cls = GPSD_CLS_TPV; return 1; }
    if (strcmp(cls, "SKY") == 0)     { out->cls = GPSD_CLS_SKY; return 1; }
    if (strcmp(cls, "VERSION") == 0) { out->cls = GPSD_CLS_VERSION; return 1; }
    out->cls = GPSD_CLS_OTHER;
    return 0;
}

/* ── The --gps SPEC ────────────────────────────────────────────── */

#define GPSD_DEFAULT_PORT 2947

int gps_spec_parse(const char *spec, gps_spec_t *out, char *err, size_t errsz) {
    memset(out, 0, sizeof(*out));
    if (!spec || !spec[0]) {
        if (err && errsz) snprintf(err, errsz, "empty SPEC");
        return -1;
    }
    if (spec[0] == '/') {
        if (strlen(spec) >= sizeof(out->path)) {
            if (err && errsz) snprintf(err, errsz, "device path too long");
            return -1;
        }
        out->kind = GPS_SPEC_SERIAL;
        snprintf(out->path, sizeof(out->path), "%s", spec);
        return 0;
    }
    if (strncmp(spec, "gpsd://", 7) != 0) {
        if (err && errsz)
            snprintf(err, errsz, "SPEC is /dev/PATH (NMEA serial) or "
                     "gpsd://[HOST[:PORT]] (gpsd has no Unix data socket)");
        return -1;
    }
    const char *h = spec + 7;
    char host[64];
    const char *portp = NULL;
    if (*h == '\0') {
        snprintf(host, sizeof(host), "127.0.0.1");
    } else if (*h == '[') {
        const char *rb = strchr(h, ']');
        if (!rb || (size_t)(rb - h - 1) >= sizeof(host) || rb == h + 1) goto bad;
        memcpy(host, h + 1, (size_t)(rb - h - 1));
        host[rb - h - 1] = '\0';
        if (rb[1] == ':') portp = rb + 2;
        else if (rb[1] != '\0') goto bad;
        struct in6_addr a6;
        if (inet_pton(AF_INET6, host, &a6) != 1) goto bad;
    } else {
        const char *colon = strchr(h, ':');
        size_t hl = colon ? (size_t)(colon - h) : strlen(h);
        if (hl == 0 || hl >= sizeof(host)) goto bad;
        memcpy(host, h, hl);
        host[hl] = '\0';
        if (colon) portp = colon + 1;
        struct in_addr a4;
        if (inet_pton(AF_INET, host, &a4) != 1) goto bad;
    }
    long port = GPSD_DEFAULT_PORT;
    if (portp && (parse_uint(portp, strlen(portp), &port) != 0 ||
                  port < 1 || port > 65535))
        goto bad;
    out->kind = GPS_SPEC_GPSD;
    snprintf(out->host, sizeof(out->host), "%s", host);
    out->port = (int)port;
    return 0;
bad:
    if (err && errsz)
        snprintf(err, errsz, "gpsd HOST must be a numeric address "
                 "(127.0.0.1, [::1]) and PORT 1..65535");
    return -1;
}

int gps_spec_is_remote(const gps_spec_t *sp) {
    if (!sp || sp->kind != GPS_SPEC_GPSD) return 0;
    struct in_addr a4;
    if (inet_pton(AF_INET, sp->host, &a4) == 1)
        return (ntohl(a4.s_addr) >> 24) != 127;
    struct in6_addr a6;
    if (inet_pton(AF_INET6, sp->host, &a6) == 1) {
        static const unsigned char lo[16] = { [15] = 1 };
        return memcmp(a6.s6_addr, lo, 16) != 0;
    }
    return 1;   /* unparseable: fail closed */
}

void gps_spec_label(const gps_spec_t *sp, char *out, size_t outsz) {
    if (!out || !outsz) return;
    if (!sp) { out[0] = '\0'; return; }
    if (sp->kind == GPS_SPEC_SERIAL)
        snprintf(out, outsz, "nmea:%.200s", sp->path);
    else if (strchr(sp->host, ':'))
        snprintf(out, outsz, "gpsd:[%s]:%d", sp->host, sp->port);
    else
        snprintf(out, outsz, "gpsd:%s:%d", sp->host, sp->port);
}

void gps_spec_announce(const gps_spec_t *sp, char *out, size_t outsz) {
    if (!out || !outsz) return;
    if (!sp) { out[0] = '\0'; return; }
    char label[300];
    gps_spec_label(sp, label, sizeof(label));
    if (sp->kind == GPS_SPEC_SERIAL)
        snprintf(out, outsz, "reading NMEA 0183 from %s (receive-only: "
                 "nothing is written to the device)", sp->path);
    else
        snprintf(out, outsz, "connecting to gpsd at %s over TCP after the "
                 "privilege drop; sloth sends one ?WATCH line, then only "
                 "reads", label + 5);   /* past "gpsd:" */
}

/* ── Arbitration state ─────────────────────────────────────────── */

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct {
    int      has_fixed;
    double   f_lat, f_lon, f_alt;
    int      f_has_alt;
    int      has_gps;
    char     label[48];
    int      ever_fix;      /* a usable fix has arrived at least once */
    int      fix_live;      /* the receiver has not since said "no fix" */
    loc_stamp_t fix;        /* the newest usable fix */
    int      sats;
    double   hdop;
    int      quality;
    char     err[96];
    uint64_t sentences, bad_checksum, parse_errors, reconnects;
} g_loc = { .quality = -1 };

static int range_ok(double lat, double lon) {
    return lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0 &&
           lat == lat && lon == lon;   /* NaN fails both */
}

int gps_location_set_fixed(double lat, double lon, double alt_m, int has_alt,
                           char *err, size_t errsz) {
    if (!range_ok(lat, lon)) {
        if (err && errsz)
            snprintf(err, errsz, "latitude must be -90..90 and longitude "
                     "-180..180 (WGS84 decimal degrees)");
        return -1;
    }
    if (has_alt && !(alt_m >= -1000.0 && alt_m <= 20000.0)) {
        if (err && errsz)
            snprintf(err, errsz, "altitude must be -1000..20000 metres");
        return -1;
    }
    pthread_mutex_lock(&g_mu);
    g_loc.has_fixed = 1;
    g_loc.f_lat = lat;
    g_loc.f_lon = lon;
    g_loc.f_alt = has_alt ? alt_m : 0.0;
    g_loc.f_has_alt = has_alt ? 1 : 0;
    pthread_mutex_unlock(&g_mu);
    return 0;
}

int gps_location_parse_fixed(const char *arg, char *err, size_t errsz) {
    double v[3] = { 0, 0, 0 };
    int k = 0;
    const char *p = arg ? arg : "";
    for (;;) {
        const char *comma = strchr(p, ',');
        size_t l = comma ? (size_t)(comma - p) : strlen(p);
        if (k == 3 || parse_dec(p, l, 1, &v[k]) != 0) {
            if (err && errsz)
                snprintf(err, errsz, "expected LAT,LON[,ALT] in decimal "
                         "degrees and metres, e.g. 51.50074,-0.12469,12");
            return -1;
        }
        k++;
        if (!comma) break;
        p = comma + 1;
    }
    if (k < 2) {
        if (err && errsz) snprintf(err, errsz, "expected LAT,LON[,ALT]");
        return -1;
    }
    return gps_location_set_fixed(v[0], v[1], v[2], k == 3, err, errsz);
}

void gps_location_set_gps(const char *label) {
    pthread_mutex_lock(&g_mu);
    g_loc.has_gps = 1;
    snprintf(g_loc.label, sizeof(g_loc.label), "%s", label ? label : "");
    pthread_mutex_unlock(&g_mu);
}

/* Caller holds g_mu. */
static void take_fix(double lat, double lon, int has_alt, double alt,
                     int has_acc, double acc, time_t wall) {
    if (!range_ok(lat, lon)) return;
    g_loc.fix.src = LOC_SRC_GPS;
    g_loc.fix.lat = lat;
    g_loc.fix.lon = lon;
    g_loc.fix.has_alt = has_alt ? 1 : 0;
    g_loc.fix.alt_m = has_alt ? alt : 0.0;
    g_loc.fix.has_acc = has_acc ? 1 : 0;
    g_loc.fix.acc_m = has_acc ? acc : 0.0;
    g_loc.fix.ts = wall;
    g_loc.ever_fix = 1;
    g_loc.fix_live = 1;
}

void gps_location_feed_nmea(const nmea_fix_t *f, time_t wall) {
    if (!f) return;
    pthread_mutex_lock(&g_mu);
    if (f->sats >= 0) g_loc.sats = f->sats;
    if (f->has_hdop) g_loc.hdop = f->hdop;
    g_loc.quality = f->quality >= 0 ? f->quality : g_loc.quality;
    /* Only a sentence that carried a position stamps one: a GSA (or a
     * GGA/RMC that still says "fix") leaves the older position to age
     * out against gps.max_fix_age_s rather than renewing it at `wall`. */
    if (!nmea_fix_usable(f))
        g_loc.fix_live = 0;   /* the receiver said it has no fix */
    else if (f->pos_new)
        take_fix(f->lat, f->lon, f->has_alt, f->alt_m,
                 f->has_hdop, nmea_acc_m(f->hdop), wall);
    pthread_mutex_unlock(&g_mu);
}

void gps_location_feed_gpsd(const gpsd_msg_t *m, time_t wall) {
    if (!m) return;
    pthread_mutex_lock(&g_mu);
    if (m->cls == GPSD_CLS_SKY) {
        if (m->has_usat) g_loc.sats = m->usat;
        if (m->has_hdop) g_loc.hdop = m->hdop;
    } else if (m->cls == GPSD_CLS_TPV && m->mode >= 0) {
        g_loc.quality = m->mode;
        if (m->mode >= 2 && m->has_lat && m->has_lon) {
            int has_acc = 1;
            double acc;
            if (m->has_eph)                    acc = m->eph;
            else if (m->has_epx && m->has_epy) acc = sqrt(m->epx * m->epx + m->epy * m->epy);
            else if (g_loc.hdop > 0)           acc = nmea_acc_m(g_loc.hdop);
            else { has_acc = 0; acc = 0.0; }
            /* A 2D fix has no altitude worth recording. */
            take_fix(m->lat, m->lon, m->mode == 3 && m->has_alt, m->alt_m,
                     has_acc, acc, wall);
        } else {
            g_loc.fix_live = 0;
        }
    }
    pthread_mutex_unlock(&g_mu);
}

void gps_location_note(int sentences, int bad_checksum, int parse_errors,
                       int reconnects) {
    pthread_mutex_lock(&g_mu);
    g_loc.sentences    += (uint64_t)(sentences > 0 ? sentences : 0);
    g_loc.bad_checksum += (uint64_t)(bad_checksum > 0 ? bad_checksum : 0);
    g_loc.parse_errors += (uint64_t)(parse_errors > 0 ? parse_errors : 0);
    g_loc.reconnects   += (uint64_t)(reconnects > 0 ? reconnects : 0);
    pthread_mutex_unlock(&g_mu);
}

void gps_location_set_err(const char *err) {
    pthread_mutex_lock(&g_mu);
    snprintf(g_loc.err, sizeof(g_loc.err), "%s", err ? err : "");
    pthread_mutex_unlock(&g_mu);
}

/* Caller holds g_mu. 1 when the newest fix may stamp at `now`. */
static int fix_fresh(time_t now) {
    if (!g_loc.has_gps || !g_loc.ever_fix || !g_loc.fix_live) return 0;
    long age = (long)(now - g_loc.fix.ts);
    return age <= tune_val(TUNE_GPS_MAX_FIX_AGE_S);
}

int gps_location_current(loc_stamp_t *out, time_t now) {
    if (!out) return LOC_SRC_NONE;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&g_mu);
    if (fix_fresh(now)) {
        *out = g_loc.fix;
    } else if (g_loc.has_fixed) {
        out->src = LOC_SRC_FIXED;
        out->lat = g_loc.f_lat;
        out->lon = g_loc.f_lon;
        out->has_alt = (uint8_t)g_loc.f_has_alt;
        out->alt_m = g_loc.f_alt;
        out->ts = now;
    }
    pthread_mutex_unlock(&g_mu);
    return out->src;
}

int gps_location_last_fix(loc_stamp_t *out) {
    int have;
    pthread_mutex_lock(&g_mu);
    have = g_loc.ever_fix;
    if (have && out) *out = g_loc.fix;
    pthread_mutex_unlock(&g_mu);
    return have;
}

void gps_health_poll(sloth_state_t *s, time_t now) {
    if (!s) return;
    gps_health_t *h = &s->gps;
    memset(h, 0, sizeof(*h));
    pthread_mutex_lock(&g_mu);
    h->has_fixed = g_loc.has_fixed;
    h->has_gps = g_loc.has_gps;
    h->configured = h->has_fixed || h->has_gps;
    h->fix_age_s = -1;
    if (g_loc.ever_fix) {
        long age = (long)(now - g_loc.fix.ts);
        h->fix_age_s = age < 0 ? 0 : (age > 0x7fffffffL ? 0x7fffffff : (int)age);
    }
    if (!h->configured)            h->state = GPS_NONE;
    else if (!h->has_gps)          h->state = GPS_FIXED_ONLY;
    else if (fix_fresh(now))       h->state = GPS_FIX;
    else if (g_loc.ever_fix && g_loc.fix_live) h->state = GPS_STALE;
    else                           h->state = GPS_SEARCHING;
    h->sats = g_loc.sats;
    h->hdop = g_loc.hdop;
    h->quality = g_loc.quality;
    snprintf(h->src, sizeof(h->src), "%s",
             h->has_gps ? g_loc.label : (h->has_fixed ? "fixed" : ""));
    snprintf(h->err, sizeof(h->err), "%s", g_loc.err);
    h->sentences = g_loc.sentences;
    h->bad_checksum = g_loc.bad_checksum;
    h->parse_errors = g_loc.parse_errors;
    h->reconnects = g_loc.reconnects;
    pthread_mutex_unlock(&g_mu);
}

void gps_location_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(&g_loc, 0, sizeof(g_loc));
    g_loc.quality = -1;
    pthread_mutex_unlock(&g_mu);
}

double gps_distance_m(double lat1, double lon1, double lat2, double lon2) {
    const double r = 6371008.8;   /* IUGG mean Earth radius, metres */
    const double k = 3.14159265358979323846 / 180.0;
    double dlat = (lat2 - lat1) * k, dlon = (lon2 - lon1) * k;
    double a = sin(dlat / 2) * sin(dlat / 2) +
               cos(lat1 * k) * cos(lat2 * k) * sin(dlon / 2) * sin(dlon / 2);
    if (a > 1.0) a = 1.0;
    return 2.0 * r * asin(sqrt(a));
}

const char *gps_state_name(int state) {
    switch (state) {
    case GPS_FIXED_ONLY: return "fixed";
    case GPS_SEARCHING:  return "searching";
    case GPS_FIX:        return "fix";
    case GPS_STALE:      return "stale";
    default:             return "none";
    }
}

/* ── Line framing ──────────────────────────────────────────────── */

void gps_lines_init(gps_lines_t *l, int kind) {
    memset(l, 0, sizeof(*l));
    l->kind = kind;
    nmea_fix_init(&l->nmea);
}

static void gps_line_done(gps_lines_t *l, time_t wall) {
    size_t n = l->len;
    while (n > 0 && (l->buf[n - 1] == '\r' || l->buf[n - 1] == ' ')) n--;
    if (n == 0) return;
    if (l->kind == GPS_FEED_NMEA) {
        int r = nmea_parse(l->buf, n, &l->nmea);
        if (r < 0) {
            int bad = n <= NMEA_MAX_LINE && l->buf[0] == '$' &&
                      !nmea_checksum_ok(l->buf, n);
            gps_location_note(0, bad, !bad, 0);
            return;
        }
        gps_location_note(1, 0, 0, 0);
        if (r == 1) gps_location_feed_nmea(&l->nmea, wall);
    } else {
        gpsd_msg_t m;
        int r = gpsd_json_parse(l->buf, n, &m);
        if (r < 0) { gps_location_note(0, 0, 1, 0); return; }
        gps_location_note(1, 0, 0, 0);
        if (r == 1) gps_location_feed_gpsd(&m, wall);
    }
}

void gps_lines_feed(gps_lines_t *l, const uint8_t *data, size_t n, time_t wall) {
    size_t max = l->kind == GPS_FEED_NMEA ? NMEA_MAX_LINE : GPSD_MAX_LINE;
    for (size_t i = 0; i < n; i++) {
        char ch = (char)data[i];
        if (ch == '\n') {
            if (l->overlong) gps_location_note(0, 0, 1, 0);
            else             gps_line_done(l, wall);
            l->len = 0;
            l->overlong = 0;
            continue;
        }
        if (l->overlong) continue;
        if (l->len >= max) { l->overlong = 1; continue; }
        l->buf[l->len++] = ch;
    }
}

/* ── Formatting ────────────────────────────────────────────────── */

void gps_fmt_fixed(char *out, size_t outsz, double v, int decimals) {
    if (!out || !outsz) return;
    if (decimals < 0) decimals = 0;
    if (decimals > 9) decimals = 9;
    if (!(v == v) || v > 1e12 || v < -1e12) { snprintf(out, outsz, "0"); return; }
    long long scale = 1;
    for (int i = 0; i < decimals; i++) scale *= 10;
    int neg = v < 0;
    double a = neg ? -v : v;
    long long q = (long long)(a * (double)scale + 0.5);
    long long ip = q / scale, fp = q % scale;
    if (q == 0) neg = 0;
    if (decimals == 0)
        snprintf(out, outsz, "%s%lld", neg ? "-" : "", ip);
    else
        snprintf(out, outsz, "%s%lld.%0*lld", neg ? "-" : "", ip, decimals, fp);
}

const char *gps_loc_src_name(int src) {
    switch (src) {
    case LOC_SRC_GPS:   return "gps";
    case LOC_SRC_FIXED: return "fixed";
    default:            return "";
    }
}

int gps_loc_json(const loc_stamp_t *l, char *out, size_t outsz) {
    if (!out || !outsz) return 0;
    out[0] = '\0';
    if (!l || (l->src != LOC_SRC_GPS && l->src != LOC_SRC_FIXED)) return 0;
    char lat[32], lon[32], alt[32] = "", acc[32] = "";
    gps_fmt_fixed(lat, sizeof(lat), l->lat, 7);
    gps_fmt_fixed(lon, sizeof(lon), l->lon, 7);
    if (l->has_alt) gps_fmt_fixed(alt, sizeof(alt), l->alt_m, 1);
    if (l->has_acc) gps_fmt_fixed(acc, sizeof(acc), l->acc_m, 1);
    int n = snprintf(out, outsz,
                     "\"loc\":{\"lat\":%s,\"lon\":%s%s%s%s%s%s,\"src\":\"%s\",\"ts\":%lld}",
                     lat, lon,
                     l->has_alt ? ",\"alt_m\":" : "", alt,
                     l->has_acc ? ",\"acc_m\":" : "", acc,
                     "", gps_loc_src_name(l->src), (long long)l->ts);
    if (n <= 0 || (size_t)n >= outsz) { out[0] = '\0'; return 0; }
    return n;
}

void gps_loc_text(const loc_stamp_t *l, time_t opened, char *out, size_t outsz) {
    if (!out || !outsz) return;
    out[0] = '\0';
    if (!l || (l->src != LOC_SRC_GPS && l->src != LOC_SRC_FIXED)) return;
    char lat[32], lon[32], acc[48] = "", alt[48] = "", why[48];
    gps_fmt_fixed(lat, sizeof(lat), l->lat, 7);
    gps_fmt_fixed(lon, sizeof(lon), l->lon, 7);
    if (l->has_acc) {
        char v[24];
        gps_fmt_fixed(v, sizeof(v), l->acc_m, 0);
        snprintf(acc, sizeof(acc), "  +/-%s m", v);
    }
    if (l->has_alt) {
        char v[24];
        gps_fmt_fixed(v, sizeof(v), l->alt_m, 0);
        snprintf(alt, sizeof(alt), "  alt %s m", v);
    }
    if (l->src == LOC_SRC_GPS) {
        long age = (long)(opened - l->ts);
        snprintf(why, sizeof(why), "(gps, fix %ld s before)", age < 0 ? 0 : age);
    } else {
        snprintf(why, sizeof(why), "(fixed)");
    }
    snprintf(out, outsz, "%s, %s%s%s  %s", lat, lon, acc, alt, why);
}
