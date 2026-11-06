#include <arpa/inet.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "gps.h"
#include "sloth_clock.h"
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
        /* GSA never ends a fix. From NMEA 4.10 a multi-GNSS receiver
         * sends one GSA per constellation (field 18, the system ID), and
         * one that contributes no satellites says mode 1 while the
         * combined fix is 3D: clearing on it flapped the position inside
         * every epoch. GGA quality 0 and RMC status V are the receiver's
         * "no fix", and they are per fix, not per constellation. */
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

/* A JSON literal true / false at c->p. */
static int jbool(jcur_t *c, int *out) {
    if ((size_t)(c->e - c->p) >= 4 && memcmp(c->p, "true", 4) == 0) {
        c->p += 4; *out = 1; return 0;
    }
    if ((size_t)(c->e - c->p) >= 5 && memcmp(c->p, "false", 5) == 0) {
        c->p += 5; *out = 0; return 0;
    }
    return -1;
}

/* A small integer field, or -1 when gpsd's value is not one. */
static int jsmall(double d, double hi) {
    return (d >= 0 && d <= hi && d == (double)(int)d) ? (int)d : -1;
}

/* One object of SKY's satellites[]: flat numbers and the `used`
 * boolean; anything else inside it is skipped by depth. */
static int parse_sat(jcur_t *c, gpsd_sat_t *s) {
    memset(s, 0, sizeof(*s));
    s->prn = s->gnssid = s->svid = s->sigid = s->health = -1;
    if (c->p >= c->e || *c->p != '{') return -1;
    c->p++;
    jws(c);
    if (c->p < c->e && *c->p == '}') { c->p++; return 0; }
    for (;;) {
        char key[24];
        jws(c);
        if (jstr(c, key, sizeof(key)) != 0) return -1;
        jws(c);
        if (c->p >= c->e || *c->p != ':') return -1;
        c->p++;
        jws(c);
        if (c->p >= c->e) return -1;
        if (*c->p == '-' || (*c->p >= '0' && *c->p <= '9')) {
            double d;
            if (jnum(c, &d) != 0) return -1;
            if      (strcmp(key, "PRN") == 0)    s->prn = jsmall(d, 32767);
            else if (strcmp(key, "gnssid") == 0) s->gnssid = jsmall(d, 127);
            else if (strcmp(key, "svid") == 0)   s->svid = jsmall(d, 32767);
            else if (strcmp(key, "sigid") == 0)  s->sigid = jsmall(d, 127);
            else if (strcmp(key, "health") == 0) s->health = jsmall(d, 2);
            else if (strcmp(key, "el") == 0 && isfinite(d) && d >= -90 && d <= 90)
                                                 { s->el = d; s->has_el = 1; }
            else if (strcmp(key, "az") == 0 && isfinite(d) && d >= 0 && d <= 360)
                                                 { s->az = d; s->has_az = 1; }
            else if (strcmp(key, "ss") == 0 && isfinite(d) && d >= 0 && d <= 99)
                                                 { s->cn0 = d; s->has_cn0 = 1; }
        } else if (*c->p == 't' || *c->p == 'f') {
            int b;
            if (jbool(c, &b) != 0) return -1;
            if (strcmp(key, "used") == 0) s->used = (uint8_t)b;
        } else {
            if (jskip(c) != 0) return -1;
        }
        jws(c);
        if (c->p >= c->e) return -1;
        if (*c->p == ',') { c->p++; continue; }
        if (*c->p == '}') { c->p++; return 0; }
        return -1;
    }
}

/* satellites: [ {...}, ... ]. Entries past GPSD_MAX_SATS are parsed
 * (the line must still balance) and counted, not kept. A PRN-less
 * entry is dropped: gpsd always writes PRN, so one without it is not
 * a satellite. */
static int parse_sats(jcur_t *c, gpsd_msg_t *out) {
    if (c->p >= c->e || *c->p != '[') return -1;
    c->p++;
    jws(c);
    if (c->p < c->e && *c->p == ']') { c->p++; return 0; }
    for (;;) {
        gpsd_sat_t s;
        jws(c);
        if (c->p < c->e && *c->p == '{') {
            if (parse_sat(c, &s) != 0) return -1;
            if (s.prn >= 0) {
                if (out->nsats < GPSD_MAX_SATS) out->sats[out->nsats++] = s;
                else out->sats_overflow++;
            }
        } else {
            if (jskip(c) != 0) return -1;
        }
        jws(c);
        if (c->p >= c->e) return -1;
        if (*c->p == ',') { c->p++; continue; }
        if (*c->p == ']') { c->p++; return 0; }
        return -1;
    }
}

int gpsd_json_parse(const char *line, size_t n, gpsd_msg_t *out) {
    if (!line || !out || n > GPSD_MAX_LINE) return -1;
    memset(out, 0, sizeof(*out));
    out->mode = -1;
    out->status = out->jam = out->leap = -1;
    out->gst_rms = out->gst_major = out->gst_minor = out->gst_orient = -1;
    out->gst_lat = out->gst_lon = out->gst_alt = -1;
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
            if      (strcmp(key, "mode") == 0)   out->mode = jsmall(d, 3) < 0 ? 0 : jsmall(d, 3);
            else if (strcmp(key, "lat") == 0)    { out->lat = d; out->has_lat = 1; }
            else if (strcmp(key, "lon") == 0)    { out->lon = d; out->has_lon = 1; }
            else if (strcmp(key, "altMSL") == 0) { msl = d; have_msl = 1; }
            else if (strcmp(key, "altHAE") == 0) { hae = d; have_hae = 1; }
            else if (strcmp(key, "alt") == 0 && !have_hae) { hae = d; have_hae = 1; }
            else if (strcmp(key, "eph") == 0)    { out->eph = d; out->has_eph = 1; }
            else if (strcmp(key, "epx") == 0)    { out->epx = d; out->has_epx = 1; }
            else if (strcmp(key, "epy") == 0)    { out->epy = d; out->has_epy = 1; }
            else if (strcmp(key, "epv") == 0)    { out->epv = d; out->has_epv = 1; }
            else if (strcmp(key, "eps") == 0)    { out->eps = d; out->has_eps = 1; }
            else if (strcmp(key, "hdop") == 0)   { out->hdop = d; out->has_hdop = 1; }
            else if (strcmp(key, "pdop") == 0)   { out->pdop = d; out->has_pdop = 1; }
            else if (strcmp(key, "vdop") == 0)   { out->vdop = d; out->has_vdop = 1; }
            else if (strcmp(key, "gdop") == 0)   { out->gdop = d; out->has_gdop = 1; }
            else if (strcmp(key, "tdop") == 0)   { out->tdop = d; out->has_tdop = 1; }
            else if (strcmp(key, "speed") == 0)  { out->speed = d; out->has_speed = 1; }
            else if (strcmp(key, "track") == 0)  { out->track = d; out->has_track = 1; }
            else if (strcmp(key, "climb") == 0)  { out->climb = d; out->has_climb = 1; }
            else if (strcmp(key, "status") == 0) out->status = jsmall(d, 9);
            else if (strcmp(key, "jam") == 0)    out->jam = jsmall(d, 255);
            else if (strcmp(key, "leapseconds") == 0) out->leap = jsmall(d, 127);
            else if (strcmp(key, "uSat") == 0 && d >= 0 && d < 1000)
                                                 { out->usat = (int)d; out->has_usat = 1; }
            else if (strcmp(key, "nSat") == 0 && d >= 0 && d < 1000)
                                                 { out->nsat = (int)d; out->has_nsat = 1; }
            else if (strcmp(key, "rms") == 0)    out->gst_rms = d;
            else if (strcmp(key, "major") == 0)  out->gst_major = d;
            else if (strcmp(key, "minor") == 0)  out->gst_minor = d;
            else if (strcmp(key, "orient") == 0) out->gst_orient = d;
        } else if (*c.p == '[' && strcmp(key, "satellites") == 0) {
            out->has_sats = 1;
            if (parse_sats(&c, out) != 0) return -1;
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
    if (strcmp(cls, "GST") == 0) {
        /* GST's lat / lon / alt are standard deviations in metres, not a
         * position: moved out of the position fields so no caller can
         * mistake them for one. */
        out->cls = GPSD_CLS_GST;
        if (out->has_lat) out->gst_lat = out->lat;
        if (out->has_lon) out->gst_lon = out->lon;
        if (out->has_alt) out->gst_alt = out->alt_m;
        out->has_lat = out->has_lon = out->has_alt = 0;
        out->lat = out->lon = out->alt_m = 0.0;
        return 1;
    }
    out->cls = GPSD_CLS_OTHER;
    return 0;
}

/* ── gpsd's "time" ─────────────────────────────────────────────── */

static int digits(const char *s, int n, long *out) {
    long v = 0;
    for (int i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return 0;
}

/* Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
 * days_from_civil), so no mktime and no TZ. */
static long days_from_civil(long y, long m, long d) {
    y -= m <= 2;
    long era = (y >= 0 ? y : y - 399) / 400;
    long yoe = y - era * 400;
    long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

int gpsd_time_parse(const char *s, int64_t *epoch_ms) {
    if (!s || !epoch_ms) return -1;
    size_t n = strlen(s);
    if (n < 20) return -1;
    long y, mo, d, h, mi, se, frac = 0;
    if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':')
        return -1;
    if (digits(s, 4, &y) || digits(s + 5, 2, &mo) || digits(s + 8, 2, &d) ||
        digits(s + 11, 2, &h) || digits(s + 14, 2, &mi) || digits(s + 17, 2, &se))
        return -1;
    size_t i = 19;
    if (s[i] == '.') {
        i++;
        int k = 0;
        long scale = 100;
        while (i < n && s[i] >= '0' && s[i] <= '9') {
            if (k < 3) { frac += (s[i] - '0') * scale; scale /= 10; }
            k++;
            i++;
        }
        if (k == 0) return -1;
    }
    if (i + 1 != n || s[i] != 'Z') return -1;
    if (y < 1970 || y > 2999 || mo < 1 || mo > 12 || d < 1 || d > 31 ||
        h > 23 || mi > 59 || se > 60)
        return -1;
    static const int mdays[12] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (d > mdays[mo - 1]) return -1;
    if (mo == 2 && d == 29 && !((y % 4 == 0 && y % 100 != 0) || y % 400 == 0))
        return -1;
    int64_t days = days_from_civil(y, mo, d);
    *epoch_ms = ((days * 86400 + h * 3600 + mi * 60 + se) * 1000) + frac;
    return 0;
}

const char *gnss_name(int gnssid) {
    switch (gnssid) {
    case 0: return "GPS";
    case 1: return "SBAS";
    case 2: return "Galileo";
    case 3: return "BeiDou";
    case 4: return "IMES";
    case 5: return "QZSS";
    case 6: return "GLONASS";
    case 7: return "NavIC";
    default: return "?";
    }
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
    loc_stamp_t fix;        /* the newest usable fix; fix.ts is wall */
    uint64_t fix_mono;      /* sloth_mono_ms() at its receipt: the age */
    int      sats;
    double   hdop;
    int      quality;
    char     err[96];
    uint64_t sentences, bad_checksum, parse_errors, reconnects;
    /* GNSS observation (2026-11-02): the sky, the newest TPV, and the
     * history the GNSS rules read (src/alerts/rules_gnss.c). */
    gnss_sky_t  sky;
    gnss_fix_t  gfix;
    gnss_hist_t hist;
    time_t      sec_last;   /* the second the newest series point is for */
    int         fix_gap;    /* a TPV said no fix, or the source went away,
                             * since the newest positioned fix: the next
                             * one is a reacquisition (gnss_fix_pt_t.reacq) */
} g_loc = { .quality = -1 };

/* The per-poll copy of g_loc.hist that s->gnss_hist points at: written
 * only by gps_health_poll() on the main thread, read by the rules on the
 * same thread after it. */
static gnss_hist_t g_hist_snap;

static int range_ok(double lat, double lon) {
    return isfinite(lat) && isfinite(lon) &&
           lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0;
}

/* The bounds a receiver's figures must sit inside before sloth records
 * them. gpsd's JSON numbers may carry any exponent ("eph":1e400 reads as
 * +inf) and a GGA field may hold 24 digits, and either would reach the
 * JSONL, the --db REAL columns and /api/positions as inf or as a value
 * gps_fmt_fixed() cannot print. Altitude takes --location's range. */
#define GPS_ACC_MAX_M 1e5
static int acc_ok(double acc) {
    return isfinite(acc) && acc >= 0.0 && acc <= GPS_ACC_MAX_M;
}
static int alt_ok(double alt) {
    return isfinite(alt) && alt >= -1000.0 && alt <= 20000.0;
}
static int hdop_ok(double hdop) {
    return isfinite(hdop) && hdop >= 0.0 && acc_ok(nmea_acc_m(hdop));
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
    if (has_alt && !alt_ok(alt)) has_alt = 0;
    if (has_acc && !acc_ok(acc)) has_acc = 0;
    g_loc.fix.src = LOC_SRC_GPS;
    g_loc.fix.lat = lat;
    g_loc.fix.lon = lon;
    g_loc.fix.has_alt = has_alt ? 1 : 0;
    g_loc.fix.alt_m = has_alt ? alt : 0.0;
    g_loc.fix.has_acc = has_acc ? 1 : 0;
    g_loc.fix.acc_m = has_acc ? acc : 0.0;
    g_loc.fix.ts = wall;
    g_loc.fix_mono = sloth_mono_ms();
    g_loc.ever_fix = 1;
    g_loc.fix_live = 1;
}

void gps_location_feed_nmea(const nmea_fix_t *f, time_t wall) {
    if (!f) return;
    pthread_mutex_lock(&g_mu);
    if (f->sats >= 0) g_loc.sats = f->sats;
    int hdop_good = f->has_hdop && hdop_ok(f->hdop);
    if (hdop_good) g_loc.hdop = f->hdop;
    g_loc.quality = f->quality >= 0 ? f->quality : g_loc.quality;
    /* Only a sentence that carried a position stamps one: a GSA (or a
     * GGA/RMC that still says "fix") leaves the older position to age
     * out against gps.max_fix_age_s rather than renewing it at `wall`. */
    if (!nmea_fix_usable(f))
        g_loc.fix_live = 0;   /* the receiver said it has no fix */
    else if (f->pos_new)
        take_fix(f->lat, f->lon, f->has_alt, f->alt_m,
                 hdop_good, nmea_acc_m(f->hdop), wall);
    pthread_mutex_unlock(&g_mu);
}

/* A DOP is kept when finite and inside the range a receiver reports
 * (0..100); 0 marks absent. */
static double dop_ok(int has, double v) {
    return (has && isfinite(v) && v >= 0.0 && v <= 100.0) ? v : 0.0;
}

/* Caller holds g_mu. The SKY's satellites into the sky state, with the
 * C/N0 statistics the records and the later detectors read. */
static void take_sky(const gpsd_msg_t *m, time_t wall) {
    gnss_sky_t *k = &g_loc.sky;
    if (!m->has_sats && !m->has_nsat && !m->has_usat) {
        /* A SKY carrying only DOPs (gpsd splits them on some drivers):
         * the DOPs update, the satellite rows stand. One that carries
         * the satellites key, empty, or nSat / uSat is a sky with that
         * in it, and empties the rows: the antenna is gone. */
        if (m->has_hdop && hdop_ok(m->hdop)) k->hdop = m->hdop;
        if (dop_ok(m->has_pdop, m->pdop) > 0) k->pdop = m->pdop;
        if (dop_ok(m->has_vdop, m->vdop) > 0) k->vdop = m->vdop;
        return;
    }
    k->valid = 1;
    k->ts = wall;
    k->mono_ms = sloth_mono_ms();
    k->nsat = m->has_nsat ? m->nsat : (m->nsats ? m->nsats + m->sats_overflow : -1);
    k->usat = m->has_usat ? m->usat : -1;
    k->n = 0;
    k->overflow = m->sats_overflow;
    double sum = 0, sq = 0, mx = 0;
    int cn = 0;
    for (int i = 0; i < m->nsats && i < GNSS_MAX_SATS; i++) {
        const gpsd_sat_t *a = &m->sats[i];
        gnss_sat_t *b = &k->sats[k->n++];
        b->prn = (int16_t)a->prn;
        b->gnssid = (int8_t)a->gnssid;
        b->svid = (int16_t)a->svid;
        b->sigid = (int8_t)a->sigid;
        b->health = (int8_t)a->health;
        b->has_el = a->has_el;
        b->has_az = a->has_az;
        b->el = (int16_t)(a->has_el ? (int)(a->el + (a->el >= 0 ? 0.5 : -0.5)) : 0);
        b->az = (int16_t)(a->has_az ? (int)(a->az + 0.5) : 0);
        b->used = a->used;
        b->has_cn0 = a->has_cn0;
        b->cn0_x10 = (int16_t)(a->has_cn0 ? (int)(a->cn0 * 10.0 + 0.5) : 0);
        if (a->has_cn0) {
            sum += a->cn0;
            sq += a->cn0 * a->cn0;
            if (a->cn0 > mx) mx = a->cn0;
            cn++;
        }
    }
    k->cn0_n = cn;
    k->cn0_mean = cn ? sum / cn : 0.0;
    k->cn0_max = mx;
    double var = cn ? sq / cn - k->cn0_mean * k->cn0_mean : 0.0;
    k->cn0_sd = var > 0 ? sqrt(var) : 0.0;
    /* A full SKY's DOPs are the pass's: one it does not carry is
     * unknown for this pass, hdop as the other four. */
    k->hdop = (m->has_hdop && hdop_ok(m->hdop)) ? m->hdop : 0.0;
    k->pdop = dop_ok(m->has_pdop, m->pdop);
    k->vdop = dop_ok(m->has_vdop, m->vdop);
    k->gdop = dop_ok(m->has_gdop, m->gdop);
    k->tdop = dop_ok(m->has_tdop, m->tdop);
    k->passes++;
}

/* The median C/N0 x 10 of the sky's tracked rows (ss > 0), 0 when none
 * is. Tracked only: gpsd lists satellites it is not tracking at ss 0,
 * and averaging those in turned a building blocking four of ten
 * satellites into a 12 dB "collapse" while the other six sat at exactly
 * their old level. The median, because the jamming signature is most of
 * the tracked set falling together; a subset lost to an obstruction
 * leaves it where the rest are. */
static int sky_tracked_median_x10(const gnss_sky_t *k, int *n_out) {
    int16_t v[GNSS_MAX_SATS];
    int n = 0;
    for (int i = 0; i < k->n && i < GNSS_MAX_SATS; i++) {
        const gnss_sat_t *a = &k->sats[i];
        if (!a->has_cn0 || a->cn0_x10 <= 0) continue;
        int j = n++;
        while (j > 0 && v[j - 1] > a->cn0_x10) { v[j] = v[j - 1]; j--; }
        v[j] = a->cn0_x10;
    }
    *n_out = n;
    if (n == 0) return 0;
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2] + 1) / 2;
}

/* Caller holds g_mu. One point per second of the sky's summary, for
 * the jamming detector's window; the newest point of a second wins. */
static void push_sec(time_t wall) {
    gnss_hist_t *h = &g_loc.hist;
    gnss_sec_pt_t pt;
    memset(&pt, 0, sizeof(pt));
    pt.ts = wall;
    pt.mono_ms = g_loc.gfix.host_mono_ms;
    pt.mode = (uint8_t)(g_loc.gfix.mode > 0 && g_loc.gfix.mode <= 3 ? g_loc.gfix.mode : 0);
    int trk = 0;
    pt.cn0_med_x10 = (int16_t)sky_tracked_median_x10(&g_loc.sky, &trk);
    pt.trk = (uint8_t)(trk > 255 ? 255 : trk);
    pt.jam = (int16_t)g_loc.gfix.jam;
    pt.usat = (uint8_t)(g_loc.sky.usat > 0 ? (g_loc.sky.usat > 255 ? 255 : g_loc.sky.usat) : 0);
    pt.nsat = (uint8_t)(g_loc.sky.nsat > 0 ? (g_loc.sky.nsat > 255 ? 255 : g_loc.sky.nsat) : 0);
    if (h->sec_n > 0 && g_loc.sec_last == wall) {
        int last = (h->sec_head + GNSS_SERIES_S - 1) % GNSS_SERIES_S;
        h->secs[last] = pt;
        return;
    }
    h->secs[h->sec_head] = pt;
    h->sec_head = (h->sec_head + 1) % GNSS_SERIES_S;
    if (h->sec_n < GNSS_SERIES_S) h->sec_n++;
    g_loc.sec_last = wall;
}

/* Caller holds g_mu. */
static void push_fix_pt(const gnss_fix_t *f) {
    gnss_hist_t *h = &g_loc.hist;
    gnss_fix_pt_t *p = &h->fixes[h->fix_head];
    memset(p, 0, sizeof(*p));
    p->ts = f->ts;
    p->seq = f->count;
    p->mono_ms = f->host_mono_ms;
    p->wall_ms = f->host_wall_ms;
    p->has_speed = f->has_speed;
    p->speed = f->speed;
    p->has_eps = f->has_eps;
    p->eps = f->eps;
    p->has_rx_time = f->has_rx_time;
    p->rx_time_ms = f->rx_time_ms;
    p->leap = f->leap;
    p->reacq = (h->fix_n == 0 || g_loc.fix_gap) ? 1 : 0;
    g_loc.fix_gap = 0;
    p->lat = f->lat;
    p->lon = f->lon;
    p->has_alt = f->has_alt;
    p->alt_m = f->alt_m;
    p->has_eph = f->has_eph;
    p->eph = f->eph;
    p->mode = f->mode;
    p->usat = g_loc.sky.usat;
    p->has_time_off = f->has_time_off;
    p->time_off_ms = f->time_off_ms;
    h->fix_head = (h->fix_head + 1) % GNSS_FIX_HIST;
    if (h->fix_n < GNSS_FIX_HIST) h->fix_n++;
}

/* The clock-offset band with hysteresis. The raw band
 * (gps_time_off_band) has edges at 500 ms, 2 s and 10 s; the held band
 * moves to a new one only once |off| is past the edge between them by
 * a quarter of that edge (125 ms, 500 ms, 2.5 s). A 9600-baud receiver
 * through gpsd with no PPS sits 200..700 ms behind the host at line
 * framing and jitters, so the raw band flipped 0 <-> 1 TPV by TPV and
 * each flip was a gnss_fix line, a sensor_health line and a gnss_fixes
 * row. `held` is -1 before any offset. */
static int time_off_band_held(int held, long long off_ms) {
    static const long long edge[3] = { 500, 2000, 10000 };
    int raw = gps_time_off_band(1, off_ms);
    if (held < 0 || raw == held) return raw;
    long long a = off_ms < 0 ? -off_ms : off_ms;
    if (raw > held) {
        long long e = edge[raw - 1];
        return a >= e + e / 4 ? raw : held;
    }
    long long e = edge[raw];
    return a <= e - e / 4 ? raw : held;
}

/* Caller holds g_mu. The TPV into the fix state. Every figure is range
 * checked as take_fix() checks the position's; one outside is dropped
 * (has_* 0), never recorded. The GST figures outlive a TPV. */
static void take_tpv(const gpsd_msg_t *m, time_t wall, int64_t wall_ms) {
    gnss_fix_t *f = &g_loc.gfix;
    gnss_fix_t keep = *f;
    memset(f, 0, sizeof(*f));
    f->valid = 1;
    f->ts = wall;
    f->host_wall_ms = (long long)wall_ms;
    f->host_mono_ms = sloth_mono_ms();
    f->count = keep.count + 1;
    f->mode = m->mode < 0 ? 0 : m->mode;
    /* An explicit mode 0 or 1 is the receiver saying it has no fix; a
     * TPV without a mode says nothing either way. */
    if (m->mode >= 0 && m->mode < 2) g_loc.fix_gap = 1;
    f->status = m->status;
    f->leap = m->leap;
    /* jam rides only the TPV after a UBX-MON-HW poll: a TPV without it
     * keeps the last value for GNSS_JAM_HOLD_TPVS TPVs, then it is
     * absent again. Per TPV it flipped -1 / value every second and
     * signed gnss_fix and sensor_health on every tick. */
    if (m->jam >= 0) {
        f->jam = m->jam;
        f->jam_tpv = f->count;
    } else if (keep.jam >= 0 && f->count - keep.jam_tpv <= GNSS_JAM_HOLD_TPVS) {
        f->jam = keep.jam;
        f->jam_tpv = keep.jam_tpv;
    } else {
        f->jam = -1;
    }
    f->time_off_band = -1;
    if (m->has_lat && m->has_lon && range_ok(m->lat, m->lon)) {
        f->has_pos = 1;
        f->lat = m->lat;
        f->lon = m->lon;
    }
    if (m->has_alt && alt_ok(m->alt_m)) { f->has_alt = 1; f->alt_m = m->alt_m; }
    if (m->has_eph && acc_ok(m->eph)) { f->has_eph = 1; f->eph = m->eph; }
    if (m->has_epv && acc_ok(m->epv)) { f->has_epv = 1; f->epv = m->epv; }
    if (m->has_speed && isfinite(m->speed) && m->speed >= 0 && m->speed < 1e4)
        { f->has_speed = 1; f->speed = m->speed; }
    if (m->has_eps && isfinite(m->eps) && m->eps >= 0 && m->eps < 1e4)
        { f->has_eps = 1; f->eps = m->eps; }
    if (m->has_track && isfinite(m->track) && m->track >= 0 && m->track <= 360)
        { f->has_track = 1; f->track = m->track; }
    if (m->has_climb && isfinite(m->climb) && m->climb > -1e4 && m->climb < 1e4)
        { f->has_climb = 1; f->climb = m->climb; }
    int64_t rx;
    if (m->time[0] && gpsd_time_parse(m->time, &rx) == 0) {
        f->has_rx_time = 1;
        f->rx_time_ms = rx;
        /* The receiver's stamp against the host's clock as the line was
         * framed. Coarse: serial / USB and gpsd latency sit in it, and
         * there is no PPS; it shows a multi-second step, not sync
         * quality (docs/wiki/gnss.md). */
        f->has_time_off = 1;
        f->time_off_ms = rx - wall_ms;
        f->time_off_band = time_off_band_held(keep.time_off_band, f->time_off_ms);
    }
    if (keep.has_gst) {
        f->has_gst = 1;
        f->gst_rms = keep.gst_rms; f->gst_major = keep.gst_major;
        f->gst_minor = keep.gst_minor; f->gst_orient = keep.gst_orient;
        f->gst_lat_sd = keep.gst_lat_sd; f->gst_lon_sd = keep.gst_lon_sd;
        f->gst_alt_sd = keep.gst_alt_sd;
    }
    if (f->mode >= 2 && f->has_pos) push_fix_pt(f);
    push_sec(wall);
}

/* Caller holds g_mu. A GST's figures onto the fix; -1 means absent and
 * is kept as 0 / not recorded. */
static void take_gst(const gpsd_msg_t *m) {
    gnss_fix_t *f = &g_loc.gfix;
    double v[7] = { m->gst_rms, m->gst_major, m->gst_minor, m->gst_orient,
                    m->gst_lat, m->gst_lon, m->gst_alt };
    int any = 0;
    for (int i = 0; i < 7; i++) {
        if (!(isfinite(v[i]) && v[i] >= 0 && v[i] <= 1e5)) v[i] = 0.0;
        else any = 1;
    }
    if (!any) return;
    f->has_gst = 1;
    f->gst_rms = v[0]; f->gst_major = v[1]; f->gst_minor = v[2];
    f->gst_orient = v[3]; f->gst_lat_sd = v[4]; f->gst_lon_sd = v[5];
    f->gst_alt_sd = v[6];
}

static void feed_gpsd(const gpsd_msg_t *m, time_t wall, int64_t wall_ms) {
    if (!m) return;
    pthread_mutex_lock(&g_mu);
    if (m->cls == GPSD_CLS_SKY) {
        if (m->has_usat) g_loc.sats = m->usat;
        if (m->has_hdop && hdop_ok(m->hdop)) g_loc.hdop = m->hdop;
        take_sky(m, wall);
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
        take_tpv(m, wall, wall_ms);
    } else if (m->cls == GPSD_CLS_TPV) {
        take_tpv(m, wall, wall_ms);   /* mode absent: still a TPV */
    } else if (m->cls == GPSD_CLS_GST) {
        take_gst(m);
    }
    pthread_mutex_unlock(&g_mu);
}

void gps_location_feed_gpsd(const gpsd_msg_t *m, time_t wall) {
    feed_gpsd(m, wall, (int64_t)wall * 1000);
}

void gps_location_feed_gpsd_ms(const gpsd_msg_t *m, int64_t wall_ms) {
    int64_t w = wall_ms >= 0 ? wall_ms / 1000 : -((-wall_ms + 999) / 1000);
    feed_gpsd(m, (time_t)w, wall_ms);
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

void gps_location_source_lost(void) {
    pthread_mutex_lock(&g_mu);
    g_loc.fix_live = 0;
    g_loc.fix_gap = 1;      /* a reconnect's first fix has no prior */
    pthread_mutex_unlock(&g_mu);
}

void gps_location_set_err(const char *err) {
    pthread_mutex_lock(&g_mu);
    snprintf(g_loc.err, sizeof(g_loc.err), "%s", err ? err : "");
    pthread_mutex_unlock(&g_mu);
}

/* Caller holds g_mu. Seconds since the newest fix arrived, on sloth's
 * monotonic clock: a wall-clock step (NTP correcting a fake-hwclock Pi,
 * an operator setting the date) neither keeps an old fix fresh nor ages
 * a new one. fix.ts stays wall time, as the stamp reports it. */
static long fix_age_s(void) {
    uint64_t now = sloth_mono_ms();
    if (now <= g_loc.fix_mono) return 0;
    uint64_t s = (now - g_loc.fix_mono) / 1000u;
    return s > 0x7fffffffu ? 0x7fffffffL : (long)s;
}

/* Caller holds g_mu. 1 when the newest fix may stamp now. */
static int fix_fresh(void) {
    if (!g_loc.has_gps || !g_loc.ever_fix || !g_loc.fix_live) return 0;
    return fix_age_s() <= tune_val(TUNE_GPS_MAX_FIX_AGE_S);
}

int gps_location_current(loc_stamp_t *out, time_t now) {
    if (!out) return LOC_SRC_NONE;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&g_mu);
    if (fix_fresh()) {
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
    /* `now` stamps a fixed position only; the fix's age is monotonic
     * (fix_age_s()). */
    gps_health_t *h = &s->gps;
    memset(h, 0, sizeof(*h));
    pthread_mutex_lock(&g_mu);
    h->has_fixed = g_loc.has_fixed;
    h->has_gps = g_loc.has_gps;
    h->configured = h->has_fixed || h->has_gps;
    h->fix_age_s = -1;
    if (g_loc.ever_fix) h->fix_age_s = (int)fix_age_s();
    if (!h->configured)            h->state = GPS_NONE;
    else if (!h->has_gps)          h->state = GPS_FIXED_ONLY;
    else if (fix_fresh())          h->state = GPS_FIX;
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
    /* GNSS observation (2026-11-02). */
    h->sats_in_view = g_loc.sky.nsat > 0 ? g_loc.sky.nsat : 0;
    h->sats_used    = g_loc.sky.usat > 0 ? g_loc.sky.usat : 0;
    h->cn0_mean     = g_loc.sky.cn0_mean;
    h->cn0_max      = g_loc.sky.cn0_max;
    h->has_time_off = g_loc.gfix.has_time_off;
    h->time_off_ms  = g_loc.gfix.time_off_ms;
    h->time_off_band = g_loc.gfix.valid ? g_loc.gfix.time_off_band : -1;
    h->pdop         = g_loc.sky.pdop;
    h->vdop         = g_loc.sky.vdop;
    h->status       = g_loc.gfix.valid ? g_loc.gfix.status : -1;
    h->jam          = g_loc.gfix.valid ? g_loc.gfix.jam : -1;
    s->gnss_sky = g_loc.sky;
    s->gnss_fix = g_loc.gfix;
    g_hist_snap = g_loc.hist;
    s->gnss_hist = &g_hist_snap;
    pthread_mutex_unlock(&g_mu);
    /* After the unlock: gps_location_current() takes g_mu itself. */
    loc_stamp_t st;
    h->has_loc = gps_location_current(&st, now) != LOC_SRC_NONE;
    if (h->has_loc) {
        h->loc_src = st.src;
        h->loc_lat = st.lat;
        h->loc_lon = st.lon;
        h->loc_has_alt = st.has_alt;
        h->loc_alt_m = st.alt_m;
    }
}

void gps_location_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(&g_loc, 0, sizeof(g_loc));
    g_loc.quality = -1;
    pthread_mutex_unlock(&g_mu);
}

/* ── GNSS observation: snapshots, history, signatures ─────────── */

void gps_sky_snapshot(gnss_sky_t *out) {
    if (!out) return;
    pthread_mutex_lock(&g_mu);
    *out = g_loc.sky;
    pthread_mutex_unlock(&g_mu);
}

void gps_fix_snapshot(gnss_fix_t *out) {
    if (!out) return;
    pthread_mutex_lock(&g_mu);
    *out = g_loc.gfix;
    pthread_mutex_unlock(&g_mu);
}

void gps_gnss_history(gnss_hist_t *out) {
    if (!out) return;
    pthread_mutex_lock(&g_mu);
    *out = g_loc.hist;
    pthread_mutex_unlock(&g_mu);
}

static int dop_band(double v) {
    if (v <= 0) return -1;
    return v < 1 ? 0 : v < 2 ? 1 : v < 5 ? 2 : 3;
}

int gps_cn0_band(double cn0_mean) {
    if (cn0_mean <= 0) return -1;
    return cn0_mean < 25 ? 0 : cn0_mean < 35 ? 1 : 2;
}

int gps_time_off_band(int has, long long off_ms) {
    if (!has) return -1;
    long long a = off_ms < 0 ? -off_ms : off_ms;
    return a < 500 ? 0 : a < 2000 ? 1 : a < 10000 ? 2 : 3;
}

/* u-blox jamInd semantics (receiver description, UBX-MON-HW): 0 no
 * CW jamming, 255 strong. */
int gps_jam_band(int jam) {
    if (jam < 0) return -1;
    return jam == 0 ? 0 : jam < 64 ? 1 : jam < 128 ? 2 : 3;
}

/* The used count as a solution-quality band: none, under the four a
 * 3D fix needs, a thin fix, a fair one, a good one. Raw it flaps by
 * one every few seconds in a built-up area and wrote a record each
 * time; the per-satellite `used` flag already carries which bird
 * joined or left. */
int gps_usat_band(int usat) {
    if (usat < 0) return -1;
    return usat == 0 ? 0 : usat < 4 ? 1 : usat < 6 ? 2 : usat < 8 ? 3 : 4;
}

static uint64_t mix64(uint64_t h, long long v) {
    h ^= (uint64_t)v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h * 0x100000001b3ULL;
}

uint64_t gps_gnss_fix_sig(const gnss_fix_t *f, const gnss_sky_t *k) {
    uint64_t h = 0xcbf29ce484222325ULL;
    if (!f) return h;
    h = mix64(h, f->valid);
    h = mix64(h, f->mode);
    h = mix64(h, f->status);
    h = mix64(h, gps_usat_band(k ? k->usat : -1));
    h = mix64(h, k && k->nsat > 0 ? k->nsat / 4 : -1);
    h = mix64(h, dop_band(k ? k->hdop : 0));
    h = mix64(h, dop_band(k ? k->pdop : 0));
    h = mix64(h, f->has_time_off ? f->time_off_band : -1);
    int sp = !f->has_speed ? -1 : f->speed < 0.5 ? 0 : f->speed < 2 ? 1
           : f->speed < 30 ? 2 : 3;
    h = mix64(h, sp);
    h = mix64(h, gps_jam_band(f->jam));
    h = mix64(h, f->has_pos);
    return h;
}

uint64_t gps_gnss_sat_sig(const gnss_sat_t *s) {
    uint64_t h = 0x84222325cbf29ce4ULL;
    if (!s) return h;
    h = mix64(h, s->prn);
    h = mix64(h, s->gnssid);
    h = mix64(h, s->svid);
    h = mix64(h, s->used);
    h = mix64(h, s->health);
    h = mix64(h, s->has_cn0 ? s->cn0_x10 / 60 : -1);   /* 6 dB */
    h = mix64(h, s->has_el ? (s->el + 90) / 15 : -1);  /* 15 degrees, -90.. */
    h = mix64(h, s->has_az ? s->az / 15 : -1);
    return h;
}

uint64_t gps_gnss_sky_sig(const gnss_sky_t *k) {
    uint64_t h = 0x2325cbf29ce48422ULL;
    if (!k) return h;
    h = mix64(h, k->valid);
    h = mix64(h, k->nsat > 0 ? k->nsat / 4 : -1);
    h = mix64(h, gps_usat_band(k->usat));
    h = mix64(h, dop_band(k->hdop));
    h = mix64(h, dop_band(k->pdop));
    h = mix64(h, dop_band(k->vdop));
    h = mix64(h, gps_cn0_band(k->cn0_mean));
    return h;
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
        /* The scratch is the framer's own (gps_lines_t.msg): one
         * reader per framer is then structural, not an invariant a
         * second receiver could silently break. */
        int r = gpsd_json_parse(l->buf, n, &l->msg);
        if (r < 0) { gps_location_note(0, 0, 1, 0); return; }
        gps_location_note(1, 0, 0, 0);
        /* The clock offset is measured against the host's millisecond
         * wall clock as the line was framed; the fix keeps `wall`. */
        if (r == 1) feed_gpsd(&l->msg, wall, sloth_wall_ms());
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
