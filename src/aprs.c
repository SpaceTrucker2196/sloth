#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "aprs.h"

/* Contract in aprs.h. Pure except the table at the bottom, one
 * mutex-guarded struct the reader feeds and the main thread polls. */

/* ── CSV, as Dire Wolf's quote_for_csv() writes it ────────────────── */

typedef struct { const char *p; size_t n; } fld_t;

/* Split line[0..n) into exactly APRS_FIELDS fields, unquoting into
 * store (which holds at most n bytes plus a NUL per field). -1 on the
 * wrong count, a quoted field not closed or followed by anything but
 * ',' or the end, or a bare '"' inside an unquoted field - Dire Wolf
 * quotes every field that holds one, so a bare quote is not its
 * writing. */
static int csv_split(const char *line, size_t n, fld_t f[APRS_FIELDS],
                     char *store, size_t storesz) {
    size_t i = 0, o = 0;
    int k = 0;
    for (;;) {
        if (k >= APRS_FIELDS) return -1;
        size_t start = o;
        if (i < n && line[i] == '"') {
            i++;
            for (;;) {
                if (i >= n) return -1;               /* not closed */
                if (line[i] == '"') {
                    if (i + 1 < n && line[i + 1] == '"') {
                        if (o >= storesz) return -1;
                        store[o++] = '"';
                        i += 2;
                        continue;
                    }
                    i++;
                    break;
                }
                if (o >= storesz) return -1;
                store[o++] = line[i++];
            }
            if (i < n && line[i] != ',') return -1;
        } else {
            while (i < n && line[i] != ',') {
                if (line[i] == '"') return -1;
                if (o >= storesz) return -1;
                store[o++] = line[i++];
            }
        }
        f[k].p = store + start;
        f[k].n = o - start;
        k++;
        if (o >= storesz) return -1;
        store[o++] = '\0';
        if (i >= n) break;
        i++;                                         /* the ',' */
        if (i == n) {                                /* a trailing empty field */
            if (k >= APRS_FIELDS) return -1;
            f[k].p = store + o;
            f[k].n = 0;
            if (o >= storesz) return -1;
            store[o++] = '\0';
            k++;
            break;
        }
    }
    return k == APRS_FIELDS ? 0 : -1;
}

/* ── Field validation ──────────────────────────────────────────── */

/* A decimal integer, optional sign, at most 12 digits, nothing else. */
static int int_parse(const fld_t *f, long long *out) {
    size_t i = 0;
    int neg = 0;
    long long v = 0;
    if (f->n == 0 || f->n > 13) return -1;
    if (f->p[0] == '-' || f->p[0] == '+') { neg = f->p[0] == '-'; i++; }
    if (i >= f->n) return -1;
    for (; i < f->n; i++) {
        if (f->p[i] < '0' || f->p[i] > '9') return -1;
        v = v * 10 + (f->p[i] - '0');
    }
    *out = neg ? -v : v;
    return 0;
}

/* A decimal number as log.c's "%.1f" / "%.6f" write it: optional sign,
 * digits, optionally '.' and digits, at most 20 bytes, no exponent.
 * The same locale-free digit walk src/adsb.c uses (strtod honours
 * LC_NUMERIC, and the TUI calls setlocale). */
static int dec_parse(const fld_t *f, double *out) {
    size_t i = 0;
    int neg = 0, digits = 0;
    double v = 0.0, scale = 1.0;
    if (f->n == 0 || f->n > 20) return -1;
    if (f->p[0] == '-' || f->p[0] == '+') { neg = f->p[0] == '-'; i++; }
    while (i < f->n && f->p[i] >= '0' && f->p[i] <= '9') {
        v = v * 10.0 + (f->p[i++] - '0');
        digits++;
    }
    if (i < f->n && f->p[i] == '.') {
        i++;
        while (i < f->n && f->p[i] >= '0' && f->p[i] <= '9') {
            scale /= 10.0;
            v += (f->p[i++] - '0') * scale;
            digits++;
        }
    }
    if (!digits || i != f->n) return -1;
    *out = neg ? -v : v;
    return 0;
}

static int in_range(double d, double lo, double hi) {
    return isfinite(d) && d >= lo && d <= hi;
}

static int call_chr(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

int aprs_call_ok(const char *s) {
    if (!s) return 0;
    size_t b = 0;
    while (call_chr(s[b])) b++;
    if (b < 1 || b > 6) return 0;
    if (s[b] == '\0') return 1;
    if (s[b] != '-') return 0;
    size_t e = 1;
    while (call_chr(s[b + e])) e++;
    return (e == 2 || e == 3) && s[b + e] == '\0';
}

/* A field into dst (cap dstsz) when it is a callsign. */
static int call_take(const fld_t *f, char *dst, size_t dstsz) {
    if (f->n == 0 || f->n >= dstsz) return -1;
    memcpy(dst, f->p, f->n);
    dst[f->n] = '\0';
    if (!aprs_call_ok(dst)) { dst[0] = '\0'; return -1; }
    return 0;
}

/* Free text: printable ASCII kept, every other byte '?', cut at max. */
static void text_take(const fld_t *f, char *dst, size_t max) {
    size_t n = f->n < max ? f->n : max;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)f->p[i];
        dst[i] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
    }
    dst[n] = '\0';
}

/* A short field of one character class, whole or absent. */
static void class_take(const fld_t *f, char *dst, size_t dstsz,
                       const char *allowed) {
    dst[0] = '\0';
    if (f->n == 0 || f->n >= dstsz) return;
    for (size_t i = 0; i < f->n; i++)
        if (!f->p[i] || !strchr(allowed, f->p[i])) return;
    memcpy(dst, f->p, f->n);
    dst[f->n] = '\0';
}

static int printable(const fld_t *f) {
    for (size_t i = 0; i < f->n; i++)
        if ((unsigned char)f->p[i] < 0x20 || (unsigned char)f->p[i] > 0x7e) return 0;
    return 1;
}

/* The earliest and latest utime believed: 2000-01-01 .. 2100-01-01. */
#define APRS_UTIME_MIN 946684800LL
#define APRS_UTIME_MAX 4102444800LL

enum { F_CHAN, F_UTIME, F_ISOTIME, F_SOURCE, F_HEARD, F_LEVEL, F_ERROR,
       F_DTI, F_NAME, F_SYMBOL, F_LAT, F_LON, F_SPEED, F_COURSE, F_ALT,
       F_FREQ, F_OFFSET, F_TONE, F_SYSTEM, F_STATUS, F_TELEMETRY, F_COMMENT };

int aprs_line_parse(const char *line, size_t n, aprs_packet_t *out) {
    if (!line || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->level = out->error = -1;
    if (n && line[n - 1] == '\r') n--;
    size_t b = 0;
    while (b < n && (line[b] == ' ' || line[b] == '\t' || line[b] == '\r')) b++;
    if (b == n) return 0;                            /* blank */
    if (n > APRS_MAX_LINE) return -1;
    if (n >= 5 && memcmp(line, "chan,", 5) == 0) return 0;   /* the header */
    fld_t f[APRS_FIELDS];
    char store[APRS_MAX_LINE + APRS_FIELDS + 1];
    if (csv_split(line, n, f, store, sizeof(store)) != 0) return -1;

    long long v;
    if (int_parse(&f[F_CHAN], &v) != 0 || v < 0 || v > 255) return -1;
    out->chan = (int)v;
    if (int_parse(&f[F_UTIME], &v) != 0 || v < APRS_UTIME_MIN || v > APRS_UTIME_MAX)
        return -1;
    out->utime = (time_t)v;
    if (call_take(&f[F_SOURCE], out->source, sizeof(out->source)) != 0) return -1;
    if (f[F_HEARD].n && call_take(&f[F_HEARD], out->heard, sizeof(out->heard)) != 0)
        return -1;

    /* level: "50(14/14)" - the audio level, then mark / space levels in
     * parentheses. The leading integer only. */
    {
        size_t i = 0;
        long long lv = 0;
        while (i < f[F_LEVEL].n && i < 4 && f[F_LEVEL].p[i] >= '0' && f[F_LEVEL].p[i] <= '9')
            lv = lv * 10 + (f[F_LEVEL].p[i++] - '0');
        if (i > 0 && i < 4 && (i == f[F_LEVEL].n || f[F_LEVEL].p[i] == '('))
            out->level = (int)lv;
    }
    if (int_parse(&f[F_ERROR], &v) == 0 && v >= 0 && v <= 999) out->error = (int)v;
    if (f[F_DTI].n == 1 && printable(&f[F_DTI])) out->dti = f[F_DTI].p[0];
    {
        fld_t nm = f[F_NAME];
        while (nm.n && nm.p[nm.n - 1] == ' ') nm.n--;
        if (nm.n && nm.n <= APRS_CALL_MAX && nm.p[0] != ' ' && printable(&nm)) {
            memcpy(out->name, nm.p, nm.n);
            out->name[nm.n] = '\0';
        }
    }
    if (f[F_SYMBOL].n == 2 && printable(&f[F_SYMBOL])) {
        out->symbol[0] = f[F_SYMBOL].p[0];
        out->symbol[1] = f[F_SYMBOL].p[1];
        out->symbol[2] = '\0';
    }
    double lat, lon, d;
    if (dec_parse(&f[F_LAT], &lat) == 0 && dec_parse(&f[F_LON], &lon) == 0 &&
        in_range(lat, -90, 90) && in_range(lon, -180, 180)) {
        out->lat = lat; out->lon = lon; out->has_pos = 1;
    }
    if (dec_parse(&f[F_SPEED], &d) == 0 && in_range(d, 0, 2000)) {
        out->speed_kt = d; out->has_speed = 1;
    }
    if (dec_parse(&f[F_COURSE], &d) == 0 && in_range(d, 0, 360)) {
        out->course = d; out->has_course = 1;
    }
    if (dec_parse(&f[F_ALT], &d) == 0 && in_range(d, -1000, 100000)) {
        out->alt_m = d; out->has_alt = 1;
    }
    /* frequency "%.3f" MHz, offset "%+d" kHz, tone "%.1f" Hz or a DCS
     * code "D%03o": kept as written when they look like that. */
    class_take(&f[F_FREQ], out->freq, sizeof(out->freq), "0123456789.");
    class_take(&f[F_OFFSET], out->offset, sizeof(out->offset), "0123456789+-");
    class_take(&f[F_TONE], out->tone, sizeof(out->tone), "0123456789.D");
    text_take(&f[F_SYSTEM], out->system, APRS_TEXT_MAX);
    text_take(&f[F_STATUS], out->status, APRS_TEXT_MAX);
    text_take(&f[F_TELEMETRY], out->telemetry, APRS_TEXT_MAX);
    text_take(&f[F_COMMENT], out->comment, APRS_COMMENT_MAX);
    return 1;
}

/* ── The --aprs SPEC ───────────────────────────────────────────── */

int aprs_spec_parse(const char *spec, char *path, size_t pathsz,
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
                     "or file:///path to Dire Wolf's packet log (-L)");
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

/* ── The cell and the signature ────────────────────────────────── */

static int32_t cell_of(double deg) { return (int32_t)floor(deg * 100.0); }

/* Hold the station's cell unless the position left it by the margin. */
static void cell_hold(aprs_station_t *r) {
    if (!r->has_pos) return;
    int32_t clat = cell_of(r->lat), clon = cell_of(r->lon);
    if (r->has_cell && (clat != r->cell_lat || clon != r->cell_lon)) {
        double lo_lat = r->cell_lat / 100.0 - APRS_CELL_HYST_DEG;
        double hi_lat = (r->cell_lat + 1) / 100.0 + APRS_CELL_HYST_DEG;
        double lo_lon = r->cell_lon / 100.0 - APRS_CELL_HYST_DEG;
        double hi_lon = (r->cell_lon + 1) / 100.0 + APRS_CELL_HYST_DEG;
        if (r->lat >= lo_lat && r->lat < hi_lat &&
            r->lon >= lo_lon && r->lon < hi_lon)
            return;
    }
    r->cell_lat = clat;
    r->cell_lon = clon;
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

uint64_t aprs_station_sig(const aprs_station_t *a) {
    uint64_t h = 0xcbf29ce484222325ULL;
    if (!a) return h;
    h = mix_str(h, a->call);
    h = mix64(h, (long long)a->first_seen);
    h = mix64(h, a->has_cell ? a->cell_lat : -100000);
    h = mix64(h, a->has_cell ? a->cell_lon : -100000);
    h = mix64(h, a->has_pos);
    h = mix_str(h, a->symbol);
    h = mix64(h, a->heard_direct);
    return h;
}

/* ── The table ─────────────────────────────────────────────────── */

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct {
    int            configured;
    char           label[48];
    char           err[96];
    int            missing;
    int            ever_read;
    time_t         last_read, last_packet;
    uint64_t       bytes, lines, packets, bad, overflow, expired;
    uint64_t       truncations, rotations, read_errors;
    time_t         first_read;     /* wall of this run's first good read */
    uint32_t       freq_hz;        /* --aprs-freq, 0 none */
    int            silent_set, silent_after_s;  /* --aprs-silent-hours */
    int            region;         /* the last region derived, held */
    uint64_t       seq;            /* the newest packet's */
    int            ring_head, ring_n;
    aprs_packet_t  ring[APRS_PKT_RING];
    int            n;
    aprs_station_t rows[APRS_MAX_STATIONS];
} g;

/* The poll's copies, which the sloth_state_t pointers name. Main
 * thread only. */
static aprs_station_t g_snap[APRS_MAX_STATIONS];
static aprs_station_t g_gone[APRS_MAX_STATIONS];
static aprs_packet_t  g_pkts[APRS_PKT_RING];

void aprs_set_source(const char *label) {
    pthread_mutex_lock(&g_mu);
    g.configured = 1;
    snprintf(g.label, sizeof(g.label), "%s", label ? label : "");
    pthread_mutex_unlock(&g_mu);
}

static aprs_station_t *row_find(const char *call) {
    for (int i = 0; i < g.n; i++)
        if (strcmp(g.rows[i].call, call) == 0) return &g.rows[i];
    return NULL;
}

static void merge(aprs_station_t *r, const aprs_packet_t *p, uint64_t mono_ms) {
    r->packets++;
    if (p->utime > r->last_seen) r->last_seen = p->utime;
    r->last_mono_ms = mono_ms;
    snprintf(r->via, sizeof(r->via), "%s", p->heard);
    r->last_direct = p->heard[0] && strcmp(p->heard, p->source) == 0;
    if (r->last_direct) r->heard_direct = 1;
    r->level = p->level;
    if (p->level > r->best_level) r->best_level = p->level;
    if (p->dti) r->dti = p->dti;
    if (p->system[0]) memcpy(r->system, p->system, sizeof(r->system));
    if (p->status[0]) memcpy(r->status, p->status, sizeof(r->status));
    /* An object or item names something else: its position, symbol and
     * comment are that thing's (APRS101 ch. 11). */
    if (p->dti == ';' || p->dti == ')') return;
    if (p->symbol[0]) memcpy(r->symbol, p->symbol, sizeof(r->symbol));
    if (p->comment[0]) memcpy(r->comment, p->comment, sizeof(r->comment));
    if (p->has_pos) {
        r->has_pos = 1; r->lat = p->lat; r->lon = p->lon;
        r->pos_ts = p->utime;
        /* The figures that came with the position, or none: a speed
         * kept from an older fix would describe a different moment. */
        r->has_speed = p->has_speed;   r->speed_kt = p->speed_kt;
        r->has_course = p->has_course; r->course = p->course;
        r->has_alt = p->has_alt;       r->alt_m = p->alt_m;
        cell_hold(r);
    }
}

void aprs_feed_packet(const aprs_packet_t *p, time_t wall, uint64_t mono_ms) {
    if (!p) return;
    (void)wall;
    pthread_mutex_lock(&g_mu);
    g.packets++;
    if (p->utime > g.last_packet) g.last_packet = p->utime;
    aprs_station_t *r = row_find(p->source);
    if (!r) {
        if (g.n >= APRS_MAX_STATIONS) {
            g.overflow++;
        } else {
            r = &g.rows[g.n++];
            memset(r, 0, sizeof(*r));
            snprintf(r->call, sizeof(r->call), "%s", p->source);
            r->first_seen = p->utime;
            r->level = r->best_level = -1;
        }
    }
    if (r) merge(r, p, mono_ms);
    aprs_packet_t *q = &g.ring[g.ring_head];
    *q = *p;
    q->seq = ++g.seq;
    q->stn_first_seen = r ? r->first_seen : 0;
    g.ring_head = (g.ring_head + 1) % APRS_PKT_RING;
    if (g.ring_n < APRS_PKT_RING) g.ring_n++;
    pthread_mutex_unlock(&g_mu);
}

int aprs_feed_line(const char *line, size_t n, time_t wall, uint64_t mono_ms) {
    aprs_packet_t p;
    int r = aprs_line_parse(line, n, &p);
    size_t b = 0;
    while (b < n && (line[b] == ' ' || line[b] == '\t' || line[b] == '\r')) b++;
    pthread_mutex_lock(&g_mu);
    if (b < n) g.lines++;
    if (r < 0) g.bad++;
    pthread_mutex_unlock(&g_mu);
    if (r == 1) aprs_feed_packet(&p, wall, mono_ms);
    return r;
}

void aprs_note_read(time_t wall, uint64_t bytes, int rotated, int truncated) {
    pthread_mutex_lock(&g_mu);
    if (!g.ever_read) g.first_read = wall;
    g.ever_read = 1;
    g.missing = 0;
    g.err[0] = '\0';
    g.last_read = wall;
    g.bytes += bytes;
    if (rotated) g.rotations++;
    if (truncated) g.truncations++;
    pthread_mutex_unlock(&g_mu);
}

void aprs_note_missing(void) {
    pthread_mutex_lock(&g_mu);
    g.missing = 1;
    g.err[0] = '\0';
    pthread_mutex_unlock(&g_mu);
}

void aprs_note_read_error(const char *err) {
    pthread_mutex_lock(&g_mu);
    g.read_errors++;
    g.missing = 0;
    snprintf(g.err, sizeof(g.err), "%s", err ? err : "error");
    pthread_mutex_unlock(&g_mu);
}

void aprs_note_bad_line(void) {
    pthread_mutex_lock(&g_mu);
    g.lines++;
    g.bad++;
    pthread_mutex_unlock(&g_mu);
}

void aprs_health_poll(sloth_state_t *s, time_t wall, uint64_t mono_ms) {
    if (!s) return;
    aprs_health_t *h = &s->aprs;
    memset(h, 0, sizeof(*h));
    int ngone = 0, npk = 0;
    pthread_mutex_lock(&g_mu);
    /* Expire first, so the copy below never carries a station this poll
     * also reports gone. Order is not kept: the table is a set. */
    for (int i = 0; i < g.n; ) {
        aprs_station_t *r = &g.rows[i];
        if (mono_ms >= r->last_mono_ms &&
            mono_ms - r->last_mono_ms >= (uint64_t)APRS_EXPIRE_S * 1000u) {
            g_gone[ngone++] = *r;
            g.expired++;
            g.rows[i] = g.rows[--g.n];
            continue;
        }
        i++;
    }
    h->configured = g.configured;
    h->missing = g.missing;
    snprintf(h->src, sizeof(h->src), "%s", g.label);
    snprintf(h->err, sizeof(h->err), "%s", g.err);
    h->last_read = g.last_read;
    h->last_packet = g.last_packet;
    h->bytes = g.bytes;
    h->lines = g.lines;
    h->packets = g.packets;
    h->bad_lines = g.bad;
    h->overflow = g.overflow;
    h->expired = g.expired;
    h->truncations = g.truncations;
    h->rotations = g.rotations;
    h->read_errors = g.read_errors;
    h->stations = g.n;
    if (!g.configured)              h->state = APRS_NONE;
    else if (g.err[0])              h->state = APRS_ERROR;
    else if (!g.ever_read || g.missing) h->state = APRS_WAITING;
    else                            h->state = APRS_LIVE;
    /* #204. The region from this tick's position, else the one held. */
    {
        int rg = aprs_region_of(s->gps.has_loc, s->gps.loc_lat, s->gps.loc_lon);
        if (rg != APRS_REGION_NONE) g.region = rg;
        h->region = g.region;
        h->region_hz = aprs_region_hz(g.region);
        h->freq_hz = g.freq_hz;
        h->freq_mismatch = aprs_freq_mismatch(g.freq_hz, h->region_hz);
        h->silent_after_s = g.silent_set ? g.silent_after_s : APRS_SILENT_S_DEFAULT;
        if (g.ever_read)
            h->quiet_since = g.last_packet > g.first_read ? g.last_packet
                                                          : g.first_read;
        /* A decoder clock ahead of the host's reads as not quiet yet. */
        h->silent = h->state == APRS_LIVE && h->silent_after_s > 0 &&
                    h->quiet_since > 0 && wall > h->quiet_since &&
                    wall - h->quiet_since >= h->silent_after_s;
    }
    memcpy(g_snap, g.rows, sizeof(g.rows[0]) * (size_t)g.n);
    s->aprs_count = g.n;
    int start = (g.ring_head + APRS_PKT_RING - g.ring_n) % APRS_PKT_RING;
    for (int i = 0; i < g.ring_n; i++)
        g_pkts[npk++] = g.ring[(start + i) % APRS_PKT_RING];
    pthread_mutex_unlock(&g_mu);
    s->aprs_rows = g_snap;
    s->aprs_gone = g_gone;
    s->aprs_gone_count = ngone;
    s->aprs_pkts = g_pkts;
    s->aprs_pkt_count = npk;
}

void aprs_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(&g, 0, sizeof(g));
    pthread_mutex_unlock(&g_mu);
}

/* ── The region (#204) ─────────────────────────────────────────── */

typedef struct { double lat0, lat1, lon0, lon1; int region; } region_box_t;

/* Most specific first: the first box holding the point wins, so the
 * overlaps resolve by order (Hokkaido before the Russia box). Edges
 * inclusive. */
static const region_box_t REGION_BOXES[] = {
    /* New Zealand: the main islands and Stewart Island; the Chathams
     * (176.5 W) and the Kermadecs across the antimeridian. */
    { -53.0, -29.0,  165.0,  180.0, APRS_REGION_NZ },
    { -53.0, -29.0, -180.0, -175.0, APRS_REGION_NZ },
    /* Australia: the mainland and Tasmania, Cape York to 10 S so New
     * Guinea's south coast and Timor stay out. */
    { -45.0, -10.0,  112.0,  160.0, APRS_REGION_AU },
    /* Japan: Honshu (west edge east of Korea, north edge south of
     * Vladivostok), Hokkaido, Kyushu (south of Busan), the Ryukyus
     * (east of Taiwan). */
    {  33.0,  41.6,  130.8,  142.2, APRS_REGION_JP },
    {  41.3,  45.6,  139.3,  146.0, APRS_REGION_JP },
    {  30.9,  34.0,  128.5,  132.0, APRS_REGION_JP },
    {  24.0,  30.9,  122.9,  131.5, APRS_REGION_JP },
    /* Brazil: the north-east bulk, the western Amazon, the south. */
    { -20.0,   5.3,  -60.0,  -34.7, APRS_REGION_BR },
    { -11.0,   2.0,  -74.0,  -60.0, APRS_REGION_BR },
    { -34.0, -20.0,  -55.0,  -39.0, APRS_REGION_BR },
    /* North America: Central America's north to the Arctic, the
     * Aleutians to Newfoundland; Hawaii is inside. */
    {  14.0,  72.0, -180.0,  -50.0, APRS_REGION_NA },
    /* IARU Region 1: Europe, Africa and the Middle East west of 60 E;
     * the Azores; Russia and northern Kazakhstan east of it. */
    { -35.0,  82.0,  -25.0,   60.0, APRS_REGION_IARU1 },
    {  36.0,  40.5,  -32.0,  -24.0, APRS_REGION_IARU1 },
    {  50.0,  82.0,   60.0,  180.0, APRS_REGION_IARU1 },
};

int aprs_region_of(int has_fix, double lat, double lon) {
    if (!has_fix || !in_range(lat, -90, 90) || !in_range(lon, -180, 180))
        return APRS_REGION_NONE;
    for (size_t i = 0; i < sizeof(REGION_BOXES) / sizeof(REGION_BOXES[0]); i++) {
        const region_box_t *b = &REGION_BOXES[i];
        if (lat >= b->lat0 && lat <= b->lat1 && lon >= b->lon0 && lon <= b->lon1)
            return b->region;
    }
    return APRS_REGION_UNKNOWN;
}

uint32_t aprs_region_hz(int region) {
    switch (region) {
    case APRS_REGION_NA:    return 144390000u;
    case APRS_REGION_IARU1: return 144800000u;
    case APRS_REGION_AU:    return 145175000u;
    case APRS_REGION_NZ:    return 144575000u;
    case APRS_REGION_JP:    return 144640000u;
    case APRS_REGION_BR:    return 145570000u;
    default:                return 0;
    }
}

const char *aprs_region_name(int region) {
    switch (region) {
    case APRS_REGION_UNKNOWN: return "unknown";
    case APRS_REGION_NA:      return "north-america";
    case APRS_REGION_IARU1:   return "iaru-r1";
    case APRS_REGION_AU:      return "australia";
    case APRS_REGION_NZ:      return "new-zealand";
    case APRS_REGION_JP:      return "japan";
    case APRS_REGION_BR:      return "brazil";
    default:                  return "none";
    }
}

int aprs_freq_parse(const char *s, uint32_t *out) {
    if (!s || !out) return -1;
    uint64_t v = 0;
    size_t i = 0;
    for (; s[i]; i++) {
        if (s[i] < '0' || s[i] > '9' || i >= 10) return -1;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    if (i == 0 || v < APRS_FREQ_MIN_HZ || v > APRS_FREQ_MAX_HZ) return -1;
    *out = (uint32_t)v;
    return 0;
}

int aprs_freq_mismatch(uint32_t declared_hz, uint32_t region_hz) {
    if (!declared_hz || !region_hz) return 0;
    uint32_t d = declared_hz > region_hz ? declared_hz - region_hz
                                         : region_hz - declared_hz;
    return d > APRS_FREQ_TOL_HZ;
}

void aprs_set_expect(uint32_t freq_hz, int silent_after_s) {
    pthread_mutex_lock(&g_mu);
    g.freq_hz = freq_hz;
    g.silent_set = 1;
    g.silent_after_s = silent_after_s < 0 ? 0 : silent_after_s;
    pthread_mutex_unlock(&g_mu);
}

const char *aprs_state_name(int state) {
    switch (state) {
    case APRS_WAITING: return "waiting";
    case APRS_LIVE:    return "live";
    case APRS_ERROR:   return "error";
    default:           return "none";
    }
}
