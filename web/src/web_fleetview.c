#include "web_fleetview.h"

#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_adsb.h"
#include "web_ble.h"
#include "web_bledev.h"
#include "web_fleet.h"
#include "web_json.h"
#include "web_jsonl.h"
#include "web_metrics.h"
#include "web_probes.h"
#include "web_query.h"
#include "web_series.h"
#include "web_slothdb.h"
#include "web_ssid.h"
#include "web_store.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

static int fail(char *err, size_t errsz, const char *why) {
    snprintf(err, errsz, "%s", why);
    return -1;
}

/* ── fleet= ──────────────────────────────────────────────────────────── */

int web_fv_take(const char *query, char *rest, size_t restsz, int *mode,
                char *err, size_t errsz) {
    *mode = WEB_FV_DEFAULT;
    if (!restsz) return fail(err, errsz, "query_too_long");
    rest[0] = '\0';
    if (!query || !query[0]) return 0;
    size_t ro = 0;
    int given = 0;
    const char *p = query;
    for (;;) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        if (!seg) return fail(err, errsz, "bad_query");
        if (seg > 6 && !memcmp(p, "fleet=", 6)) {
            if (given) return fail(err, errsz, "repeated_parameter");
            given = 1;
            if (seg == 7 && p[6] == '0') *mode = WEB_FV_OFF;
            else if (seg == 7 && p[6] == '1') *mode = WEB_FV_ON;
            else return fail(err, errsz, "bad_fleet");
        } else if (seg == 6 && !memcmp(p, "fleet=", 6)) {
            return fail(err, errsz, "empty_value");
        } else if (seg == 5 && !memcmp(p, "fleet", 5)) {
            return fail(err, errsz, "bad_query");
        } else {
            /* The route's own, left for its parser byte for byte. */
            if (ro + seg + 2 > restsz) return fail(err, errsz, "query_too_long");
            if (ro) rest[ro++] = '&';
            memcpy(rest + ro, p, seg);
            ro += seg;
            rest[ro] = '\0';
        }
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

int web_fv_on(const web_fleet_t *f, int mode, const web_scope_ctx_t *sc) {
    if (mode == WEB_FV_OFF || !f || f->npeer <= 0) return 0;
    if (sc && sc->scope != WEB_SCOPE_HYBRID) return 0;
    return 1;
}

#ifdef WITH_SQLITE

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ── the peers' rows ─────────────────────────────────────────────────── */

/* One peer_sightings row, with what its extra holds for the kind. */
typedef struct {
    char      key[WEB_KEY_MAX + 1];
    char      peer[WEB_FLEET_NAME_MAX + 1];
    char      label[WEB_FLEET_STR_MAX + 1];
    char      vendor[WEB_FLEET_STR_MAX + 1];
    int       has_rssi, rssi;
    long long first, last;
    int       has_ap, is_ap;           /* wifi */
    char      bssid[WEB_KEY_MAX + 1];  /* wifi, "" none */
    int       channel;                 /* ap, 0 none */
    char      enc[64];                 /* ap, "" none */
    char      atype;                   /* ble, 0 none */
    struct {                           /* aircraft (#192 I7's extra) */
        char      squawk[5], emergency[12];
        int       on_ground, has_alt, alt, has_msgs, has_pos, has_palt, palt;
        int       has_gs, has_track, has_rssi;
        double    gs, track, rssi, lat, lon;
        long long msgs, pos_ts, pos_prev, visit_first;
    } ac;
} fv_row_t;

/* A site's names: the --peer name and the label its export last sent. */
typedef struct {
    char name[WEB_FLEET_NAME_MAX + 1];
    char label[WEB_FLEET_STR_MAX + 1];
} fv_site_t;

static const char *KIND[] = { "wifi", "ap", "ble", "probe", "probe", "aircraft", "aircraft" };

static int is_probe(int view) {
    return view == WEB_FV_PROBE_CLIENTS || view == WEB_FV_PROBE_SSIDS;
}

static int is_ac(int view) {
    return view == WEB_FV_ADSB || view == WEB_FV_ADSB_SEEN;
}

/* sloth's spelling of an aircraft address (web_adsb.h): '~' first for
 * a non-ICAO one, then six lower-case hex digits, as the importer keys
 * it. */
static int icao_ok(const char *h) {
    size_t i = h[0] == '~' ? 1 : 0;
    if (strlen(h) != i + 6) return 0;
    for (; h[i]; i++)
        if (!((h[i] >= '0' && h[i] <= '9') || (h[i] >= 'a' && h[i] <= 'f'))) return 0;
    return 1;
}

/* A canonical MAC, as the importer keys every row of these kinds; a row
 * that is not one is passed over. */
static int mac_ok(const char *k) {
    char c[WEB_KEY_MAX + 1];
    return web_key_mac(k, c) == 0 && !strcmp(c, k);
}

static void copy_col(sqlite3_stmt *q, int i, char *dst, size_t cap) {
    const unsigned char *t = sqlite3_column_text(q, i);
    snprintf(dst, cap, "%s", t ? (const char *)t : "");
}

/* The configured peers and each one's label (peer_sites). */
static int read_sites(web_fleet_t *f, fv_site_t *st) {
    int n = f->npeer < WEB_FLEET_PEERS ? f->npeer : WEB_FLEET_PEERS;
    for (int i = 0; i < n; i++) {
        snprintf(st[i].name, sizeof(st[i].name), "%s", f->peer[i].cfg.name);
        st[i].label[0] = '\0';
    }
    web_store_t *s = f->store;
    if (!s || !s->rd) return n;
    pthread_mutex_lock(&s->rmu);
    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(s->rd, "SELECT peer,label FROM peer_sites", -1, &q, NULL) == SQLITE_OK)
        while (sqlite3_step(q) == SQLITE_ROW) {
            const unsigned char *p = sqlite3_column_text(q, 0);
            for (int i = 0; p && i < n; i++)
                if (!strcmp(st[i].name, (const char *)p))
                    copy_col(q, 1, st[i].label, sizeof(st[i].label));
        }
    sqlite3_finalize(q);
    pthread_mutex_unlock(&s->rmu);
    return n;
}

static int site_of(const fv_site_t *st, int n, const char *peer) {
    for (int i = 0; i < n; i++)
        if (!strcmp(st[i].name, peer)) return i;
    return -1;
}

/* What extra holds, by the importer's own members (web_fleet.c
 * row_of()): written by slothweb from validated values, read here with
 * the stream's decoder all the same. */
static void extra_of(web_jrec_t *r, const char *extra, int view, fv_row_t *o) {
    /* The decoder takes a stream record, which names its type: one is
     * put in front. */
    char line[2100];
    size_t el = strlen(extra);
    if (el < 2 || extra[0] != '{' || el + 16 > sizeof(line)) return;
    int ln = snprintf(line, sizeof(line), "{\"type\":\"x\"%s%s", el > 2 ? "," : "", extra + 1);
    if (ln < 0 || web_jl_parse(line, (size_t)ln, r) != WEB_JL_OK) return;
    const web_jfield_t *f;
    if (view == WEB_FV_DEVICES) {
        if ((f = web_jl_get(r, "is_ap")) && f->kind == WEB_J_BOOL) {
            o->has_ap = 1;
            o->is_ap = f->i != 0;
        }
        const char *b = web_jl_str(r, "bssid");
        if (b && mac_ok(b)) snprintf(o->bssid, sizeof(o->bssid), "%s", b);
    } else if (view == WEB_FV_APS) {
        if ((f = web_jl_get(r, "channel")) && f->kind == WEB_J_INT && f->i > 0 && f->i < 256)
            o->channel = (int)f->i;
        const char *e = web_jl_str(r, "enc");
        if (e) web_utf8_copy(o->enc, sizeof(o->enc) - 1, e);
    } else if (is_ac(view)) {
        /* What ac_row() put in extra, each held to its own range again
         * and taken only whole: a position with its time, or none. */
        double v;
        const char *t = web_jl_str(r, "squawk");
        if (t && strlen(t) == 4 && strspn(t, "01234567") == 4)
            snprintf(o->ac.squawk, sizeof(o->ac.squawk), "%s", t);
        t = web_jl_str(r, "emergency");
        for (int e = 0; t && e < WEB_ADSB_EMERG_COUNT; e++)
            if (!strcmp(t, web_adsb_emergency_name(e)))
                snprintf(o->ac.emergency, sizeof(o->ac.emergency), "%s", t);
        if ((f = web_jl_get(r, "on_ground")) && f->kind == WEB_J_BOOL) o->ac.on_ground = f->i != 0;
        if ((f = web_jl_get(r, "alt")) && f->kind == WEB_J_INT && f->i >= -2000 && f->i <= 100000) {
            o->ac.has_alt = 1;
            o->ac.alt = (int)f->i;
        }
        if (web_jl_num(r, "gs", &v) && v >= 0 && v <= 2000) { o->ac.has_gs = 1; o->ac.gs = v; }
        if (web_jl_num(r, "track", &v) && v >= 0 && v <= 360) { o->ac.has_track = 1; o->ac.track = v; }
        if (web_jl_num(r, "rssi", &v) && v >= -100 && v <= 10) { o->ac.has_rssi = 1; o->ac.rssi = v; }
        if ((f = web_jl_get(r, "messages")) && f->kind == WEB_J_INT && f->i >= 0) {
            o->ac.has_msgs = 1;
            o->ac.msgs = f->i;
        }
        if ((f = web_jl_get(r, "visit_first")) && f->kind == WEB_J_INT && f->i > 0)
            o->ac.visit_first = f->i;
        double la, lo;
        const web_jfield_t *pt = web_jl_get(r, "pos_ts"), *pp = web_jl_get(r, "pos_prev");
        if (web_jl_num(r, "lat", &la) && web_jl_num(r, "lon", &lo) && la >= -90 && la <= 90 &&
            lo >= -180 && lo <= 180 && pt && pt->kind == WEB_J_INT && pt->i > 0 && pp &&
            pp->kind == WEB_J_INT && pp->i >= 0 && pp->i <= pt->i) {
            o->ac.has_pos = 1;
            o->ac.lat = la;
            o->ac.lon = lo;
            o->ac.pos_ts = pt->i;
            o->ac.pos_prev = pp->i;
            if ((f = web_jl_get(r, "pos_alt")) && f->kind == WEB_J_INT && f->i >= -2000 &&
                f->i <= 100000) {
                o->ac.has_palt = 1;
                o->ac.palt = (int)f->i;
            }
        }
    } else if (is_probe(view)) {
        /* The probing client's MAC: the row's key is "mac|ssid". */
        const char *m = web_jl_str(r, "mac");
        if (m && mac_ok(m)) snprintf(o->bssid, sizeof(o->bssid), "%s", m);
    } else {
        const char *t = web_jl_str(r, "addr_type");
        if (t && strlen(t) == 1 && isalpha((unsigned char)t[0])) o->atype = t[0];
    }
}

/* The configured peers' rows of the view's kind last seen at or after
 * since (key NULL: every key, newest first, at most max; else the one
 * key's, a probe row's by its client's MAC). Their number; -1 when
 * memory was short. *partial when more were left unread. A probe row's
 * key is read back as its client's MAC, its label the SSID, and one
 * naming no SSID (a wildcard) is passed over, as the route refuses it. */
static int read_rows(web_fleet_t *f, const fv_site_t *st, int nst, int view,
                     const char *key, long long since, fv_row_t *rows, int max,
                     int *partial) {
    *partial = 0;
    web_store_t *s = f->store;
    if (!s || !s->rd || max <= 0) return 0;
    web_jrec_t *jr = malloc(sizeof(*jr));
    if (!jr) return -1;
    int n = 0;
    pthread_mutex_lock(&s->rmu);
    sqlite3_stmt *q = NULL;
    int pr = is_probe(view);
    const char *sql = key && pr
        ? "SELECT key,peer,label,vendor,rssi,first_seen,last_seen,extra FROM peer_sightings"
          " WHERE kind=?1 AND key>=?2 AND key<?5 AND last_seen>=?4"
          " ORDER BY last_seen DESC LIMIT ?3"
        : key
        ? "SELECT key,peer,label,vendor,rssi,first_seen,last_seen,extra FROM peer_sightings"
          " WHERE kind=?1 AND key=?2 AND last_seen>=?4 ORDER BY last_seen DESC LIMIT ?3"
        : "SELECT key,peer,label,vendor,rssi,first_seen,last_seen,extra FROM peer_sightings"
          " WHERE kind=?1 AND last_seen>=?4 ORDER BY last_seen DESC LIMIT ?3";
    if (sqlite3_prepare_v2(s->rd, sql, -1, &q, NULL) == SQLITE_OK) {
        sqlite3_bind_text(q, 1, KIND[view], -1, SQLITE_STATIC);
        if (key && pr) {
            /* "mac|" up to, not including, "mac}": the MAC's every SSID. */
            char lo[WEB_KEY_MAX + 2], hi[WEB_KEY_MAX + 2];
            snprintf(lo, sizeof(lo), "%s|", key);
            snprintf(hi, sizeof(hi), "%s}", key);
            sqlite3_bind_text(q, 2, lo, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(q, 5, hi, -1, SQLITE_TRANSIENT);
        } else if (key) {
            sqlite3_bind_text(q, 2, key, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int(q, 3, max + 1);
        sqlite3_bind_int64(q, 4, since);
        int seen = 0;
        while (sqlite3_step(q) == SQLITE_ROW) {
            if (seen++ >= max) { *partial = 1; break; }
            fv_row_t *r = &rows[n];
            memset(r, 0, sizeof(*r));
            copy_col(q, 0, r->key, sizeof(r->key));
            copy_col(q, 1, r->peer, sizeof(r->peer));
            copy_col(q, 2, r->label, sizeof(r->label));
            const unsigned char *ex = sqlite3_column_text(q, 7);
            if (pr) {
                r->key[0] = '\0';
                if (ex) extra_of(jr, (const char *)ex, view, r);
                snprintf(r->key, sizeof(r->key), "%s", r->bssid);
                r->bssid[0] = '\0';
                if (!r->label[0] || (key && strcmp(r->key, key))) continue;
            }
            /* A peer no longer named keeps its rows until the age limit;
             * the merged views show the fleet as configured. */
            if (!(is_ac(view) ? icao_ok(r->key) : mac_ok(r->key)) ||
                site_of(st, nst, r->peer) < 0)
                continue;
            copy_col(q, 3, r->vendor, sizeof(r->vendor));
            /* sloth's 0 is "never heard on the air", not a reading
             * (#192 I5), as /api/fleet/shared reads it. */
            r->has_rssi = sqlite3_column_type(q, 4) != SQLITE_NULL &&
                          sqlite3_column_int(q, 4) < 0;
            r->rssi = sqlite3_column_int(q, 4);
            r->first = sqlite3_column_int64(q, 5);
            r->last = sqlite3_column_int64(q, 6);
            if (ex && !pr) extra_of(jr, (const char *)ex, view, r);
            n++;
        }
    }
    sqlite3_finalize(q);
    pthread_mutex_unlock(&s->rmu);
    free(jr);
    return n;
}

/* ── the answer as the route wrote it ────────────────────────────────── */

/* The routes' own output, read back far enough to splice into: string,
 * nesting and the top-level members. Not a validator; anything it does
 * not follow leaves the answer as it was. */
#define BAD ((size_t)-1)

static size_t ws(const char *s, size_t i, size_t n) {
    while (i < n && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) i++;
    return i;
}

static size_t skip_str(const char *s, size_t i, size_t n) {
    if (i >= n || s[i] != '"') return BAD;
    for (i++; i < n; i++) {
        if (s[i] == '\\') { i++; continue; }
        if (s[i] == '"') return i + 1;
    }
    return BAD;
}

static size_t skip_val(const char *s, size_t i, size_t n) {
    if (i >= n) return BAD;
    if (s[i] == '"') return skip_str(s, i, n);
    if (s[i] == '{' || s[i] == '[') {
        int depth = 0;
        while (i < n) {
            char c = s[i];
            if (c == '"') { i = skip_str(s, i, n); if (i == BAD) return BAD; continue; }
            if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') { if (--depth == 0) return i + 1; }
            i++;
        }
        return BAD;
    }
    while (i < n && s[i] != ',' && s[i] != '}' && s[i] != ']' && s[i] != ' ' && s[i] != '\n') i++;
    return i;
}

/* The members of the object at i: fn is called with each name (as it
 * stands between the quotes) and its value's span. The index after the
 * object's '}' is *end (that '}' is at *end - 1). 0, or -1. */
typedef void (*member_fn)(void *ctx, const char *name, size_t nl, size_t vs, size_t ve);

static int members(const char *s, size_t i, size_t n, member_fn fn, void *ctx, size_t *end) {
    i = ws(s, i, n);
    if (i >= n || s[i] != '{') return -1;
    i = ws(s, i + 1, n);
    if (i < n && s[i] == '}') { *end = i + 1; return 0; }
    for (;;) {
        size_t ke = skip_str(s, i, n);
        if (ke == BAD) return -1;
        size_t c = ws(s, ke, n);
        if (c >= n || s[c] != ':') return -1;
        size_t vs = ws(s, c + 1, n), ve = skip_val(s, vs, n);
        if (ve == BAD) return -1;
        fn(ctx, s + i + 1, ke - i - 2, vs, ve);
        i = ws(s, ve, n);
        if (i < n && s[i] == ',') { i = ws(s, i + 1, n); continue; }
        if (i < n && s[i] == '}') { *end = i + 1; return 0; }
        return -1;
    }
}

typedef struct {
    const char *s;
    const char *want;               /* a row's key member */
    const char *arr;                /* the list's member, NULL "rows" */
    size_t rows_s, rows_e;          /* "rows": its [ and after its ] */
    size_t tot_s, tot_e;            /* "total" (/api/adsb) */
    size_t ac_s, ac_e;              /* "aircraft" (/api/adsb/aircraft) */
    size_t more_s, more_e;
    size_t rec_s, rec_e;            /* "record" (the device drawer) */
    char   key[WEB_KEY_MAX + 1];
    size_t key_s, key_e;            /* the key member's value, any length */
} top_t;

static int name_is(const char *name, size_t nl, const char *w) {
    return strlen(w) == nl && !memcmp(name, w, nl);
}

static void top_member(void *ctx, const char *name, size_t nl, size_t vs, size_t ve) {
    top_t *t = ctx;
    if (name_is(name, nl, t->arr ? t->arr : "rows") && t->s[vs] == '[') {
        t->rows_s = vs;
        t->rows_e = ve;
    }
    else if (name_is(name, nl, "more")) { t->more_s = vs; t->more_e = ve; }
    else if (name_is(name, nl, "total")) { t->tot_s = vs; t->tot_e = ve; }
    else if (name_is(name, nl, "aircraft")) { t->ac_s = vs; t->ac_e = ve; }
    else if (name_is(name, nl, "record")) { t->rec_s = vs; t->rec_e = ve; }
}

static void row_member(void *ctx, const char *name, size_t nl, size_t vs, size_t ve) {
    top_t *t = ctx;
    if (!name_is(name, nl, t->want) || t->s[vs] != '"') return;
    t->key_s = vs;
    t->key_e = ve;
    if (ve - vs - 2 > WEB_KEY_MAX) return;
    memcpy(t->key, t->s + vs + 1, ve - vs - 2);
    t->key[ve - vs - 2] = '\0';
}

/* Bytes of the route's own answer, spliced as they are: they came out
 * of slothweb's own writers, never off a stream. */
static void splice(web_jw_t *w, const char *s, size_t n) {
    if (w->overflow) return;
    if (w->len + n + 1 > w->cap) { w->overflow = 1; return; }
    memcpy(w->buf + w->len, s, n);
    w->len += n;
    w->buf[w->len] = '\0';
}

/* ── a group of rows of one key ──────────────────────────────────────── */

typedef struct {
    int at, n;                      /* rows[at..at+n), newest first (a
                                       probe client's: by SSID) */
    int local;                      /* a row on this page */
    long long first, last;          /* what the group sorts by */
    int nss;                        /* a probe client's distinct SSIDs */
    uint64_t h;                     /* a probe SSID's display form, hashed */
} fv_group_t;

static int by_key_last(const void *pa, const void *pb) {
    const fv_row_t *a = pa, *b = pb;
    int c = strcmp(a->key, b->key);
    if (c) return c;
    if (a->last != b->last) return a->last > b->last ? -1 : 1;
    return strcmp(a->peer, b->peer);
}

/* A probe client's rows: by MAC, then SSID, so each SSID's rows sit
 * together. */
static int by_key_label(const void *pa, const void *pb) {
    const fv_row_t *a = pa, *b = pb;
    int c = strcmp(a->key, b->key);
    if (c) return c;
    if ((c = strcmp(a->label, b->label))) return c;
    if (a->last != b->last) return a->last > b->last ? -1 : 1;
    return strcmp(a->peer, b->peer);
}

/* A probe SSID's rows: by the SSID, newest first. */
static int by_label_last(const void *pa, const void *pb) {
    const fv_row_t *a = pa, *b = pb;
    int c = strcmp(a->label, b->label);
    if (c) return c;
    if (a->last != b->last) return a->last > b->last ? -1 : 1;
    if ((c = strcmp(a->peer, b->peer))) return c;
    return strcmp(a->key, b->key);
}

/* A row's group key: a probe SSID's is its label. */
static const char *gkey(int view, const fv_row_t *r) {
    return view == WEB_FV_PROBE_SSIDS ? r->label : r->key;
}

static uint64_t fnv64(const char *s, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char)s[i]; h *= 0x100000001b3ULL; }
    return h;
}

/* The SSID's value as web_jw_ssid() writes it, into buf; its length, 0
 * when it did not fit. A local row's "ssid" is matched on these bytes,
 * so the display form decides, never a decoding of it. */
static size_t ssid_json(const char *ssid, char *buf, size_t cap) {
    web_jw_t w;
    web_jw_init(&w, buf, cap);
    web_jw_ssid(&w, ssid);
    return w.overflow ? 0 : w.len;
}

static void jstr_or_null(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s); else web_jw_raw(w, "null");
}

/* A site's name for people: its label when its export sent one. */
static const char *site_word(const fv_site_t *st, int nst, const char *peer) {
    int i = site_of(st, nst, peer);
    return i >= 0 && st[i].label[0] ? st[i].label : peer;
}

/* r[0..n), one key's rows, as one per peer (the earliest first_seen,
 * the latest last_seen, the newest row's other members), newest first:
 * a probe key has a row per SSID or per client. Their number. */
static int per_site(const fv_row_t *r, int n, fv_row_t *out) {
    int k = 0;
    for (int i = 0; i < n; i++) {
        int j = 0;
        while (j < k && strcmp(out[j].peer, r[i].peer)) j++;
        if (j == k) {
            if (k == WEB_FLEET_PEERS) continue;
            out[k++] = r[i];
            continue;
        }
        if (r[i].first < out[j].first) out[j].first = r[i].first;
        if (r[i].last > out[j].last) {
            long long fs = out[j].first;
            out[j] = r[i];
            out[j].first = fs;
        }
    }
    for (int i = 1; i < k; i++)
        for (int j = i; j > 0 && (out[j].last > out[j - 1].last ||
                                  (out[j].last == out[j - 1].last &&
                                   strcmp(out[j].peer, out[j - 1].peer) < 0)); j--) {
            fv_row_t t = out[j];
            out[j] = out[j - 1];
            out[j - 1] = t;
        }
    return k;
}

static void sites_json(web_jw_t *w, const fv_row_t *rows, int nrows, const fv_site_t *st,
                       int nst) {
    fv_row_t r[WEB_FLEET_PEERS];
    int n = per_site(rows, nrows, r);
    web_jw_raw(w, "\"sites\":[");
    for (int i = 0; i < n; i++) {
        int k = site_of(st, nst, r[i].peer);
        web_jw_raw(w, i ? ",{\"site\":" : "{\"site\":");
        web_jw_str(w, r[i].peer);
        web_jw_raw(w, ",\"label\":");
        jstr_or_null(w, k >= 0 ? st[k].label : NULL);
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, r[i].first);
        web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, r[i].last);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "]");
}

/* A figure with dp decimals (0: an integer), or null. */
static void jw_num_or_null(web_jw_t *w, int has, double v, int dp) {
    char t[40];
    if (!has || !isfinite(v)) { web_jw_raw(w, "null"); return; }
    snprintf(t, sizeof(t), "%.*f", dp, v);
    web_jw_raw(w, t);
}

static void signal_json(web_jw_t *w, const fv_row_t *r) {
    if (r->has_rssi) web_jw_int(w, r->rssi); else web_jw_raw(w, "null");
}

/* The BLE address type's number for the letter the export sent
 * (web_ble_type_ch()'s inverse); -1 for none. */
static int ble_type_of(char ch) {
    static const int T[] = { 0, 1, 2, 3, 255 };
    for (size_t i = 0; ch && i < sizeof(T) / sizeof(T[0]); i++)
        if (web_ble_type_ch(T[i]) == ch) return T[i];
    return -1;
}

/* A class word the export sent, as the BLE table's slug, when it is one
 * of the closed list; NULL otherwise. */
static const char *ble_class_slug(const char *word) {
    char want[24];
    if (!word[0] || strlen(word) > 15) return NULL;
    snprintf(want, sizeof(want), "b:%s", word);
    for (int i = 0; i < WEB_BC_COUNT; i++)
        if (!strcmp(web_ble_classes[i].slug, want)) return web_ble_classes[i].slug;
    return NULL;
}

/* A remote probe client's SSIDs: the newest WEB_PROBE_ROW_SSIDS of
 * r[0..n) (sorted by SSID), each with its earliest first_seen and latest
 * last_seen over the peers, as the route lists a local client's. */
static void probe_ssids_json(web_jw_t *w, const fv_row_t *r, int n, int nss) {
    struct { int at; long long first, last; } top[WEB_PROBE_ROW_SSIDS];
    int nt = 0;
    for (int i = 0; i < n;) {
        int j = i + 1;
        long long fs = r[i].first, ls = r[i].last;
        while (j < n && !strcmp(r[j].label, r[i].label)) {
            if (r[j].first < fs) fs = r[j].first;
            if (r[j].last > ls) ls = r[j].last;
            j++;
        }
        /* Newest first, then by name: an insertion into the kept few. */
        int at = nt;
        while (at > 0 && (top[at - 1].last < ls ||
                          (top[at - 1].last == ls && strcmp(r[top[at - 1].at].label, r[i].label) > 0)))
            at--;
        if (at < WEB_PROBE_ROW_SSIDS) {
            int last = nt < WEB_PROBE_ROW_SSIDS ? nt : WEB_PROBE_ROW_SSIDS - 1;
            for (int k = last; k > at; k--) top[k] = top[k - 1];
            top[at].at = i;
            top[at].first = fs;
            top[at].last = ls;
            if (nt < WEB_PROBE_ROW_SSIDS) nt++;
        }
        i = j;
    }
    web_jw_raw(w, ",\"ssid_count\":"); web_jw_int(w, nss);
    web_jw_raw(w, ",\"ssids\":[");
    for (int k = 0; k < nt; k++) {
        web_jw_raw(w, k ? ",{\"ssid\":" : "{\"ssid\":");
        web_jw_ssid(w, r[top[k].at].label);
        web_jw_ssid_meta(w, "ssid", r[top[k].at].label);
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, top[k].first);
        web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, top[k].last);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"ssids_more\":"); web_jw_raw(w, nss > nt ? "true" : "false");
}

/* One remote-only row (r[0..n), its group g) under the route's names. */
static void remote_json(web_jw_t *w, int view, const fv_row_t *r, int n, const fv_group_t *g,
                        const web_fv_src_t *src, const fv_site_t *st, int nst) {
    const fv_row_t *h = &r[0];
    for (int i = 1; i < n; i++) if (r[i].last > h->last) h = &r[i];
    if (is_ac(view)) {
        /* The newest peer row's figures under the route's names; what
         * only this decoder or sloth.db can say is absent. */
        web_jw_raw(w, "{\"hex\":");        web_jw_str(w, h->key);
        web_jw_raw(w, ",\"non_icao\":");   web_jw_int(w, h->key[0] == '~');
        if (view == WEB_FV_ADSB_SEEN) {
            web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, g->first);
            web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, g->last);
        }
        web_jw_raw(w, ",\"flight\":");     web_jw_str(w, h->label);
        web_jw_raw(w, ",\"squawk\":");     web_jw_str(w, h->ac.squawk);
        web_jw_raw(w, ",\"category\":");   web_jw_str(w, h->vendor);
        if (view == WEB_FV_ADSB) {
            web_jw_raw(w, ",\"emergency\":"); web_jw_str(w, h->ac.emergency);
            web_jw_raw(w, ",\"on_ground\":"); web_jw_int(w, h->ac.on_ground);
        }
        web_jw_raw(w, ",\"alt\":");        jw_num_or_null(w, h->ac.has_alt, h->ac.alt, 0);
        if (view == WEB_FV_ADSB) {
            web_jw_raw(w, ",\"gs\":");     jw_num_or_null(w, h->ac.has_gs, h->ac.gs, 1);
            web_jw_raw(w, ",\"track\":");  jw_num_or_null(w, h->ac.has_track, h->ac.track, 1);
            web_jw_raw(w, ",\"lat\":");    jw_num_or_null(w, h->ac.has_pos, h->ac.lat, 5);
            web_jw_raw(w, ",\"lon\":");    jw_num_or_null(w, h->ac.has_pos, h->ac.lon, 5);
            web_jw_raw(w, ",\"pos_ts\":");
            if (h->ac.has_pos) web_jw_int(w, h->ac.pos_ts); else web_jw_raw(w, "null");
            web_jw_raw(w, ",\"rssi\":");   jw_num_or_null(w, h->ac.has_rssi, h->ac.rssi, 1);
        }
        web_jw_raw(w, ",\"messages\":");
        if (h->ac.has_msgs) web_jw_int(w, h->ac.msgs); else web_jw_raw(w, "null");
        if (view == WEB_FV_ADSB) {
            web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, h->first);
            web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, h->last);
        }
    } else if (view == WEB_FV_PROBE_CLIENTS) {
        /* What sloth.db alone can say of a client is null: no frame
         * count, signal, channel, OS or PHY label, devices row or
         * association, and no seqnum siblings or presence strip. The
         * vendor is this site's OUI table's, as a local row's. */
        int rnd = (hexv((unsigned char)h->key[1]) & 2) != 0;
        uint8_t mb[6];
        web_oui_hit_t hit;
        web_jw_raw(w, "{\"mac\":");      web_jw_str(w, h->key);
        web_jw_raw(w, ",\"random\":");   web_jw_raw(w, rnd ? "true" : "false");
        web_jw_raw(w, ",\"vendor\":");
        if (src && src->oui && !rnd && web_oui_mac_bytes(h->key, mb) == 0 &&
            web_oui_lookup(src->oui, mb, &hit))
            web_jw_str(w, hit.name);
        else
            web_jw_raw(w, "null");
        web_jw_raw(w, ",\"frames\":null,\"directed\":null,\"signal\":null,\"channel\":null,"
                      "\"os\":null,\"phy\":null");
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, g->first);
        web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, g->last);
        probe_ssids_json(w, r, n, g->nss);
        web_jw_raw(w, ",\"device\":null,\"assoc\":null");
    } else if (view == WEB_FV_PROBE_SSIDS) {
        /* Every count is this site's (stations, randomised, the APs
         * beaconing it, uncommon, designated): null. */
        web_jw_raw(w, "{\"ssid\":");    web_jw_ssid(w, h->label);
        web_jw_ssid_meta(w, "ssid", h->label);
        web_jw_raw(w, ",\"clients\":null,\"random\":null");
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, g->first);
        web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, g->last);
        web_jw_raw(w, ",\"aps\":null,\"ap_signal\":null,\"uncommon\":null,\"designated\":null");
    } else if (view == WEB_FV_DEVICES) {
        uint8_t b0 = (uint8_t)(hexv((unsigned char)h->key[0]) << 4 | hexv((unsigned char)h->key[1]));
        web_jw_raw(w, "{\"mac\":");      web_jw_str(w, h->key);
        web_jw_raw(w, ",\"random\":");   web_jw_raw(w, (b0 & 2) ? "true" : "false");
        web_jw_raw(w, ",\"vendor\":");   jstr_or_null(w, h->vendor);
        web_jw_raw(w, ",\"ssid\":");     web_jw_ssid(w, h->label);
        web_jw_raw(w, ",\"signal\":");   signal_json(w, h);
        if (h->has_ap) { web_jw_raw(w, ",\"is_ap\":"); web_jw_raw(w, h->is_ap ? "true" : "false"); }
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, h->first);
        web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, h->last);
        web_jw_ssid_meta(w, "ssid", h->label);
    } else if (view == WEB_FV_APS) {
        web_jw_raw(w, "{\"bssid\":");    web_jw_str(w, h->key);
        web_jw_raw(w, ",\"ssid\":");     web_jw_ssid(w, h->label);
        web_jw_raw(w, ",\"signal\":");   signal_json(w, h);
        web_jw_raw(w, ",\"channel\":");
        if (h->channel > 0) web_jw_int(w, h->channel); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"enc\":");      jstr_or_null(w, h->enc);
        web_jw_raw(w, ",\"vendor\":");   jstr_or_null(w, h->vendor);
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, h->first);
        web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, h->last);
        web_jw_ssid_meta(w, "ssid", h->label);
    } else {
        int ty = ble_type_of(h->atype);
        char ch[2] = { h->atype, 0 };
        const char *cls = ble_class_slug(h->vendor);
        web_jw_raw(w, "{\"addr\":");     web_jw_str(w, h->key);
        web_jw_raw(w, ",\"addr_type\":");
        if (ty >= 0) web_jw_int(w, ty); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"type\":");     jstr_or_null(w, ty >= 0 ? ch : NULL);
        web_jw_raw(w, ",\"name\":");     jstr_or_null(w, h->label);
        web_jw_raw(w, ",\"rssi\":");     signal_json(w, h);
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, h->first);
        web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, h->last);
        web_jw_raw(w, ",\"class\":");    jstr_or_null(w, cls);
        if (cls) {
            for (int i = 0; i < WEB_BC_COUNT; i++)
                if (web_ble_classes[i].slug == cls) {
                    web_jw_raw(w, ",\"class_label\":");
                    web_jw_str(w, web_ble_classes[i].label);
                }
        }
    }
    web_jw_raw(w, ",\"remote\":true,\"site\":"); web_jw_str(w, h->peer);
    web_jw_raw(w, ",\"site_label\":");
    int k = site_of(st, nst, h->peer);
    jstr_or_null(w, k >= 0 ? st[k].label : NULL);
    web_jw_raw(w, ",");
    sites_json(w, r, n, st, nst);
    web_jw_raw(w, "}");
}

/* ── filters and order ───────────────────────────────────────────────── */

/* A tolerant read of one parameter of a query the route has already
 * taken whole: its value percent-decoded (plus: '+' is a space). */
static int qparam(const char *query, const char *name, int plus, char *out, size_t cap) {
    size_t nl = strlen(name);
    out[0] = '\0';
    for (const char *p = query; p && *p;) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        if (seg > nl && !memcmp(p, name, nl) && p[nl] == '=') {
            size_t o = 0;
            for (const char *v = p + nl + 1; v < p + seg && o + 1 < cap; v++) {
                int c = (unsigned char)*v;
                if (c == '%' && (size_t)(p + seg - v) >= 3 && hexv((unsigned char)v[1]) >= 0 &&
                    hexv((unsigned char)v[2]) >= 0) {
                    c = hexv((unsigned char)v[1]) << 4 | hexv((unsigned char)v[2]);
                    v += 2;
                } else if (c == '+' && plus) {
                    c = ' ';
                }
                out[o++] = (char)c;
            }
            out[o] = '\0';
            return 1;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

static int lc(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

/* LIKE '%needle%' as SQLite reads it: ASCII case folded. */
static int ci_has(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    if (!n) return 1;
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < n && p[i] && lc((unsigned char)p[i]) == lc((unsigned char)needle[i])) i++;
        if (i == n) return 1;
    }
    return 0;
}

static int ci_prefix(const char *s, const char *pre) {
    for (; *pre; s++, pre++)
        if (!*s || lc((unsigned char)*s) != lc((unsigned char)*pre)) return 0;
    return 1;
}

static int cmp_op(long long v, int op, long long a, long long b) {
    switch (op) {
    case WEB_QOP_LT: return v < a;
    case WEB_QOP_GT: return v > a;
    case WEB_QOP_LE: return v <= a;
    case WEB_QOP_GE: return v >= a;
    default:         return v >= a && v < b;
    }
}

/* Can a peer's row answer every term? */
static int query_peerable(const web_query_t *q) {
    for (int i = 0; i < q->n; i++)
        switch (q->t[i].kind) {
        case WEB_QT_FREE: case WEB_QT_VENDOR: case WEB_QT_MAC: case WEB_QT_SSID:
        case WEB_QT_RANDOM: case WEB_QT_SEEN: case WEB_QT_FIRST:
            break;
        default:
            return 0;
        }
    return 1;
}

/* The device query (web_query.h) over a peer's row: the terms
 * query_peerable() admits, as web_query.c compiles them. */
static int dev_matches(const web_query_t *q, const fv_row_t *r) {
    for (int i = 0; i < q->n; i++) {
        const web_qterm_t *t = &q->t[i];
        int m;
        switch (t->kind) {
        case WEB_QT_FREE:
            m = ci_has(r->key, t->text) || ci_has(r->vendor, t->text) || ci_has(r->label, t->text);
            break;
        case WEB_QT_VENDOR: m = ci_has(r->vendor, t->text); break;
        case WEB_QT_MAC:    m = ci_prefix(r->key, t->text); break;
        case WEB_QT_SSID:   m = ci_has(r->label, t->text); break;
        case WEB_QT_RANDOM: m = ((hexv((unsigned char)r->key[1]) & 2) != 0) == (t->num != 0); break;
        case WEB_QT_SEEN:   m = cmp_op(r->last, t->op, t->num, t->num2); break;
        case WEB_QT_FIRST:  m = cmp_op(r->first, t->op, t->num, t->num2); break;
        default:            m = 0; break;
        }
        if (t->neg) m = !m;
        if (!m) return 0;
    }
    return 1;
}

/* The BLE search (web_ble.c dev_matches()): an address prefix or a name
 * substring; a peer sends no watch category. */
static int ble_matches(const char *q, const fv_row_t *r) {
    if (!q[0]) return 1;
    return ci_prefix(r->key, q) || (r->label[0] && ci_has(r->label, q));
}

/* /api/adsb/seen's q (web_slothdb.c web_sdb_adsb_seen()): a hex or a
 * callsign prefix, any case. */
static int ac_matches(const char *q, const fv_row_t *r) {
    if (!q[0]) return 1;
    return ci_prefix(r->key, q) || ci_prefix(r->label, q);
}

/* What a route's sort word orders by, for a peer's row. */
enum { F_NONE = 0, F_LAST, F_FIRST, F_KEY, F_VENDOR, F_LABEL, F_SIGNAL, F_CHANNEL, F_ENC,
       F_NSS };
typedef struct { const char *word; int field, dir; } fv_sort_t;

/* Each route's words with its default direction (-1 descending), as
 * web_query.c, web_slothdb.c and web_ble.c order them. */
static const fv_sort_t SORT_DEV[] = {
    { "last", F_LAST, -1 }, { "first", F_FIRST, -1 }, { "mac", F_KEY, 1 },
    { "vendor", F_VENDOR, 1 }, { "ssid", F_LABEL, 1 }, { "signal", F_SIGNAL, -1 },
    { NULL, 0, 0 } };
static const fv_sort_t SORT_AP[] = {
    { "last", F_LAST, -1 }, { "first", F_FIRST, -1 }, { "bssid", F_KEY, 1 },
    { "ssid", F_LABEL, 1 }, { "channel", F_CHANNEL, 1 }, { "signal", F_SIGNAL, -1 },
    { "enc", F_ENC, 1 }, { NULL, 0, 0 } };
/* web_probes.c's words: a column only sloth.db has (frames, signal,
 * clients) reads as empty, so the remote rows fall back to last seen. */
static const fv_sort_t SORT_PCL[] = {
    { "last", F_LAST, -1 }, { "first", F_FIRST, 1 }, { "ssids", F_NSS, -1 },
    { "frames", F_NONE, -1 }, { "signal", F_NONE, -1 }, { "mac", F_KEY, 1 },
    { NULL, 0, 0 } };
static const fv_sort_t SORT_PSS[] = {
    { "clients", F_NONE, -1 }, { "last", F_LAST, -1 }, { "first", F_FIRST, 1 },
    { "ssid", F_LABEL, 1 }, { NULL, 0, 0 } };
static const fv_sort_t SORT_BLE[] = {
    { "last", F_LAST, -1 }, { "first", F_FIRST, -1 }, { "rssi", F_SIGNAL, -1 },
    { "addr", F_KEY, 1 }, { "name", F_LABEL, 1 }, { NULL, 0, 0 } };
/* The ADS-B routes take no sort: both order by last seen (the panel puts
 * an emergency first and live before gone, which a peer row has neither
 * of). */
static const fv_sort_t SORT_AC[] = { { "last", F_LAST, -1 }, { NULL, 0, 0 } };

typedef struct {
    const fv_row_t *rows;
    int field, dir, ci, view;
} fv_order_t;

static fv_order_t g_ord;           /* one HTTP thread: qsort's context */

static int empty_of(const fv_row_t *r, int field) {
    switch (field) {
    case F_VENDOR:  return !r->vendor[0];
    case F_LABEL:   return !r->label[0];
    case F_SIGNAL:  return !r->has_rssi;
    case F_CHANNEL: return r->channel <= 0;
    case F_ENC:     return !r->enc[0];
    case F_NONE:    return 1;
    default:        return 0;
    }
}

static int ci_cmp(const char *a, const char *b) {
    for (;; a++, b++) {
        int x = lc((unsigned char)*a), y = lc((unsigned char)*b);
        if (x != y || !x) return x - y;
    }
}

static int by_order(const void *pa, const void *pb) {
    const fv_group_t *ga = pa, *gb = pb;
    const fv_row_t *a = &g_ord.rows[ga->at], *b = &g_ord.rows[gb->at];
    int f = g_ord.field, ea = empty_of(a, f), eb = empty_of(b, f), r = 0;
    /* An empty value last either way, as the routes order it. */
    if (ea != eb) return ea ? 1 : -1;
    if (!ea) {
        switch (f) {
        case F_LAST:    r = (ga->last > gb->last) - (ga->last < gb->last); break;
        case F_FIRST:   r = (ga->first > gb->first) - (ga->first < gb->first); break;
        case F_NSS:     r = ga->nss - gb->nss; break;
        case F_KEY:     r = strcmp(a->key, b->key); break;
        case F_VENDOR:  r = strcmp(a->vendor, b->vendor); break;
        case F_LABEL:   r = g_ord.ci ? ci_cmp(a->label, b->label) : strcmp(a->label, b->label); break;
        case F_SIGNAL:  r = (a->rssi > b->rssi) - (a->rssi < b->rssi); break;
        case F_CHANNEL: r = a->channel - b->channel; break;
        case F_ENC:     r = strcmp(a->enc, b->enc); break;
        default: break;
        }
        if (r) return r * g_ord.dir;
    }
    if (ga->last != gb->last) return ga->last > gb->last ? -1 : 1;
    return strcmp(gkey(g_ord.view, a), gkey(g_ord.view, b));
}

/* Is the key held by this sensor anywhere (whatever page or filter)?
 * 1, 0, or -1 when it could not be told (the read's budget ran out). */
static int held_here(int view, const web_fv_src_t *src, web_sdb_conn_t *c, int have_c,
                     sqlite3_stmt *pq, const char *key) {
    if (view == WEB_FV_BLE) {
        uint8_t a[6];
        for (int i = 0; i < 6; i++)
            a[i] = (uint8_t)(hexv((unsigned char)key[i * 3]) << 4 | hexv((unsigned char)key[i * 3 + 1]));
        web_ble_cand_t cand;
        return src->ble && web_ble_addr_info(src->ble, a, &cand) == 1;
    }
    if (is_ac(view)) {
        /* The panel's table (live or gone) for either list; for the
         * inventory, sloth.db's adsb_aircraft as well, whatever the
         * window, page or q. No panel (no --adsb) lists nothing. */
        if (src && src->adsb && web_adsb_has(src->adsb, key)) return 1;
        if (view == WEB_FV_ADSB) return 0;
        if (!have_c || web_sdb_spent(c)) return -1;
        web_sdb_ac_t a;
        int rc = web_sdb_adsb_one(c, key, &a);
        if (c->timed_out) return -1;
        return rc < 0 ? -1 : rc > 0;
    }
    if (!have_c || web_sdb_spent(c)) return -1;
    if (is_probe(view)) {
        /* A probe client sloth.db has a probe_clients or pnl_clients row
         * of, an SSID a pnl_ssids row names: whatever the window. */
        if (!pq) return -1;
        sqlite3_reset(pq);
        sqlite3_bind_text(pq, 1, key, -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(pq);
        if (c->timed_out) return -1;
        return rc == SQLITE_ROW ? 1 : rc == SQLITE_DONE ? 0 : -1;
    }
    web_sdb_item_t it;
    int rc = web_sdb_seen(c, view == WEB_FV_APS ? WEB_SEEN_AP : WEB_SEEN_DEVICE, key, NULL, &it);
    return rc < 0 ? -1 : rc > 0;
}

/* ── the list ────────────────────────────────────────────────────────── */

typedef struct {
    size_t s, e;                    /* the element's span */
    int    at, n;                   /* its key's peer rows; n 0: none */
} fv_el_t;

static void fleet_member(web_jw_t *w, const fv_site_t *st, int nst, int nremote,
                         int remote_more, int partial, const char *off) {
    web_jw_raw(w, ",\"fleet\":{\"peers\":[");
    for (int i = 0; i < nst; i++) {
        web_jw_raw(w, i ? ",{\"site\":" : "{\"site\":");
        web_jw_str(w, st[i].name);
        web_jw_raw(w, ",\"label\":");
        jstr_or_null(w, st[i].label);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"remote\":");     web_jw_int(w, nremote);
    web_jw_raw(w, ",\"remote_cap\":");  web_jw_int(w, WEB_FV_REMOTE_MAX);
    web_jw_raw(w, ",\"remote_more\":"); web_jw_raw(w, remote_more ? "true" : "false");
    web_jw_raw(w, ",\"partial\":");     web_jw_raw(w, partial ? "true" : "false");
    web_jw_raw(w, ",\"remote_off\":");  jstr_or_null(w, off);
    web_jw_raw(w, "}");
}

void web_fv_list(web_fleet_t *f, const web_fv_src_t *src, int view, const char *query,
                 long long now_s, char *body, size_t cap, size_t *len) {
    if (!f || view < 0 || view > WEB_FV_ADSB_SEEN || !*len || *len > cap) return;
    web_query_t *q = NULL;
    int *pick = NULL;
    const char *s = body;
    size_t n = *len;
    top_t t;
    memset(&t, 0, sizeof(t));
    t.s = s;
    t.arr = view == WEB_FV_ADSB_SEEN ? "aircraft" : NULL;
    size_t root_e;
    if (members(s, 0, n, top_member, &t, &root_e) != 0 || !t.rows_e) return;
    fv_site_t st[WEB_FLEET_PEERS];
    int nst = read_sites(f, st);

    fv_row_t *rows = malloc(sizeof(*rows) * WEB_FV_SCAN);
    fv_group_t *g = malloc(sizeof(*g) * WEB_FV_SCAN);
    fv_el_t *el = malloc(sizeof(*el) * 1100);
    char *out = malloc(cap);
    if (!rows || !g || !el || !out) goto done;
    int partial = 0;
    /* The Probes lists' window, as the route reads days= (it has already
     * refused a bad one): the peers' rows last seen in it. */
    long long since = 0;
    if (is_probe(view)) {
        char dv[16];
        long long days = WEB_PROBE_DAYS;
        if (qparam(query, "days", 0, dv, sizeof(dv)) && dv[0]) days = atoll(dv);
        since = days > 0 ? now_s - days * 86400 : 0;
    } else if (view == WEB_FV_ADSB_SEEN) {
        /* The inventory's window, days= as the route reads it (7). */
        char dv[16];
        long long days = 7;
        if (qparam(query, "days", 0, dv, sizeof(dv)) && dv[0]) days = atoll(dv);
        since = now_s - days * 86400;
    } else if (view == WEB_FV_ADSB) {
        /* The decoder's table is now: a peer's aircraft last seen within
         * the panel's own expiry (two of sloth's 300 s write heartbeats
         * and a margin) plus one pull interval, the most a peer's still
         * heard aircraft can lag here. */
        since = now_s - WEB_ADSB_TTL_S - (f->interval_s > 0 ? f->interval_s : 0);
    }
    int nr = read_rows(f, st, nst, view, NULL, since, rows, WEB_FV_SCAN, &partial);
    if (nr < 0) goto done;
    qsort(rows, (size_t)nr, sizeof(*rows),
          view == WEB_FV_PROBE_CLIENTS ? by_key_label
          : view == WEB_FV_PROBE_SSIDS ? by_label_last : by_key_last);
    int ng = 0;
    for (int i = 0; i < nr;) {
        int j = i + 1;
        while (j < nr && !strcmp(gkey(view, &rows[j]), gkey(view, &rows[i]))) j++;
        g[ng].at = i;
        g[ng].n = j - i;
        g[ng].local = 0;
        g[ng].first = rows[i].first;
        g[ng].last = rows[i].last;
        g[ng].nss = 0;
        g[ng].h = 0;
        if (is_probe(view)) {
            /* A probe key's rows are per SSID or per client: its times
             * are the earliest and the latest of them. */
            for (int k = i; k < j; k++) {
                if (rows[k].first < g[ng].first) g[ng].first = rows[k].first;
                if (rows[k].last > g[ng].last) g[ng].last = rows[k].last;
                if (k == i || strcmp(rows[k].label, rows[k - 1].label)) g[ng].nss++;
            }
        }
        if (view == WEB_FV_PROBE_SSIDS) {
            char sj[WEB_SSID_JSON_MAX(WEB_FLEET_STR_MAX)];
            size_t sl = ssid_json(rows[i].label, sj, sizeof(sj));
            g[ng].h = sl ? fnv64(sj, sl) : 0;
        }
        ng++;
        i = j;
    }

    /* The page's rows, each matched to its key's group. */
    static const char *const KEYM[] = { "mac", "bssid", "addr", "mac", "ssid", "hex", "hex" };
    int nel = 0;
    size_t i = ws(s, t.rows_s + 1, t.rows_e);
    if (i < t.rows_e && s[i] != ']') {
        for (;;) {
            size_t ee;
            top_t rt;
            memset(&rt, 0, sizeof(rt));
            rt.s = s;
            rt.want = KEYM[view];
            if (nel >= 1100 || members(s, i, t.rows_e, row_member, &rt, &ee) != 0) goto done;
            el[nel].s = i;
            el[nel].e = ee;
            el[nel].at = el[nel].n = 0;
            if (view == WEB_FV_PROBE_SSIDS && rt.key_e) {
                /* The SSID as the route wrote it, against each group's
                 * written the same way. */
                uint64_t hv = fnv64(s + rt.key_s, rt.key_e - rt.key_s);
                for (int k = 0; k < ng; k++) {
                    char sj[WEB_SSID_JSON_MAX(WEB_FLEET_STR_MAX)];
                    size_t sl;
                    if (g[k].h != hv) continue;
                    sl = ssid_json(rows[g[k].at].label, sj, sizeof(sj));
                    if (sl != rt.key_e - rt.key_s || memcmp(sj, s + rt.key_s, sl)) continue;
                    el[nel].at = g[k].at;
                    el[nel].n = g[k].n;
                    g[k].local = 1;
                    break;
                }
            } else if (rt.key[0]) {
                int lo = 0, hi = ng - 1;
                while (lo <= hi) {
                    int mid = (lo + hi) / 2, c = strcmp(rows[g[mid].at].key, rt.key);
                    if (!c) {
                        el[nel].at = g[mid].at;
                        el[nel].n = g[mid].n;
                        g[mid].local = 1;
                        break;
                    }
                    if (c < 0) lo = mid + 1; else hi = mid - 1;
                }
            }
            nel++;
            i = ws(s, ee, t.rows_e);
            if (i < t.rows_e && s[i] == ',') { i = ws(s, i + 1, t.rows_e); continue; }
            if (i < t.rows_e && s[i] == ']') break;
            goto done;
        }
    }

    /* The remote rows: on the page that ends the local list, the
     * filter's, in the route's order, none this sensor holds. */
    const char *off = NULL;
    int last_page = t.more_e && t.more_e - t.more_s == 5 && !memcmp(s + t.more_s, "false", 5);
    if (view == WEB_FV_ADSB) {
        /* /api/adsb pages nothing: its list ends when limit= cut none. */
        char tv[24] = "";
        if (t.tot_e > t.tot_s && t.tot_e - t.tot_s < sizeof(tv))
            memcpy(tv, s + t.tot_s, t.tot_e - t.tot_s);
        last_page = tv[0] && atoll(tv) == (long long)nel;
    }
    char qv[WEB_Q_LEN + 1] = "";
    if (!last_page) off = "not_last_page";
    if (!off && view == WEB_FV_DEVICES) {
        q = malloc(sizeof(*q));
        char err[48];
        if (!q) goto done;
        qparam(query, "q", 1, qv, sizeof(qv));
        if (web_query_parse(qv, now_s, q, err, sizeof(err)) != 0 || !query_peerable(q))
            off = "query";
    } else if (!off && (view == WEB_FV_BLE || view == WEB_FV_ADSB_SEEN)) {
        qparam(query, "q", 0, qv, sizeof(qv));
    }
    int npick = 0, cut = 0;
    if (!off) {
        int nc = 0;
        for (int k = 0; k < ng; k++) {
            if (g[k].local) continue;
            const fv_row_t *h = &rows[g[k].at];
            if (view == WEB_FV_DEVICES ? !dev_matches(q, h)
                : view == WEB_FV_BLE ? !ble_matches(qv, h)
                : view == WEB_FV_ADSB_SEEN ? !ac_matches(qv, h) : 0)
                continue;
            g[nc++] = g[k];
        }
        const fv_sort_t *so = view == WEB_FV_DEVICES ? SORT_DEV : view == WEB_FV_APS ? SORT_AP
                            : view == WEB_FV_PROBE_CLIENTS ? SORT_PCL
                            : view == WEB_FV_PROBE_SSIDS ? SORT_PSS
                            : is_ac(view) ? SORT_AC : SORT_BLE;
        char sw[16], dw[8];
        qparam(query, "sort", 0, sw, sizeof(sw));
        qparam(query, "dir", 0, dw, sizeof(dw));
        g_ord.rows = rows;
        g_ord.field = F_NONE;
        g_ord.dir = -1;
        g_ord.ci = view == WEB_FV_BLE;
        g_ord.view = view;
        if (!sw[0]) snprintf(sw, sizeof(sw), "%s", view == WEB_FV_PROBE_SSIDS ? "clients" : "last");
        for (int k = 0; so[k].word; k++)
            if (!strcmp(so[k].word, sw)) { g_ord.field = so[k].field; g_ord.dir = so[k].dir; }
        if (!strcmp(dw, "asc")) g_ord.dir = 1;
        else if (!strcmp(dw, "desc")) g_ord.dir = -1;
        qsort(g, (size_t)nc, sizeof(*g), by_order);
        pick = malloc(sizeof(*pick) * (WEB_FV_REMOTE_MAX + 1));
        if (!pick) goto done;
        web_sdb_conn_t c;
        memset(&c, 0, sizeof(c));
        int have_c = 0;
        sqlite3_stmt *pq = NULL;
        /* The ADS-B table answers from the panel alone. */
        if (view != WEB_FV_BLE && view != WEB_FV_ADSB && nc) {
            char oerr[WEB_SDB_ERR_MAX];
            if (src && src->sdb && src->sdb->configured &&
                web_slothdb_open(src->sdb, &c, WEB_SDB_HTTP_MS, now_s, oerr, sizeof(oerr)) == 0)
                have_c = 1;
            else
                off = "sloth_db";
        }
        if (have_c && is_probe(view)) {
            const char *hq = view == WEB_FV_PROBE_CLIENTS
                ? "SELECT 1 FROM probe_clients WHERE mac = ?1"
                  " UNION ALL SELECT 1 FROM pnl_clients WHERE mac = ?1 LIMIT 1"
                : "SELECT 1 FROM pnl_ssids WHERE ssid = ?1 LIMIT 1";
            if (sqlite3_prepare_v2(c.db, hq, -1, &pq, NULL) != SQLITE_OK) {
                sqlite3_finalize(pq);
                pq = NULL;
                off = "sloth_db";
            }
        }
        for (int k = 0; !off && k < nc; k++) {
            int hr = held_here(view, src, &c, have_c, pq, gkey(view, &rows[g[k].at]));
            if (hr < 0) { partial = 1; cut = 1; break; }
            if (hr) continue;
            if (npick == WEB_FV_REMOTE_MAX) { cut = 1; break; }
            pick[npick++] = k;
        }
        sqlite3_finalize(pq);
        if (have_c) web_slothdb_close(&c);
    }

    /* Write it: the route's bytes, each shared row's sites, the remote
     * rows, the fleet member; fewer remote rows, then no sites, until it
     * fits, else the answer as it was. */
    for (int pass = 0; pass < 12; pass++) {
        int with_sites = pass < 11;
        int nrem = pass >= 10 ? 0 : npick >> pass;
        web_jw_t w;
        web_jw_init(&w, out, cap);
        size_t pos = 0;
        splice(&w, s, t.rows_s + 1);
        pos = t.rows_s + 1;
        for (int e = 0; e < nel; e++) {
            splice(&w, s + pos, el[e].e - 1 - pos);
            if (with_sites && el[e].n) {
                web_jw_raw(&w, ",");
                sites_json(&w, &rows[el[e].at], el[e].n, st, nst);
            }
            splice(&w, "}", 1);
            pos = el[e].e;
        }
        size_t close = t.rows_e - 1;          /* the rows' ']' */
        splice(&w, s + pos, close - pos);
        for (int k = 0; k < nrem; k++) {
            if (nel || k) web_jw_raw(&w, ",");
            const fv_group_t *x = &g[pick[k]];
            remote_json(&w, view, &rows[x->at], x->n, x, src, st, nst);
        }
        splice(&w, s + close, root_e - 1 - close);
        fleet_member(&w, st, nst, nrem, cut || nrem < npick, partial, off);
        splice(&w, s + root_e - 1, n - (root_e - 1));
        if (!w.overflow) {
            memcpy(body, out, w.len);
            *len = w.len;
            break;
        }
    }
    free(pick);
done:
    free(q);
    free(rows);
    free(g);
    free(el);
    free(out);
}

/* ── the drawers ─────────────────────────────────────────────────────── */

/* The path's segment as a canonical MAC: percent-decoded, '-' as ':'. */
static int path_mac(const char *p, char *out) {
    char raw[24];
    size_t o = 0;
    for (; *p; p++) {
        int c = (unsigned char)*p;
        if (c == '%') {
            int h = hexv((unsigned char)p[1]), l = h >= 0 ? hexv((unsigned char)p[2]) : -1;
            if (h < 0 || l < 0) return -1;
            c = h * 16 + l;
            p += 2;
        }
        if (o + 1 >= sizeof(raw)) return -1;
        raw[o++] = (char)(c == '-' ? ':' : c);
    }
    raw[o] = '\0';
    return web_key_mac(raw, out);
}

static void detail_rows(web_jw_t *w, const char *name, int view, const fv_row_t *r, int n,
                        const fv_site_t *st, int nst) {
    web_jw_key(w, name);
    web_jw_raw(w, "[");
    for (int i = 0; i < n; i++) {
        const fv_row_t *x = &r[i];
        int k = site_of(st, nst, x->peer);
        web_jw_raw(w, i ? ",{\"site\":" : "{\"site\":");
        web_jw_str(w, x->peer);
        web_jw_raw(w, ",\"label\":");      jstr_or_null(w, k >= 0 ? st[k].label : NULL);
        web_jw_raw(w, ",\"kind\":");       web_jw_str(w, KIND[view]);
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, x->first);
        web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, x->last);
        if (is_ac(view)) {
            /* An aircraft row: every figure its line carried, null one
             * it did not; never a track. */
            const fv_row_t *a = x;
            web_jw_raw(w, ",\"visit_first\":");
            if (a->ac.visit_first) web_jw_int(w, a->ac.visit_first); else web_jw_raw(w, "null");
            web_jw_raw(w, ",\"flight\":");    jstr_or_null(w, a->label);
            web_jw_raw(w, ",\"squawk\":");    jstr_or_null(w, a->ac.squawk);
            web_jw_raw(w, ",\"category\":");  jstr_or_null(w, a->vendor);
            web_jw_raw(w, ",\"emergency\":"); jstr_or_null(w, a->ac.emergency);
            web_jw_raw(w, ",\"on_ground\":"); web_jw_raw(w, a->ac.on_ground ? "true" : "false");
            web_jw_raw(w, ",\"alt\":");       jw_num_or_null(w, a->ac.has_alt, a->ac.alt, 0);
            web_jw_raw(w, ",\"gs\":");        jw_num_or_null(w, a->ac.has_gs, a->ac.gs, 1);
            web_jw_raw(w, ",\"track\":");     jw_num_or_null(w, a->ac.has_track, a->ac.track, 1);
            web_jw_raw(w, ",\"rssi\":");      jw_num_or_null(w, a->ac.has_rssi, a->ac.rssi, 1);
            web_jw_raw(w, ",\"messages\":");
            if (a->ac.has_msgs) web_jw_int(w, a->ac.msgs); else web_jw_raw(w, "null");
            web_jw_raw(w, ",\"lat\":");       jw_num_or_null(w, a->ac.has_pos, a->ac.lat, 5);
            web_jw_raw(w, ",\"lon\":");       jw_num_or_null(w, a->ac.has_pos, a->ac.lon, 5);
            web_jw_raw(w, ",\"pos_ts\":");
            if (a->ac.has_pos) web_jw_int(w, a->ac.pos_ts); else web_jw_raw(w, "null");
            web_jw_raw(w, ",\"pos_prev\":");
            if (a->ac.has_pos) web_jw_int(w, a->ac.pos_prev); else web_jw_raw(w, "null");
            web_jw_raw(w, ",\"pos_alt\":");   jw_num_or_null(w, a->ac.has_palt, a->ac.palt, 0);
        } else if (is_probe(view)) {
            /* A probe row: the SSID the client asked for, nothing more. */
            web_jw_raw(w, ",\"ssid\":");   web_jw_ssid(w, x->label);
            web_jw_ssid_meta(w, "ssid", x->label);
        } else if (view == WEB_FV_BLE) {
            web_jw_raw(w, ",\"name\":");   jstr_or_null(w, x->label);
            web_jw_raw(w, ",\"class\":");  jstr_or_null(w, ble_class_slug(x->vendor));
            web_jw_raw(w, ",\"rssi\":");   signal_json(w, x);
        } else {
            web_jw_raw(w, ",\"ssid\":");   web_jw_ssid(w, x->label);
            web_jw_raw(w, ",\"vendor\":"); jstr_or_null(w, x->vendor);
            web_jw_raw(w, ",\"signal\":"); signal_json(w, x);
            if (view == WEB_FV_DEVICES) {
                if (x->has_ap) { web_jw_raw(w, ",\"is_ap\":"); web_jw_raw(w, x->is_ap ? "true" : "false"); }
                web_jw_raw(w, ",\"bssid\":"); jstr_or_null(w, x->bssid);
            } else {
                web_jw_raw(w, ",\"channel\":");
                if (x->channel > 0) web_jw_int(w, x->channel); else web_jw_raw(w, "null");
                web_jw_raw(w, ",\"enc\":"); jstr_or_null(w, x->enc);
            }
            web_jw_ssid_meta(w, "ssid", x->label);
        }
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "]");
}

/* "seen at NAME, NAME": each host that saw it, once, newest first. */
static void seen_at(web_jw_t *w, const fv_row_t *r, int n, const fv_site_t *st, int nst) {
    char note[WEB_FLEET_PEERS * (WEB_FLEET_STR_MAX + 2) + 16];
    size_t o = (size_t)snprintf(note, sizeof(note), "seen at ");
    for (int i = 0; i < n; i++) {
        int dup = 0;
        for (int j = 0; j < i; j++) if (!strcmp(r[j].peer, r[i].peer)) dup = 1;
        if (dup) continue;
        int m = snprintf(note + o, sizeof(note) - o, "%s%s", o > 8 ? ", " : "",
                         site_word(st, nst, r[i].peer));
        if (m < 0 || (size_t)m >= sizeof(note) - o) break;
        o += (size_t)m;
    }
    web_jw_str(w, note);
}

/* One list's rows (nwifi < 0: of the kind one; else a device's three)
 * under the host that saw it last. */
static void fleet_detail(web_jw_t *w, int remote, const fv_row_t *r, int n, int nwifi,
                         int nap, int one, const fv_site_t *st, int nst) {
    web_jw_raw(w, "\"fleet\":{\"remote\":");
    web_jw_raw(w, remote ? "true" : "false");
    int nb = 0;                                 /* the host that saw it last */
    for (int i = 1; i < n; i++) if (r[i].last > r[nb].last) nb = i;
    web_jw_raw(w, ",\"site\":");
    web_jw_str(w, r[nb].peer);
    web_jw_raw(w, ",\"site_label\":");
    jstr_or_null(w, site_of(st, nst, r[nb].peer) >= 0 ? st[site_of(st, nst, r[nb].peer)].label : NULL);
    web_jw_raw(w, ",\"note\":");
    if (remote) seen_at(w, r, n, st, nst); else web_jw_raw(w, "null");
    web_jw_raw(w, ",");
    /* A device's rows are the wifi rows, the AP rows, then the probe
     * rows of the MAC. */
    if (nwifi >= 0) {
        detail_rows(w, "rows", WEB_FV_DEVICES, r, nwifi, st, nst);
        web_jw_raw(w, ",");
        detail_rows(w, "ap_rows", WEB_FV_APS, r + nwifi, nap, st, nst);
        web_jw_raw(w, ",");
        detail_rows(w, "probe_rows", WEB_FV_PROBE_CLIENTS, r + nwifi + nap, n - nwifi - nap,
                    st, nst);
    } else {
        detail_rows(w, "rows", one, r, n, st, nst);
    }
    web_jw_raw(w, "}");
}

void web_fv_detail(web_fleet_t *f, int ble, const char *path_key, long long now_s,
                   char *body, size_t cap, size_t *len, int *status) {
    char key[WEB_KEY_MAX + 1];
    if (!f || !path_key || path_mac(path_key, key) != 0 || *len > cap) return;
    fv_site_t st[WEB_FLEET_PEERS];
    int nst = read_sites(f, st);
    enum { PER = 2 * WEB_FLEET_PEERS };
    fv_row_t *rows = malloc(sizeof(*rows) * (2 * PER + WEB_FV_DRAWER_PROBES));
    char *out = malloc(cap);
    if (!rows || !out) goto done;
    int partial, nw, na = 0, np = 0;
    nw = read_rows(f, st, nst, ble ? WEB_FV_BLE : WEB_FV_DEVICES, key, 0, rows, PER, &partial);
    if (nw < 0) goto done;
    if (!ble) {
        na = read_rows(f, st, nst, WEB_FV_APS, key, 0, rows + nw, PER, &partial);
        if (na < 0) goto done;
        /* The SSIDs a peer heard the MAC probe for: a client only a peer
         * heard probing opens here from the Probes view. */
        np = read_rows(f, st, nst, WEB_FV_PROBE_CLIENTS, key, 0, rows + nw + na,
                       WEB_FV_DRAWER_PROBES, &partial);
        if (np < 0) goto done;
    }
    if (nw + na + np == 0) goto done;
    web_jw_t w;
    web_jw_init(&w, out, cap);
    if (ble && *status == 404) {
        /* No row of this sensor's: the peers' rows only. */
        web_jw_raw(&w, "{\"now\":");  web_jw_int(&w, now_s);
        web_jw_raw(&w, ",\"rows\":[],\"alerts\":[],\"count\":0,");
        fleet_detail(&w, 1, rows, nw, -1, 0, WEB_FV_BLE, st, nst);
        web_jw_raw(&w, "}\n");
    } else {
        top_t t;
        memset(&t, 0, sizeof(t));
        t.s = body;
        size_t root_e;
        if ((*status != 200) || members(body, 0, *len, top_member, &t, &root_e) != 0) goto done;
        int remote = !ble && t.rec_e - t.rec_s == 4 && !memcmp(body + t.rec_s, "null", 4);
        splice(&w, body, root_e - 1);
        web_jw_raw(&w, ",");
        if (ble) fleet_detail(&w, 0, rows, nw, -1, 0, WEB_FV_BLE, st, nst);
        else fleet_detail(&w, remote, rows, nw + na + np, nw, na, 0, st, nst);
        splice(&w, body + root_e - 1, *len - (root_e - 1));
    }
    if (w.overflow) goto done;
    memcpy(body, out, w.len);
    *len = w.len;
    *status = 200;
done:
    free(rows);
    free(out);
}

void web_fv_aircraft(web_fleet_t *f, const web_fv_src_t *src, const char *query,
                     long long now_s, char *body, size_t cap, size_t *len, int status) {
    char hex[16];
    (void)now_s;
    if (!f || status != 200 || !*len || *len > cap) return;
    if (!qparam(query, "hex", 0, hex, sizeof(hex)) || !icao_ok(hex)) return;
    fv_site_t st[WEB_FLEET_PEERS];
    int nst = read_sites(f, st);
    enum { PER = 2 * WEB_FLEET_PEERS };
    fv_row_t *rows = malloc(sizeof(*rows) * PER);
    char *out = malloc(cap);
    if (!rows || !out) goto done;
    int partial;
    int n = read_rows(f, st, nst, WEB_FV_ADSB, hex, 0, rows, PER, &partial);
    if (n <= 0) goto done;
    top_t t;
    memset(&t, 0, sizeof(t));
    t.s = body;
    size_t root_e;
    if (members(body, 0, *len, top_member, &t, &root_e) != 0 || !t.ac_e) goto done;
    /* Held here: sloth.db's inventory row, or the panel's table. */
    int remote = t.ac_e - t.ac_s == 4 && !memcmp(body + t.ac_s, "null", 4) &&
                 !(src && src->adsb && web_adsb_has(src->adsb, hex));
    web_jw_t w;
    web_jw_init(&w, out, cap);
    splice(&w, body, root_e - 1);
    web_jw_raw(&w, ",");
    fleet_detail(&w, remote, rows, n, -1, 0, WEB_FV_ADSB, st, nst);
    splice(&w, body + root_e - 1, *len - (root_e - 1));
    if (w.overflow) goto done;
    memcpy(body, out, w.len);
    *len = w.len;
done:
    free(rows);
    free(out);
}

#else  /* !WITH_SQLITE: no store, nothing to merge */

void web_fv_list(web_fleet_t *f, const web_fv_src_t *src, int view, const char *query,
                 long long now_s, char *body, size_t cap, size_t *len) {
    (void)f; (void)src; (void)view; (void)query; (void)now_s; (void)body; (void)cap;
    (void)len;
}

void web_fv_detail(web_fleet_t *f, int ble, const char *path_key, long long now_s,
                   char *body, size_t cap, size_t *len, int *status) {
    (void)f; (void)ble; (void)path_key; (void)now_s; (void)body; (void)cap; (void)len;
    (void)status;
}

void web_fv_aircraft(web_fleet_t *f, const web_fv_src_t *src, const char *query,
                     long long now_s, char *body, size_t cap, size_t *len, int status) {
    (void)f; (void)src; (void)query; (void)now_s; (void)body; (void)cap; (void)len;
    (void)status;
}

#endif
