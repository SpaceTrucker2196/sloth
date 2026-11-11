#include "web_fleet.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "web_alertkb.h"
#include "web_ble.h"
#include "web_bledev.h"
#include "web_frrs.h"
#include "web_gnss.h"
#include "web_jsonl.h"
#include "web_metrics.h"
#include "web_series.h"
#include "web_slothdb.h"
#include "web_store.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

#ifndef SLOTHWEB_BUILD_VERSION
#define SLOTHWEB_BUILD_VERSION "unknown"
#endif

#define T_MAX 4102444800LL           /* 2100-01-01: no clock reads later */
#define AFTER_K(q, k) ((q).only == (k) && (q).has_after)

/* ── the members ───────────────────────────────────────────────────── */

static const char *const KIND_WORD[WEB_FK_COUNT] = {
    "wifi", "ble", "ap", "probe", "alert", "verdict",
};

const char *web_fleet_kind_word(int k) {
    return k >= 0 && k < WEB_FK_COUNT ? KIND_WORD[k] : "";
}

int web_fleet_kind_pages(int k) {
    return k == WEB_FK_WIFI || k == WEB_FK_AP || k == WEB_FK_ALERT || k == WEB_FK_VERDICT;
}

/* The BLE table is read whole every export: it holds fewer advertisers
 * than the kind's cap, so the BLE kind is never cut and needs no page. */
typedef char web_fleet_ble_never_cut[WEB_FLEET_CAP_BLE >= WEB_BLE_DEVICES ? 1 : -1];

int web_fleet_cursor_ok(const char *s) {
    if (!s) return 0;
    const char *t = strchr(s, '~');
    if (!t || t == s || t - s > 12) return 0;
    for (const char *p = s; p < t; p++)
        if (*p < '0' || *p > '9') return 0;
    size_t n = strlen(t + 1);
    if (n > WEB_FLEET_TOK_MAX) return 0;
    for (const char *p = t + 1; *p; p++) {
        char c = *p;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              c == ':'))
            return 0;
    }
    return 1;
}

/* "<ts>~<tok>" into its parts; the caller checked it. */
static void cursor_split(const char *s, long long *ts, char *tok, size_t cap) {
    *ts = 0;
    const char *t = strchr(s, '~');
    for (const char *p = s; p < t; p++) *ts = *ts * 10 + (*p - '0');
    snprintf(tok, cap, "%s", t + 1);
}

/* Each row: the line's type, then its members ("type" is implied). The
 * writer names no member that is not here (jk() fails the export if it
 * tries) and the reader refuses a line holding one that is not. */
static const char *const M_HDR[] = {
    "fleet_export", "fleet_export_version", "generated", "since", "site_label",
    "slothweb_version", "sloth_version", "sloth_db", "lat", "lon", "alt_m",
    "pos_source", "pos_ts", "pos_age_s", NULL };
static const char *const M_GNSS[] = {
    "gnss", "gps_state", "sats_in_view", "sats_used", "cn0_mean",
    "time_offset_ms", "jam", "ts", NULL };
static const char *const M_WIFI[] = {
    "wifi", "mac", "vendor", "ssid", "rssi", "bssid", "is_ap", "first_seen",
    "last_seen", NULL };
static const char *const M_BLE[] = {
    "ble", "addr", "addr_type", "name", "class", "rssi", "first_seen",
    "last_seen", NULL };
static const char *const M_AP[] = {
    "ap", "bssid", "ssid", "channel", "enc", "vendor", "rssi", "first_seen",
    "last_seen", NULL };
static const char *const M_PROBE[] = {
    "probe", "mac", "ssid", "first_seen", "last_seen", NULL };
static const char *const M_ALERT[] = {
    "alert", "alert_type", "ty", "fingerprint", "title", "ip", "sev", "count",
    "first_seen", "last_seen", NULL };
static const char *const M_VERDICT[] = {
    "verdict", "alert_type", "addr", "port", "alert_first_seen", "state", "ts",
    NULL };
static const char *const M_END[] = {
    "fleet_end", "rows", "wifi", "ble", "ap", "probe", "alert", "verdict",
    "truncated_wifi", "truncated_ble", "truncated_ap", "truncated_probe",
    "truncated_alert", "truncated_verdict", "next_wifi", "next_ap", "next_alert",
    "next_verdict", "complete", NULL };

const char *const *const web_fleet_members[] = {
    M_HDR, M_GNSS, M_WIFI, M_BLE, M_AP, M_PROBE, M_ALERT, M_VERDICT, M_END,
};
const size_t web_fleet_members_n = sizeof(web_fleet_members) / sizeof(web_fleet_members[0]);

const char *const *web_fleet_members_of(const char *type) {
    if (!type) return NULL;
    for (size_t i = 0; i < web_fleet_members_n; i++)
        if (!strcmp(web_fleet_members[i][0], type)) return web_fleet_members[i];
    return NULL;
}

static int is_member(const char *const *m, const char *name) {
    for (int i = 1; m[i]; i++)
        if (!strcmp(m[i], name)) return 1;
    return 0;
}

/* A member's key, from the table only: an unlisted name fails the
 * whole answer rather than reach the wire. */
static void jk(web_jw_t *w, const char *const *m, const char *name) {
    if (!is_member(m, name)) { w->overflow = 1; return; }
    web_jw_raw(w, ",\"");
    web_jw_raw(w, name);
    web_jw_raw(w, "\":");
}

static void jstr_or_null(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s);
    else web_jw_raw(w, "null");
}

static void jfix(web_jw_t *w, double v, int dp) {
    char b[48];
    snprintf(b, sizeof(b), "%.*f", dp, v);
    web_jw_raw(w, b);
}

/* ── the peer list ─────────────────────────────────────────────────── */

static int name_ok(const char *s, size_t n) {
    if (n == 0 || n > WEB_FLEET_NAME_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

int web_fleet_parse_peer(const char *spec, web_fleet_peer_cfg_t *out,
                         char *err, size_t errsz) {
    memset(out, 0, sizeof(*out));
    const char *eq = spec ? strchr(spec, '=') : NULL;
    if (!eq) {
        snprintf(err, errsz, "want NAME=http://A.B.C.D[:PORT]");
        return -1;
    }
    if (!name_ok(spec, (size_t)(eq - spec))) {
        snprintf(err, errsz, "the name must be 1 to %d of A-Z a-z 0-9 . _ -",
                 WEB_FLEET_NAME_MAX);
        return -1;
    }
    memcpy(out->name, spec, (size_t)(eq - spec));
    const char *u = eq + 1;
    if (strncmp(u, "http://", 7) != 0) {
        snprintf(err, errsz, "the URL must start http:// (no TLS: the tailnet "
                             "encrypts the link)");
        return -1;
    }
    if (strlen(u) > WEB_FLEET_URL_MAX) {
        snprintf(err, errsz, "the URL is longer than %d bytes", WEB_FLEET_URL_MAX);
        return -1;
    }
    const char *h = u + 7;
    size_t hl = strcspn(h, ":/");
    char host[24];
    if (hl == 0 || hl >= sizeof(host)) {
        snprintf(err, errsz, "not a literal IPv4 address (names are not resolved)");
        return -1;
    }
    memcpy(host, h, hl);
    host[hl] = '\0';
    struct in_addr a;
    if (inet_pton(AF_INET, host, &a) != 1) {
        snprintf(err, errsz, "not a literal IPv4 address (names are not resolved)");
        return -1;
    }
    memcpy(out->addr, &a, 4);
    const char *p = h + hl;
    long port = 80;
    if (*p == ':') {
        p++;
        if (*p < '0' || *p > '9') {
            snprintf(err, errsz, "bad port");
            return -1;
        }
        port = 0;
        while (*p >= '0' && *p <= '9') {
            port = port * 10 + (*p++ - '0');
            if (port > 65535) break;
        }
        if (port < 1 || port > 65535) {
            snprintf(err, errsz, "bad port");
            return -1;
        }
    }
    if (*p == '/') p++;
    if (*p) {
        snprintf(err, errsz, "the URL is the peer's address only, with no path");
        return -1;
    }
    out->port = (uint16_t)port;
    snprintf(out->url, sizeof(out->url), "http://%s:%ld", host, port);
    return 0;
}

int web_fleet_in_tailnet(const uint8_t a[4]) {
    return a[0] == 100 && (a[1] & 0xc0) == 64;
}

int web_fleet_check_peer(const web_fleet_peer_cfg_t *p, int allow_outside,
                         char *err, size_t errsz) {
    if (web_fleet_in_tailnet(p->addr) || allow_outside) return 0;
    snprintf(err, errsz, "%s is outside the tailnet (100.64.0.0/10); refused "
             "without --peer-allow-outside-tailnet", p->url);
    return -1;
}

/* ── the export ────────────────────────────────────────────────────── */

/* The importer's own checks (below), which the export holds each line it
 * writes to: a row the importer would refuse is never sent, because one
 * such row refuses the peer's whole answer, at every pull, for as long as
 * the row is in the window. */
typedef struct frow {
    int       kind;                  /* WEB_FK_*, or -1 for gnss */
    char      key[2 * WEB_FLEET_STR_MAX + 4];
    char      label[WEB_FLEET_STR_MAX + 1];
    char      vendor[WEB_FLEET_STR_MAX + 1];
    int       has_rssi, rssi;
    long long first, last;
    char      extra[2048];
} frow_t;

typedef struct fhdr {
    long long generated, pos_ts;
    char      label[WEB_FLEET_STR_MAX + 1];
    char      version[32];
    char      pos_source[8];
    int       has_pos, has_alt;
    double    lat, lon, alt;
} fhdr_t;

static int row_of(const web_jrec_t *r, const char *type, frow_t *o, const char **why);
static int hdr_of(const web_jrec_t *r, fhdr_t *h);

/* The request: since, whether the end line carries each pageable kind's
 * cursor (next=1, or any page), and a page of one kind after a cursor. */
typedef struct {
    long long since;
    int       next;
    int       only;                  /* -1 every kind, else the page's WEB_FK_* */
    int       has_after;
    long long after_ts;
    char      after_tok[WEB_FLEET_TOK_MAX + 1];
    char      after[WEB_FLEET_CUR_MAX + 1];
} xq_t;

typedef struct {
    web_jw_t   *w;
    long long   since;
    const xq_t *q;
    int         n[WEB_FK_COUNT];
    int         cut[WEB_FK_COUNT];
    int         skip[WEB_FK_COUNT];  /* a row the importer would refuse, left out */
    /* Each pageable kind's last row sent, in its reader's order: the
     * next page starts after it. */
    int         has_cur[WEB_FK_COUNT];
    long long   cur_ts[WEB_FK_COUNT];
    char        cur_tok[WEB_FK_COUNT][WEB_FLEET_TOK_MAX + 1];
    size_t      soft;                /* rows stop here; the end line after */
    web_sdb_conn_t *c;
    const char *pnl_mac;
    int         pnl_cut;
    long long   alert_after_rid;     /* the alert page's rid bound */
    /* Every key of the alert reader's scan was sent and the scan did
     * not reach the range's floor: the next page starts at its oldest
     * row's last_seen, every key there included. */
    int         alert_bottom;
    long long   alert_bottom_ts;
    web_jrec_t *rec;                 /* the self-check's decoder record */
} xp_t;

static void set_cur(xp_t *x, int k, long long ts, const char *tok) {
    size_t n = strlen(tok);
    if (n > WEB_FLEET_TOK_MAX) return;    /* never a key the row passed with */
    x->has_cur[k] = 1;
    x->cur_ts[k] = ts;
    memcpy(x->cur_tok[k], tok, n + 1);
}

static void set_cur_n(xp_t *x, int k, long long ts, long long id) {
    char b[24];
    snprintf(b, sizeof(b), "%lld", id);
    set_cur(x, k, ts, b);
}

/* Would the importer take the line at buf[mark..len)? type NULL: the
 * header. */
static int line_takes(xp_t *x, size_t mark, const char *type) {
    web_jw_t *w = x->w;
    if (web_jl_parse(w->buf + mark, w->len - mark, x->rec) != WEB_JL_OK) return 0;
    if (!type) {
        fhdr_t h;
        return hdr_of(x->rec, &h) == 0;
    }
    frow_t o;
    const char *why;
    return row_of(x->rec, type, &o, &why) == 0;
}

/* A row is written whole or not at all: past the soft bound it is taken
 * back and its kind marked cut, and so is a row the importer would refuse
 * (a sensor's value outside the importer's range: the row is not sent and
 * the kind says it is not whole). 1 when it was kept, 0 cut (stop), 2
 * dropped (go on), -1 a fault. */
static void row_begin(xp_t *x, size_t *mark) {
    *mark = x->w->len;
}

static int row_end(xp_t *x, int k, size_t mark) {
    web_jw_t *w = x->w;
    if (w->overflow || w->len > x->soft) {
        /* Overflow short of the soft bound is jk() refusing an unlisted
         * member, not room: a fault, left set so the answer is a 503. */
        if (w->overflow && w->len <= x->soft) return -1;
        w->len = mark;
        w->overflow = 0;
        x->cut[k] = 1;
        return 0;
    }
    web_jw_raw(w, "}");
    if (!w->overflow && !line_takes(x, mark, KIND_WORD[k])) {
        w->len = mark;
        x->skip[k] = 1;
        return 2;
    }
    web_jw_raw(w, "\n");
    if (w->overflow || w->len > x->soft) {
        w->len = mark;
        w->overflow = 0;
        x->cut[k] = 1;
        return 0;
    }
    x->n[k]++;
    return 1;
}

static void xp_header(xp_t *x, long long now_s, long long since, const char *label,
                      const char *sdb_word, const web_loc_t *loc) {
    web_jw_t *w = x->w;
    w->len = 0;
    web_jw_raw(w, "{\"type\":\"fleet_export\"");
    jk(w, M_HDR, "fleet_export_version"); web_jw_int(w, WEB_FLEET_EXPORT_VERSION);
    jk(w, M_HDR, "generated");            web_jw_int(w, now_s);
    jk(w, M_HDR, "since");                web_jw_int(w, since);
    jk(w, M_HDR, "site_label");           jstr_or_null(w, label);
    jk(w, M_HDR, "slothweb_version");     web_jw_str(w, SLOTHWEB_BUILD_VERSION);
    /* The running sensor's own version is not kept by slothweb. */
    jk(w, M_HDR, "sloth_version");        web_jw_raw(w, "null");
    jk(w, M_HDR, "sloth_db");             web_jw_str(w, sdb_word);
    jk(w, M_HDR, "lat");
    if (loc->has) jfix(w, loc->lat, 7); else web_jw_raw(w, "null");
    jk(w, M_HDR, "lon");
    if (loc->has) jfix(w, loc->lon, 7); else web_jw_raw(w, "null");
    jk(w, M_HDR, "alt_m");
    if (loc->has && loc->has_alt) jfix(w, loc->alt_m, 1); else web_jw_raw(w, "null");
    jk(w, M_HDR, "pos_source");           jstr_or_null(w, loc->has ? loc->src : NULL);
    jk(w, M_HDR, "pos_ts");
    if (loc->has) web_jw_int(w, loc->ts); else web_jw_raw(w, "null");
    jk(w, M_HDR, "pos_age_s");
    if (loc->has) web_jw_int(w, now_s > loc->ts ? now_s - loc->ts : 0);
    else web_jw_raw(w, "null");
    web_jw_raw(w, "}");
}

static int xp_assoc(void *ctx, const web_sdb_item_t *it) {
    char *bssid = ctx;
    char k[WEB_KEY_MAX + 1];
    if (web_key_mac(it->a, k) == 0) snprintf(bssid, WEB_KEY_MAX + 1, "%s", k);
    return 1;
}

static int xp_pnl(void *ctx, const web_sdb_item_t *it);

/* A client's wifi line, then its probe list's lines: a device goes with
 * all of its probes or not at all, so the probe kind rides the wifi
 * kind's cursor and is never cut on its own. */
static int xp_dev(void *ctx, const web_sdb_dev_t *d) {
    xp_t *x = ctx;
    if (x->n[WEB_FK_WIFI] >= WEB_FLEET_CAP_WIFI) { x->cut[WEB_FK_WIFI] = 1; return 1; }
    char mac[WEB_KEY_MAX + 1];
    if (web_key_mac(d->mac, mac) != 0) return 0;
    char bssid[WEB_KEY_MAX + 1] = "";
    if (!d->is_ap) web_sdb_assocs(x->c, mac, 1, xp_assoc, bssid);
    size_t dmark = x->w->len;
    int np0 = x->n[WEB_FK_PROBE];
    size_t mark;
    row_begin(x, &mark);
    web_jw_t *w = x->w;
    web_jw_raw(w, "{\"type\":\"wifi\"");
    jk(w, M_WIFI, "mac");        web_jw_str(w, mac);
    jk(w, M_WIFI, "vendor");     jstr_or_null(w, d->vendor);
    jk(w, M_WIFI, "ssid");       jstr_or_null(w, d->ssid);
    jk(w, M_WIFI, "rssi");
    if (d->has_signal) web_jw_int(w, d->signal_dbm); else web_jw_raw(w, "null");
    jk(w, M_WIFI, "bssid");      jstr_or_null(w, bssid);
    jk(w, M_WIFI, "is_ap");      web_jw_raw(w, d->is_ap ? "true" : "false");
    jk(w, M_WIFI, "first_seen"); web_jw_int(w, d->first_seen);
    jk(w, M_WIFI, "last_seen");  web_jw_int(w, d->last_seen);
    int r = row_end(x, WEB_FK_WIFI, mark);
    if (r != 1) return r == 2 ? 0 : 1;
    if (!d->is_ap) {
        x->pnl_mac = mac;
        x->pnl_cut = 0;
        int pr = web_sdb_ssids(x->c, mac, WEB_FLEET_PNL_PER, xp_pnl, x);
        if (x->pnl_cut || pr < 0 || x->c->timed_out) {
            /* The probe kind's cap or the body's bound mid-list, or the
             * read's budget: this device is taken back whole and the
             * next page starts at it. */
            x->w->len = dmark;
            x->w->overflow = 0;
            x->n[WEB_FK_WIFI]--;
            x->n[WEB_FK_PROBE] = np0;
            x->cut[WEB_FK_WIFI] = x->cut[WEB_FK_PROBE] = 1;
            return 1;
        }
    }
    set_cur(x, WEB_FK_WIFI, d->last_seen, d->mac);
    return 0;
}

static int xp_ap(void *ctx, const web_sdb_ap_t *a) {
    xp_t *x = ctx;
    if (a->last_seen < x->since) return 1;     /* newest first: the rest are older */
    if (x->n[WEB_FK_AP] >= WEB_FLEET_CAP_AP) { x->cut[WEB_FK_AP] = 1; return 1; }
    char bssid[WEB_KEY_MAX + 1];
    if (web_key_mac(a->bssid, bssid) != 0) return 0;
    size_t mark;
    row_begin(x, &mark);
    web_jw_t *w = x->w;
    web_jw_raw(w, "{\"type\":\"ap\"");
    jk(w, M_AP, "bssid");      web_jw_str(w, bssid);
    jk(w, M_AP, "ssid");       jstr_or_null(w, a->ssid);
    jk(w, M_AP, "channel");
    if (a->channel > 0) web_jw_int(w, a->channel); else web_jw_raw(w, "null");
    jk(w, M_AP, "enc");        jstr_or_null(w, a->enc);
    jk(w, M_AP, "vendor");     jstr_or_null(w, a->vendor);
    jk(w, M_AP, "rssi");
    if (a->has_signal) web_jw_int(w, a->signal_dbm); else web_jw_raw(w, "null");
    jk(w, M_AP, "first_seen"); web_jw_int(w, a->first_seen);
    jk(w, M_AP, "last_seen");  web_jw_int(w, a->last_seen);
    int r = row_end(x, WEB_FK_AP, mark);
    if (r == 1) set_cur(x, WEB_FK_AP, a->last_seen, a->bssid);
    return r <= 0;
}

static int xp_pnl(void *ctx, const web_sdb_item_t *it) {
    xp_t *x = ctx;
    if (it->last_seen < x->since) return 1;    /* newest first */
    if (x->n[WEB_FK_PROBE] >= WEB_FLEET_CAP_PROBE) { x->pnl_cut = 1; return 1; }
    size_t mark;
    row_begin(x, &mark);
    web_jw_t *w = x->w;
    web_jw_raw(w, "{\"type\":\"probe\"");
    jk(w, M_PROBE, "mac");        web_jw_str(w, x->pnl_mac);
    jk(w, M_PROBE, "ssid");       web_jw_str(w, it->a);
    jk(w, M_PROBE, "first_seen"); web_jw_int(w, it->first_seen);
    jk(w, M_PROBE, "last_seen");  web_jw_int(w, it->last_seen);
    int r = row_end(x, WEB_FK_PROBE, mark);
    if (r == 0 || r < 0) x->pnl_cut = 1;
    return r <= 0;
}

/* An alert's fingerprint: its type and title (sloth's own words, or an
 * SSID it named), hashed. Never its key, which the reader cannot read
 * (it can hold a credential's username, web_slothdb.h). */
static void alert_fp(long long ty, const char *title, char out[17]) {
    char s[WEB_SDB_TEXT_MAX + 32];
    snprintf(s, sizeof(s), "%lld|%s", ty, title ? title : "");
    web_ble_key_hash(s, out);
}

static int xp_alert(void *ctx, const web_sdb_item_t *it) {
    xp_t *x = ctx;
    /* A page: the reader's order is (last_seen, rid) newest first, so
     * the rows at or before the cursor are passed over here. */
    if (x->q->only == WEB_FK_ALERT && x->q->has_after &&
        !(it->last_seen < x->q->after_ts ||
          (it->last_seen == x->q->after_ts && it->rid < x->alert_after_rid)))
        return 0;
    if (x->n[WEB_FK_ALERT] >= WEB_FLEET_CAP_ALERT) { x->cut[WEB_FK_ALERT] = 1; return 1; }
    long long ty = it->n1 & 0xffff;
    const web_akb_t *k = web_akb_get(ty);
    char fp[17], ip[WEB_KEY_MAX + 1] = "";
    alert_fp(ty, it->a, fp);
    if (it->b[0] && web_key_ip(it->b, ip) != 0) ip[0] = '\0';
    size_t mark;
    row_begin(x, &mark);
    web_jw_t *w = x->w;
    web_jw_raw(w, "{\"type\":\"alert\"");
    jk(w, M_ALERT, "alert_type");  jstr_or_null(w, k ? k->name : NULL);
    jk(w, M_ALERT, "ty");          web_jw_int(w, ty);
    jk(w, M_ALERT, "fingerprint"); web_jw_str(w, fp);
    jk(w, M_ALERT, "title");       jstr_or_null(w, it->a);
    jk(w, M_ALERT, "ip");          jstr_or_null(w, ip);
    jk(w, M_ALERT, "sev");         web_jw_int(w, it->n2 < 0 ? 0 : it->n2 > 2 ? 2 : it->n2);
    jk(w, M_ALERT, "count");       web_jw_int(w, it->has_n3 && it->n3 > 0 ? it->n3 : 0);
    jk(w, M_ALERT, "first_seen");  web_jw_int(w, it->first_seen);
    jk(w, M_ALERT, "last_seen");   web_jw_int(w, it->last_seen);
    int r = row_end(x, WEB_FK_ALERT, mark);
    if (r == 1) set_cur_n(x, WEB_FK_ALERT, it->last_seen, it->rid);
    return r <= 0;
}

static int xp_verdict(void *ctx, const web_frrs_verdict_t *v) {
    xp_t *x = ctx;
    if (x->n[WEB_FK_VERDICT] >= WEB_FLEET_CAP_VERDICT) { x->cut[WEB_FK_VERDICT] = 1; return 1; }
    const web_akb_t *k = web_akb_get(v->type);
    if (!k) return 0;
    size_t mark;
    row_begin(x, &mark);
    web_jw_t *w = x->w;
    web_jw_raw(w, "{\"type\":\"verdict\"");
    jk(w, M_VERDICT, "alert_type");       web_jw_str(w, k->name);
    jk(w, M_VERDICT, "addr");             jstr_or_null(w, v->addr);
    jk(w, M_VERDICT, "port");             web_jw_int(w, v->port);
    jk(w, M_VERDICT, "alert_first_seen"); web_jw_int(w, v->first_seen);
    jk(w, M_VERDICT, "state");            web_jw_str(w, web_frrs_state_word(v->state));
    jk(w, M_VERDICT, "ts");               web_jw_int(w, v->ts);
    int r = row_end(x, WEB_FK_VERDICT, mark);
    if (r == 1) set_cur_n(x, WEB_FK_VERDICT, v->ts, v->id);
    return r <= 0;
}

static void xp_ble(xp_t *x, struct web_ble *ble, long long now_s) {
    web_ble_cand_t *cand = malloc(sizeof(*cand) * WEB_FLEET_CAP_BLE);
    if (!cand) { x->cut[WEB_FK_BLE] = 1; return; }
    int more = 0;
    int n = web_ble_candidates(ble, x->since, now_s + 1, cand, WEB_FLEET_CAP_BLE,
                               &more, NULL);
    if (more) x->cut[WEB_FK_BLE] = 1;
    for (int i = 0; i < n; i++) {
        const web_ble_cand_t *c = &cand[i];
        char addr[18], ty[2] = { web_ble_type_ch(c->addr_type), 0 };
        snprintf(addr, sizeof(addr), "%02x:%02x:%02x:%02x:%02x:%02x", c->addr[0],
                 c->addr[1], c->addr[2], c->addr[3], c->addr[4], c->addr[5]);
        const char *cls = c->cls >= 0 && c->cls < WEB_BC_COUNT
                        ? web_ble_classes[c->cls].slug : "b:unk";
        if (!strncmp(cls, "b:", 2)) cls += 2;
        size_t mark;
        row_begin(x, &mark);
        web_jw_t *w = x->w;
        web_jw_raw(w, "{\"type\":\"ble\"");
        jk(w, M_BLE, "addr");       web_jw_str(w, addr);
        jk(w, M_BLE, "addr_type");  web_jw_str(w, ty);
        jk(w, M_BLE, "name");       jstr_or_null(w, c->name);
        jk(w, M_BLE, "class");      web_jw_str(w, cls);
        jk(w, M_BLE, "rssi");
        if (c->has_rssi) web_jw_int(w, c->rssi); else web_jw_raw(w, "null");
        jk(w, M_BLE, "first_seen"); web_jw_int(w, c->first_seen);
        jk(w, M_BLE, "last_seen");  web_jw_int(w, c->last_seen);
        if (row_end(x, WEB_FK_BLE, mark) <= 0) break;
    }
    free(cand);
}

static int kind_of_word(const char *s, size_t n) {
    for (int k = 0; k < WEB_FK_COUNT; k++)
        if (strlen(KIND_WORD[k]) == n && !strncmp(KIND_WORD[k], s, n)) return k;
    return -1;
}

/* since=EPOCH, next=1, kind=wifi|ap|alert|verdict, after=CURSOR (with
 * kind), each at most once, nothing else. */
static int parse_query(const char *q, xq_t *x, const char **why) {
    memset(x, 0, sizeof(*x));
    x->only = -1;
    if (!q || !q[0]) return 0;
    int seen_since = 0, seen_kind = 0;
    for (const char *p = q; *p;) {
        size_t n = strcspn(p, "&");
        const char *eq = memchr(p, '=', n);
        if (!eq) { *why = "unknown_parameter"; return -1; }
        size_t kl = (size_t)(eq - p), vl = n - kl - 1;
        const char *v = eq + 1;
        if (kl == 5 && !strncmp(p, "since", 5) && !seen_since) {
            seen_since = 1;
            if (vl == 0 || vl > 12) { *why = "bad_since"; return -1; }
            for (size_t i = 0; i < vl; i++) {
                if (v[i] < '0' || v[i] > '9') { *why = "bad_since"; return -1; }
                x->since = x->since * 10 + (v[i] - '0');
            }
        } else if (kl == 4 && !strncmp(p, "next", 4) && !x->next) {
            if (vl != 1 || v[0] != '1') { *why = "bad_next"; return -1; }
            x->next = 1;
        } else if (kl == 4 && !strncmp(p, "kind", 4) && !seen_kind) {
            seen_kind = 1;
            int k = kind_of_word(v, vl);
            if (k < 0 || !web_fleet_kind_pages(k)) { *why = "bad_kind"; return -1; }
            x->only = k;
        } else if (kl == 5 && !strncmp(p, "after", 5) && !x->has_after) {
            if (vl == 0 || vl > WEB_FLEET_CUR_MAX) { *why = "bad_after"; return -1; }
            memcpy(x->after, v, vl);
            x->after[vl] = '\0';
            if (!web_fleet_cursor_ok(x->after)) { *why = "bad_after"; return -1; }
            cursor_split(x->after, &x->after_ts, x->after_tok, sizeof(x->after_tok));
            x->has_after = 1;
        } else {
            *why = "unknown_parameter";
            return -1;
        }
        p += n;
        if (*p == '&') p++;
    }
    if (x->has_after && x->only < 0) { *why = "after_needs_kind"; return -1; }
    if (x->only >= 0) x->next = 1;
    return 0;
}

int web_fleet_export_route(const web_fleet_src_t *src, const char *query,
                           long long now_s, char **body, size_t *len,
                           int *status) {
    *body = NULL;
    *len = 0;
    xq_t xq;
    const char *why = NULL;
    if (parse_query(query, &xq, &why) != 0) {
        char *b = malloc(256);
        if (!b) return -1;
        *len = web_series_error_json(why, b, 256);
        *body = b;
        *status = 400;
        return *len ? 0 : -1;
    }
    long long since = xq.since;
    char *buf = malloc(WEB_FLEET_EXPORT_MAX);
    web_jrec_t *rec = malloc(sizeof(*rec));
    if (!buf || !rec) { free(buf); free(rec); return -1; }
    web_jw_t w;
    web_jw_init(&w, buf, WEB_FLEET_EXPORT_MAX);
    xp_t x;
    memset(&x, 0, sizeof(x));
    x.w = &w;
    x.since = since;
    x.q = &xq;
    x.soft = WEB_FLEET_EXPORT_MAX - 4096;
    x.rec = rec;
    x.alert_after_rid = LLONG_MAX;
    if (xq.only == WEB_FK_ALERT && xq.has_after && xq.after_tok[0]) {
        long long r = 0;
        for (const char *p = xq.after_tok; *p >= '0' && *p <= '9' && r < LLONG_MAX / 20; p++)
            r = r * 10 + (*p - '0');
        x.alert_after_rid = r;
    }

    /* sloth.db, through the M4 reader and its column allow-list. */
    web_sdb_conn_t c;
    memset(&c, 0, sizeof(c));
    const char *sdb_word = "none";
    int have_c = 0;
    if (src->sdb && src->sdb->configured) {
        char err[WEB_SDB_ERR_MAX];
        if (web_slothdb_open(src->sdb, &c, WEB_SDB_OVERVIEW_MS, now_s, err,
                             sizeof(err)) == 0) {
            have_c = 1;
            sdb_word = "open";
        } else {
            web_slothdb_close(&c);
            sdb_word = "unavailable";
        }
    }
    x.c = have_c ? &c : NULL;
    char label[WEB_SDB_TEXT_MAX + 1] = "";
    if (have_c) {
        web_sdb_session_t ss;
        if (web_sdb_sessions(&c, &ss, 1) == 1) snprintf(label, sizeof(label), "%s", ss.label);
    }
    web_loc_t loc;
    web_gnss_sh_t sh;
    web_gnss_site(src->gnss, &loc, &sh);

    /* The header, held to the importer's checks like every line: a
     * position it would refuse goes as none rather than refuse the
     * answer; a header it refuses without one is a fault (a 503). */
    xp_header(&x, now_s, since, label, sdb_word, &loc);
    if (!w.overflow && !line_takes(&x, 0, NULL)) {
        loc.has = 0;
        xp_header(&x, now_s, since, label, sdb_word, &loc);
        if (!line_takes(&x, 0, NULL)) w.overflow = 1;
    }
    web_jw_raw(&w, "\n");

    if (sh.seen && !w.overflow && xq.only < 0) {
        size_t gmark = w.len;
        web_jw_raw(&w, "{\"type\":\"gnss\"");
        jk(&w, M_GNSS, "gps_state");    web_jw_str(&w, sh.gps_state);
        jk(&w, M_GNSS, "sats_in_view"); web_jw_int(&w, sh.sats_in_view);
        jk(&w, M_GNSS, "sats_used");    web_jw_int(&w, sh.sats_used);
        jk(&w, M_GNSS, "cn0_mean");     jfix(&w, sh.cn0_mean, 1);
        jk(&w, M_GNSS, "time_offset_ms");
        if (sh.has_time_off) web_jw_int(&w, sh.time_off_ms); else web_jw_raw(&w, "null");
        jk(&w, M_GNSS, "jam");
        if (sh.jam >= 0) web_jw_int(&w, sh.jam); else web_jw_raw(&w, "null");
        jk(&w, M_GNSS, "ts");           web_jw_int(&w, sh.ts);
        web_jw_raw(&w, "}");
        /* The receiver's summary is optional: one the importer would
         * refuse is left out. */
        if (!w.overflow && !line_takes(&x, gmark, "gnss")) w.len = gmark;
        else web_jw_raw(&w, "\n");
    }
    int fault = w.overflow;

    /* A page reads its one kind after the cursor; the whole export
     * reads every kind from the top. */
    int all = xq.only < 0;
#define WANT(k) (all || xq.only == (k))
#define AFTER(k) (xq.only == (k) && xq.has_after)
    if (have_c && !fault) {
        if (WANT(WEB_FK_WIFI) &&
            (AFTER(WEB_FK_WIFI)
                 ? web_sdb_devices_after(&c, since, LLONG_MAX / 2, xq.after_ts, xq.after_tok,
                                         WEB_FLEET_CAP_WIFI + 1, xp_dev, &x)
                 : web_sdb_devices_between(&c, since, LLONG_MAX / 2, WEB_FLEET_CAP_WIFI + 1,
                                           0, xp_dev, &x)) < 0)
            x.cut[WEB_FK_WIFI] = 1;
        if (WANT(WEB_FK_AP) && !c.timed_out &&
            (AFTER(WEB_FK_AP)
                 ? web_sdb_aps_after(&c, xq.after_ts, xq.after_tok, WEB_FLEET_CAP_AP + 1,
                                     xp_ap, &x)
                 : web_sdb_aps(&c, WEB_AP_SORT_LAST, WEB_FLEET_CAP_AP + 1, 0, xp_ap, &x)) < 0)
            x.cut[WEB_FK_AP] = 1;
        /* The alert reader takes its keys from the newest
         * WEB_SDB_ALERT_SCAN rows of the range, which on a busy sensor
         * (one key's incidents by the thousand) hold far fewer keys than
         * the cap: the rows past the scan are a cut like any other, and
         * the cursor is then the scan's oldest last_seen. A page reads
         * the rows at or before its cursor (web_sdb_alerts_upto()) and
         * passes over the keys at it that were sent (xp_alert()); a key
         * newer than the cursor may come again with an older last_seen,
         * which the importer's widening takes as it is. */
        if (WANT(WEB_FK_ALERT) && !c.timed_out) {
            long long ub = AFTER(WEB_FK_ALERT) ? xq.after_ts : -1;
            int ar = ub >= 0
                ? web_sdb_alerts_upto(&c, since, LLONG_MAX / 2, ub, WEB_SDB_ALERT_SCAN,
                                      xp_alert, &x)
                : web_sdb_alerts_between(&c, since, LLONG_MAX / 2, WEB_FLEET_CAP_ALERT + 1,
                                         xp_alert, &x);
            if (ar < 0) {
                x.cut[WEB_FK_ALERT] = 1;
            } else if (!x.cut[WEB_FK_ALERT] && !c.timed_out) {
                long long rows = 0, oldest = 0;
                int sr = ub >= 0
                    ? web_sdb_alerts_scan_upto(&c, since, LLONG_MAX / 2, ub, &rows, &oldest)
                    : web_sdb_alerts_scan(&c, since, LLONG_MAX / 2, &rows, &oldest);
                if (sr < 0) {
                    x.cut[WEB_FK_ALERT] = 1;
                } else if (rows >= WEB_SDB_ALERT_SCAN) {
                    x.cut[WEB_FK_ALERT] = 1;
                    x.alert_bottom = 1;
                    x.alert_bottom_ts = oldest;
                }
            }
        }
        /* A read that ran out of budget is a cut, never an error: what
         * was read before it went out, and the cursor says where. */
        if (c.timed_out) {
            if (WANT(WEB_FK_WIFI)) x.cut[WEB_FK_WIFI] = x.cut[WEB_FK_PROBE] = 1;
            if (WANT(WEB_FK_AP)) x.cut[WEB_FK_AP] = 1;
            if (WANT(WEB_FK_ALERT)) x.cut[WEB_FK_ALERT] = 1;
        }
    }
    if (have_c) web_slothdb_close(&c);
    if (all && src->ble && !fault) xp_ble(&x, src->ble, now_s);
    if (WANT(WEB_FK_VERDICT) && src->frrs && !fault) {
        long long ats = -1, aid = 0;
        if (AFTER(WEB_FK_VERDICT)) {
            ats = xq.after_ts;
            aid = LLONG_MAX;
            if (xq.after_tok[0]) {
                aid = 0;
                for (const char *p = xq.after_tok; *p >= '0' && *p <= '9' && aid < LLONG_MAX / 20; p++)
                    aid = aid * 10 + (*p - '0');
            }
        }
        if (web_frrs_verdicts(src->frrs, since, ats, aid, WEB_FLEET_CAP_VERDICT + 1,
                              xp_verdict, &x) < 0)
            x.cut[WEB_FK_VERDICT] = 1;
    }
#undef WANT
#undef AFTER
    fault = fault || w.overflow;

    long long rows = 0;
    for (int k = 0; k < WEB_FK_COUNT; k++) rows += x.n[k];
    web_jw_raw(&w, "{\"type\":\"fleet_end\"");
    jk(&w, M_END, "rows"); web_jw_int(&w, rows);
    for (int k = 0; k < WEB_FK_COUNT; k++) {
        jk(&w, M_END, KIND_WORD[k]);
        web_jw_int(&w, x.n[k]);
    }
    for (int k = 0; k < WEB_FK_COUNT; k++) {
        char nm[32];
        snprintf(nm, sizeof(nm), "truncated_%s", KIND_WORD[k]);
        jk(&w, M_END, nm);
        web_jw_raw(&w, x.cut[k] || x.skip[k] ? "true" : "false");
    }
    /* Each pageable kind's cursor when it was cut: the next page starts
     * after the last row sent (a page that sent none starts where it
     * was asked to, a whole export that sent none at the top). Asked
     * for only, so an F1 puller, which refuses a member it does not
     * know, is still answered. */
    if (xq.next) {
        for (int k = 0; k < WEB_FK_COUNT; k++) {
            if (!web_fleet_kind_pages(k)) continue;
            char nm[32], cur[WEB_FLEET_CUR_MAX + 1];
            snprintf(nm, sizeof(nm), "next_%s", KIND_WORD[k]);
            jk(&w, M_END, nm);
            if (!x.cut[k]) { web_jw_raw(&w, "null"); continue; }
            if (k == WEB_FK_ALERT && x.alert_bottom)
                snprintf(cur, sizeof(cur), "%lld~", x.alert_bottom_ts);
            else if (x.has_cur[k])
                snprintf(cur, sizeof(cur), "%lld~%s", x.cur_ts[k], x.cur_tok[k]);
            else if (AFTER_K(xq, k))
                snprintf(cur, sizeof(cur), "%s", xq.after);
            else
                snprintf(cur, sizeof(cur), "%lld~", T_MAX);
            if (!web_fleet_cursor_ok(cur)) w.overflow = 1;
            web_jw_str(&w, cur);
        }
    }
    jk(&w, M_END, "complete"); web_jw_raw(&w, "true");
    web_jw_raw(&w, "}\n");
    free(rec);
    if (fault || w.overflow) {
        *len = web_series_error_json("export_failed", buf, WEB_FLEET_EXPORT_MAX);
        *status = 503;
    } else {
        *len = w.len;
        *status = 200;
    }
    *body = buf;
    return *len ? 0 : -1;
}

/* ── the pull: one HTTP/1.1 GET ────────────────────────────────────── */

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int stopping(web_fleet_t *f) {
    pthread_mutex_lock(&f->mu);
    int s = f->stop;
    pthread_mutex_unlock(&f->mu);
    return s;
}

/* Wait for ev on fd until deadline, a quarter second at a time so a
 * stop is seen. 1 ready, 0 timed out, -1 stopped or failed. */
static int wait_fd(web_fleet_t *f, int fd, short ev, long long deadline) {
    for (;;) {
        long long left = deadline - mono_ms();
        if (left <= 0) return 0;
        if (stopping(f)) return -1;
        struct pollfd p = { fd, ev, 0 };
        int r = poll(&p, 1, left > 250 ? 250 : (int)left);
        if (r > 0) return 1;
        if (r < 0 && errno != EINTR) return -1;
    }
}

static int ci_prefix(const char *a, const char *b) {
    for (; *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (x != y) return 0;
    }
    return 1;
}

/* *unknown_param (may be NULL): set when the answer was a 400 naming
 * unknown_parameter, an F1 export's word for next=1. */
static int http_get(web_fleet_t *f, const web_fleet_peer_cfg_t *p, const char *query,
                    char **out, size_t *outlen, char *err, size_t errsz,
                    int *unknown_param) {
    *out = NULL;
    *outlen = 0;
    if (unknown_param) *unknown_param = 0;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        snprintf(err, errsz, "socket: %s", strerror(errno));
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    memcpy(&sa.sin_addr, p->addr, 4);
    sa.sin_port = htons(p->port);
    long long deadline = mono_ms() + f->connect_ms;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (errno != EINPROGRESS) {
            snprintf(err, errsz, "connect: %s", strerror(errno));
            close(fd);
            return -1;
        }
        int r = wait_fd(f, fd, POLLOUT, deadline);
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (r <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr) {
            snprintf(err, errsz, "connect: %s",
                     r == 0 ? "timed out" : r < 0 ? "stopped" : strerror(soerr ? soerr : errno));
            close(fd);
            return -1;
        }
    }
    char host[INET_ADDRSTRLEN] = "";
    inet_ntop(AF_INET, p->addr, host, sizeof(host));
    char rq[384];
    int rl = snprintf(rq, sizeof(rq), "GET /api/fleet/export?%s HTTP/1.1\r\n"
                      "Host: %s:%u\r\nUser-Agent: slothweb-fleet\r\n"
                      "Accept: application/x-ndjson\r\nConnection: close\r\n\r\n",
                      query, host, (unsigned)p->port);
    if (rl <= 0 || (size_t)rl >= sizeof(rq)) {
        snprintf(err, errsz, "request too long");
        close(fd);
        return -1;
    }
    deadline = mono_ms() + f->read_ms;
    for (int off = 0; off < rl;) {
        ssize_t n = send(fd, rq + off, (size_t)(rl - off), MSG_NOSIGNAL);
        if (n > 0) { off += (int)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            if (wait_fd(f, fd, POLLOUT, deadline) == 1) continue;
        }
        snprintf(err, errsz, "send: %s", n < 0 ? strerror(errno) : "closed");
        close(fd);
        return -1;
    }
    size_t limit = f->resp_max + WEB_FLEET_HDR_MAX, cap = 65536, len = 0;
    char *b = malloc(cap + 1);
    if (!b) { close(fd); snprintf(err, errsz, "out of memory"); return -1; }
    for (;;) {
        if (len == cap) {
            if (cap >= limit) {
                snprintf(err, errsz, "response over %zu bytes: refused", f->resp_max);
                goto fail;
            }
            size_t nc = cap * 2 > limit ? limit : cap * 2;
            char *nb = realloc(b, nc + 1);
            if (!nb) { snprintf(err, errsz, "out of memory"); goto fail; }
            b = nb;
            cap = nc;
        }
        ssize_t n = recv(fd, b + len, cap - len, 0);
        if (n > 0) { len += (size_t)n; continue; }
        if (n == 0) break;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            int r = wait_fd(f, fd, POLLIN, deadline);
            if (r == 1) continue;
            snprintf(err, errsz, "read: %s", r == 0 ? "timed out" : "stopped");
            goto fail;
        }
        snprintf(err, errsz, "read: %s", strerror(errno));
        goto fail;
    }
    close(fd);
    fd = -1;
    b[len] = '\0';
    if (len < 12 || (strncmp(b, "HTTP/1.1 ", 9) && strncmp(b, "HTTP/1.0 ", 9))) {
        snprintf(err, errsz, "not an HTTP response");
        goto fail;
    }
    if (strncmp(b + 9, "200 ", 4) != 0) {
        char st[4] = "???";
        for (int i = 0; i < 3; i++)
            if (b[9 + i] >= '0' && b[9 + i] <= '9') st[i] = b[9 + i];
        snprintf(err, errsz, "HTTP status %s", st);
        if (unknown_param && !strcmp(st, "400") && strstr(b, "\"unknown_parameter\""))
            *unknown_param = 1;
        goto fail;
    }
    char *end = strstr(b, "\r\n\r\n");
    if (!end || (size_t)(end - b) > WEB_FLEET_HDR_MAX) {
        snprintf(err, errsz, "no end to the response header");
        goto fail;
    }
    size_t hl = (size_t)(end - b) + 4, bl = len - hl;
    long long clen = -1;
    for (char *h = strstr(b, "\r\n"); h && h < end; h = strstr(h + 2, "\r\n")) {
        /* A transfer coding is not read (the export never uses one, and
         * a chunked body read as lines would be refused for the wrong
         * reason), and a second Content-Length is refused as RFC 9112
         * 6.3 asks, not resolved. */
        if (ci_prefix(h + 2, "transfer-encoding:")) {
            snprintf(err, errsz, "a Transfer-Encoding response is not read: refused");
            goto fail;
        }
        if (ci_prefix(h + 2, "content-length:")) {
            if (clen >= 0) {
                snprintf(err, errsz, "two Content-Length headers: refused");
                goto fail;
            }
            const char *v = h + 2 + 15;
            while (*v == ' ' || *v == '\t') v++;
            if (*v < '0' || *v > '9') {
                snprintf(err, errsz, "a Content-Length that is not a number: refused");
                goto fail;
            }
            clen = 0;
            while (*v >= '0' && *v <= '9' && clen < (1LL << 40)) clen = clen * 10 + (*v++ - '0');
        }
    }
    if (bl > f->resp_max || (clen >= 0 && (size_t)clen > f->resp_max)) {
        snprintf(err, errsz, "response over %zu bytes: refused", f->resp_max);
        goto fail;
    }
    if (clen >= 0 && (size_t)clen != bl) {
        snprintf(err, errsz, "response cut short (%zu of %lld bytes): refused", bl, clen);
        goto fail;
    }
    memmove(b, b + hl, bl);
    b[bl] = '\0';
    *out = b;
    *outlen = bl;
    return 0;
fail:
    if (fd >= 0) close(fd);
    free(b);
    return -1;
}

/* ── the ingest: check whole, then store ───────────────────────────── */

/* Absent or null: "" and 0. A string at most max bytes: 1. Anything
 * else: -1. */
static int v_str(const web_jrec_t *r, const char *k, size_t max, char *out, size_t cap) {
    out[0] = '\0';
    const web_jfield_t *f = web_jl_get(r, k);
    if (!f || f->kind == WEB_J_NULL) return 0;
    if (f->kind != WEB_J_STR || f->slen > max || f->slen >= cap) return -1;
    memcpy(out, f->str, f->slen + 1);
    return 1;
}

/* Absent or null: 0. An integer in lo..hi: 1 (in *v). Else -1. */
static int v_int(const web_jrec_t *r, const char *k, long long lo, long long hi,
                 long long *v) {
    *v = 0;
    const web_jfield_t *f = web_jl_get(r, k);
    if (!f || f->kind == WEB_J_NULL) return 0;
    if (f->kind != WEB_J_INT || f->i < lo || f->i > hi) return -1;
    *v = f->i;
    return 1;
}

static int v_bool(const web_jrec_t *r, const char *k, int *v) {
    *v = 0;
    const web_jfield_t *f = web_jl_get(r, k);
    if (!f || f->kind == WEB_J_NULL) return 0;
    if (f->kind != WEB_J_BOOL) return -1;
    *v = f->i != 0;
    return 1;
}

static int v_num(const web_jrec_t *r, const char *k, double lo, double hi, double *v) {
    *v = 0;
    const web_jfield_t *f = web_jl_get(r, k);
    if (!f || f->kind == WEB_J_NULL) return 0;
    if (!web_jl_num(r, k, v) || !isfinite(*v) || *v < lo || *v > hi) return -1;
    return 1;
}

static int v_mac(const web_jrec_t *r, const char *k, char *out) {
    char s[WEB_KEY_MAX + 1];
    if (v_str(r, k, WEB_KEY_MAX, s, sizeof(s)) != 1) return -1;
    return web_key_mac(s, out) == 0 ? 1 : -1;
}

/* Every member known, and nothing twice (the decoder refuses that). */
static int members_ok(const web_jrec_t *r, const char *const *m) {
    for (int i = 0; i < r->n; i++) {
        if (!strcmp(r->f[i].key, "type")) continue;
        if (!is_member(m, r->f[i].key)) return 0;
    }
    return 1;
}

static int times_ok(const web_jrec_t *r, long long *first, long long *last) {
    if (v_int(r, "first_seen", 0, T_MAX, first) != 1 ||
        v_int(r, "last_seen", 0, T_MAX, last) != 1 || *first > *last)
        return 0;
    return 1;
}

static int rssi_of(const web_jrec_t *r, frow_t *o) {
    long long v;
    int g = v_int(r, "rssi", -150, 30, &v);
    if (g < 0) return 0;
    o->has_rssi = g == 1;
    o->rssi = (int)v;
    return 1;
}

static void ex_begin(web_jw_t *w, char *buf, size_t cap) {
    web_jw_init(w, buf, cap);
    web_jw_raw(w, "{");
}

static void ex_key(web_jw_t *w, int *first, const char *k) {
    web_jw_raw(w, *first ? "\"" : ",\"");
    web_jw_raw(w, k);
    web_jw_raw(w, "\":");
    *first = 0;
}

/* One of triage's five state words (web_frrs.h), not a filter group. */
static int state_word(const char *s) {
    int v = web_frrs_filter_find(s);
    return v >= 0 && v < WEB_TRI_COUNT;
}

/* One data line into a row. 0, or -1 with why. */
static int row_of(const web_jrec_t *r, const char *type, frow_t *o, const char **why) {
    memset(o, 0, sizeof(o[0]));
    *why = "bad_value";
    web_jw_t w;
    int fst = 1;
    char a[WEB_FLEET_STR_MAX + 1], b[WEB_FLEET_STR_MAX + 1];
    long long v;
    if (!strcmp(type, "wifi")) {
        o->kind = WEB_FK_WIFI;
        int ap;
        if (v_mac(r, "mac", o->key) != 1 || !times_ok(r, &o->first, &o->last) ||
            !rssi_of(r, o) || v_str(r, "vendor", WEB_FLEET_STR_MAX, o->vendor, sizeof(o->vendor)) < 0 ||
            v_str(r, "ssid", WEB_FLEET_STR_MAX, o->label, sizeof(o->label)) < 0 ||
            v_bool(r, "is_ap", &ap) < 0)
            return -1;
        char bs[WEB_KEY_MAX + 1] = "";
        if (web_jl_get(r, "bssid") && web_jl_get(r, "bssid")->kind != WEB_J_NULL &&
            v_mac(r, "bssid", bs) != 1)
            return -1;
        ex_begin(&w, o->extra, sizeof(o->extra));
        ex_key(&w, &fst, "bssid");
        jstr_or_null(&w, bs);
        ex_key(&w, &fst, "is_ap");
        web_jw_raw(&w, ap ? "true" : "false");
    } else if (!strcmp(type, "ble")) {
        o->kind = WEB_FK_BLE;
        if (v_mac(r, "addr", o->key) != 1 || !times_ok(r, &o->first, &o->last) ||
            !rssi_of(r, o) || v_str(r, "name", WEB_FLEET_STR_MAX, o->label, sizeof(o->label)) < 0 ||
            v_str(r, "class", 15, o->vendor, sizeof(o->vendor)) < 0 ||
            v_str(r, "addr_type", 1, a, sizeof(a)) < 0)
            return -1;
        ex_begin(&w, o->extra, sizeof(o->extra));
        ex_key(&w, &fst, "addr_type");
        jstr_or_null(&w, a);
    } else if (!strcmp(type, "ap")) {
        o->kind = WEB_FK_AP;
        if (v_mac(r, "bssid", o->key) != 1 || !times_ok(r, &o->first, &o->last) ||
            !rssi_of(r, o) || v_str(r, "ssid", WEB_FLEET_STR_MAX, o->label, sizeof(o->label)) < 0 ||
            v_str(r, "vendor", WEB_FLEET_STR_MAX, o->vendor, sizeof(o->vendor)) < 0 ||
            v_str(r, "enc", 63, a, sizeof(a)) < 0 || v_int(r, "channel", 0, 255, &v) < 0)
            return -1;
        ex_begin(&w, o->extra, sizeof(o->extra));
        ex_key(&w, &fst, "channel");
        if (v > 0) web_jw_int(&w, v); else web_jw_raw(&w, "null");
        ex_key(&w, &fst, "enc");
        jstr_or_null(&w, a);
    } else if (!strcmp(type, "probe")) {
        o->kind = WEB_FK_PROBE;
        char mac[WEB_KEY_MAX + 1];
        if (v_mac(r, "mac", mac) != 1 || !times_ok(r, &o->first, &o->last) ||
            v_str(r, "ssid", WEB_FLEET_STR_MAX, o->label, sizeof(o->label)) != 1)
            return -1;
        snprintf(o->key, sizeof(o->key), "%s|%s", mac, o->label);
        ex_begin(&w, o->extra, sizeof(o->extra));
        ex_key(&w, &fst, "mac");
        web_jw_str(&w, mac);
    } else if (!strcmp(type, "alert")) {
        o->kind = WEB_FK_ALERT;
        long long ty, sev, count;
        char ip[WEB_KEY_MAX + 1] = "";
        if (v_str(r, "fingerprint", 16, a, sizeof(a)) != 1 || strlen(a) != 16 ||
            strspn(a, "0123456789abcdef") != 16 || !times_ok(r, &o->first, &o->last) ||
            v_int(r, "ty", 0, 65535, &ty) != 1 || v_int(r, "sev", 0, 2, &sev) != 1 ||
            v_int(r, "count", 0, LLONG_MAX / 4, &count) < 0 ||
            v_str(r, "alert_type", 47, b, sizeof(b)) < 0 ||
            v_str(r, "title", WEB_FLEET_STR_MAX, o->label, sizeof(o->label)) < 0)
            return -1;
        char ipr[WEB_FLEET_STR_MAX + 1];
        int gi = v_str(r, "ip", 45, ipr, sizeof(ipr));
        if (gi < 0 || (gi == 1 && web_key_ip(ipr, ip) != 0)) return -1;
        snprintf(o->key, sizeof(o->key), "%s", a);
        ex_begin(&w, o->extra, sizeof(o->extra));
        ex_key(&w, &fst, "alert_type"); jstr_or_null(&w, b);
        ex_key(&w, &fst, "ty");         web_jw_int(&w, ty);
        ex_key(&w, &fst, "ip");         jstr_or_null(&w, ip);
        ex_key(&w, &fst, "sev");        web_jw_int(&w, sev);
        ex_key(&w, &fst, "count");      web_jw_int(&w, count);
    } else if (!strcmp(type, "verdict")) {
        o->kind = WEB_FK_VERDICT;
        long long port, afs, ts;
        char st[16], addr[WEB_KEY_MAX + 1] = "", ar[WEB_FLEET_STR_MAX + 1];
        if (v_str(r, "alert_type", 47, b, sizeof(b)) != 1 || web_akb_find(b) < 0 ||
            v_str(r, "state", 12, st, sizeof(st)) != 1 || !state_word(st) ||
            v_int(r, "port", 0, 65535, &port) < 0 ||
            v_int(r, "alert_first_seen", 0, T_MAX, &afs) < 0 ||
            v_int(r, "ts", 1, T_MAX, &ts) != 1)
            return -1;
        int ga = v_str(r, "addr", 45, ar, sizeof(ar));
        if (ga < 0 || (ga == 1 && web_key_ip(ar, addr) != 0 && web_key_mac(ar, addr) != 0))
            return -1;
        snprintf(o->key, sizeof(o->key), "%s|%s|%lld|%lld", b, addr, port, afs);
        snprintf(o->label, sizeof(o->label), "%s", st);
        o->first = o->last = ts;
        ex_begin(&w, o->extra, sizeof(o->extra));
        ex_key(&w, &fst, "alert_type");       web_jw_str(&w, b);
        ex_key(&w, &fst, "addr");             jstr_or_null(&w, addr);
        ex_key(&w, &fst, "port");             web_jw_int(&w, port);
        ex_key(&w, &fst, "alert_first_seen"); web_jw_int(&w, afs);
    } else if (!strcmp(type, "gnss")) {
        o->kind = -1;
        long long sv, su, off, jam, ts;
        double cn0;
        int goff;
        if (v_str(r, "gps_state", 15, a, sizeof(a)) < 0 ||
            v_int(r, "sats_in_view", 0, 999, &sv) < 0 || v_int(r, "sats_used", 0, 999, &su) < 0 ||
            v_num(r, "cn0_mean", 0, 99, &cn0) < 0 ||
            (goff = v_int(r, "time_offset_ms", -(1LL << 46), 1LL << 46, &off)) < 0 ||
            v_int(r, "jam", 0, 255, &jam) < 0 || v_int(r, "ts", 0, T_MAX, &ts) < 0)
            return -1;
        snprintf(o->key, sizeof(o->key), "receiver");
        snprintf(o->label, sizeof(o->label), "%s", a);
        o->first = o->last = ts;
        ex_begin(&w, o->extra, sizeof(o->extra));
        ex_key(&w, &fst, "sats_in_view"); web_jw_int(&w, sv);
        ex_key(&w, &fst, "sats_used");    web_jw_int(&w, su);
        ex_key(&w, &fst, "cn0_mean");     jfix(&w, cn0, 1);
        ex_key(&w, &fst, "time_offset_ms");
        if (goff == 1) web_jw_int(&w, off); else web_jw_raw(&w, "null");
        ex_key(&w, &fst, "jam");          web_jw_int(&w, jam);
    } else {
        *why = "unknown_type";
        return -1;
    }
    web_jw_raw(&w, "}");
    if (w.overflow) return -1;
    return 0;
}

static int hdr_of(const web_jrec_t *r, fhdr_t *h) {
    memset(h, 0, sizeof(*h));
    long long v;
    double d;
    if (v_int(r, "fleet_export_version", 1, 1, &v) != 1 ||
        v_int(r, "generated", 1, T_MAX, &h->generated) != 1 ||
        v_int(r, "since", 0, T_MAX, &v) < 0 ||
        v_str(r, "site_label", WEB_FLEET_STR_MAX, h->label, sizeof(h->label)) < 0 ||
        v_str(r, "slothweb_version", 31, h->version, sizeof(h->version)) < 0 ||
        v_str(r, "pos_source", 5, h->pos_source, sizeof(h->pos_source)) < 0 ||
        v_int(r, "pos_ts", 0, T_MAX, &h->pos_ts) < 0 || v_int(r, "pos_age_s", 0, T_MAX, &v) < 0)
        return -1;
    char tmp[64];
    if (v_str(r, "sloth_version", 31, tmp, sizeof(tmp)) < 0 ||
        v_str(r, "sloth_db", 15, tmp, sizeof(tmp)) < 0)
        return -1;
    int ga = v_num(r, "lat", -90, 90, &h->lat), gb = v_num(r, "lon", -180, 180, &h->lon);
    int gc = v_num(r, "alt_m", -1000, 100000, &d);   /* web_loc_set()'s range */
    if (ga < 0 || gb < 0 || gc < 0 || ga != gb) return -1;
    h->has_pos = ga == 1;
    h->has_alt = gc == 1;
    h->alt = d;
    if (h->pos_source[0] && strcmp(h->pos_source, "gps") && strcmp(h->pos_source, "fixed"))
        return -1;
    return 0;
}

/* Walk the body's lines. fn gets each decoded record and its index;
 * nonzero stops the walk with that value. */
typedef int (*line_fn)(void *ctx, const web_jrec_t *r, long long idx, const char *type);

static int walk(const char *body, size_t len, web_jrec_t *rec, line_fn fn, void *ctx,
                long long *nlines, char *err, size_t errsz) {
    long long idx = 0;
    for (size_t i = 0; i < len;) {
        const char *nl = memchr(body + i, '\n', len - i);
        size_t n = nl ? (size_t)(nl - (body + i)) : len - i;
        if (n == 0) { i += 1; continue; }
        if (n > WEB_JL_MAX_LINE) {
            snprintf(err, errsz, "line %lld is too long: refused", idx + 1);
            return -1;
        }
        int pe = web_jl_parse(body + i, n, rec);
        if (pe != WEB_JL_OK) {
            snprintf(err, errsz, "line %lld: %s: refused", idx + 1, web_jl_error_name(pe));
            return -1;
        }
        const char *type = web_jl_str(rec, "type");
        const char *const *m = web_fleet_members_of(type);
        if (!m) {
            snprintf(err, errsz, "line %lld: unknown type: refused", idx + 1);
            return -1;
        }
        if (!members_ok(rec, m)) {
            snprintf(err, errsz, "line %lld: a %s line with a member it may not "
                     "carry: refused", idx + 1, m[0]);
            return -1;
        }
        int r = fn(ctx, rec, idx, m[0]);
        if (r) return r;
        idx++;
        i += n + (nl ? 1 : 0);
    }
    *nlines = idx;
    return 0;
}

typedef struct {
    fhdr_t    hdr;
    long long data, end_rows, counts[WEB_FK_COUNT];
    int       has_next[WEB_FK_COUNT];
    char      next[WEB_FK_COUNT][WEB_FLEET_CUR_MAX + 1];
    int       seen_end, bad_line;
    long long bad_idx;
    const char *why;
    char     *err;
    size_t    errsz;
} chk_t;

static int check_line(void *ctx, const web_jrec_t *r, long long idx, const char *type) {
    chk_t *k = ctx;
    if (k->seen_end) {
        snprintf(k->err, k->errsz, "line %lld after the end line: refused", idx + 1);
        return -1;
    }
    if (idx == 0) {
        if (strcmp(type, "fleet_export") || hdr_of(r, &k->hdr) != 0) {
            snprintf(k->err, k->errsz, "no fleet_export header of version %d: refused",
                     WEB_FLEET_EXPORT_VERSION);
            return -1;
        }
        return 0;
    }
    if (!strcmp(type, "fleet_export")) {
        snprintf(k->err, k->errsz, "line %lld: a second header: refused", idx + 1);
        return -1;
    }
    if (!strcmp(type, "fleet_end")) {
        int complete;
        long long v;
        if (v_bool(r, "complete", &complete) != 1 || !complete ||
            v_int(r, "rows", 0, LLONG_MAX / 4, &k->end_rows) != 1) {
            snprintf(k->err, k->errsz, "the end line does not say complete: refused");
            return -1;
        }
        for (int i = 0; i < WEB_FK_COUNT; i++) {
            if (v_int(r, KIND_WORD[i], 0, LLONG_MAX / 4, &v) != 1 || v != k->counts[i]) {
                snprintf(k->err, k->errsz, "the end line's %s count is not the rows "
                         "sent: refused", KIND_WORD[i]);
                return -1;
            }
            if (!web_fleet_kind_pages(i)) continue;
            char nm[32];
            snprintf(nm, sizeof(nm), "next_%s", KIND_WORD[i]);
            int g = v_str(r, nm, WEB_FLEET_CUR_MAX, k->next[i], sizeof(k->next[i]));
            if (g < 0 || (g == 1 && !web_fleet_cursor_ok(k->next[i]))) {
                snprintf(k->err, k->errsz, "the end line's %s is not a cursor: refused", nm);
                return -1;
            }
            k->has_next[i] = g == 1;
        }
        k->seen_end = 1;
        return 0;
    }
    frow_t row;
    const char *why;
    if (row_of(r, type, &row, &why) != 0) {
        snprintf(k->err, k->errsz, "line %lld: a %s line with a value out of range: "
                 "refused", idx + 1, type);
        return -1;
    }
    if (row.kind >= 0) {
        k->counts[row.kind]++;
        k->data++;
    }
    return 0;
}

#ifdef WITH_SQLITE

typedef struct {
    web_fleet_t  *f;
    const char   *peer;
    sqlite3_stmt *up;
    long long     rows;
    int           failed;
} put_t;

static const char UPSERT_SQL[] =
    "INSERT INTO peer_sightings (peer,kind,key,label,vendor,rssi,first_seen,"
    "last_seen,extra) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"
    " ON CONFLICT (peer,kind,key) DO UPDATE SET label=excluded.label,"
    " vendor=excluded.vendor, rssi=excluded.rssi, extra=excluded.extra,"
    " first_seen=CASE WHEN excluded.first_seen>0 AND (peer_sightings.first_seen<=0"
    " OR excluded.first_seen<peer_sightings.first_seen) THEN excluded.first_seen"
    " ELSE peer_sightings.first_seen END,"
    " last_seen=MAX(peer_sightings.last_seen,excluded.last_seen)";

static int put_line(void *ctx, const web_jrec_t *r, long long idx, const char *type) {
    put_t *p = ctx;
    if (idx == 0 || !strcmp(type, "fleet_end")) return 0;
    frow_t row;
    const char *why;
    if (row_of(r, type, &row, &why) != 0) return -1;   /* checked already */
    sqlite3_stmt *s = p->up;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, p->peer, -1, SQLITE_STATIC);
    sqlite3_bind_text(s, 2, row.kind >= 0 ? KIND_WORD[row.kind] : "gnss", -1, SQLITE_STATIC);
    sqlite3_bind_text(s, 3, row.key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, row.label, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, row.vendor, -1, SQLITE_TRANSIENT);
    if (row.has_rssi) sqlite3_bind_int(s, 6, row.rssi); else sqlite3_bind_null(s, 6);
    sqlite3_bind_int64(s, 7, row.first);
    sqlite3_bind_int64(s, 8, row.last);
    sqlite3_bind_text(s, 9, row.extra, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(s) != SQLITE_DONE) { p->failed = 1; return -1; }
    p->rows++;
    return 0;
}

static int run1(sqlite3 *db, const char *sql, const char *peer, long long n) {
    sqlite3_stmt *s = NULL;
    int ok = sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_text(s, 1, peer, -1, SQLITE_STATIC);
        sqlite3_bind_int64(s, 2, n);
        ok = sqlite3_step(s) == SQLITE_DONE;
    }
    sqlite3_finalize(s);
    return ok ? 0 : -1;
}

/* slothweb.db's meta table holds each kind's backfill while it runs, one
 * row a peer and kind, so a restart resumes it rather than lose the rows
 * a cut answer left behind: no new column, no schema step. */
static void bf_meta_name(char *out, size_t cap, const char *peer, int k) {
    snprintf(out, cap, "fleet.backfill.%s.%s", peer, KIND_WORD[k]);
}

static int bf_meta_write(sqlite3 *db, const char *peer, const web_fleet_bf_t *bf) {
    sqlite3_stmt *up = NULL, *del = NULL;
    int ok = sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta (name,value) VALUES (?1,?2)",
                                -1, &up, NULL) == SQLITE_OK &&
             sqlite3_prepare_v2(db, "DELETE FROM meta WHERE name=?1", -1, &del,
                                NULL) == SQLITE_OK;
    for (int k = 0; ok && k < WEB_FK_COUNT; k++) {
        if (!web_fleet_kind_pages(k)) continue;
        char nm[96], v[WEB_FLEET_CUR_MAX + 32];
        bf_meta_name(nm, sizeof(nm), peer, k);
        sqlite3_stmt *s = bf[k].active ? up : del;
        sqlite3_reset(s);
        sqlite3_bind_text(s, 1, nm, -1, SQLITE_TRANSIENT);
        if (bf[k].active) {
            snprintf(v, sizeof(v), "%lld %s", bf[k].floor, bf[k].cur);
            sqlite3_bind_text(s, 2, v, -1, SQLITE_TRANSIENT);
        }
        ok = sqlite3_step(s) == SQLITE_DONE;
    }
    sqlite3_finalize(up);
    sqlite3_finalize(del);
    return ok ? 0 : -1;
}

static void bf_meta_read(sqlite3 *db, const char *peer, web_fleet_bf_t *bf) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE name=?1", -1, &s,
                           NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        return;
    }
    for (int k = 0; k < WEB_FK_COUNT; k++) {
        memset(&bf[k], 0, sizeof(bf[k]));
        if (!web_fleet_kind_pages(k)) continue;
        char nm[96];
        bf_meta_name(nm, sizeof(nm), peer, k);
        sqlite3_reset(s);
        sqlite3_bind_text(s, 1, nm, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(s) != SQLITE_ROW) continue;
        const char *v = (const char *)sqlite3_column_text(s, 0);
        long long fl = 0;
        const char *p = v;
        while (p && *p >= '0' && *p <= '9' && fl < T_MAX) fl = fl * 10 + (*p++ - '0');
        /* Only a value this file wrote: a floor, one space, a cursor. */
        if (!p || p == v || *p != ' ' || !web_fleet_cursor_ok(p + 1) ||
            strlen(p + 1) > WEB_FLEET_CUR_MAX)
            continue;
        bf[k].active = 1;
        bf[k].floor = fl;
        snprintf(bf[k].cur, sizeof(bf[k].cur), "%s", p + 1);
    }
    sqlite3_finalize(s);
}

static int store_answer(web_fleet_t *f, const web_fleet_peer_cfg_t *pc, const chk_t *k,
                        const char *body, size_t len, web_jrec_t *rec, long long now_s,
                        int page, const web_fleet_bf_t *bf, char *err, size_t errsz) {
    sqlite3 *db = f->wr;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(err, errsz, "store: %s", sqlite3_errmsg(db));
        return -1;
    }
    put_t p;
    memset(&p, 0, sizeof(p));
    p.f = f;
    p.peer = pc->name;
    long long nl;
    char e2[WEB_FLEET_ERR_MAX + 1];
    int ok = sqlite3_prepare_v2(db, UPSERT_SQL, -1, &p.up, NULL) == SQLITE_OK &&
             walk(body, len, rec, put_line, &p, &nl, e2, sizeof(e2)) == 0 && !p.failed;
    sqlite3_finalize(p.up);
    sqlite3_stmt *s = NULL;
    /* A page is the same answer's older rows: the site, its clock and
     * the last pull's figures are the whole export's. */
    if (ok && page < 0)
        ok = sqlite3_prepare_v2(db,
            "INSERT INTO peer_sites (peer,url,label,last_attempt,last_ok,last_error,lat,"
            "lon,alt,pos_source,pos_ts,remote_version,remote_ts,rows_last) VALUES"
            " (?1,?2,?3,?4,?4,'',?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT (peer) DO UPDATE"
            " SET url=excluded.url, label=excluded.label, last_attempt=excluded.last_attempt,"
            " last_ok=excluded.last_ok, last_error='', lat=excluded.lat, lon=excluded.lon,"
            " alt=excluded.alt, pos_source=excluded.pos_source, pos_ts=excluded.pos_ts,"
            " remote_version=excluded.remote_version, remote_ts=excluded.remote_ts,"
            " rows_last=excluded.rows_last", -1, &s, NULL) == SQLITE_OK;
    if (ok && page < 0) {
        sqlite3_bind_text(s, 1, pc->name, -1, SQLITE_STATIC);
        sqlite3_bind_text(s, 2, pc->url, -1, SQLITE_STATIC);
        sqlite3_bind_text(s, 3, k->hdr.label, -1, SQLITE_STATIC);
        sqlite3_bind_int64(s, 4, now_s);
        if (k->hdr.has_pos) {
            sqlite3_bind_double(s, 5, k->hdr.lat);
            sqlite3_bind_double(s, 6, k->hdr.lon);
        } else {
            sqlite3_bind_null(s, 5);
            sqlite3_bind_null(s, 6);
        }
        if (k->hdr.has_alt) sqlite3_bind_double(s, 7, k->hdr.alt); else sqlite3_bind_null(s, 7);
        sqlite3_bind_text(s, 8, k->hdr.pos_source, -1, SQLITE_STATIC);
        sqlite3_bind_int64(s, 9, k->hdr.pos_ts);
        sqlite3_bind_text(s, 10, k->hdr.version, -1, SQLITE_STATIC);
        sqlite3_bind_int64(s, 11, k->hdr.generated);
        sqlite3_bind_int64(s, 12, k->data);
        ok = sqlite3_step(s) == SQLITE_DONE;
    }
    sqlite3_finalize(s);
    /* The bounds: none older than WEB_FLEET_KEEP_S by the peer's own
     * clock, then at most WEB_FLEET_ROWS_PER_PEER, the least recently
     * seen first. */
    if (ok)
        ok = run1(db, "DELETE FROM peer_sightings WHERE peer=?1 AND last_seen<?2",
                  pc->name, k->hdr.generated - WEB_FLEET_KEEP_S) == 0 &&
             run1(db, "DELETE FROM peer_sightings WHERE rowid IN (SELECT rowid FROM"
                      " peer_sightings WHERE peer=?1 ORDER BY last_seen DESC, rowid DESC"
                      " LIMIT -1 OFFSET ?2)", pc->name, WEB_FLEET_ROWS_PER_PEER) == 0;
    /* The backfill's state commits with the rows it follows. */
    if (ok) ok = bf_meta_write(db, pc->name, bf) == 0;
    if (ok) ok = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok) {
        snprintf(err, errsz, "store: %s", sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    return 0;
}

static void store_failure(web_fleet_t *f, const web_fleet_peer_cfg_t *pc, long long now_s,
                          const char *why) {
    if (!f->wr) return;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(f->wr,
            "INSERT INTO peer_sites (peer,url,last_attempt,last_error) VALUES (?1,?2,?3,?4)"
            " ON CONFLICT (peer) DO UPDATE SET url=excluded.url,"
            " last_attempt=excluded.last_attempt, last_error=excluded.last_error",
            -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_text(s, 1, pc->name, -1, SQLITE_STATIC);
        sqlite3_bind_text(s, 2, pc->url, -1, SQLITE_STATIC);
        sqlite3_bind_int64(s, 3, now_s);
        sqlite3_bind_text(s, 4, why, -1, SQLITE_STATIC);
        sqlite3_step(s);
    }
    sqlite3_finalize(s);
}

#else

static int store_answer(web_fleet_t *f, const web_fleet_peer_cfg_t *pc, const chk_t *k,
                        const char *body, size_t len, web_jrec_t *rec, long long now_s,
                        int page, const web_fleet_bf_t *bf, char *err, size_t errsz) {
    (void)f; (void)pc; (void)k; (void)body; (void)len; (void)rec; (void)now_s;
    (void)page; (void)bf;
    snprintf(err, errsz, "built without SQLite");
    return -1;
}

static void store_failure(web_fleet_t *f, const web_fleet_peer_cfg_t *pc, long long now_s,
                          const char *why) {
    (void)f; (void)pc; (void)now_s; (void)why;
}

#endif

/* The backfill after an answer: a whole export's cut kind starts one
 * (or, while one runs, widens it to the older floor and restarts it from
 * the new cut, which covers both gaps); a page's kind moves its cursor
 * on, or ends when the page was not cut. */
static void bf_next(const web_fleet_bf_t *old, const chk_t *k, int page,
                    long long since_asked, web_fleet_bf_t *nb) {
    for (int j = 0; j < WEB_FK_COUNT; j++) {
        nb[j] = old[j];
        if (!web_fleet_kind_pages(j)) continue;
        if (page < 0) {
            if (!k->has_next[j]) continue;
            nb[j].floor = old[j].active && old[j].floor < since_asked ? old[j].floor
                                                                       : since_asked;
            nb[j].active = 1;
            snprintf(nb[j].cur, sizeof(nb[j].cur), "%s", k->next[j]);
        } else if (j == page) {
            if (k->has_next[j]) {
                snprintf(nb[j].cur, sizeof(nb[j].cur), "%s", k->next[j]);
            } else {
                memset(&nb[j], 0, sizeof(nb[j]));
            }
        }
    }
}

static int ingest(web_fleet_t *f, int i, const char *body, size_t len,
                  long long now_s, int write, int page, long long since_asked,
                  long long *rows, long long *remote_ts, char *err, size_t errsz) {
    *rows = 0;
    *remote_ts = 0;
    if (i < 0 || i >= f->npeer) {
        snprintf(err, errsz, "no such peer");
        return -1;
    }
    web_jrec_t *rec = malloc(sizeof(*rec));
    if (!rec) {
        snprintf(err, errsz, "out of memory");
        return -1;
    }
    chk_t k;
    memset(&k, 0, sizeof(k));
    k.err = err;
    k.errsz = errsz;
    long long nl = 0;
    int rc = walk(body, len, rec, check_line, &k, &nl, err, errsz);
    if (rc == 0 && nl == 0) {
        snprintf(err, errsz, "an empty answer: refused");
        rc = -1;
    }
    if (rc == 0 && !k.seen_end) {
        snprintf(err, errsz, "no end line (the answer was cut short): refused");
        rc = -1;
    }
    if (rc == 0 && k.seen_end && k.end_rows != k.data) {
        snprintf(err, errsz, "the end line's rows is not the rows sent: refused");
        rc = -1;
    }
    web_fleet_bf_t nb[WEB_FK_COUNT];
    if (rc == 0 && write) {
        web_fleet_bf_t old[WEB_FK_COUNT];
        pthread_mutex_lock(&f->mu);
        memcpy(old, f->peer[i].bf, sizeof(old));
        pthread_mutex_unlock(&f->mu);
        bf_next(old, &k, page, since_asked, nb);
        rc = store_answer(f, &f->peer[i].cfg, &k, body, len, rec, now_s, page, nb,
                          err, errsz);
        if (rc == 0) {
            pthread_mutex_lock(&f->mu);
            memcpy(f->peer[i].bf, nb, sizeof(nb));
            pthread_mutex_unlock(&f->mu);
        }
    }
    free(rec);
    if (rc != 0) return -1;
    *rows = k.data;
    *remote_ts = k.hdr.generated;
    return 0;
}

int web_fleet_ingest(web_fleet_t *f, int i, const char *body, size_t len,
                     long long now_s, int write, long long *rows,
                     long long *remote_ts, char *err, size_t errsz) {
    return ingest(f, i, body, len, now_s, write, -1, 0, rows, remote_ts, err, errsz);
}

/* The pages of each kind with a backfill running, after a good pull: at
 * most pages_per_pull a kind a pull, so a backlog is fetched a bounded
 * amount at a time and nothing already held is asked for again; a
 * refused page stops its kind until the next pull. */
static void backfill_pages(web_fleet_t *f, int i, long long now_s) {
    web_fleet_peer_t *p = &f->peer[i];
    for (int k = 0; k < WEB_FK_COUNT; k++)
    for (int pg = 0; pg < f->pages_per_pull; pg++) {
        if (!web_fleet_kind_pages(k) || stopping(f)) break;
        pthread_mutex_lock(&f->mu);
        web_fleet_bf_t bf = p->bf[k];
        pthread_mutex_unlock(&f->mu);
        if (!bf.active) break;
        char q[160], err[WEB_FLEET_ERR_MAX + 1] = "", e2[WEB_FLEET_ERR_MAX - 31];
        snprintf(q, sizeof(q), "since=%lld&kind=%s&after=%s", bf.floor, KIND_WORD[k], bf.cur);
        char *body = NULL;
        size_t len = 0;
        long long rows = 0, remote = 0;
        int rc = -1;
        if (http_get(f, &p->cfg, q, &body, &len, e2, sizeof(e2), NULL) == 0)
            rc = ingest(f, i, body, len, now_s, 1, k, bf.floor, &rows, &remote, e2, sizeof(e2));
        free(body);
        if (rc != 0) {
            snprintf(err, sizeof(err), "backfill %s: %s", KIND_WORD[k], e2);
            store_failure(f, &p->cfg, now_s, err);
        }
        pthread_mutex_lock(&f->mu);
        int stuck = 0;
        if (rc == 0) {
            p->pages++;
            /* A page that did not move its cursor (the peer's read ran
             * out of budget before its first row): asked again at the
             * next pull, not again now. */
            stuck = p->bf[k].active && !strcmp(p->bf[k].cur, bf.cur);
        } else {
            p->page_failures++;
            snprintf(p->last_error, sizeof(p->last_error), "%s", err);
        }
        pthread_mutex_unlock(&f->mu);
        if (rc != 0 || stuck) break;
    }
}

int web_fleet_pull_one(web_fleet_t *f, int i, long long now_s) {
    if (i < 0 || i >= f->npeer) return -1;
    web_fleet_peer_t *p = &f->peer[i];
    pthread_mutex_lock(&f->mu);
    long long since = p->remote_ts > WEB_FLEET_OVERLAP_S ? p->remote_ts - WEB_FLEET_OVERLAP_S : 0;
    p->last_attempt = now_s;
    pthread_mutex_unlock(&f->mu);
    char err[WEB_FLEET_ERR_MAX + 1] = "";
    char *body = NULL;
    size_t len = 0;
    long long rows = 0, remote = 0;
    int rc = -1, skip_pages = 0;
    if (!f->store || !f->wr)
        snprintf(err, sizeof(err), "no store: nothing is pulled");
    else {
        /* An F1 peer's export refuses next=1 as an unknown parameter:
         * asked again without it, and not asked with it for
         * WEB_FLEET_NONEXT_S, so a fleet is upgraded a host at a time.
         * Its answers carry no cursor, so nothing is backfilled from it
         * until it is upgraded. */
        pthread_mutex_lock(&f->mu);
        int plain = p->no_next_until > now_s;
        pthread_mutex_unlock(&f->mu);
        char q[64];
        snprintf(q, sizeof(q), plain ? "since=%lld" : "since=%lld&next=1", since);
        int unk = 0;
        int g = http_get(f, &p->cfg, q, &body, &len, err, sizeof(err), &unk);
        if (g != 0 && unk && !plain) {
            plain = 1;
            pthread_mutex_lock(&f->mu);
            p->no_next_until = now_s + WEB_FLEET_NONEXT_S;
            pthread_mutex_unlock(&f->mu);
            snprintf(q, sizeof(q), "since=%lld", since);
            g = http_get(f, &p->cfg, q, &body, &len, err, sizeof(err), NULL);
        }
        if (g == 0)
            rc = ingest(f, i, body, len, now_s, 1, -1, since, &rows, &remote, err, sizeof(err));
        if (rc == 0 && plain) skip_pages = 1;
    }
    free(body);
    if (rc != 0) store_failure(f, &p->cfg, now_s, err);
    pthread_mutex_lock(&f->mu);
    p->pulls++;
    if (rc == 0) {
        p->last_ok = now_s;
        p->remote_ts = remote;
        p->rows_last = rows;
        p->last_error[0] = '\0';
    } else {
        p->failures++;
        snprintf(p->last_error, sizeof(p->last_error), "%s", err);
    }
    pthread_mutex_unlock(&f->mu);
    if (rc == 0 && !skip_pages) backfill_pages(f, i, now_s);
    return rc;
}

/* ── the thread ────────────────────────────────────────────────────── */

void web_fleet_init(web_fleet_t *f, const web_fleet_peer_cfg_t *peers, int n,
                    int interval_s, int allow_outside, web_store_t *store) {
    memset(f, 0, sizeof(*f));
    pthread_mutex_init(&f->mu, NULL);
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&f->cv, &ca);
    pthread_condattr_destroy(&ca);
    if (n > WEB_FLEET_PEERS) n = WEB_FLEET_PEERS;
    for (int i = 0; i < n; i++) f->peer[i].cfg = peers[i];
    f->npeer = n < 0 ? 0 : n;
    f->interval_s = interval_s > 0 ? interval_s : WEB_FLEET_INTERVAL_DEF;
    f->allow_outside = allow_outside;
    f->store = store;
    f->connect_ms = WEB_FLEET_CONNECT_MS;
    f->read_ms = WEB_FLEET_READ_MS;
    f->resp_max = WEB_FLEET_RESP_MAX;
    f->pages_per_pull = WEB_FLEET_PAGES_PER_PULL;
}

static void *pull_main(void *arg) {
    web_fleet_t *f = arg;
    for (;;) {
        for (int i = 0; i < f->npeer && !stopping(f); i++)
            web_fleet_pull_one(f, i, (long long)time(NULL));
        pthread_mutex_lock(&f->mu);
        long long until = mono_ms() + (long long)f->interval_s * 1000;
        while (!f->stop) {
            long long left = until - mono_ms();
            if (left <= 0) break;
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            ts.tv_sec += left / 1000;
            ts.tv_nsec += (left % 1000) * 1000000;
            if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
            pthread_cond_timedwait(&f->cv, &f->mu, &ts);
        }
        int stop = f->stop;
        pthread_mutex_unlock(&f->mu);
        if (stop) break;
    }
    return NULL;
}

int web_fleet_start(web_fleet_t *f, char *err, size_t errsz) {
    if (!f->npeer) return 0;
    if (!f->store) {
        snprintf(err, errsz, "--peer needs the store (slothweb.db), and there is none");
        return -1;
    }
#ifdef WITH_SQLITE
    if (web_store_open_aux(f->store, &f->wr, err, errsz) != 0) return -1;
    sqlite3_busy_timeout(f->wr, WEB_FLEET_BUSY_MS);
    web_fleet_load(f);
#else
    snprintf(err, errsz, "--peer needs SQLite; this slothweb was built with WITH_SQLITE=0");
    return -1;
#endif
    if (pthread_create(&f->th, NULL, pull_main, f) != 0) {
        snprintf(err, errsz, "pthread_create failed");
        return -1;
    }
    f->started = 1;
    return 0;
}

void web_fleet_load(web_fleet_t *f) {
#ifdef WITH_SQLITE
    if (!f->wr) return;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(f->wr, "SELECT last_attempt, last_ok, last_error, remote_ts,"
                           " rows_last FROM peer_sites WHERE peer=?1", -1, &s, NULL) == SQLITE_OK) {
        for (int i = 0; i < f->npeer; i++) {
            web_fleet_peer_t *p = &f->peer[i];
            sqlite3_reset(s);
            sqlite3_bind_text(s, 1, p->cfg.name, -1, SQLITE_STATIC);
            if (sqlite3_step(s) == SQLITE_ROW) {
                p->last_attempt = sqlite3_column_int64(s, 0);
                p->last_ok = sqlite3_column_int64(s, 1);
                const unsigned char *t = sqlite3_column_text(s, 2);
                snprintf(p->last_error, sizeof(p->last_error), "%s", t ? (const char *)t : "");
                p->remote_ts = sqlite3_column_int64(s, 3);
                p->rows_last = sqlite3_column_int64(s, 4);
            }
        }
    }
    sqlite3_finalize(s);
    for (int i = 0; i < f->npeer; i++) bf_meta_read(f->wr, f->peer[i].cfg.name, f->peer[i].bf);
#else
    (void)f;
#endif
}

void web_fleet_stop(web_fleet_t *f) {
    if (!f->started) return;
    pthread_mutex_lock(&f->mu);
    f->stop = 1;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
    pthread_join(f->th, NULL);
    f->started = 0;
}

void web_fleet_destroy(web_fleet_t *f) {
    web_fleet_stop(f);
#ifdef WITH_SQLITE
    if (f->wr) sqlite3_close(f->wr);
#endif
    f->wr = NULL;
    pthread_cond_destroy(&f->cv);
    pthread_mutex_destroy(&f->mu);
}

/* ── the readouts ──────────────────────────────────────────────────── */

static void age_or_null(web_jw_t *w, long long t, long long now_s) {
    if (t > 0) web_jw_int(w, now_s > t ? now_s - t : 0);
    else web_jw_raw(w, "null");
}

void web_fleet_health_json(web_fleet_t *f, web_jw_t *w, long long now_s) {
    pthread_mutex_lock(&f->mu);
    web_jw_raw(w, "{\"export\":true,\"export_version\":");
    web_jw_int(w, WEB_FLEET_EXPORT_VERSION);
    web_jw_raw(w, ",\"interval_s\":");      web_jw_int(w, f->interval_s);
    web_jw_raw(w, ",\"outside_tailnet\":"); web_jw_raw(w, f->allow_outside ? "true" : "false");
    web_jw_raw(w, ",\"peers\":[");
    for (int i = 0; i < f->npeer; i++) {
        const web_fleet_peer_t *p = &f->peer[i];
        web_jw_raw(w, i ? ",{\"name\":" : "{\"name\":");
        web_jw_str(w, p->cfg.name);
        web_jw_raw(w, ",\"url\":");               web_jw_str(w, p->cfg.url);
        web_jw_raw(w, ",\"last_ok_age_s\":");     age_or_null(w, p->last_ok, now_s);
        web_jw_raw(w, ",\"last_attempt_age_s\":"); age_or_null(w, p->last_attempt, now_s);
        web_jw_raw(w, ",\"last_error\":");        jstr_or_null(w, p->last_error);
        web_jw_raw(w, ",\"rows\":");              web_jw_int(w, p->rows_last);
        web_jw_raw(w, ",\"pulls\":");             web_jw_int(w, (long long)p->pulls);
        web_jw_raw(w, ",\"failures\":");          web_jw_int(w, (long long)p->failures);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "]}");
    pthread_mutex_unlock(&f->mu);
}

#ifdef WITH_SQLITE
static int configured(web_fleet_t *f, const char *name) {
    for (int i = 0; i < f->npeer; i++)
        if (!strcmp(f->peer[i].cfg.name, name)) return 1;
    return 0;
}
#endif

int web_fleet_peers_route(web_fleet_t *f, const char *query, long long now_s,
                          char *body, size_t cap, size_t *len, int *status) {
    if (query && query[0]) {
        *status = 400;
        *len = web_series_error_json("unknown_parameter", body, cap);
        return *len ? 0 : -1;
    }
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"export\":true,\"interval_s\":");
    web_jw_int(&w, f ? f->interval_s : WEB_FLEET_INTERVAL_DEF);
    web_jw_raw(&w, ",\"store\":");
    int n = 0;
#ifdef WITH_SQLITE
    web_store_t *s = f ? f->store : NULL;
    if (s && s->rd) {
        web_jw_raw(&w, "true,\"peers\":[");
        pthread_mutex_lock(&s->rmu);
        sqlite3_stmt *q = NULL, *c = NULL;
        int ok = sqlite3_prepare_v2(s->rd,
            "SELECT peer,url,label,last_attempt,last_ok,last_error,lat,lon,alt,pos_source,"
            "pos_ts,remote_version,remote_ts,rows_last FROM peer_sites ORDER BY peer"
            " LIMIT 32", -1, &q, NULL) == SQLITE_OK &&
            sqlite3_prepare_v2(s->rd, "SELECT kind, COUNT(*) FROM peer_sightings"
                               " WHERE peer=?1 GROUP BY kind ORDER BY kind", -1, &c,
                               NULL) == SQLITE_OK;
        while (ok && sqlite3_step(q) == SQLITE_ROW) {
            const char *peer = (const char *)sqlite3_column_text(q, 0);
            if (!peer) continue;
            web_jw_raw(&w, n++ ? ",{\"name\":" : "{\"name\":");
            web_jw_str(&w, peer);
            web_jw_raw(&w, ",\"configured\":");
            web_jw_raw(&w, configured(f, peer) ? "true" : "false");
            static const char *const TXT[] = { ",\"url\":", ",\"label\":" };
            for (int k = 0; k < 2; k++) {
                web_jw_raw(&w, TXT[k]);
                jstr_or_null(&w, (const char *)sqlite3_column_text(q, 1 + k));
            }
            web_jw_raw(&w, ",\"last_attempt_age_s\":");
            age_or_null(&w, sqlite3_column_int64(q, 3), now_s);
            web_jw_raw(&w, ",\"last_ok_age_s\":");
            age_or_null(&w, sqlite3_column_int64(q, 4), now_s);
            web_jw_raw(&w, ",\"last_error\":");
            jstr_or_null(&w, (const char *)sqlite3_column_text(q, 5));
            static const char *const POS[] = { ",\"lat\":", ",\"lon\":", ",\"alt_m\":" };
            for (int k = 0; k < 3; k++) {
                web_jw_raw(&w, POS[k]);
                if (sqlite3_column_type(q, 6 + k) == SQLITE_NULL) web_jw_raw(&w, "null");
                else jfix(&w, sqlite3_column_double(q, 6 + k), k == 2 ? 1 : 7);
            }
            web_jw_raw(&w, ",\"pos_source\":");
            jstr_or_null(&w, (const char *)sqlite3_column_text(q, 9));
            web_jw_raw(&w, ",\"pos_ts\":");
            long long pts = sqlite3_column_int64(q, 10);
            if (pts > 0) web_jw_int(&w, pts); else web_jw_raw(&w, "null");
            web_jw_raw(&w, ",\"remote_version\":");
            jstr_or_null(&w, (const char *)sqlite3_column_text(q, 11));
            web_jw_raw(&w, ",\"remote_ts\":");
            long long rts = sqlite3_column_int64(q, 12);
            if (rts > 0) web_jw_int(&w, rts); else web_jw_raw(&w, "null");
            web_jw_raw(&w, ",\"rows_last\":");
            web_jw_int(&w, sqlite3_column_int64(q, 13));
            web_jw_raw(&w, ",\"counts\":{");
            sqlite3_reset(c);
            sqlite3_bind_text(c, 1, peer, -1, SQLITE_TRANSIENT);
            int nk = 0;
            while (sqlite3_step(c) == SQLITE_ROW) {
                const char *kind = (const char *)sqlite3_column_text(c, 0);
                if (!kind) continue;
                if (nk++) web_jw_raw(&w, ",");
                web_jw_str(&w, kind);
                web_jw_raw(&w, ":");
                web_jw_int(&w, sqlite3_column_int64(c, 1));
            }
            web_jw_raw(&w, "}}");
        }
        sqlite3_finalize(q);
        sqlite3_finalize(c);
        pthread_mutex_unlock(&s->rmu);
        web_jw_raw(&w, "]");
        if (!ok) {
            *status = 503;
            *len = web_series_error_json("store_read_failed", body, cap);
            return *len ? 0 : -1;
        }
    } else
#endif
    {
        web_jw_raw(&w, "false,\"peers\":[]");
    }
    (void)n;
    (void)now_s;
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *status = 200;
    *len = w.len;
    return 0;
}

/* ── the Fleet tab's routes (F2) ───────────────────────────────────── */

double web_fleet_dist_m(double lat1, double lon1, double lat2, double lon2) {
    const double d = 3.14159265358979323846 / 180.0, R = 6371008.8;
    double p1 = lat1 * d, p2 = lat2 * d, dp = p2 - p1, dl = (lon2 - lon1) * d;
    double a = sin(dp / 2) * sin(dp / 2) + cos(p1) * cos(p2) * sin(dl / 2) * sin(dl / 2);
    if (a > 1) a = 1;
    if (a < 0) a = 0;
    return 2 * R * atan2(sqrt(a), sqrt(1 - a));
}

/* A query of the tab's routes: kind and limit for the shared list, and
 * nothing for the overview. The router has taken scope= out already
 * (web_routes.h); a site is the whole sensor whatever the scope. 0, or
 * -1 with why. */
typedef struct {
    int kind, limit;
} fq_t;

static int parse_tab_query(const char *q, int shared, fq_t *o, const char **why) {
    o->kind = WEB_FK_WIFI;
    o->limit = WEB_FLEET_SHARED_DEF;
    int sk = 0, sl = 0;
    for (const char *p = q ? q : ""; *p;) {
        size_t n = strcspn(p, "&");
        const char *eq = memchr(p, '=', n);
        if (!eq) { *why = "unknown_parameter"; return -1; }
        size_t kl = (size_t)(eq - p), vl = n - kl - 1;
        const char *v = eq + 1;
        if (shared && kl == 4 && !strncmp(p, "kind", 4) && !sk) {
            sk = 1;
            int k = kind_of_word(v, vl);
            if (k != WEB_FK_WIFI && k != WEB_FK_BLE && k != WEB_FK_AP && k != WEB_FK_PROBE) {
                *why = "bad_kind";
                return -1;
            }
            o->kind = k;
        } else if (shared && kl == 5 && !strncmp(p, "limit", 5) && !sl) {
            sl = 1;
            long v2 = 0;
            if (vl == 0 || vl > 4) { *why = "bad_limit"; return -1; }
            for (size_t i = 0; i < vl; i++) {
                if (v[i] < '0' || v[i] > '9') { *why = "bad_limit"; return -1; }
                v2 = v2 * 10 + (v[i] - '0');
            }
            if (v2 < 1 || v2 > WEB_FLEET_SHARED_MAX) { *why = "bad_limit"; return -1; }
            o->limit = (int)v2;
        } else {
            *why = "unknown_parameter";
            return -1;
        }
        p += n;
        if (*p == '&') p++;
    }
    return 0;
}

static void jnum_or_null(web_jw_t *w, int has, double v, int dp) {
    if (has) jfix(w, v, dp); else web_jw_raw(w, "null");
}

/* The local site: sloth.db's newest session label, and the position the
 * export sends (sensor_health's loc_*). */
typedef struct {
    char      label[WEB_SDB_TEXT_MAX + 1];
    const char *sdb;
    web_loc_t loc;
} fsite_t;

static void local_site(const web_fleet_src_t *src, long long now_s, fsite_t *o) {
    memset(o, 0, sizeof(*o));
    o->sdb = "none";
    if (src->sdb && src->sdb->configured) {
        web_sdb_conn_t c;
        memset(&c, 0, sizeof(c));
        char err[WEB_SDB_ERR_MAX];
        if (web_slothdb_open(src->sdb, &c, WEB_SDB_OVERVIEW_MS, now_s, err, sizeof(err)) == 0) {
            o->sdb = "open";
            web_sdb_session_t ss;
            if (web_sdb_sessions(&c, &ss, 1) == 1) snprintf(o->label, sizeof(o->label), "%s", ss.label);
        } else {
            o->sdb = "unavailable";
        }
        web_slothdb_close(&c);
    }
    web_gnss_sh_t sh;
    web_gnss_site(src->gnss, &o->loc, &sh);
}

/* One site of the overview, from peer_sites or, for a peer named but not
 * yet pulled, from its configuration. */
typedef struct {
    char      name[WEB_FLEET_NAME_MAX + 1];
    char      url[WEB_FLEET_URL_MAX + 1];
    char      label[WEB_FLEET_STR_MAX + 1];
    char      err[WEB_FLEET_ERR_MAX + 1];
    char      pos_source[8];
    char      version[32];
    int       configured, cfg_i, has_pos, has_alt;
    double    lat, lon, alt;
    long long pos_ts, last_attempt, last_ok, remote_ts, rows_last;
    long long counts[WEB_FK_COUNT + 1];          /* + gnss */
} fpeer_t;

#define FLEET_SITES_MAX 32

int web_fleet_overview_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                             long long now_s, char *body, size_t cap, size_t *len,
                             int *status) {
    fq_t fq;
    const char *why = NULL;
    if (parse_tab_query(query, 0, &fq, &why) != 0) {
        *status = 400;
        *len = web_series_error_json(why, body, cap);
        return *len ? 0 : -1;
    }
    fpeer_t *ps = calloc(FLEET_SITES_MAX, sizeof(*ps));
    if (!ps) return -1;
    int np = 0, store = 0, store_bad = 0;
#ifdef WITH_SQLITE
    web_store_t *s = f ? f->store : NULL;
    if (s && s->rd) {
        store = 1;
        pthread_mutex_lock(&s->rmu);
        sqlite3_stmt *q = NULL, *c = NULL;
        int ok = sqlite3_prepare_v2(s->rd,
            "SELECT peer,url,label,last_attempt,last_ok,last_error,lat,lon,alt,pos_source,"
            "pos_ts,remote_version,remote_ts,rows_last FROM peer_sites ORDER BY peer"
            " LIMIT 32", -1, &q, NULL) == SQLITE_OK &&
            sqlite3_prepare_v2(s->rd, "SELECT kind, COUNT(*) FROM peer_sightings"
                               " WHERE peer=?1 GROUP BY kind", -1, &c, NULL) == SQLITE_OK;
        while (ok && np < FLEET_SITES_MAX && sqlite3_step(q) == SQLITE_ROW) {
            const char *nm = (const char *)sqlite3_column_text(q, 0);
            if (!nm || strlen(nm) > WEB_FLEET_NAME_MAX) continue;
            fpeer_t *o = &ps[np++];
            o->cfg_i = -1;
            snprintf(o->name, sizeof(o->name), "%s", nm);
#define COLS(i, dst) do { const unsigned char *t_ = sqlite3_column_text(q, i); \
            snprintf(dst, sizeof(dst), "%s", t_ ? (const char *)t_ : ""); } while (0)
            COLS(1, o->url);
            COLS(2, o->label);
            COLS(5, o->err);
            COLS(9, o->pos_source);
            COLS(11, o->version);
#undef COLS
            o->last_attempt = sqlite3_column_int64(q, 3);
            o->last_ok = sqlite3_column_int64(q, 4);
            o->has_pos = sqlite3_column_type(q, 6) != SQLITE_NULL &&
                         sqlite3_column_type(q, 7) != SQLITE_NULL;
            o->lat = sqlite3_column_double(q, 6);
            o->lon = sqlite3_column_double(q, 7);
            o->has_alt = sqlite3_column_type(q, 8) != SQLITE_NULL;
            o->alt = sqlite3_column_double(q, 8);
            o->pos_ts = sqlite3_column_int64(q, 10);
            o->remote_ts = sqlite3_column_int64(q, 12);
            o->rows_last = sqlite3_column_int64(q, 13);
            sqlite3_reset(c);
            sqlite3_bind_text(c, 1, o->name, -1, SQLITE_TRANSIENT);
            while (sqlite3_step(c) == SQLITE_ROW) {
                const char *kind = (const char *)sqlite3_column_text(c, 0);
                if (!kind) continue;
                int k = kind_of_word(kind, strlen(kind));
                if (k < 0 && !strcmp(kind, "gnss")) k = WEB_FK_COUNT;
                if (k >= 0) o->counts[k] = sqlite3_column_int64(c, 1);
            }
        }
        if (!ok) store_bad = 1;
        sqlite3_finalize(q);
        sqlite3_finalize(c);
        pthread_mutex_unlock(&s->rmu);
    }
#endif
    if (store_bad) {
        free(ps);
        *status = 503;
        *len = web_series_error_json("store_read_failed", body, cap);
        return *len ? 0 : -1;
    }
    /* The configured peers: each one's live state; one not yet in
     * peer_sites listed from its configuration. */
    if (f) {
        pthread_mutex_lock(&f->mu);
        for (int i = 0; i < f->npeer; i++) {
            int j = 0;
            while (j < np && strcmp(ps[j].name, f->peer[i].cfg.name)) j++;
            if (j == np) {
                if (np >= FLEET_SITES_MAX) continue;
                fpeer_t *o = &ps[np++];
                snprintf(o->name, sizeof(o->name), "%s", f->peer[i].cfg.name);
                snprintf(o->url, sizeof(o->url), "%s", f->peer[i].cfg.url);
                snprintf(o->err, sizeof(o->err), "%s", f->peer[i].last_error);
                o->last_attempt = f->peer[i].last_attempt;
            }
            ps[j].configured = 1;
            ps[j].cfg_i = i;
        }
        pthread_mutex_unlock(&f->mu);
    }
    fsite_t me;
    local_site(src, now_s, &me);

    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"local\":{\"name\":\"self\",\"label\":");
    jstr_or_null(&w, me.label);
    web_jw_raw(&w, ",\"sloth_db\":");    web_jw_str(&w, me.sdb);
    web_jw_raw(&w, ",\"lat\":");         jnum_or_null(&w, me.loc.has, me.loc.lat, 7);
    web_jw_raw(&w, ",\"lon\":");         jnum_or_null(&w, me.loc.has, me.loc.lon, 7);
    web_jw_raw(&w, ",\"alt_m\":");       jnum_or_null(&w, me.loc.has && me.loc.has_alt, me.loc.alt_m, 1);
    web_jw_raw(&w, ",\"pos_source\":");  jstr_or_null(&w, me.loc.has ? me.loc.src : NULL);
    web_jw_raw(&w, ",\"pos_age_s\":");
    age_or_null(&w, me.loc.has ? me.loc.ts : 0, now_s);
    web_jw_raw(&w, "},\"export\":true,\"interval_s\":");
    web_jw_int(&w, f ? f->interval_s : WEB_FLEET_INTERVAL_DEF);
    web_jw_raw(&w, ",\"store\":");       web_jw_raw(&w, store ? "true" : "false");
    web_jw_raw(&w, ",\"configured\":");  web_jw_int(&w, f ? f->npeer : 0);
    web_jw_raw(&w, ",\"peers\":[");
    for (int j = 0; j < np; j++) {
        fpeer_t *o = &ps[j];
        web_jw_raw(&w, j ? ",{\"name\":" : "{\"name\":");
        web_jw_str(&w, o->name);
        web_jw_raw(&w, ",\"configured\":");   web_jw_raw(&w, o->configured ? "true" : "false");
        web_jw_raw(&w, ",\"url\":");          jstr_or_null(&w, o->url);
        web_jw_raw(&w, ",\"label\":");        jstr_or_null(&w, o->label);
        web_jw_raw(&w, ",\"lat\":");          jnum_or_null(&w, o->has_pos, o->lat, 7);
        web_jw_raw(&w, ",\"lon\":");          jnum_or_null(&w, o->has_pos, o->lon, 7);
        web_jw_raw(&w, ",\"alt_m\":");        jnum_or_null(&w, o->has_pos && o->has_alt, o->alt, 1);
        web_jw_raw(&w, ",\"pos_source\":");   jstr_or_null(&w, o->has_pos ? o->pos_source : NULL);
        /* The position's age by the peer's own clock at its last answer:
         * the two clocks need not agree. */
        web_jw_raw(&w, ",\"pos_age_s\":");
        if (o->has_pos && o->pos_ts > 0 && o->remote_ts > 0)
            web_jw_int(&w, o->remote_ts > o->pos_ts ? o->remote_ts - o->pos_ts : 0);
        else
            web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"last_ok_age_s\":");      age_or_null(&w, o->last_ok, now_s);
        web_jw_raw(&w, ",\"last_attempt_age_s\":"); age_or_null(&w, o->last_attempt, now_s);
        web_jw_raw(&w, ",\"last_error\":");         jstr_or_null(&w, o->err);
        /* The peer's clock less this one's at the last good pull: + the
         * peer runs ahead. Within a pull's own time of the truth. */
        web_jw_raw(&w, ",\"skew_s\":");
        if (o->remote_ts > 0 && o->last_ok > 0) web_jw_int(&w, o->remote_ts - o->last_ok);
        else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"remote_version\":");     jstr_or_null(&w, o->version);
        web_jw_raw(&w, ",\"rows_last\":");          web_jw_int(&w, o->rows_last);
        web_jw_raw(&w, ",\"counts\":{");
        for (int k = 0; k <= WEB_FK_COUNT; k++) {
            if (k) web_jw_raw(&w, ",");
            web_jw_str(&w, k < WEB_FK_COUNT ? KIND_WORD[k] : "gnss");
            web_jw_raw(&w, ":");
            web_jw_int(&w, o->counts[k]);
        }
        web_jw_raw(&w, "},\"backfill\":{");
        int nb = 0, plain = 0;
        unsigned long pages = 0, pfail = 0;
        if (f && o->cfg_i >= 0) {
            pthread_mutex_lock(&f->mu);
            const web_fleet_peer_t *p = &f->peer[o->cfg_i];
            pages = p->pages;
            pfail = p->page_failures;
            plain = p->no_next_until > now_s;
            for (int k = 0; k < WEB_FK_COUNT; k++) {
                if (!p->bf[k].active) continue;
                if (nb++) web_jw_raw(&w, ",");
                web_jw_str(&w, KIND_WORD[k]);
                web_jw_raw(&w, ":{\"floor\":");
                web_jw_int(&w, p->bf[k].floor);
                web_jw_raw(&w, ",\"cursor\":");
                web_jw_str(&w, p->bf[k].cur);
                web_jw_raw(&w, "}");
            }
            pthread_mutex_unlock(&f->mu);
        }
        web_jw_raw(&w, "},\"pages\":");          web_jw_int(&w, (long long)pages);
        web_jw_raw(&w, ",\"page_failures\":");   web_jw_int(&w, (long long)pfail);
        /* The peer's export refused next=1 (an F1 build): pulled
         * without it, nothing backfilled from it. */
        web_jw_raw(&w, ",\"pages_refused\":");   web_jw_raw(&w, plain ? "true" : "false");
        web_jw_raw(&w, ",\"distance_m\":");
        if (o->has_pos && me.loc.has)
            jfix(&w, web_fleet_dist_m(me.loc.lat, me.loc.lon, o->lat, o->lon), 1);
        else
            web_jw_raw(&w, "null");
        web_jw_raw(&w, "}");
    }
    /* Every pair of sites with a position, this one named "self". */
    web_jw_raw(&w, "],\"distances\":[");
    int nd = 0;
    for (int a = -1; a < np; a++) {
        int ha = a < 0 ? me.loc.has : ps[a].has_pos;
        if (!ha) continue;
        double la = a < 0 ? me.loc.lat : ps[a].lat, loa = a < 0 ? me.loc.lon : ps[a].lon;
        for (int b = a + 1; b < np; b++) {
            if (!ps[b].has_pos) continue;
            web_jw_raw(&w, nd++ ? ",{\"a\":" : "{\"a\":");
            web_jw_str(&w, a < 0 ? "self" : ps[a].name);
            web_jw_raw(&w, ",\"b\":");
            web_jw_str(&w, ps[b].name);
            web_jw_raw(&w, ",\"m\":");
            jfix(&w, web_fleet_dist_m(la, loa, ps[b].lat, ps[b].lon), 1);
            web_jw_raw(&w, "}");
        }
    }
    web_jw_raw(&w, "]}\n");
    free(ps);
    if (w.overflow) return -1;
    *status = 200;
    *len = w.len;
    return 0;
}

/* ── seen at more than one site ────────────────────────────────────── */

typedef struct {
    char      key[2 * WEB_FLEET_STR_MAX + 4];
    char      peer[WEB_FLEET_NAME_MAX + 1];
    char      label[WEB_FLEET_STR_MAX + 1];
    char      vendor[WEB_FLEET_STR_MAX + 1];
    int       has_rssi, rssi;
    long long first, last;
} srow_t;

typedef struct {
    int       at, n;                 /* rows[at .. at + n) */
    long long peer_last;
    int       has_local, local_has_rssi, local_rssi;
    long long local_first, local_last, last;
} sgroup_t;

static int by_key_then_last(const void *pa, const void *pb) {
    const srow_t *a = pa, *b = pb;
    int c = strcmp(a->key, b->key);
    if (c) return c;
    if (a->last != b->last) return a->last > b->last ? -1 : 1;
    return strcmp(a->peer, b->peer);
}

static int by_peer_last(const void *pa, const void *pb) {
    const sgroup_t *a = pa, *b = pb;
    if (a->peer_last != b->peer_last) return a->peer_last > b->peer_last ? -1 : 1;
    return a->at - b->at;
}

static int by_last(const void *pa, const void *pb) {
    const sgroup_t *a = pa, *b = pb;
    if (a->last != b->last) return a->last > b->last ? -1 : 1;
    return a->at - b->at;
}

static int parse_mac6(const char *s, uint8_t out[6]) {
    char k[WEB_KEY_MAX + 1];
    if (web_key_mac(s, k) != 0) return -1;
    for (int i = 0; i < 6; i++) {
        unsigned v = 0;
        for (int j = 0; j < 2; j++) {
            char c = k[i * 3 + j];
            v = v * 16 + (unsigned)(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* A listed row's address (the device drawer's; a probe's client) and
 * its verdict, this site's state or a peer's word and name. */
typedef struct {
    char      addr[WEB_KEY_MAX + 1];
    int       row, state;
    char      peer[WEB_FLEET_NAME_MAX + 1];
    char      pstate[16];
} sverd_t;

static void row_addr(const char *key, char out[WEB_KEY_MAX + 1]) {
    const char *bar = strchr(key, '|');
    if (bar && (size_t)(bar - key) <= WEB_KEY_MAX) {
        memcpy(out, key, (size_t)(bar - key));
        out[bar - key] = '\0';
    } else {
        snprintf(out, WEB_KEY_MAX + 1, "%.*s", WEB_KEY_MAX, key);
    }
}

static int by_vaddr(const void *pa, const void *pb) {
    return strcmp(((const sverd_t *)pa)->addr, ((const sverd_t *)pb)->addr);
}

static int by_vrow(const void *pa, const void *pb) {
    return ((const sverd_t *)pa)->row - ((const sverd_t *)pb)->row;
}

int web_fleet_shared_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                           long long now_s, char **body, size_t *len, int *status) {
    *body = NULL;
    *len = 0;
    (void)f;                            /* the store's, with SQLite */
    fq_t fq;
    const char *why = NULL;
    size_t cap = WEB_FLEET_SHARED_BODY;
    char *buf = malloc(cap);
    if (!buf) return -1;
    if (parse_tab_query(query, 1, &fq, &why) != 0) {
        *status = 400;
        *len = web_series_error_json(why, buf, cap);
        *body = buf;
        return *len ? 0 : -1;
    }
    web_jw_t w;
    web_jw_init(&w, buf, cap);
    web_jw_raw(&w, "{\"kind\":");
    web_jw_str(&w, KIND_WORD[fq.kind]);
    web_jw_raw(&w, ",\"limit\":");
    web_jw_int(&w, fq.limit);
    srow_t *rows = NULL;
    sgroup_t *g = NULL;
    int nr = 0, ng = 0, store = 0, partial = 0, looked = 0;
    const char *sdb_word = "none";
#ifdef WITH_SQLITE
    web_store_t *s = f ? f->store : NULL;
    if (s && s->rd) {
        store = 1;
        rows = malloc(sizeof(*rows) * WEB_FLEET_SHARED_SCAN);
        if (!rows) { free(buf); return -1; }
        pthread_mutex_lock(&s->rmu);
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(s->rd,
                "SELECT key,peer,label,vendor,rssi,first_seen,last_seen FROM peer_sightings"
                " WHERE kind=?1 ORDER BY last_seen DESC LIMIT ?2", -1, &q, NULL) == SQLITE_OK) {
            sqlite3_bind_text(q, 1, KIND_WORD[fq.kind], -1, SQLITE_STATIC);
            sqlite3_bind_int(q, 2, WEB_FLEET_SHARED_SCAN);
            while (nr < WEB_FLEET_SHARED_SCAN && sqlite3_step(q) == SQLITE_ROW) {
                srow_t *r = &rows[nr];
                memset(r, 0, sizeof(*r));
#define COLT(i, dst) do { const unsigned char *t_ = sqlite3_column_text(q, i); \
                snprintf(dst, sizeof(dst), "%s", t_ ? (const char *)t_ : ""); } while (0)
                COLT(0, r->key);
                COLT(1, r->peer);
                COLT(2, r->label);
                COLT(3, r->vendor);
#undef COLT
                r->has_rssi = sqlite3_column_type(q, 4) != SQLITE_NULL;
                r->rssi = sqlite3_column_int(q, 4);
                r->first = sqlite3_column_int64(q, 5);
                r->last = sqlite3_column_int64(q, 6);
                nr++;
            }
            /* More rows of the kind than the scan reads: the oldest are
             * not looked at. */
            if (nr == WEB_FLEET_SHARED_SCAN && sqlite3_step(q) == SQLITE_ROW) partial = 1;
        }
        sqlite3_finalize(q);
        pthread_mutex_unlock(&s->rmu);
    }
#endif
    /* Group by key; each key's rows newest first, one per peer. */
    if (nr) {
        qsort(rows, (size_t)nr, sizeof(*rows), by_key_then_last);
        g = calloc((size_t)nr, sizeof(*g));
        if (!g) { free(rows); free(buf); return -1; }
        for (int i = 0; i < nr;) {
            int j = i + 1;
            while (j < nr && !strcmp(rows[j].key, rows[i].key)) j++;
            g[ng].at = i;
            g[ng].n = j - i;
            g[ng].peer_last = rows[i].last;
            ng++;
            i = j;
        }
        qsort(g, (size_t)ng, sizeof(*g), by_peer_last);
    }
    /* The local side, the most recently seen at a peer first, while the
     * read's budget lasts: sloth.db through the M4 reader (read-only),
     * the BLE advertisers from slothweb's own table. */
    web_sdb_conn_t c;
    memset(&c, 0, sizeof(c));
    int have_c = 0;
    if (ng && fq.kind != WEB_FK_BLE && src->sdb && src->sdb->configured) {
        char err[WEB_SDB_ERR_MAX];
        if (web_slothdb_open(src->sdb, &c, WEB_SDB_OVERVIEW_MS, now_s, err, sizeof(err)) == 0) {
            have_c = 1;
            sdb_word = "open";
        } else {
            sdb_word = "unavailable";
        }
    }
    if (fq.kind == WEB_FK_BLE) sdb_word = src->ble ? "ble" : "none";
    int nshared = 0;
    for (int i = 0; i < ng; i++) {
        sgroup_t *x = &g[i];
        const char *key = rows[x->at].key;
        if (fq.kind == WEB_FK_BLE) {
            uint8_t a[6];
            web_ble_cand_t cand;
            if (!src->ble || parse_mac6(key, a) != 0 ||
                web_ble_addr_info(src->ble, a, &cand) != 1)
                continue;
            x->has_local = 1;
            x->local_has_rssi = cand.has_rssi;
            x->local_rssi = cand.rssi;
            x->local_first = cand.first_seen;
            x->local_last = cand.last_seen;
        } else {
            if (!have_c) break;
            /* Each lookup is too short for the reader's progress handler
             * to see the budget run out, so it is asked here. */
            if (web_sdb_spent(&c)) { partial = 1; break; }
            web_sdb_item_t it;
            int rc;
            looked++;
            if (fq.kind == WEB_FK_PROBE) {
                char mac[WEB_KEY_MAX + 1];
                const char *bar = strchr(key, '|');
                if (!bar || (size_t)(bar - key) > WEB_KEY_MAX) continue;
                memcpy(mac, key, (size_t)(bar - key));
                mac[bar - key] = '\0';
                rc = web_sdb_seen(&c, WEB_SEEN_PNL, mac, bar + 1, &it);
            } else {
                rc = web_sdb_seen(&c, fq.kind == WEB_FK_AP ? WEB_SEEN_AP : WEB_SEEN_DEVICE,
                                  key, NULL, &it);
            }
            if (rc < 0) { partial = 1; break; }
            if (rc == 0) continue;
            x->has_local = 1;
            x->local_has_rssi = it.has_n3;
            x->local_rssi = (int)it.n3;
            x->local_first = it.first_seen;
            x->local_last = it.last_seen;
        }
        x->last = x->local_last > x->peer_last ? x->local_last : x->peer_last;
        g[nshared++] = *x;
    }
    if (have_c) web_slothdb_close(&c);
    if (nshared > 1) qsort(g, (size_t)nshared, sizeof(*g), by_last);
    if (nshared > fq.limit) nshared = fq.limit;
    /* Each listed row's address and its verdict: this site's triage, one
     * pass over it for every row; else a peer's, one pass over the
     * verdicts the peers sent. Never a scan a row. */
    sverd_t *vd = nshared > 0 ? calloc((size_t)nshared, sizeof(*vd)) : NULL;
    if (nshared > 0 && !vd) { free(rows); free(g); free(buf); return -1; }
    for (int i = 0; i < nshared; i++) {
        row_addr(rows[g[i].at].key, vd[i].addr);
        vd[i].row = i;
        vd[i].state = -1;
    }
    if (nshared > 1) qsort(vd, (size_t)nshared, sizeof(*vd), by_vaddr);
    if (src->frrs && nshared > 0) {
        size_t nv = (size_t)nshared;
        const char **av = malloc(sizeof(*av) * nv);
        int *sv = malloc(sizeof(*sv) * nv);
        if (av && sv) {
            for (int i = 0; i < nshared; i++) av[i] = vd[i].addr;
            if (web_frrs_addr_states(src->frrs, av, nshared, sv) >= 0)
                for (int i = 0; i < nshared; i++) vd[i].state = sv[i];
        }
        free(av);
        free(sv);
    }
#ifdef WITH_SQLITE
    if (s && s->rd && nshared > 0) {
        pthread_mutex_lock(&s->rmu);
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(s->rd,
                "SELECT key,peer,label FROM peer_sightings WHERE kind='verdict'"
                " ORDER BY last_seen DESC", -1, &q, NULL) == SQLITE_OK) {
            while (sqlite3_step(q) == SQLITE_ROW) {
                /* The key: TYPE|addr|port|first_seen (row_of()). */
                const char *k = (const char *)sqlite3_column_text(q, 0);
                const char *a = k ? strchr(k, '|') : NULL;
                const char *e = a ? strchr(a + 1, '|') : NULL;
                if (!e || e == a + 1 || (size_t)(e - a - 1) > WEB_KEY_MAX) continue;
                sverd_t key;
                memset(&key, 0, sizeof(key));
                memcpy(key.addr, a + 1, (size_t)(e - a - 1));
                key.addr[e - a - 1] = '\0';
                sverd_t *hit = bsearch(&key, vd, (size_t)nshared, sizeof(*vd), by_vaddr);
                if (!hit) continue;
                /* Equal addresses sit together; the first unset takes it. */
                while (hit > vd && !strcmp(hit[-1].addr, key.addr)) hit--;
                for (; hit < vd + nshared && !strcmp(hit->addr, key.addr); hit++) {
                    if (hit->state >= 0 || hit->peer[0]) continue;
                    const char *pe = (const char *)sqlite3_column_text(q, 1);
                    const char *lb = (const char *)sqlite3_column_text(q, 2);
                    snprintf(hit->peer, sizeof(hit->peer), "%s", pe ? pe : "");
                    snprintf(hit->pstate, sizeof(hit->pstate), "%s", lb ? lb : "");
                }
            }
        }
        sqlite3_finalize(q);
        pthread_mutex_unlock(&s->rmu);
    }
#endif
    if (nshared > 1) qsort(vd, (size_t)nshared, sizeof(*vd), by_vrow);

    web_jw_raw(&w, ",\"store\":");     web_jw_raw(&w, store ? "true" : "false");
    web_jw_raw(&w, ",\"local\":");     web_jw_str(&w, sdb_word);
    web_jw_raw(&w, ",\"scanned\":");   web_jw_int(&w, nr);
    web_jw_raw(&w, ",\"keys\":");      web_jw_int(&w, ng);
    web_jw_raw(&w, ",\"partial\":");   web_jw_raw(&w, partial ? "true" : "false");
    web_jw_raw(&w, ",\"rows\":[");
    for (int i = 0; i < nshared && !w.overflow; i++) {
        const sgroup_t *x = &g[i];
        const srow_t *r0 = &rows[x->at];
        const char *mac = vd[i].addr;
        web_jw_raw(&w, i ? ",{\"key\":" : "{\"key\":");
        web_jw_str(&w, r0->key);
        /* The address the device page opens: a probe's client. */
        web_jw_raw(&w, ",\"addr\":");   web_jw_str(&w, mac);
        web_jw_raw(&w, ",\"label\":");  jstr_or_null(&w, r0->label);
        web_jw_raw(&w, ",\"vendor\":"); jstr_or_null(&w, r0->vendor);
        web_jw_raw(&w, ",\"last\":");   web_jw_int(&w, x->last);
        web_jw_raw(&w, ",\"sites\":[{\"site\":\"self\",\"first_seen\":");
        web_jw_int(&w, x->local_first);
        web_jw_raw(&w, ",\"last_seen\":"); web_jw_int(&w, x->local_last);
        web_jw_raw(&w, ",\"rssi\":");
        if (x->local_has_rssi) web_jw_int(&w, x->local_rssi); else web_jw_raw(&w, "null");
        web_jw_raw(&w, "}");
        for (int j = 0; j < x->n; j++) {
            const srow_t *r = &rows[x->at + j];
            web_jw_raw(&w, ",{\"site\":");     web_jw_str(&w, r->peer);
            web_jw_raw(&w, ",\"first_seen\":"); web_jw_int(&w, r->first);
            web_jw_raw(&w, ",\"last_seen\":");  web_jw_int(&w, r->last);
            web_jw_raw(&w, ",\"rssi\":");
            if (r->has_rssi) web_jw_int(&w, r->rssi); else web_jw_raw(&w, "null");
            web_jw_raw(&w, "}");
        }
        /* The verdict: this site's triage of a finding at the address,
         * else the newest a peer sent (I8 is F3's; this only shows it). */
        web_jw_raw(&w, "],\"verdict\":");
        if (vd[i].state >= 0) {
            web_jw_raw(&w, "{\"state\":");
            web_jw_str(&w, web_frrs_state_word(vd[i].state));
            web_jw_raw(&w, ",\"site\":\"self\"}");
        } else if (vd[i].peer[0]) {
            web_jw_raw(&w, "{\"state\":");
            jstr_or_null(&w, vd[i].pstate);
            web_jw_raw(&w, ",\"site\":");
            web_jw_str(&w, vd[i].peer);
            web_jw_raw(&w, "}");
        } else {
            web_jw_raw(&w, "null");
        }
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"looked_up\":");
    web_jw_int(&w, looked);
    web_jw_raw(&w, "}\n");
    free(rows);
    free(g);
    free(vd);
    if (w.overflow) {
        *len = web_series_error_json("too_large", buf, cap);
        *status = 503;
    } else {
        *len = w.len;
        *status = 200;
    }
    *body = buf;
    return *len ? 0 : -1;
}
