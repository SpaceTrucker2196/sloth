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

/* ── the members ───────────────────────────────────────────────────── */

static const char *const KIND_WORD[WEB_FK_COUNT] = {
    "wifi", "ble", "ap", "probe", "alert", "verdict",
};

const char *web_fleet_kind_word(int k) {
    return k >= 0 && k < WEB_FK_COUNT ? KIND_WORD[k] : "";
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
    "truncated_alert", "truncated_verdict", "complete", NULL };

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

typedef struct {
    web_jw_t   *w;
    long long   since;
    int         n[WEB_FK_COUNT];
    int         cut[WEB_FK_COUNT];
    int         skip[WEB_FK_COUNT];  /* a row the importer would refuse, left out */
    size_t      soft;                /* rows stop here; the end line after */
    web_sdb_conn_t *c;
    char       (*macs)[WEB_KEY_MAX + 1];
    int         nmacs;
    const char *pnl_mac;
    web_jrec_t *rec;                 /* the self-check's decoder record */
} xp_t;

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

static int xp_dev(void *ctx, const web_sdb_dev_t *d) {
    xp_t *x = ctx;
    if (x->n[WEB_FK_WIFI] >= WEB_FLEET_CAP_WIFI) { x->cut[WEB_FK_WIFI] = 1; return 1; }
    char mac[WEB_KEY_MAX + 1];
    if (web_key_mac(d->mac, mac) != 0) return 0;
    char bssid[WEB_KEY_MAX + 1] = "";
    if (!d->is_ap) web_sdb_assocs(x->c, mac, 1, xp_assoc, bssid);
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
    if (!d->is_ap && x->nmacs < WEB_FLEET_CAP_WIFI)
        snprintf(x->macs[x->nmacs++], WEB_KEY_MAX + 1, "%s", mac);
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
    return row_end(x, WEB_FK_AP, mark) <= 0;
}

static int xp_pnl(void *ctx, const web_sdb_item_t *it) {
    xp_t *x = ctx;
    if (it->last_seen < x->since) return 1;    /* newest first */
    if (x->n[WEB_FK_PROBE] >= WEB_FLEET_CAP_PROBE) { x->cut[WEB_FK_PROBE] = 1; return 1; }
    size_t mark;
    row_begin(x, &mark);
    web_jw_t *w = x->w;
    web_jw_raw(w, "{\"type\":\"probe\"");
    jk(w, M_PROBE, "mac");        web_jw_str(w, x->pnl_mac);
    jk(w, M_PROBE, "ssid");       web_jw_str(w, it->a);
    jk(w, M_PROBE, "first_seen"); web_jw_int(w, it->first_seen);
    jk(w, M_PROBE, "last_seen");  web_jw_int(w, it->last_seen);
    return row_end(x, WEB_FK_PROBE, mark) <= 0;
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
    return row_end(x, WEB_FK_ALERT, mark) <= 0;
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
    return row_end(x, WEB_FK_VERDICT, mark) <= 0;
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

static int parse_since(const char *q, long long *since, const char **why) {
    *since = 0;
    if (!q || !q[0]) return 0;
    if (strncmp(q, "since=", 6) != 0) { *why = "unknown_parameter"; return -1; }
    const char *p = q + 6;
    if (!*p || strlen(p) > 12) { *why = "bad_since"; return -1; }
    long long v = 0;
    for (; *p; p++) {
        if (*p < '0' || *p > '9') { *why = *p == '&' ? "unknown_parameter" : "bad_since"; return -1; }
        v = v * 10 + (*p - '0');
    }
    *since = v;
    return 0;
}

int web_fleet_export_route(const web_fleet_src_t *src, const char *query,
                           long long now_s, char **body, size_t *len,
                           int *status) {
    *body = NULL;
    *len = 0;
    long long since;
    const char *why = NULL;
    if (parse_since(query, &since, &why) != 0) {
        char *b = malloc(256);
        if (!b) return -1;
        *len = web_series_error_json(why, b, 256);
        *body = b;
        *status = 400;
        return *len ? 0 : -1;
    }
    char *buf = malloc(WEB_FLEET_EXPORT_MAX);
    char (*macs)[WEB_KEY_MAX + 1] = malloc(sizeof(*macs) * WEB_FLEET_CAP_WIFI);
    web_jrec_t *rec = malloc(sizeof(*rec));
    if (!buf || !macs || !rec) { free(buf); free(macs); free(rec); return -1; }
    web_jw_t w;
    web_jw_init(&w, buf, WEB_FLEET_EXPORT_MAX);
    xp_t x;
    memset(&x, 0, sizeof(x));
    x.w = &w;
    x.since = since;
    x.soft = WEB_FLEET_EXPORT_MAX - 4096;
    x.macs = macs;
    x.rec = rec;

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

    if (sh.seen && !w.overflow) {
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

    if (have_c && !fault) {
        if (web_sdb_devices_between(&c, since, LLONG_MAX / 2, WEB_FLEET_CAP_WIFI + 1, 0,
                                    xp_dev, &x) < 0)
            x.cut[WEB_FK_WIFI] = 1;
        if (!c.timed_out && web_sdb_aps(&c, WEB_AP_SORT_LAST, WEB_FLEET_CAP_AP + 1, 0,
                                        xp_ap, &x) < 0)
            x.cut[WEB_FK_AP] = 1;
        for (int i = 0; i < x.nmacs && !c.timed_out && !x.cut[WEB_FK_PROBE]; i++) {
            x.pnl_mac = x.macs[i];
            if (web_sdb_ssids(&c, x.macs[i], WEB_FLEET_PNL_PER, xp_pnl, &x) < 0) break;
        }
        if (!c.timed_out &&
            web_sdb_alerts_between(&c, since, LLONG_MAX / 2, WEB_FLEET_CAP_ALERT + 1,
                                   xp_alert, &x) < 0)
            x.cut[WEB_FK_ALERT] = 1;
        /* A read that ran out of budget is a cut, never an error: what
         * was read before it went out. */
        if (c.timed_out)
            x.cut[WEB_FK_WIFI] = x.cut[WEB_FK_AP] = x.cut[WEB_FK_PROBE] =
                x.cut[WEB_FK_ALERT] = 1;
    }
    if (have_c) web_slothdb_close(&c);
    if (src->ble && !fault) xp_ble(&x, src->ble, now_s);
    if (src->frrs && !fault &&
        web_frrs_verdicts(src->frrs, since, WEB_FLEET_CAP_VERDICT + 1, xp_verdict, &x) < 0)
        x.cut[WEB_FK_VERDICT] = 1;
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
    jk(&w, M_END, "complete"); web_jw_raw(&w, "true");
    web_jw_raw(&w, "}\n");
    free(macs);
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

static int http_get(web_fleet_t *f, const web_fleet_peer_cfg_t *p, long long since,
                    char **out, size_t *outlen, char *err, size_t errsz) {
    *out = NULL;
    *outlen = 0;
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
    char rq[256];
    int rl = snprintf(rq, sizeof(rq), "GET /api/fleet/export?since=%lld HTTP/1.1\r\n"
                      "Host: %s:%u\r\nUser-Agent: slothweb-fleet\r\n"
                      "Accept: application/x-ndjson\r\nConnection: close\r\n\r\n",
                      since, host, (unsigned)p->port);
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

#define T_MAX 4102444800LL           /* 2100-01-01: no clock reads later */

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

static int store_answer(web_fleet_t *f, const web_fleet_peer_cfg_t *pc, const chk_t *k,
                        const char *body, size_t len, web_jrec_t *rec, long long now_s,
                        char *err, size_t errsz) {
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
    if (ok)
        ok = sqlite3_prepare_v2(db,
            "INSERT INTO peer_sites (peer,url,label,last_attempt,last_ok,last_error,lat,"
            "lon,alt,pos_source,pos_ts,remote_version,remote_ts,rows_last) VALUES"
            " (?1,?2,?3,?4,?4,'',?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT (peer) DO UPDATE"
            " SET url=excluded.url, label=excluded.label, last_attempt=excluded.last_attempt,"
            " last_ok=excluded.last_ok, last_error='', lat=excluded.lat, lon=excluded.lon,"
            " alt=excluded.alt, pos_source=excluded.pos_source, pos_ts=excluded.pos_ts,"
            " remote_version=excluded.remote_version, remote_ts=excluded.remote_ts,"
            " rows_last=excluded.rows_last", -1, &s, NULL) == SQLITE_OK;
    if (ok) {
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
                        char *err, size_t errsz) {
    (void)f; (void)pc; (void)k; (void)body; (void)len; (void)rec; (void)now_s;
    snprintf(err, errsz, "built without SQLite");
    return -1;
}

static void store_failure(web_fleet_t *f, const web_fleet_peer_cfg_t *pc, long long now_s,
                          const char *why) {
    (void)f; (void)pc; (void)now_s; (void)why;
}

#endif

int web_fleet_ingest(web_fleet_t *f, int i, const char *body, size_t len,
                     long long now_s, int write, long long *rows,
                     long long *remote_ts, char *err, size_t errsz) {
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
    if (rc == 0 && write)
        rc = store_answer(f, &f->peer[i].cfg, &k, body, len, rec, now_s, err, errsz);
    free(rec);
    if (rc != 0) return -1;
    *rows = k.data;
    *remote_ts = k.hdr.generated;
    return 0;
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
    int rc = -1;
    if (!f->store || !f->wr)
        snprintf(err, sizeof(err), "no store: nothing is pulled");
    else if (http_get(f, &p->cfg, since, &body, &len, err, sizeof(err)) == 0)
        rc = web_fleet_ingest(f, i, body, len, now_s, 1, &rows, &remote, err, sizeof(err));
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
