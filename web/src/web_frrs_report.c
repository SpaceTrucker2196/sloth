/* The FRRS emitter record (docs/web-frrs-spec.md §4): BEI, SCS, EC/S,
 * TACDB and the COMINT report for one emitter, every field
 * {"v":value,"src":"where sloth keeps it"} and v null when sloth has
 * not observed it. Built from three places only: sloth.db through the
 * M4 reader's allow-list (web_slothdb.h), the stream's latest records
 * in the ledger (web_frrs.c), and slothweb's own state (the baseline,
 * the anomaly episodes, the TACDB). Nothing is sent anywhere to fill a
 * field, and nothing here is a location or a decryption. */
#include "web_frrs_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_alertkb.h"
#include "web_anomaly.h"
#include "web_baseline.h"
#include "web_metrics.h"
#include "web_oui.h"
#include "web_rollup.h"
#include "web_scope.h"
#include "web_ssid.h"
#include "web_vendorkb.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

/* The two limits every record states, in these words (§4.5). */
static const char POSITION_LIMIT[] =
    "no location axis: a single passive sensor has no bearing and no position; "
    "est_dist_* is a distance estimate from signal strength, not a location";
static const char CONTENT_LIMIT[] =
    "sloth decrypts nothing (MISSION §2): 'language' here means the protocols observed "
    "on the wire, and whether they were in the clear";

/* ── fields ─────────────────────────────────────────────────────────── */

typedef struct {
    web_jw_t *w;
    int       n;          /* fields written in the open group */
} G;

static void g_open(G *g, web_jw_t *w, const char *name, int comma) {
    g->w = w;
    g->n = 0;
    if (comma) web_jw_raw(w, ",");
    web_jw_key(w, name);
    web_jw_raw(w, "{");
}

static void g_close(G *g) { web_jw_raw(g->w, "}"); }

static void f_head(G *g, const char *name) {
    if (g->n++) web_jw_raw(g->w, ",");
    web_jw_key(g->w, name);
    web_jw_raw(g->w, "{\"v\":");
}

static void f_tail(G *g, const char *src, long long since) {
    web_jw_raw(g->w, ",\"src\":");
    web_jw_str(g->w, src);
    if (since > 0) {
        web_jw_raw(g->w, ",\"since\":");
        web_jw_int(g->w, since);
    }
    web_jw_raw(g->w, "}");
}

static void fi(G *g, const char *name, int have, long long v, const char *src, long long since) {
    f_head(g, name);
    if (have) web_jw_int(g->w, v); else web_jw_raw(g->w, "null");
    f_tail(g, src, have ? since : 0);
}

static void fs(G *g, const char *name, const char *v, const char *src, long long since) {
    f_head(g, name);
    int have = v && v[0];
    if (have) web_jw_str(g->w, v); else web_jw_raw(g->w, "null");
    f_tail(g, src, have ? since : 0);
}

/* A string from sloth.db that may hold a peer's octets (an SSID): its
 * display form (web_ssid.h). */
static void ft(G *g, const char *name, const char *v, const char *src) {
    f_head(g, name);
    if (v && v[0]) web_jw_text(g->w, v); else web_jw_raw(g->w, "null");
    f_tail(g, src, 0);
}

static void fb(G *g, const char *name, int have, int v, const char *src, long long since) {
    f_head(g, name);
    web_jw_raw(g->w, !have ? "null" : v ? "true" : "false");
    f_tail(g, src, have ? since : 0);
}

static void fd(G *g, const char *name, int have, double v, const char *src, long long since) {
    f_head(g, name);
    if (have) {
        char b[32];
        snprintf(b, sizeof(b), "%.1f", v);
        web_jw_raw(g->w, b);
    } else {
        web_jw_raw(g->w, "null");
    }
    f_tail(g, src, have ? since : 0);
}

/* A field whose value is said in a word of ours, because sloth has no
 * field for it: v null, and why. */
static void fnone(G *g, const char *name, const char *src, const char *why) {
    f_head(g, name);
    web_jw_raw(g->w, "null,\"why\":");
    web_jw_str(g->w, why);
    f_tail(g, src, 0);
}

/* SCS's certification: the vendor research entry for the registrant
 * (web_vendorkb.h), its fcc_grantee values as the entry writes them,
 * each with its [n], and the Sources lines those numbers name. A
 * grantee code is a company's: a registrant found through an affiliate
 * is a different company, so its entry's codes are not shown as its. */
static void f_cert(G *g, int have_oui, const web_oui_hit_t *oh) {
    static const char WHERE[] = "web/data/vendors/ (the vendor research KB: fcc_grantee)";
    int aff = 0;
    const web_vkb_t *e = have_oui ? web_vendorkb_lookup(oh->name, &aff) : NULL;
    if (!e) {
        fnone(g, "certification_fcc", WHERE, have_oui ? "no vendor research entry for this registrant"
                                                     : "no registrant: the address is in no OUI block");
        return;
    }
    char src[160];
    snprintf(src, sizeof(src), "%s fcc_grantee", e->file);
    if (aff) {
        char why[256];
        snprintf(why, sizeof(why), "the registrant is an affiliate of %s, a separate company; that "
                 "entry's grantee codes are not this registrant's", e->name);
        fnone(g, "certification_fcc", src, why);
        return;
    }
    if (!e->nfcc_grantee) {
        fnone(g, "certification_fcc", src, "the vendor research entry documents no FCC grantee code");
        return;
    }
    f_head(g, "certification_fcc");
    web_jw_raw(g->w, "{\"grantee\":[");
    unsigned char used[64] = { 0 };
    for (int i = 0; i < e->nfcc_grantee; i++) {
        if (i) web_jw_raw(g->w, ",");
        web_jw_str(g->w, e->fcc_grantee[i]);
        /* A citation as web/tools/vendorkb.c reads one: "[" digits,
         * commas and spaces "]". */
        for (const char *p = strchr(e->fcc_grantee[i], '['); p; p = strchr(p + 1, '[')) {
            const char *q = p + 1;
            int ok = 1;
            for (; *q && *q != ']'; q++)
                if (!(*q >= '0' && *q <= '9') && *q != ',' && *q != ' ') ok = 0;
            if (*q != ']' || !ok) continue;
            for (q = p + 1; *q != ']'; ) {
                if (*q < '0' || *q > '9') { q++; continue; }
                int n = 0;
                while (*q >= '0' && *q <= '9' && n < 1000) n = n * 10 + (*q++ - '0');
                if (n >= 1 && n <= e->nsources && n < 64) used[n] = 1;
            }
        }
    }
    web_jw_raw(g->w, "],\"sources\":[");
    int k = 0;
    for (int n = 1; n < 64 && n <= e->nsources; n++) {
        if (!used[n]) continue;
        const web_vkb_src_t *sv = &e->sources[n - 1];
        char line[1024];
        snprintf(line, sizeof(line), "[%d] %s, %s (accessed %s)", n, sv->title, sv->url, sv->accessed);
        if (k++) web_jw_raw(g->w, ",");
        web_jw_str(g->w, line);
    }
    web_jw_raw(g->w, "]}");
    f_tail(g, src, 0);
}

static void f_est(G *g, const frrs_est_t *e, const char *src, long long since) {
    fd(g, "est_dist_m", e && e->have, e ? e->m : 0, src, since);
    fs(g, "est_dist_band", e && e->have ? e->band : NULL, src, since);
    fs(g, "est_dist_trend", e && e->have ? e->trend : NULL, src, since);
    fs(g, "est_ptx_source", e && e->have ? e->ptx : NULL, src, since);
}

/* ── what is read from sloth.db ─────────────────────────────────────── */

typedef struct {
    int       have;
    char      ssid[WEB_SDB_TEXT_MAX + 1], enc[16], pairwise[48], group[32], akm[48];
    char      vendor[WEB_SDB_TEXT_MAX + 1], phy[24];
    int       has_sig, signal, has_ch, channel, has_bms, beacon_ms, has_mfp, mfp;
    int       has_wps, has_wst, wps_state, has_wl, wps_locked;
    int       has_qbss, has_qsta, qsta, has_qutil, qutil;
    long long akm_bits, dg, frames, first, last;
} ap_row_t;

typedef struct {
    int       have;
    char      ssid[WEB_SDB_TEXT_MAX + 1];
    int       has_sig, signal, has_ch, channel, presence;
    long long frames, first, last;
} probe_row_t;

typedef struct {
    int       have;
    int       mac_random, phy_confirmed;
    char      os_fp[24], phy[24];
    long long probes, first, last, pnl_n;
} pnl_row_t;

typedef struct {
    int       have;
    char      bssid[18], phy[24];
    long long akm_bits, pairwise_bits, rates, dg, prev_akm, first, last;
    int       mfp, prev_mfp, has_li, listen_interval;
} ar_row_t;

typedef struct {
    int       have;
    long long mask, seen_by, obs, first, last;
    int       has_best, best_rssi, has_bs, best_sensor, has_ch, channel;
} merged_row_t;

typedef struct {
    int       have;
    char      ip[WEB_SDB_TEXT_MAX + 1], host[WEB_SDB_TEXT_MAX + 1];
    char      cam[WEB_SDB_TEXT_MAX + 1];
    long long cls;
    int       is_ap, has_sig, signal;
    long long first, last;
} dev_row_t;

typedef struct {
    char      a[WEB_SDB_TEXT_MAX + 1], b[WEB_SDB_TEXT_MAX + 1];
    long long n1, n2, n3, first, last, rid;
    int       has_n3;
} item_t;

#define ITEMS 8
typedef struct {
    item_t    it[ITEMS];
    int       n, more, read;
} list_t;

typedef struct {
    char      db[16];                 /* "open", "none", "unreadable", "unbuilt" */
    ap_row_t  ap;
    probe_row_t pr;
    pnl_row_t pnl;
    ar_row_t  ar;
    merged_row_t mg;
    dev_row_t dev;
    list_t    vaps, akmh, cochan, clients, assocs, seq, arp, names, alerts, smb, ssh, snmp;
    long long cochan_n, vaps_n, btm_req, btm_imm, ldap_anon;
    int       has_btm, has_ldap, karma, karma_score, wsta_have, wsta_sig;
    long long wsta_tx, wsta_rx;
    int       smb1, snmp_v12;
} sdb_t;

#ifdef WITH_SQLITE

static sqlite3_stmt *sq(web_sdb_conn_t *c, const char *sql, const char *a, long long bi) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &s, NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        return NULL;
    }
    if (a) sqlite3_bind_text(s, 1, a, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_int64(s, 1, bi);
    return s;
}

static int cnull(sqlite3_stmt *s, int i) { return sqlite3_column_type(s, i) == SQLITE_NULL; }
static void ctext(sqlite3_stmt *s, int i, char *out, size_t cap) {
    const unsigned char *t = sqlite3_column_text(s, i);
    web_utf8_copy(out, cap - 1, t ? (const char *)t : "");
}

static void read_ap(web_sdb_conn_t *c, const char *mac, ap_row_t *a) {
    sqlite3_stmt *s = sq(c, "SELECT ssid, signal_dbm, channel, enc, beacon_ms, pairwise,"
                            " group_ciph, akm, akm_bits, mfp, vendor, has_wps, wps_state,"
                            " wps_locked, phy, downgrade_flags, has_qbss, qbss_stations,"
                            " qbss_chan_util, frame_count, first_seen, last_seen"
                            " FROM beacon_aps WHERE bssid = ?1", mac, 0);
    if (!s) return;
    if (sqlite3_step(s) == SQLITE_ROW) {
        a->have = 1;
        ctext(s, 0, a->ssid, sizeof(a->ssid));
        a->has_sig = !cnull(s, 1); a->signal = sqlite3_column_int(s, 1);
        a->has_ch = !cnull(s, 2);  a->channel = sqlite3_column_int(s, 2);
        ctext(s, 3, a->enc, sizeof(a->enc));
        a->has_bms = !cnull(s, 4); a->beacon_ms = sqlite3_column_int(s, 4);
        ctext(s, 5, a->pairwise, sizeof(a->pairwise));
        ctext(s, 6, a->group, sizeof(a->group));
        ctext(s, 7, a->akm, sizeof(a->akm));
        a->akm_bits = sqlite3_column_int64(s, 8);
        a->has_mfp = !cnull(s, 9); a->mfp = sqlite3_column_int(s, 9);
        ctext(s, 10, a->vendor, sizeof(a->vendor));
        a->has_wps = sqlite3_column_int(s, 11);
        a->has_wst = !cnull(s, 12); a->wps_state = sqlite3_column_int(s, 12);
        a->has_wl = !cnull(s, 13);  a->wps_locked = sqlite3_column_int(s, 13);
        ctext(s, 14, a->phy, sizeof(a->phy));
        a->dg = sqlite3_column_int64(s, 15);
        a->has_qbss = sqlite3_column_int(s, 16);
        a->has_qsta = !cnull(s, 17); a->qsta = sqlite3_column_int(s, 17);
        a->has_qutil = !cnull(s, 18); a->qutil = sqlite3_column_int(s, 18);
        a->frames = sqlite3_column_int64(s, 19);
        a->first = sqlite3_column_int64(s, 20);
        a->last = sqlite3_column_int64(s, 21);
    }
    sqlite3_finalize(s);
}

/* A list from a statement: columns a, b, n1, n2, n3, first, last as the
 * statement names them (fewer is fine: ncols). */
static void read_list(web_sdb_conn_t *c, const char *sql, const char *a, long long bi,
                      int ncols, list_t *l) {
    sqlite3_stmt *s = sq(c, sql, a, bi);
    if (!s) return;
    l->read = 1;
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        if (l->n >= ITEMS) { l->more = 1; break; }
        item_t *it = &l->it[l->n++];
        memset(it, 0, sizeof(*it));
        if (ncols > 0) ctext(s, 0, it->a, sizeof(it->a));
        if (ncols > 1) ctext(s, 1, it->b, sizeof(it->b));
        if (ncols > 2) it->n1 = sqlite3_column_int64(s, 2);
        if (ncols > 3) it->n2 = sqlite3_column_int64(s, 3);
        if (ncols > 4) { it->has_n3 = !cnull(s, 4); it->n3 = sqlite3_column_int64(s, 4); }
        if (ncols > 5) it->first = sqlite3_column_int64(s, 5);
        if (ncols > 6) it->last = sqlite3_column_int64(s, 6);
    }
    sqlite3_finalize(s);
}

static long long one_int(web_sdb_conn_t *c, const char *sql, const char *a, long long bi, int *have) {
    sqlite3_stmt *s = sq(c, sql, a, bi);
    long long v = 0;
    *have = 0;
    if (!s) return 0;
    if (sqlite3_step(s) == SQLITE_ROW && !cnull(s, 0)) { v = sqlite3_column_int64(s, 0); *have = 1; }
    sqlite3_finalize(s);
    return v;
}

static int take_item(void *ctx, const web_sdb_item_t *x) {
    list_t *l = ctx;
    l->read = 1;
    if (l->n >= ITEMS) { l->more = 1; return 1; }
    item_t *it = &l->it[l->n++];
    memset(it, 0, sizeof(*it));
    snprintf(it->a, sizeof(it->a), "%s", x->a);
    snprintf(it->b, sizeof(it->b), "%s", x->b);
    it->n1 = x->n1;
    it->n2 = x->n2;
    it->has_n3 = x->has_n3;
    it->n3 = x->n3;
    it->rid = x->rid;
    it->first = x->first_seen;
    it->last = x->last_seen;
    return 0;
}

static void read_sdb(const web_m4_t *m, int kind, const char *mac, long long now_s, sdb_t *d) {
    snprintf(d->db, sizeof(d->db), "none");
    if (!m->sdb || !m->sdb->configured || kind == FRRS_K_BLE) return;
    web_sdb_conn_t c;
    char err[200];
    if (web_slothdb_open(m->sdb, &c, WEB_SDB_HTTP_MS, now_s, err, sizeof(err)) != 0) {
        snprintf(d->db, sizeof(d->db), "unreadable");
        return;
    }
    snprintf(d->db, sizeof(d->db), "open");
    int h;
    /* The device row: the drawer's own reader (web_slothdb.h). */
    web_sdb_dev_t dv;
    if (web_sdb_device(&c, mac, &dv) > 0) {
        d->dev.have = 1;
        snprintf(d->dev.ip, sizeof(d->dev.ip), "%s", dv.ip);
        snprintf(d->dev.host, sizeof(d->dev.host), "%s", dv.hostname);
        d->dev.cls = dv.device_class;
        snprintf(d->dev.cam, sizeof(d->dev.cam), "%s", dv.camera_vendor);
        d->dev.is_ap = dv.is_ap;
        d->dev.has_sig = dv.has_signal;
        d->dev.signal = dv.signal_dbm;
        d->dev.first = dv.first_seen;
        d->dev.last = dv.last_seen;
    }
    sqlite3_stmt *s = sq(&c, "SELECT sensor_mask, seen_by, best_rssi, best_sensor, channel,"
                             " observations, first_seen, last_seen FROM wifi_merged"
                             " WHERE entity = ?1", mac, 0);
    if (s && sqlite3_step(s) == SQLITE_ROW) {
        merged_row_t *g = &d->mg;
        g->have = 1;
        g->mask = sqlite3_column_int64(s, 0);
        g->seen_by = sqlite3_column_int64(s, 1);
        g->has_best = !cnull(s, 2); g->best_rssi = sqlite3_column_int(s, 2);
        g->has_bs = !cnull(s, 3);   g->best_sensor = sqlite3_column_int(s, 3);
        g->has_ch = !cnull(s, 4);   g->channel = sqlite3_column_int(s, 4);
        g->obs = sqlite3_column_int64(s, 5);
        g->first = sqlite3_column_int64(s, 6);
        g->last = sqlite3_column_int64(s, 7);
    }
    sqlite3_finalize(s);
    if (kind == FRRS_K_BSSID) {
        read_ap(&c, mac, &d->ap);
        read_list(&c, "SELECT ssid, '', 0, 0, NULL, first_seen, last_seen FROM beacon_ap_ssids"
                      " WHERE bssid = ?1 ORDER BY last_seen DESC", mac, 0, 7, &d->vaps);
        d->vaps_n = one_int(&c, "SELECT COUNT(*) FROM beacon_ap_ssids WHERE bssid = ?1", mac, 0, &h);
        read_list(&c, "SELECT ssid, '', akm_bits, 0, NULL, first_seen, last_seen"
                      " FROM ssid_akm_history WHERE bssid = ?1 ORDER BY first_seen", mac, 0, 7,
                  &d->akmh);
        if (d->ap.have && d->ap.has_ch) {
            sqlite3_stmt *q = NULL;
            if (sqlite3_prepare_v2(c.db, "SELECT bssid, ssid, signal_dbm, enc, first_seen, last_seen"
                                   " FROM beacon_aps WHERE channel = ?1 AND bssid <> ?2"
                                   " ORDER BY signal_dbm DESC", -1, &q, NULL) == SQLITE_OK) {
                sqlite3_bind_int(q, 1, d->ap.channel);
                sqlite3_bind_text(q, 2, mac, -1, SQLITE_TRANSIENT);
                d->cochan.read = 1;
                while (sqlite3_step(q) == SQLITE_ROW) {
                    d->cochan_n++;
                    if (d->cochan.n >= ITEMS) { d->cochan.more = 1; continue; }
                    item_t *it = &d->cochan.it[d->cochan.n++];
                    memset(it, 0, sizeof(*it));
                    ctext(q, 0, it->a, sizeof(it->a));
                    ctext(q, 1, it->b, sizeof(it->b));
                    it->has_n3 = !cnull(q, 2);
                    it->n3 = sqlite3_column_int64(q, 2);
                    char enc[16];
                    ctext(q, 3, enc, sizeof(enc));
                    it->n1 = !strcmp(enc, "OPEN") ? 0 : !strcmp(enc, "WEP") ? 1 :
                             !strcmp(enc, "WPA") ? 2 : !strcmp(enc, "WPA2") ? 3 :
                             !strcmp(enc, "WPA3") ? 4 : -1;
                    it->first = sqlite3_column_int64(q, 4);
                    it->last = sqlite3_column_int64(q, 5);
                }
            }
            sqlite3_finalize(q);
        }
        read_list(&c, "SELECT sta_mac, ssid, channel, sta_random, signal_dbm, first_seen, last_seen"
                      " FROM assocs WHERE bssid = ?1 ORDER BY last_seen DESC", mac, 0, 7, &d->clients);
        sqlite3_stmt *b = sq(&c, "SELECT SUM(req_count), SUM(imminent_count) FROM btm_requests"
                                 " WHERE bssid = ?1", mac, 0);
        if (b && sqlite3_step(b) == SQLITE_ROW && !cnull(b, 0)) {
            d->has_btm = 1;
            d->btm_req = sqlite3_column_int64(b, 0);
            d->btm_imm = sqlite3_column_int64(b, 1);
        }
        sqlite3_finalize(b);
        d->karma_score = (int)one_int(&c, "SELECT score FROM karma_candidates WHERE bssid = ?1",
                                      mac, 0, &d->karma);
    } else {
        sqlite3_stmt *p = sq(&c, "SELECT ssid, signal_dbm, channel, frame_count, presence,"
                                 " first_seen, last_seen FROM probe_clients WHERE mac = ?1", mac, 0);
        if (p && sqlite3_step(p) == SQLITE_ROW) {
            probe_row_t *r = &d->pr;
            r->have = 1;
            ctext(p, 0, r->ssid, sizeof(r->ssid));
            r->has_sig = !cnull(p, 1); r->signal = sqlite3_column_int(p, 1);
            r->has_ch = !cnull(p, 2);  r->channel = sqlite3_column_int(p, 2);
            r->frames = sqlite3_column_int64(p, 3);
            r->presence = sqlite3_column_int(p, 4);
            r->first = sqlite3_column_int64(p, 5);
            r->last = sqlite3_column_int64(p, 6);
        }
        sqlite3_finalize(p);
        sqlite3_stmt *q = sq(&c, "SELECT mac_random, probe_count, os_fp, phy, phy_confirmed,"
                                 " first_seen, last_seen FROM pnl_clients WHERE mac = ?1", mac, 0);
        if (q && sqlite3_step(q) == SQLITE_ROW) {
            pnl_row_t *r = &d->pnl;
            r->have = 1;
            r->mac_random = sqlite3_column_int(q, 0);
            r->probes = sqlite3_column_int64(q, 1);
            ctext(q, 2, r->os_fp, sizeof(r->os_fp));
            ctext(q, 3, r->phy, sizeof(r->phy));
            r->phy_confirmed = sqlite3_column_int(q, 4);
            r->first = sqlite3_column_int64(q, 5);
            r->last = sqlite3_column_int64(q, 6);
        }
        sqlite3_finalize(q);
        d->pnl.pnl_n = one_int(&c, "SELECT COUNT(*) FROM pnl_ssids WHERE mac = ?1", mac, 0, &h);
        sqlite3_stmt *a = sq(&c, "SELECT bssid, akm_bits, pairwise_bits, requested_mfp,"
                                 " supported_rates, listen_interval, phy, downgrade_flags,"
                                 " prev_akm_bits, prev_mfp, first_seen, last_seen FROM assoc_reqs"
                                 " WHERE sta_mac = ?1 ORDER BY last_seen DESC LIMIT 1", mac, 0);
        if (a && sqlite3_step(a) == SQLITE_ROW) {
            ar_row_t *r = &d->ar;
            r->have = 1;
            ctext(a, 0, r->bssid, sizeof(r->bssid));
            r->akm_bits = sqlite3_column_int64(a, 1);
            r->pairwise_bits = sqlite3_column_int64(a, 2);
            r->mfp = sqlite3_column_int(a, 3);
            r->rates = sqlite3_column_int64(a, 4);
            r->has_li = !cnull(a, 5);
            r->listen_interval = sqlite3_column_int(a, 5);
            ctext(a, 6, r->phy, sizeof(r->phy));
            r->dg = sqlite3_column_int64(a, 7);
            r->prev_akm = sqlite3_column_int64(a, 8);
            r->prev_mfp = sqlite3_column_int(a, 9);
            r->first = sqlite3_column_int64(a, 10);
            r->last = sqlite3_column_int64(a, 11);
        }
        sqlite3_finalize(a);
        web_sdb_assocs(&c, mac, ITEMS + 1, take_item, &d->assocs);
        sqlite3_stmt *ws = sq(&c, "SELECT signal_dbm, tx_rate_kbps, rx_rate_kbps FROM wifi_stas"
                                  " WHERE mac = ?1", mac, 0);
        if (ws && sqlite3_step(ws) == SQLITE_ROW) {
            d->wsta_have = 1;
            d->wsta_sig = sqlite3_column_int(ws, 0);
            d->wsta_tx = sqlite3_column_int64(ws, 1);
            d->wsta_rx = sqlite3_column_int64(ws, 2);
        }
        sqlite3_finalize(ws);
        sqlite3_stmt *b = sq(&c, "SELECT SUM(req_count), SUM(imminent_count) FROM btm_requests"
                                 " WHERE sta_mac = ?1", mac, 0);
        if (b && sqlite3_step(b) == SQLITE_ROW && !cnull(b, 0)) {
            d->has_btm = 1;
            d->btm_req = sqlite3_column_int64(b, 0);
            d->btm_imm = sqlite3_column_int64(b, 1);
        }
        sqlite3_finalize(b);
        read_list(&c, "SELECT CASE WHEN mac_a = ?1 THEN mac_b ELSE mac_a END, '', gap, dt_ms,"
                      " a_count + b_count, first_seen, last_seen FROM seqnum_correlations"
                      " WHERE mac_a = ?1 OR mac_b = ?1 ORDER BY last_seen DESC", mac, 0, 7, &d->seq);
        web_sdb_arp_mac(&c, mac, ITEMS + 1, take_item, &d->arp);
        const char *ip = d->dev.ip[0] ? d->dev.ip : d->arp.n ? d->arp.it[0].a : NULL;
        if (ip) {
            web_sdb_names(&c, ip, ITEMS + 1, take_item, &d->names);
            read_list(&c, "SELECT server_ip, dialect, server_port, obs_count, NULL, first_seen,"
                          " last_seen FROM smb_sessions WHERE client_ip = ?1 ORDER BY last_seen DESC",
                      ip, 0, 7, &d->smb);
            for (int i = 0; i < d->smb.n; i++) if (!strcmp(d->smb.it[i].b, "SMB1")) d->smb1 = 1;
            read_list(&c, "SELECT dst_ip, '', banner_count, 0, NULL, first_seen, last_seen"
                          " FROM ssh_flows WHERE src_ip = ?1 ORDER BY last_seen DESC", ip, 0, 7,
                      &d->ssh);
            read_list(&c, "SELECT dst_ip, '', version, get_count, NULL, first_seen, last_seen"
                          " FROM snmp_flows WHERE src_ip = ?1 ORDER BY last_seen DESC", ip, 0, 7,
                      &d->snmp);
            for (int i = 0; i < d->snmp.n; i++) if (d->snmp.it[i].n1 <= 1) d->snmp_v12 = 1;
            d->ldap_anon = one_int(&c, "SELECT SUM(bind_anon_count) FROM ldap_events"
                                       " WHERE src_ip = ?1", ip, 0, &d->has_ldap);
        }
    }
    long long reached = 0;
    web_sdb_alerts(&c, mac, NULL, ITEMS, take_item, &d->alerts, &reached);
    web_slothdb_close(&c);
}

#else

static void read_sdb(const web_m4_t *m, int kind, const char *mac, long long now_s, sdb_t *d) {
    (void)kind; (void)mac; (void)now_s;
    snprintf(d->db, sizeof(d->db), m->sdb && m->sdb->configured ? "unbuilt" : "none");
}

#endif

/* ── the stream's findings naming the emitter ───────────────────────── */

typedef struct {
    char      id[40];
    int       type, sev, open;
    long long last;
} sfind_t;

static int stream_findings(web_live_t *live, const char *mac, sfind_t *out, int max) {
    if (!live) return 0;
    web_live_inc_t *inc = calloc(WEB_LIVE_INCIDENTS + WEB_LIVE_CLOSED, sizeof(*inc));
    if (!inc) return 0;
    int nopen = 0, n = web_live_incidents(live, inc, WEB_LIVE_INCIDENTS + WEB_LIVE_CLOSED, &nopen), k = 0;
    for (int i = 0; i < n && k < max; i++) {
        if (!strstr(inc[i].key, mac)) continue;
        int dup = 0;
        for (int j = 0; j < i && !dup; j++) dup = inc[i].key[0] && !strcmp(inc[j].key, inc[i].key);
        if (dup) continue;
        snprintf(out[k].id, sizeof(out[k].id), "s%s", inc[i].hid);
        out[k].type = inc[i].type;
        out[k].sev = inc[i].sev;
        out[k].open = inc[i].closed_ts < 0;
        out[k].last = inc[i].last_ts;
        k++;
    }
    free(inc);
    return k;
}

/* The DFS channels of the 5 GHz band plan (sloth's src/wifi_freq.c
 * names the same set; test_frrs.c holds the two together). */
static int is_dfs(int ch) {
    return (ch >= 52 && ch <= 64) || (ch >= 100 && ch <= 144);
}

static const char *band_of(int ch, int six) {
    if (six) return "6 GHz";
    if (ch >= 1 && ch <= 14) return "2.4 GHz";
    if (ch >= 32 && ch <= 177) return "5 GHz";
    return NULL;
}

static void list_items(G *g, const char *name, const list_t *l, const char *src,
                       const char *ka, const char *kb, const char *k1, const char *k3,
                       int text_a, int text_b) {
    f_head(g, name);
    if (!l->read) {
        web_jw_raw(g->w, "null");
    } else {
        web_jw_raw(g->w, "[");
        for (int i = 0; i < l->n; i++) {
            const item_t *it = &l->it[i];
            web_jw_raw(g->w, i ? ",{" : "{");
            web_jw_key(g->w, ka);
            if (text_a) web_jw_text(g->w, it->a); else web_jw_str(g->w, it->a);
            if (kb) {
                web_jw_raw(g->w, ",");
                web_jw_key(g->w, kb);
                if (!it->b[0]) web_jw_raw(g->w, "null");
                else if (text_b) web_jw_text(g->w, it->b);
                else web_jw_str(g->w, it->b);
            }
            if (k1) { web_jw_raw(g->w, ","); web_jw_key(g->w, k1); web_jw_int(g->w, it->n1); }
            if (k3) {
                web_jw_raw(g->w, ",");
                web_jw_key(g->w, k3);
                if (it->has_n3) web_jw_int(g->w, it->n3); else web_jw_raw(g->w, "null");
            }
            web_jw_raw(g->w, ",\"first_seen\":"); web_jw_int(g->w, it->first);
            web_jw_raw(g->w, ",\"last_seen\":");  web_jw_int(g->w, it->last);
            web_jw_raw(g->w, "}");
        }
        web_jw_raw(g->w, "]");
        if (l->more) web_jw_raw(g->w, ",\"_more\":true");
    }
    f_tail(g, src, 0);
}

/* ── the record ─────────────────────────────────────────────────────── */

typedef struct {
    frrs_bss_t  bss;  int has_bss;
    frrs_bss_t  mld;  int has_mld;    /* the MLD whose links hold it */
    frrs_sta_t  sta;  int has_sta;
    frrs_ble_t  ble[4]; int nble;
    frrs_ip_t   ip;   int has_ip;
    frrs_chan_t ch;   int has_ch;
    char        country_mode[8];
    int         country_n;
} led_t;

static void led_take(web_frrs_t *f, int kind, const char *mac, int at, const char *ip, int chan,
                     led_t *l) {
    memset(l, 0, sizeof(*l));
    if (!f || !f->led) return;
    pthread_mutex_lock(&f->lmu);
    const frrs_bss_t *b = frrs_led_bss(f, mac);
    if (b) { l->bss = *b; l->has_bss = 1; }
    const frrs_bss_t *mb = frrs_led_mld_of(f, mac);
    if (mb) { l->mld = *mb; l->has_mld = 1; }
    const frrs_sta_t *s = frrs_led_sta(f, mac);
    if (s) { l->sta = *s; l->has_sta = 1; }
    if (kind == FRRS_K_BLE) {
        const frrs_ble_t *bl[4] = { NULL };
        l->nble = frrs_led_ble(f, mac, at, bl, 4);
        for (int i = 0; i < l->nble; i++) l->ble[i] = *bl[i];
    }
    const frrs_ip_t *p = frrs_led_ip(f, ip);
    if (p) { l->ip = *p; l->has_ip = 1; }
    if (chan <= 0 && l->has_bss) chan = l->bss.channel;
    const frrs_chan_t *c = frrs_led_chan(f, chan);
    if (c) { l->ch = *c; l->has_ch = 1; }
    /* The regulatory domain the air claims: the modal country over the
     * BSSIDs that sent one. */
    char seen[16][8];
    int cnt[16], ns = 0;
    for (int i = 0; i < f->led->nbss; i++) {
        const frrs_bss_t *x = &f->led->bss[i];
        if (!x->has_r || !x->country_present || !x->country[0]) continue;
        int k = 0;
        while (k < ns && strcmp(seen[k], x->country)) k++;
        if (k == ns) {
            if (ns == 16) continue;
            snprintf(seen[ns], sizeof(seen[ns]), "%s", x->country);
            cnt[ns++] = 0;
        }
        cnt[k]++;
    }
    for (int k = 0; k < ns; k++)
        if (cnt[k] > l->country_n) { l->country_n = cnt[k]; snprintf(l->country_mode, 8, "%.7s", seen[k]); }
    pthread_mutex_unlock(&f->lmu);
}

static const char *const ENC_WORD[] = { "OPEN", "WEP", "WPA", "WPA2", "WPA3" };

void frrs_report_json(const web_m4_t *m, web_live_t *live, int kind, const char *addr,
                      long long now_s, web_jw_t *w) {
    web_frrs_t *f = m->frrs;
    char mac[18];
    int at = -1;
    snprintf(mac, sizeof(mac), "%.17s", addr);
    if (kind == FRRS_K_BLE && strlen(addr) > 18) at = atoi(addr + 18);
    sdb_t *d = calloc(1, sizeof(*d));
    led_t *L = calloc(1, sizeof(*L));
    sfind_t *sf = calloc(16, sizeof(*sf));
    if (!d || !L || !sf) {
        free(d); free(L); free(sf);
        web_jw_raw(w, "null");
        return;
    }
    read_sdb(m, kind, mac, now_s, d);
    const char *ip = d->dev.ip[0] ? d->dev.ip : d->arp.n ? d->arp.it[0].a : NULL;
    int chan = d->ap.have && d->ap.has_ch ? d->ap.channel : d->pr.have && d->pr.has_ch ? d->pr.channel : 0;
    led_take(f, kind, mac, at, ip, chan, L);
    int nsf = stream_findings(live, mac, sf, 16);
    const frrs_ble_t *bl = L->nble ? &L->ble[0] : NULL;
    for (int i = 1; i < L->nble; i++) if (L->ble[i].ts > bl->ts) bl = &L->ble[i];
    const frrs_bss_t *B = L->has_bss ? &L->bss : NULL;
    const frrs_sta_t *S = L->has_sta ? &L->sta : NULL;
    if (!chan && B && B->has_b) chan = B->channel;
    if (!chan && S && S->has_p) chan = S->channel;

    uint8_t mb[6];
    web_oui_hit_t oh;
    memset(&oh, 0, sizeof(oh));
    int have_oui = web_oui_mac_bytes(mac, mb) == 0 && m->oui && web_oui_lookup(m->oui, mb, &oh);
    int local = web_oui_mac_bytes(mac, mb) == 0 && (mb[0] & 2);
    if (web_oui_mac_bytes(mac, mb) == 0) { oh.local = (mb[0] & 2) != 0; oh.multicast = mb[0] & 1; }

    web_jw_raw(w, "{\"emitter\":{\"kind\":");
    web_jw_str(w, frrs_kind_word(kind));
    web_jw_raw(w, ",\"addr\":");      web_jw_str(w, addr);
    web_jw_raw(w, ",\"mac\":");       web_jw_str(w, mac);
    web_jw_raw(w, ",\"addr_type\":");
    if (kind == FRRS_K_BLE) web_jw_int(w, at); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"station_class\":");
    web_jw_str(w, kind == FRRS_K_BLE ? "BLE advertiser" : kind == FRRS_K_BSSID
                  ? (L->has_bss && L->bss.has_m ? "AP (Multi-Link Device)" : "AP")
                  : (L->has_mld ? "client (Multi-Link Device link)" : "client"));
    web_jw_raw(w, ",\"scope\":\"monitor\"},\"sources\":{\"sloth_db\":");
    web_jw_str(w, d->db);
    web_jw_raw(w, ",\"ledger\":");
    web_jw_str(w, f && f->led ? "memory, since this slothweb started" : "none");
    web_jw_raw(w, "},\"position_limit\":");
    web_jw_str(w, POSITION_LIMIT);
    web_jw_raw(w, ",\"content_limit\":");
    web_jw_str(w, CONTENT_LIMIT);

    G g;
    /* ── BEI ── */
    g_open(&g, w, "bei", 1);
    fi(&g, "channel", chan > 0, chan,
       kind == FRRS_K_BSSID ? "beacon_aps.channel / beacon.channel"
       : kind == FRRS_K_BLE ? "ble_device.channel" : "probe_clients.channel / assocs.channel", 0);
    if (kind == FRRS_K_BLE) {
        fi(&g, "ll_channel", bl && bl->channel >= 0, bl ? bl->channel : 0, "ble_device.channel",
           bl ? bl->ts : 0);
    }
    fs(&g, "band", L->has_ch && L->ch.band[0] ? L->ch.band
                   : band_of(chan, B && B->has_b && B->channel_source == 3),
       "channel_summary.band (ap_band_label())", L->has_ch ? L->ch.ts : 0);
    fi(&g, "occupancy_ctrl_frames", L->has_ch, L->ch.ctrl_total, "channel_summary.ctrl_total",
       L->ch.ts);
    fi(&g, "occupancy_aps_on_channel", L->has_ch, L->ch.ap_count, "channel_summary.ap_count", L->ch.ts);
    fi(&g, "occupancy_assocs_on_channel", L->has_ch, L->ch.assoc_count, "channel_summary.assoc_count",
       L->ch.ts);
    fb(&g, "qbss_load_advertised", d->ap.have, d->ap.has_qbss, "beacon_aps.has_qbss", 0);
    fi(&g, "qbss_stations", d->ap.have && d->ap.has_qsta, d->ap.qsta, "beacon_aps.qbss_stations", 0);
    fi(&g, "qbss_chan_util", d->ap.have && d->ap.has_qutil, d->ap.qutil,
       "beacon_aps.qbss_chan_util (of 255)", 0);
    fi(&g, "co_channel_networks", d->cochan.read, d->cochan_n, "beacon_aps (same channel)", 0);
    f_head(&g, "co_channel_top");
    if (!d->cochan.read) {
        web_jw_raw(w, "null");
    } else {
        web_jw_raw(w, "[");
        for (int i = 0; i < d->cochan.n; i++) {
            const item_t *it = &d->cochan.it[i];
            web_jw_raw(w, i ? ",{\"bssid\":" : "{\"bssid\":");
            web_jw_str(w, it->a);
            web_jw_raw(w, ",\"ssid\":");
            if (it->b[0]) web_jw_text(w, it->b); else web_jw_raw(w, "null");
            web_jw_raw(w, ",\"signal_dbm\":");
            if (it->has_n3) web_jw_int(w, it->n3); else web_jw_raw(w, "null");
            web_jw_raw(w, ",\"enc\":");
            if (it->n1 >= 0 && it->n1 <= 4) web_jw_str(w, ENC_WORD[it->n1]); else web_jw_raw(w, "null");
            web_jw_raw(w, "}");
        }
        web_jw_raw(w, "]");
        if (d->cochan.more) web_jw_raw(w, ",\"_more\":true");
    }
    f_tail(&g, "beacon_aps.bssid, .ssid, .signal_dbm, .enc (same channel, strongest first)", 0);
    fs(&g, "regulatory_country", B && B->has_r && B->country_present ? B->country : NULL,
       "wifi_regulatory.country", B ? B->ts_r : 0);
    fs(&g, "regulatory_env", B && B->has_r ? B->env : NULL, "wifi_regulatory.env", B ? B->ts_r : 0);
    fs(&g, "regulatory_domain_site", L->country_mode, "wifi_regulatory.country (the modal one "
       "over every BSSID that sent a Country element)", 0);
    {
        int rf = 0, df = 0;
        for (int i = 0; i < nsf; i++) {
            const web_akb_t *k = web_akb_get(sf[i].type);
            if (k && !strcmp(k->name, "RF_DEGRADED")) rf++;
            if (k && !strcmp(k->name, "DEAUTH_FLOOD")) df++;
        }
        for (int i = 0; i < d->alerts.n; i++) {
            const web_akb_t *k = web_akb_get(d->alerts.it[i].n1);
            if (k && !strcmp(k->name, "RF_DEGRADED")) rf++;
            if (k && !strcmp(k->name, "DEAUTH_FLOOD")) df++;
        }
        fi(&g, "interference_rf_degraded", 1, rf, "alerts / alert.* RF_DEGRADED naming it", 0);
        fi(&g, "interference_deauth_floods", 1, df, "alerts / alert.* DEAUTH_FLOOD naming it", 0);
    }
    /* Time-of-day presence: the dev.present baseline's warm cells. */
    {
        web_bl_cell_t cells[WEB_BL_CELLS];
        int got = m->anomaly && m->anomaly->cfg.bl &&
                  web_baseline_cells(m->anomaly->cfg.bl, WM_DEV_PRESENT, mac, cells) == 0;
        int usual = 0, warm = 0;
        char hours[96] = "";
        static const char *const DOW[] = { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
        for (int i = 0; got && i < WEB_BL_CELLS; i++) {
            if (cells[i].n < WEB_BL_WARM_N) continue;
            warm++;
            if (cells[i].mean >= 0.5f) {
                if (usual < 6) {
                    char t[16];
                    snprintf(t, sizeof(t), "%s%s %02dh", usual ? ", " : "", DOW[i / 24], i % 24);
                    strncat(hours, t, sizeof(hours) - strlen(hours) - 1);
                }
                usual++;
            }
        }
        fi(&g, "presence_warm_cells", got, warm, "dev.present baseline (slothweb; 168 hour-of-week "
           "cells, warm at 3 weeks)", 0);
        fi(&g, "presence_usual_hours", got && warm, usual, "dev.present baseline: cells present in "
           "at least half the weeks", 0);
        fs(&g, "presence_usual_first", hours, "dev.present baseline (local hour of the sensor host)", 0);
    }
    fi(&g, "anomaly_episodes", m->anomaly != NULL,
       m->anomaly ? web_anomaly_key_count(m->anomaly, mac, -1) : 0,
       "slothweb's anomaly episodes keyed by the MAC (/api/anomalies)", 0);
    fi(&g, "coverage_radios", d->mg.have, d->mg.seen_by, "wifi_merged.seen_by", 0);
    fi(&g, "coverage_sensor_mask", d->mg.have, d->mg.mask, "wifi_merged.sensor_mask", 0);
    fi(&g, "coverage_best_sensor", d->mg.have && d->mg.has_bs, d->mg.best_sensor,
       "wifi_merged.best_sensor", 0);
    fs(&g, "coverage_monitor_iface", f && f->led ? f->led->mon_iface : NULL,
       "sensor_health.monitor_iface", f && f->led ? f->led->ts_sh : 0);
    g_close(&g);

    /* ── SCS ── */
    g_open(&g, w, "scs", 1);
    fs(&g, "vendor_registry", have_oui ? oh.name : NULL, "the OUI table (IEEE MA-L/MA-M/MA-S, "
       "web/data/)", 0);
    fs(&g, "vendor_block", have_oui ? oh.block : NULL, "the OUI table", 0);
    fb(&g, "locally_administered", web_oui_mac_bytes(mac, mb) == 0, local,
       "the address's U/L bit", 0);
    f_cert(&g, have_oui, &oh);
    if (kind != FRRS_K_BLE) {
        fb(&g, "country_element", B && B->has_r, B && B->country_present, "wifi_regulatory.country_present",
           B ? B->ts_r : 0);
        fb(&g, "country_triplets_truncated", B && B->has_r, B && B->triplets_truncated,
           "wifi_regulatory.triplets_truncated", B ? B->ts_r : 0);
        fi(&g, "country_malformed", B && B->has_r, B ? B->malformed_country : 0,
           "wifi_regulatory.malformed_country", B ? B->ts_r : 0);
        fb(&g, "tpc_report", B && B->has_r, B && B->tpc_present, "wifi_regulatory.tpc_present",
           B ? B->ts_r : 0);
        fi(&g, "tpc_tx_power_dbm", B && B->has_r && B->tpc_present, B ? B->tpc_tx_power_dbm : 0,
           "wifi_regulatory.tpc_tx_power_dbm", B ? B->ts_r : 0);
        fi(&g, "tpc_link_margin_db", B && B->has_r && B->tpc_present, B ? B->tpc_link_margin_db : 0,
           "wifi_regulatory.tpc_link_margin_db", B ? B->ts_r : 0);
        fi(&g, "power_constraint_db", B && B->has_r && B->power_constraint_present,
           B ? B->power_constraint_db : 0, "wifi_regulatory.power_constraint_db", B ? B->ts_r : 0);
        fs(&g, "he6_reg_info", B && B->has_r && B->he6_present ? B->he6_name : NULL,
           "wifi_regulatory.he6_reg_info_name", B ? B->ts_r : 0);
        fb(&g, "dfs_channel", chan > 0, is_dfs(chan), "the 5 GHz band plan (src/wifi_freq.c)", 0);
        fs(&g, "enc", d->ap.have ? d->ap.enc : B && B->has_b ? B->enc : NULL,
           "beacon_aps.enc / beacon.enc", 0);
        fs(&g, "pairwise", d->ap.have ? d->ap.pairwise : B && B->has_b ? B->pairwise : NULL,
           "beacon_aps.pairwise / beacon.pairwise", 0);
        fs(&g, "group_cipher", d->ap.have ? d->ap.group : B && B->has_b ? B->group : NULL,
           "beacon_aps.group_ciph / beacon.group", 0);
        fs(&g, "akm", d->ap.have ? d->ap.akm : B && B->has_b ? B->akm : NULL,
           "beacon_aps.akm / beacon.akm", 0);
        fi(&g, "akm_bits", d->ap.have || (B && B->has_b), d->ap.have ? d->ap.akm_bits : B ? B->akm_bits : 0,
           "beacon_aps.akm_bits (00-0F-AC suite types)", 0);
        fi(&g, "mfp", (d->ap.have && d->ap.has_mfp) || (B && B->has_b && B->mfp >= 0),
           d->ap.have && d->ap.has_mfp ? d->ap.mfp : B ? B->mfp : 0,
           "beacon_aps.mfp (0 none, 1 capable, 2 required)", 0);
        fi(&g, "downgrade_flags", d->ap.have, d->ap.dg, "beacon_aps.downgrade_flags (WPA_DG_*)", 0);
        fi(&g, "akm_history_rows", d->akmh.read, d->akmh.n, "ssid_akm_history (one row per AKM set)", 0);
        {
            int trans = 0;
            for (int i = 0; i < d->akmh.n; i++)
                if ((d->akmh.it[i].n1 & 0x4) && (d->akmh.it[i].n1 & 0x100)) trans = 1;
            fb(&g, "transition_mode", d->akmh.read && d->akmh.n, trans,
               "ssid_akm_history.akm_bits: PSK and SAE in one row", 0);
        }
        fb(&g, "wps", d->ap.have || (B && B->has_b), d->ap.have ? d->ap.has_wps : B && B->has_wps,
           "beacon_aps.has_wps", 0);
        fi(&g, "wps_state", d->ap.have && d->ap.has_wst, d->ap.wps_state, "beacon_aps.wps_state", 0);
        fi(&g, "wps_locked", d->ap.have && d->ap.has_wl, d->ap.wps_locked, "beacon_aps.wps_locked", 0);
        fi(&g, "wps_config_methods", B && B->has_b && B->wps_config_methods,
           B ? B->wps_config_methods : 0, "beacon.wps_config_methods", B ? B->ts_b : 0);
        fi(&g, "wps_device_pwd_id", B && B->has_b && B->wps_device_pwd_id,
           B ? B->wps_device_pwd_id : 0, "beacon.wps_device_pwd_id (0x0004: push-button now)",
           B ? B->ts_b : 0);
    }
    /* Every finding naming it whose type has no ATT&CK technique and is
     * the monitor radio's: the posture kinds (agents/AGENTS.md). */
    f_head(&g, "compliance_findings");
    web_jw_raw(w, "[");
    {
        int k = 0;
        for (int i = 0; i < nsf + d->alerts.n; i++) {
            int type = i < nsf ? sf[i].type : (int)d->alerts.it[i - nsf].n1;
            const web_akb_t *kb = web_akb_get(type);
            if (!kb || (kb->technique && kb->technique[0])) continue;
            web_jw_raw(w, k++ ? ",{\"type\":" : "{\"type\":");
            web_jw_str(w, kb->name);
            web_jw_raw(w, ",\"id\":");
            if (i < nsf) web_jw_str(w, sf[i].id);
            else {
                char id[32];
                snprintf(id, sizeof(id), "d%lld", d->alerts.it[i - nsf].rid);
                web_jw_str(w, id);
            }
            web_jw_raw(w, ",\"state\":");
            web_jw_str(w, i < nsf ? (sf[i].open ? "open" : "closed") : "recorded");
            web_jw_raw(w, "}");
        }
    }
    web_jw_raw(w, "]");
    f_tail(&g, "alerts and alert.* naming it, of a type with no ATT&CK technique "
           "(COUNTRY_ABSENT, TPC_ABSENT_HIGH_BAND, DFS_MASKING, ...)", 0);
    g_close(&g);

    /* ── EC/S ── */
    g_open(&g, w, "ecs", 1);
    if (kind == FRRS_K_BSSID) {
        long long ts = B ? B->ts_b : 0;
        fi(&g, "primary_channel", B && B->has_b && B->primary_channel, B ? B->primary_channel : 0,
           "beacon.primary_channel", ts);
        fi(&g, "channel_source", B && B->has_b && B->channel_source, B ? B->channel_source : 0,
           "beacon.channel_source (1 DS, 2 HT, 3 HE-6GHz, 4 EHT)", ts);
        fi(&g, "operating_width_mhz", B && B->has_b && B->operating_width, B ? B->operating_width : 0,
           "beacon.operating_width (0: not decoded)", ts);
        fi(&g, "secondary_offset", B && B->has_b, B ? B->secondary_offset : 0,
           "beacon.secondary_offset (0 none, 1 above, 3 below)", ts);
        fs(&g, "phy", d->ap.have ? d->ap.phy : B && B->has_b ? B->phy : NULL,
           "beacon_aps.phy / beacon.phy", 0);
        fi(&g, "beacon_interval_ms", (d->ap.have && d->ap.has_bms) || (B && B->has_b && B->beacon_ms),
           d->ap.have && d->ap.has_bms ? d->ap.beacon_ms : B ? B->beacon_ms : 0,
           "beacon_aps.beacon_ms / beacon.beacon_ms", 0);
        fi(&g, "tbtt_jitter_us", B && B->has_b && B->tbtt_jitter_samples, B ? B->tbtt_jitter_us : 0,
           "beacon.tbtt_jitter_us (with _samples)", ts);
        fi(&g, "tbtt_jitter_samples", B && B->has_b, B ? B->tbtt_jitter_samples : 0,
           "beacon.tbtt_jitter_samples", ts);
        fs(&g, "vendor_ies_hash", B && B->has_b ? B->vendor_ies_hash : NULL,
           "beacon.vendor_ies_hash (a fingerprint, not decoded)", ts);
        fs(&g, "ie_order_hash", B && B->has_b ? B->ie_order_hash : NULL, "beacon.ie_order_hash", ts);
        fi(&g, "ie_order_count", B && B->has_b && B->ie_order_count, B ? B->ie_order_count : 0,
           "beacon.ie_order_count", ts);
        fi(&g, "fp_flags", B && B->has_b, B ? B->fp_flags : 0, "beacon.fp_flags (AP_FP_FLAG_*)", ts);
        fs(&g, "wps_manufacturer", B && B->has_b ? B->wps_manufacturer : NULL, "beacon.wps_manufacturer", ts);
        fs(&g, "wps_model_name", B && B->has_b ? B->wps_model_name : NULL, "beacon.wps_model_name", ts);
        fs(&g, "wps_model_number", B && B->has_b ? B->wps_model_number : NULL, "beacon.wps_model_number", ts);
        fi(&g, "tx_power_dbm", B && B->has_r && B->tpc_present, B ? B->tpc_tx_power_dbm : 0,
           "wifi_regulatory.tpc_tx_power_dbm", B ? B->ts_r : 0);
        /* The Multi-Link Device this address is (its MLD address) or
         * is a link of (one of its link BSSIDs). */
        const frrs_bss_t *MB = B && B->has_m ? B : L->has_mld ? &L->mld : NULL;
        fs(&g, "mld_mac", MB ? MB->mac : NULL, "wifi_mld.mld_mac", MB ? MB->ts_m : 0);
        fi(&g, "mld_link_count", MB != NULL, MB ? MB->link_count : 0, "wifi_mld.link_count",
           MB ? MB->ts_m : 0);
        f_head(&g, "mld_links");
        if (!MB) web_jw_raw(w, "null");
        else {
            web_jw_raw(w, "[");
            for (int i = 0; i < MB->nlinks; i++) {
                if (i) web_jw_raw(w, ",");
                web_jw_str(w, MB->links[i]);
            }
            web_jw_raw(w, "]");
        }
        f_tail(&g, "wifi_mld.link_<n>_mac", MB ? MB->ts_m : 0);
        fi(&g, "ssids", d->vaps.read, d->vaps_n, "beacon_ap_ssids (every SSID this BSSID sent)", 0);
        list_items(&g, "ssid_list", &d->vaps, "beacon_ap_ssids.ssid", "ssid", NULL, NULL, NULL, 1, 0);
        fi(&g, "steering_btm_requests", d->has_btm, d->btm_req, "btm_requests.req_count", 0);
        fi(&g, "steering_imminent", d->has_btm, d->btm_imm, "btm_requests.imminent_count", 0);
        fnone(&g, "supported_rates", "beacon (no rates field)",
              "sloth does not decode an AP's supported rates; its clients' are under each "
              "client's record (assoc_reqs.supported_rates)");
    } else if (kind == FRRS_K_STA) {
        long long ts = S ? S->ts_ar : 0;
        fb(&g, "randomised", 1, d->pnl.have ? d->pnl.mac_random : local,
           d->pnl.have ? "pnl_clients.mac_random" : "the address's U/L bit", 0);
        fs(&g, "phy", d->pnl.have && d->pnl.phy[0] ? d->pnl.phy : S && S->has_pnl ? S->phy : NULL,
           "pnl_clients.phy / pnl_client.phy", 0);
        fb(&g, "phy_confirmed", d->pnl.have || (S && S->has_pnl),
           d->pnl.have ? d->pnl.phy_confirmed : S && S->phy_confirmed, "pnl_clients.phy_confirmed", 0);
        fs(&g, "os_fingerprint", d->pnl.have && d->pnl.os_fp[0] ? d->pnl.os_fp : S && S->has_pnl ? S->os_fp : NULL,
           "pnl_clients.os_fp (sloth's label)", 0);
        fs(&g, "assoc_req_bssid", d->ar.have ? d->ar.bssid : S && S->has_ar ? S->ar_bssid : NULL,
           "assoc_reqs.bssid", 0);
        fi(&g, "requested_akm_bits", d->ar.have || (S && S->has_ar),
           d->ar.have ? d->ar.akm_bits : S ? S->akm_bits : 0, "assoc_reqs.akm_bits", 0);
        fi(&g, "requested_pairwise_bits", d->ar.have || (S && S->has_ar),
           d->ar.have ? d->ar.pairwise_bits : S ? S->pairwise_bits : 0, "assoc_reqs.pairwise_bits", 0);
        fi(&g, "requested_mfp", d->ar.have || (S && S->has_ar),
           d->ar.have ? d->ar.mfp : S ? S->requested_mfp : 0, "assoc_reqs.requested_mfp", 0);
        fi(&g, "requested_downgrade_flags", d->ar.have, d->ar.dg, "assoc_reqs.downgrade_flags (ASSOC_DG_*)", 0);
        fi(&g, "prev_akm_bits", d->ar.have, d->ar.prev_akm, "assoc_reqs.prev_akm_bits", 0);
        fi(&g, "supported_rates", d->ar.have || (S && S->has_ar),
           d->ar.have ? d->ar.rates : S ? S->supported_rates : 0, "assoc_reqs.supported_rates", 0);
        fi(&g, "listen_interval", (d->ar.have && d->ar.has_li) || (S && S->has_ar),
           d->ar.have && d->ar.has_li ? d->ar.listen_interval : S ? S->listen_interval : 0,
           "assoc_reqs.listen_interval", 0);
        fi(&g, "capability_info", S && S->has_ar, S ? S->capability_info : 0,
           "wifi_assoc_req.capability_info", ts);
        fs(&g, "assoc_req_phy", d->ar.have ? d->ar.phy : S && S->has_ar ? S->ar_phy : NULL,
           "assoc_reqs.phy", 0);
        fs(&g, "vendor_ie_hash", S && S->has_ar ? S->ar_vie : NULL,
           "wifi_assoc_req.vendor_ie_hash (a fingerprint, not decoded)", ts);
        fi(&g, "link_tx_rate_kbps", d->wsta_have, d->wsta_tx, "wifi_stas.tx_rate_kbps (Local: the "
           "managed card's own station dump)", 0);
        fi(&g, "link_rx_rate_kbps", d->wsta_have, d->wsta_rx, "wifi_stas.rx_rate_kbps (Local)", 0);
        fi(&g, "probe_frames", d->pr.have || (S && S->has_p), d->pr.have ? d->pr.frames : S ? S->frame_count : 0,
           "probe_clients.frame_count (lifetime)", 0);
        fi(&g, "probe_burst_frames", S && S->has_p, S ? S->burst_frames : 0,
           "probe_client.burst_frames", S ? S->ts_p : 0);
        fi(&g, "probe_burst_span_ms", S && S->has_p, S ? S->burst_span_ms : 0,
           "probe_client.burst_span_ms", S ? S->ts_p : 0);
        fi(&g, "preferred_networks", d->pnl.have || d->db[0] == 'o', d->pnl.pnl_n,
           "pnl_ssids (a count: the list is folded, sqlite-schema.md's deanonymisation note)", 0);
        fi(&g, "steering_btm_requests", d->has_btm, d->btm_req, "btm_requests.req_count", 0);
        list_items(&g, "seqnum_trail", &d->seq, "seqnum_correlations (mac_a/mac_b, gap, dt_ms): a "
                   "hypothesis about a radio, never an identification of a person",
                   "mac", NULL, "gap", NULL, 0, 0);
        f_head(&g, "seqnum_confidence");
        if (!S || !S->nseq) web_jw_raw(w, "null");
        else {
            web_jw_raw(w, "[");
            for (int i = 0; i < S->nseq; i++) {
                web_jw_raw(w, i ? ",{\"mac\":" : "{\"mac\":");
                web_jw_str(w, S->seq[i].mac);
                web_jw_raw(w, ",\"confidence\":");
                if (S->seq[i].confidence >= 0) web_jw_int(w, S->seq[i].confidence); else web_jw_raw(w, "null");
                web_jw_raw(w, ",\"fwd_gap\":");
                if (S->seq[i].fwd_gap >= 0) web_jw_int(w, S->seq[i].fwd_gap); else web_jw_raw(w, "null");
                web_jw_raw(w, ",\"window_start\":"); web_jw_int(w, S->seq[i].window_start);
                web_jw_raw(w, ",\"window_end\":");   web_jw_int(w, S->seq[i].window_end);
                web_jw_raw(w, "}");
            }
            web_jw_raw(w, "]");
        }
        f_tail(&g, "seqnum_correlation.confidence (0..90, a ranking, not a probability), .fwd_gap", 0);
        fs(&g, "mld_of", L->has_mld ? L->mld.mac : NULL, "wifi_mld.mld_mac (this address is one of "
           "its links)", L->has_mld ? L->mld.ts_m : 0);
    } else {
        long long ts = bl ? bl->ts : 0;
        static const char *const AT[] = { "public", "random", "resolved identity (public)",
                                          "resolved identity (random)" };
        fs(&g, "addr_type", at >= 0 && at <= 3 ? AT[at] : at == 255 ? "anonymous" : NULL,
           "ble_device.addr_type", 0);
        fs(&g, "heard_by", bl ? bl->iface : NULL, "ble_device.iface", ts);
        fi(&g, "primary_phy", bl && bl->primary_phy, bl ? bl->primary_phy : 0,
           "ble_device.primary_phy (1 LE 1M, 3 Coded S=8, 4 Coded S=2)", ts);
        fi(&g, "secondary_phy", bl && bl->ext_adv, bl ? bl->secondary_phy : 0,
           "ble_device.secondary_phy", ts);
        fb(&g, "extended_advertising", bl != NULL, bl && bl->ext_adv, "ble_device.ext_adv", ts);
        fi(&g, "adv_sid", bl && bl->adv_sid >= 0, bl ? bl->adv_sid : 0, "ble_device.adv_sid", ts);
        fs(&g, "last_pdu", bl ? bl->last_pdu : NULL, "ble_device.last_pdu", ts);
        fi(&g, "pdu_mask", bl != NULL, bl ? bl->pdu_mask : 0, "ble_device.pdu_mask", ts);
        fi(&g, "adv_count", bl != NULL, bl ? bl->adv_count : 0, "ble_device.adv_count", ts);
        fb(&g, "sampled", bl != NULL, bl && bl->sampled, "ble_device.sampled (one channel: a fraction)", ts);
        fnone(&g, "adv_interval_ms", "ble_device (counts, no interval)",
              "sloth emits advertising counts, not an interval (open question Q6)");
        fi(&g, "tx_power_dbm", bl && bl->tx_power != -128, bl ? bl->tx_power : 0,
           "ble_device.tx_power", ts);
        fi(&g, "appearance", bl && bl->appearance >= 0, bl ? bl->appearance : 0, "ble_device.appearance", ts);
        fi(&g, "uuid16", bl && bl->uuid16 >= 0, bl ? bl->uuid16 : 0, "ble_device.uuid16", ts);
        fi(&g, "svc_data_uuid16", bl && bl->svc_data_uuid16 >= 0, bl ? bl->svc_data_uuid16 : 0,
           "ble_device.svc_data_uuid16", ts);
        fi(&g, "mfr_id", bl && bl->mfr_id >= 0, bl ? bl->mfr_id : 0, "ble_device.mfr_id (Company ID)", ts);
        fi(&g, "mfr_subtype", bl && bl->mfr_subtype >= 0, bl ? bl->mfr_subtype : 0,
           "ble_device.mfr_subtype", ts);
        fi(&g, "hid", bl && bl->hid, bl ? bl->hid : 0, "ble_device.hid", ts);
        fi(&g, "ad_flags", bl && bl->flags >= 0, bl ? bl->flags : 0, "ble_device.flags", ts);
        fs(&g, "name", bl ? bl->name : NULL, "ble_device.name", ts);
        fs(&g, "watch_category", bl ? bl->watch : NULL, "ble_device.watch_category (a category, "
           "never an identity)", ts);
        fnone(&g, "rotation_link", "ble_device (no link field)",
              "sloth's rotation hint is an estimate on its own panes, not a field (open question Q6)");
    }
    g_close(&g);

    web_jw_raw(w, ",\"tacdb\":");
    if (f) frrs_tacdb_of(f, kind, addr, w); else web_jw_raw(w, "null");

    /* ── the report: COMINT's seven, from a passive sensor ── */
    web_jw_raw(w, ",\"report\":{");
    g_open(&g, w, "identity", 0);
    fs(&g, "limit", "an address, not a person (mac-randomisation.md)", "slothweb", 0);
    fs(&g, "address", addr, kind == FRRS_K_BLE ? "ble_device.addr + addr_type" : "the emitter's MAC", 0);
    fb(&g, "randomised", 1, d->pnl.have ? d->pnl.mac_random : local,
       d->pnl.have ? "pnl_clients.mac_random" : "the address's U/L bit", 0);
    fs(&g, "vendor", have_oui ? oh.name : d->ap.have ? d->ap.vendor : NULL,
       have_oui ? "the OUI table" : "beacon_aps.vendor (sloth's own label)", 0);
    fs(&g, "hostname", d->dev.host, "devices.hostname", 0);
    list_items(&g, "names_seen", &d->names, "dhcp_leases.hostname, mdns_services.host, "
               "nbns_names.name (by the device's IP)", "name", "source", NULL, NULL, 0, 0);
    fs(&g, "ble_name", kind == FRRS_K_BLE && bl ? bl->name : NULL, "ble_device.name", bl ? bl->ts : 0);
    /* sloth.db's, else the stream's latest beacon (memory only). */
    if (kind == FRRS_K_BSSID) {
        if (d->ap.have && d->ap.ssid[0]) ft(&g, "ssid", d->ap.ssid, "beacon_aps.ssid");
        else fs(&g, "ssid", B && B->has_b ? B->ssid : NULL, "beacon_aps.ssid / beacon.ssid",
                B ? B->ts_b : 0);
    }
    g_close(&g);

    g_open(&g, w, "signal", 1);
    fs(&g, "limit", POSITION_LIMIT, "slothweb", 0);
    if (kind == FRRS_K_BSSID) {
        fi(&g, "rssi_last_dbm", (d->ap.have && d->ap.has_sig) || (B && B->has_b),
           d->ap.have && d->ap.has_sig ? d->ap.signal : B ? B->signal_dbm : 0,
           "beacon_aps.signal_dbm / beacon.signal_dbm", 0);
        fi(&g, "rssi_min_60s", B && B->has_rssi60, B ? B->rssi_min : 0, "beacon.rssi_min_60s", B ? B->ts_b : 0);
        fi(&g, "rssi_max_60s", B && B->has_rssi60, B ? B->rssi_max : 0, "beacon.rssi_max_60s", B ? B->ts_b : 0);
        f_est(&g, B && B->has_b ? &B->est : NULL, "beacon.est_dist_* (rf-distance.md)", B ? B->ts_b : 0);
    } else if (kind == FRRS_K_STA) {
        fi(&g, "rssi_last_dbm", (d->pr.have && d->pr.has_sig) || (S && S->has_p),
           d->pr.have && d->pr.has_sig ? d->pr.signal : S ? S->signal_dbm : 0,
           "probe_clients.signal_dbm / probe_client.signal_dbm", 0);
        f_est(&g, S && S->has_p ? &S->est : NULL, "probe_client.est_dist_* (rf-distance.md)", S ? S->ts_p : 0);
        fi(&g, "card_signal_dbm", d->wsta_have, d->wsta_sig, "wifi_stas.signal_dbm (Local)", 0);
    } else {
        fi(&g, "rssi_last_dbm", bl && bl->has_rssi, bl ? bl->rssi : 0, "ble_device.rssi", bl ? bl->ts : 0);
        fi(&g, "rssi_best_dbm", bl && bl->has_rssi, bl ? bl->rssi_best : 0, "ble_device.rssi_best",
           bl ? bl->ts : 0);
        f_est(&g, bl ? &bl->est : NULL, "ble_device.est_dist_* (rf-distance.md)", bl ? bl->ts : 0);
    }
    fi(&g, "rssi_best_dbm_radios", d->mg.have && d->mg.has_best, d->mg.best_rssi,
       "wifi_merged.best_rssi", 0);
    fi(&g, "radios_heard_it", d->mg.have, d->mg.seen_by, "wifi_merged.seen_by", 0);
    /* A series is not a value: no v, and where to read it. */
    fnone(&g, "series_presence", "slothweb series dev.present (/api/series)",
          "a series, not a value: /api/series?metric=dev.present&key=<this address>");
    if (kind == FRRS_K_BLE)
        fnone(&g, "series_frames", "slothweb series dev.frames (/api/series)",
              "no frame count is kept for a BLE advertiser");
    else
        fnone(&g, "series_frames", "slothweb series dev.frames (/api/series)",
              "a series, not a value: /api/series?metric=dev.frames&key=<this address>");
    fnone(&g, "series_rssi", "dev.rssi (not kept)",
          "RSSI over time is not a series slothweb keeps (open question Q7)");
    g_close(&g);

    g_open(&g, w, "function", 1);
    fs(&g, "limit", "function is the operator's filing or sloth's class; sloth does not infer "
       "organisational function", "slothweb", 0);
    {
        static const char *const CLS[] = { NULL, "camera vendor", "camera", "not a camera" };
        fs(&g, "device_class", d->dev.have && d->dev.cls > 0 && d->dev.cls <= 3 ? CLS[d->dev.cls] : NULL,
           "devices.device_class (DEV_CLASS_*)", 0);
    }
    fb(&g, "is_ap", d->dev.have, d->dev.is_ap, "devices.is_ap", 0);
    fs(&g, "camera_vendor", d->dev.cam, "devices.camera_vendor", 0);
    fi(&g, "ble_appearance", kind == FRRS_K_BLE && bl && bl->appearance >= 0, bl ? bl->appearance : 0,
       "ble_device.appearance", bl ? bl->ts : 0);
    fi(&g, "karma_score", d->karma, d->karma_score, "karma_candidates.score (evidence, not a verdict)", 0);
    fs(&g, "role", kind == FRRS_K_BLE ? "advertiser" : kind == FRRS_K_BSSID ? "AP" : "client",
       "slothweb (the emitter's kind)", 0);
    g_close(&g);

    g_open(&g, w, "timing", 1);
    {
        long long first = 0, last = 0;
        const char *fsrc = NULL, *lsrc = NULL;
        struct { long long f, l; const char *src; } T[] = {
            { d->dev.have ? d->dev.first : 0, d->dev.have ? d->dev.last : 0, "devices" },
            { d->ap.have ? d->ap.first : 0, d->ap.have ? d->ap.last : 0, "beacon_aps" },
            { d->pr.have ? d->pr.first : 0, d->pr.have ? d->pr.last : 0, "probe_clients" },
            { d->pnl.have ? d->pnl.first : 0, d->pnl.have ? d->pnl.last : 0, "pnl_clients" },
            { d->mg.have ? d->mg.first : 0, d->mg.have ? d->mg.last : 0, "wifi_merged" },
            { bl ? bl->first_seen : 0, bl ? bl->last_seen : 0, "ble_device" },
        };
        for (size_t i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
            if (T[i].f > 0 && (!first || T[i].f < first)) { first = T[i].f; fsrc = T[i].src; }
            if (T[i].l > last) { last = T[i].l; lsrc = T[i].src; }
        }
        char fsb[64], lsb[64];
        if (fsrc) snprintf(fsb, sizeof(fsb), "%s.first_seen (the earliest)", fsrc);
        else snprintf(fsb, sizeof(fsb), "first_seen of every table naming it");
        if (lsrc) snprintf(lsb, sizeof(lsb), "%s.last_seen (the latest)", lsrc);
        else snprintf(lsb, sizeof(lsb), "last_seen of every table naming it");
        fi(&g, "first_seen", first > 0, first, fsb, 0);
        fi(&g, "last_seen", last > 0, last, lsb, 0);
    }
    if (kind == FRRS_K_BSSID)
        fi(&g, "beacon_interval_ms", (d->ap.have && d->ap.has_bms) || (B && B->has_b && B->beacon_ms),
           d->ap.have && d->ap.has_bms ? d->ap.beacon_ms : B ? B->beacon_ms : 0,
           "beacon_aps.beacon_ms (the period it transmits on)", 0);
    if (kind == FRRS_K_STA) {
        fi(&g, "probe_burst_frames", S && S->has_p, S ? S->burst_frames : 0, "probe_client.burst_frames",
           S ? S->ts_p : 0);
        fi(&g, "probe_burst_span_ms", S && S->has_p, S ? S->burst_span_ms : 0,
           "probe_client.burst_span_ms", S ? S->ts_p : 0);
    }
    if (kind == FRRS_K_BLE) {
        fi(&g, "adv_count", bl != NULL, bl ? bl->adv_count : 0, "ble_device.adv_count", bl ? bl->ts : 0);
        fnone(&g, "adv_interval_ms", "ble_device (counts, no interval)", "not a field sloth emits (Q6)");
    }
    fs(&g, "presence_strip", "the device drawer's 24 h strip", "slothweb dev.present (/api/device/{mac})", 0);
    g_close(&g);

    g_open(&g, w, "technical", 1);
    fs(&g, "see", "ecs", "this record's EC/S group", 0);
    g_close(&g);

    g_open(&g, w, "protection", 1);
    fs(&g, "limit", CONTENT_LIMIT, "slothweb", 0);
    if (kind == FRRS_K_BSSID) {
        fs(&g, "enc", d->ap.have ? d->ap.enc : B && B->has_b ? B->enc : NULL, "beacon_aps.enc", 0);
        fi(&g, "mfp", d->ap.have && d->ap.has_mfp, d->ap.mfp, "beacon_aps.mfp", 0);
    } else if (kind == FRRS_K_STA) {
        fi(&g, "requested_akm_bits", d->ar.have, d->ar.akm_bits, "assoc_reqs.akm_bits", 0);
        fi(&g, "requested_mfp", d->ar.have, d->ar.mfp, "assoc_reqs.requested_mfp", 0);
    }
    const frrs_ip_t *P = L->has_ip ? &L->ip : NULL;
    fs(&g, "device_ip", ip, "devices.ip / arp.ip", 0);
    fb(&g, "cleartext_http", P != NULL, P && (P->proto & FRRS_P_HTTP), "http (stream, from its IP)",
       P ? P->ts : 0);
    fs(&g, "cleartext_credential_protocols", P ? P->cred_protos : NULL,
       "cleartext_cred.proto (the protocol only, never the username)", P ? P->ts : 0);
    fi(&g, "cleartext_credentials", P != NULL, P ? P->cred_n : 0, "cleartext_cred (a count)", P ? P->ts : 0);
    fb(&g, "smb1", d->smb.read, d->smb1, "smb_sessions.dialect", 0);
    fb(&g, "snmp_v1_v2c", d->snmp.read, d->snmp_v12, "snmp_flows.version (0 v1, 1 v2c)", 0);
    fi(&g, "ldap_anonymous_binds", d->has_ldap, d->ldap_anon, "ldap_events.bind_anon_count", 0);
    fi(&g, "tls_handshakes", P != NULL, P ? P->tls_n : 0, "tls (stream)", P ? P->ts : 0);
    fs(&g, "tls_version", P ? P->tls_ver : NULL, "tls.ver (the latest)", P ? P->ts : 0);
    f_head(&g, "tls_sni");
    if (!P) web_jw_raw(w, "null");
    else {
        web_jw_raw(w, "[");
        for (int i = 0; i < P->nsni; i++) {
            if (i) web_jw_raw(w, ",");
            web_jw_str(w, P->sni[i]);
        }
        web_jw_raw(w, "]");
    }
    f_tail(&g, "tls.host (the last 8 distinct, cut to 64 bytes)", P ? P->ts : 0);
    fi(&g, "quic", P != NULL, P ? P->quic_n : 0, "quic (stream)", P ? P->ts : 0);
    g_close(&g);

    g_open(&g, w, "peers", 1);
    fs(&g, "limit", "peers are addresses sloth saw frames between; sloth reads no message body",
       "slothweb", 0);
    if (kind == FRRS_K_BSSID)
        list_items(&g, "associated_stations", &d->clients, "assocs.sta_mac (signal_dbm is the AP's)",
                   "sta", "ssid", "channel", "signal_dbm", 0, 1);
    else if (kind == FRRS_K_STA)
        list_items(&g, "associated_bssids", &d->assocs, "assocs.bssid, .ssid, .channel, .signal_dbm",
                   "bssid", "ssid", "channel", "signal_dbm", 0, 1);
    list_items(&g, "arp_ips", &d->arp, "arp.ip", "ip", NULL, NULL, NULL, 0, 0);
    fi(&g, "dns_queries", P != NULL, P ? P->dns_n : 0, "dns (stream, counted per client IP)", P ? P->ts : 0);
    fnone(&g, "dns_names", "dns.qname (slothweb keeps hashes)",
          "slothweb keeps query-name hashes per client, not names (open question Q8)");
    list_items(&g, "smb_servers", &d->smb, "smb_sessions.server_ip, .dialect", "ip", "dialect", NULL,
               NULL, 0, 0);
    list_items(&g, "ssh_servers", &d->ssh, "ssh_flows.dst_ip", "ip", NULL, "banners", NULL, 0, 0);
    list_items(&g, "snmp_agents", &d->snmp, "snmp_flows.dst_ip, .version", "ip", NULL, "version", NULL,
               0, 0);
    if (kind == FRRS_K_BLE)
        fnone(&g, "ble_connection_attempts", "ble_device (none per peer)",
              "btcap_connect_ind is a sensor total; per-peer attempts are not a field sloth emits");
    g_close(&g);
    web_jw_raw(w, "}");

    /* The alerts naming it, for the page's triage chips. */
    web_jw_raw(w, ",\"alerts\":[");
    for (int i = 0; i < nsf + d->alerts.n; i++) {
        web_jw_raw(w, i ? ",{\"id\":" : "{\"id\":");
        char id[40];
        if (i < nsf) snprintf(id, sizeof(id), "%s", sf[i].id);
        else snprintf(id, sizeof(id), "d%lld", d->alerts.it[i - nsf].rid);
        web_jw_str(w, id);
        int type = i < nsf ? sf[i].type : (int)d->alerts.it[i - nsf].n1;
        const web_akb_t *kb = web_akb_get(type);
        web_jw_raw(w, ",\"type\":");
        frrs_str_or_null(w, kb ? kb->name : NULL);
        web_jw_raw(w, ",\"source\":");
        web_jw_str(w, i < nsf ? "stream" : "sloth.db");
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "]}");
    free(d);
    free(L);
    free(sf);
}
