/* Anomaly triage's subjects and the links between findings (web_frrs.h,
 * owner request 2026-11-11).
 *
 * An anomaly is triaged through the alert's own rows and routes
 * (web_frrs.c): this file only says what an anomaly's id names. The id
 * is a hash (web_anomaly_tid()), so the store keeps the rule, metric
 * and key it was first seen to stand for (anom_subject), and an id
 * whose episode in the engine is not that descriptor is refused, never
 * joined to the other's notes.
 *
 * A link is the operator's: from an anomaly to an alert, another
 * anomaly, a device or a BLE advertiser, or from an alert to a device
 * or a BLE advertiser (owner ruling 2026-11-11); never alert to alert
 * or device to device, which nothing on the page lists. Read from both
 * ends, removed by its number. Both ends are resolved against what
 * exists before a row is written (an alert by the alert routes' own
 * resolution, an anomaly in the engine or already in the store, a
 * device sloth.db, the stream or the ledger holds, a BLE advertiser
 * the ledger holds), and each end's label is slothweb's own words, kept
 * so that a
 * link whose end has aged out of sloth.db or the engine still says what
 * it pointed at ("held": false; the page says "no longer held").
 *
 * A BLE advertiser is named as the TACDB names one, its address and
 * address type ("aa:bb:cc:dd:ee:ff/1", frrs_addr_canon()): the page's
 * row is that and the sensor that heard it, and one advertiser two
 * sensors hear is one end. That is all the identity an advertiser has.
 * A resolvable or non-resolvable private address rotates, and the link
 * then names an address nothing advertises: "held" false once the
 * ledger (memory, refilled from the stream) has let it go, as any other
 * end. The anonymous address (type 255) names no one advertiser and is
 * refused. No name of it is stored: the label is empty, the id is what
 * is shown.
 *
 * A candidate is never stored. Two findings are offered as possibly
 * related when they are about the same MAC or the same IP address and
 * their spans overlap or lie within WEB_REL_WINDOW_S of each other; the
 * operator accepts one with the same POST that makes any link. An
 * anomaly's key is a MAC or an address for every rule that names a
 * device (A2-A9, and A1 on a device or host series); no rule is keyed
 * by an SSID, and a BSSID is a MAC, so those are the two subjects there
 * are. The wording is a fact about the two rows and nothing more: a
 * passive sensor corroborates, it does not confirm.
 *
 * Reads of sloth.db go through the M4 reader (web_slothdb.h) on one
 * connection per request, under the request's budget; every statement
 * on slothweb.db binds its values. */
#include "web_frrs_int.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_alertdb.h"
#include "web_alertkb.h"
#include "web_series.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

/* relation.a_kind / b_kind: appended only, the stored values stand. */
enum { REF_ALERT = 0, REF_ANOM, REF_DEVICE, REF_BLE, REF_COUNT };
static const char *const REF_WORD[REF_COUNT] = { "alert", "anomaly", "device", "ble" };
#define REF_ID_MAX 47

static const char NOT_ESTABLISHED[] =
    "possibly related, not established: these share a subject and a time; "
    "a passive sensor corroborates, it does not confirm";

/* One end of a link, or the finding a request asks about. */
typedef struct {
    int        kind;
    char       id[REF_ID_MAX + 1];      /* as a link stores it */
    char       alt[40];                 /* an alert's stream handle, or "" */
    char       label[WEB_REL_LABEL_MAX + 1];
    int        held;
    char       key[WEB_KEY_MAX + 1];    /* the MAC or address it is about, or "" */
    long long  first, last;
    int        has_subj;                /* subj is its triage subject */
    tri_subj_t subj;
    frrs_anom_t an;
    char       iface[24];               /* a held BLE advertiser's sensor, or "" */
} ref_t;

/* ── an anomaly's id ───────────────────────────────────────────────── */

int frrs_anom_id_ok(const char *id) {
    if (!id || id[0] != 'a' || strlen(id) != WEB_ANOM_TID_MAX) return 0;
    for (const char *p = id + 1; *p; p++)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return 0;
    return 1;
}

static int rule_index(const char *name) {
    for (int i = 0; i < WEB_ANOM_RULE_COUNT; i++)
        if (!strcmp(web_anomaly_rule(i), name)) return i;
    return -1;
}

#ifdef WITH_SQLITE
static void col_text(sqlite3_stmt *s, int i, char *out, size_t cap) {
    const unsigned char *t = sqlite3_column_text(s, i);
    web_utf8_copy(out, cap - 1, t ? (const char *)t : "");
}

static long long count_of(web_frrs_t *f, const char *sql) {
    sqlite3_stmt *s = NULL;
    long long n = -1;
    if (sqlite3_prepare_v2(f->wr, sql, -1, &s, NULL) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW)
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

/* The stored descriptor of id: 1 into a, 0 none, -1. */
static int anom_stored(web_frrs_t *f, const char *id, frrs_anom_t *a) {
    if (!f || !f->wr) return 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(f->wr, "SELECT rule, metric, key FROM anom_subject WHERE subject = ?1",
                           -1, &s, NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        return -1;
    }
    sqlite3_bind_text(s, 1, id, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s), got = 0;
    if (rc == SQLITE_ROW) {
        col_text(s, 0, a->rule, sizeof(a->rule));
        col_text(s, 1, a->metric, sizeof(a->metric));
        col_text(s, 2, a->key, sizeof(a->key));
        got = 1;
    }
    sqlite3_finalize(s);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? got : -1;
}

int frrs_anom_register(web_frrs_t *f, const frrs_anom_t *a, long long now_s, const char **why) {
    frrs_anom_t have;
    memset(&have, 0, sizeof(have));
    int st = anom_stored(f, a->id, &have);
    if (st < 0) { *why = "store_error"; return -1; }
    if (st > 0) return 0;
    long long n = count_of(f, "SELECT COUNT(*) FROM anom_subject");
    if (n < 0) { *why = "store_error"; return -1; }
    if (n >= WEB_FRRS_ANOM_SUBJECTS) { *why = "anomaly_subjects_full"; return 1; }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(f->wr, "INSERT INTO anom_subject (subject, rule, metric, key, ts)"
                           " VALUES (?1, ?2, ?3, ?4, ?5)", -1, &s, NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        *why = "store_error";
        return -1;
    }
    sqlite3_bind_text(s, 1, a->id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, a->rule, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, a->metric, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, a->key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 5, now_s);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) { *why = "store_error"; return -1; }
    return 0;
}
#else
static int anom_stored(web_frrs_t *f, const char *id, frrs_anom_t *a) {
    (void)f; (void)id; (void)a;
    return 0;
}
int frrs_anom_register(web_frrs_t *f, const frrs_anom_t *a, long long now_s, const char **why) {
    (void)f; (void)a; (void)now_s;
    *why = "no_store";
    return -1;
}
#endif

int frrs_anom_resolve(const web_m4_t *m, const char *id, frrs_anom_t *a) {
    memset(a, 0, sizeof(*a));
    if (!frrs_anom_id_ok(id)) return 0;
    web_anom_ep_t *e = calloc(1, sizeof(*e));
    if (!e) return -1;
    int live = m && m->anomaly && web_anomaly_tid_find(m->anomaly, id, e);
    frrs_anom_t st;
    memset(&st, 0, sizeof(st));
    int stored = anom_stored(m ? m->frrs : NULL, id, &st);
    if (stored < 0) { free(e); return -1; }
    /* A stored rule this build does not have names nothing it can show. */
    if (stored > 0 && rule_index(st.rule) < 0) stored = 0;
    snprintf(a->id, sizeof(a->id), "%s", id);
    if (live) {
        snprintf(a->rule, sizeof(a->rule), "%s", web_anomaly_rule(e->rule));
        snprintf(a->metric, sizeof(a->metric), "%s",
                 e->metric >= 0 && e->metric < WM_COUNT ? web_metric_defs[e->metric].name : "");
        snprintf(a->key, sizeof(a->key), "%s", e->key);
        a->held = 1;
        a->open = e->state == WEB_EP_OPEN;
        a->first = e->first_seen;
        a->last = e->last_seen;
        free(e);
        /* The id is a hash: what the store filed under it must be what
         * the engine holds under it, or the notes are another's. */
        if (stored > 0 && (strcmp(st.rule, a->rule) || strcmp(st.metric, a->metric) ||
                           strcmp(st.key, a->key)))
            return -2;
        return 1;
    }
    free(e);
    if (stored <= 0) return 0;
    memcpy(a->rule, st.rule, sizeof(a->rule));
    memcpy(a->metric, st.metric, sizeof(a->metric));
    memcpy(a->key, st.key, sizeof(a->key));
    return 1;
}

void frrs_anom_subj(const frrs_anom_t *a, tri_subj_t *s) {
    memset(s, 0, sizeof(*s));
    snprintf(s->subject, sizeof(s->subject), "%s", a->id);
    snprintf(s->addr, sizeof(s->addr), "%s", a->id);
    s->type = -1;
    s->first = a->held ? a->first : 0;
    s->anom = 1;
}

void frrs_anom_json(web_jw_t *w, const frrs_anom_t *a) {
    int ri = rule_index(a->rule);
    web_jw_raw(w, "{\"rule\":");      web_jw_str(w, a->rule);
    web_jw_raw(w, ",\"kind\":");      web_jw_str(w, ri >= 0 ? web_anomaly_kind(ri) : "?");
    web_jw_raw(w, ",\"metric\":");    frrs_str_or_null(w, a->metric);
    web_jw_raw(w, ",\"key\":");       web_jw_str(w, a->key);
    web_jw_raw(w, ",\"held\":");      web_jw_raw(w, a->held ? "true" : "false");
    web_jw_raw(w, ",\"open\":");      web_jw_raw(w, a->open ? "true" : "false");
    web_jw_raw(w, ",\"first_seen\":");
    if (a->held) web_jw_int(w, a->first); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"last_seen\":");
    if (a->held) web_jw_int(w, a->last); else web_jw_raw(w, "null");
    web_jw_raw(w, "}");
}

/* ── one end resolved ──────────────────────────────────────────────── */

static void anom_label(const frrs_anom_t *a, char *out, size_t cap) {
    int ri = rule_index(a->rule);
    snprintf(out, cap, "%s %s %s", a->rule, ri >= 0 ? web_anomaly_kind(ri) : "?",
             a->key[0] ? a->key : "(sensor)");
}

/* Is mac a device anything here holds: an anomaly keyed by it, sloth's
 * latest pass, the ledger, or sloth.db's devices. */
static int device_held(const web_m4_t *m, web_live_t *live, web_sdb_conn_t *c, const char *mac) {
    if (m->anomaly && web_anomaly_key_count(m->anomaly, mac, -1) > 0) return 1;
    if (live && web_live_pass_has(live, mac)) return 1;
    web_frrs_t *f = m->frrs;
    if (f && f->lmu_init) {
        pthread_mutex_lock(&f->lmu);
        int led = frrs_led_sta(f, mac) != NULL || frrs_led_bss(f, mac) != NULL;
        pthread_mutex_unlock(&f->lmu);
        if (led) return 1;
    }
    if (!c) return 0;
    web_sdb_dev_t *d = calloc(1, sizeof(*d));
    if (!d) return 0;
    int r = web_sdb_device(c, mac, d);
    free(d);
    return r > 0;
}

/* Does the ledger hold a row of the BLE address id ("addr/type")? The
 * sensor of the first into iface, when it is one of sloth's two words. */
static int ble_held(const web_m4_t *m, const char *id, char *iface, size_t cap) {
    web_frrs_t *f = m->frrs;
    iface[0] = '\0';
    if (!f || !f->lmu_init) return 0;
    char addr[18];
    memcpy(addr, id, 17);
    addr[17] = '\0';
    const frrs_ble_t *row = NULL;
    pthread_mutex_lock(&f->lmu);
    int n = frrs_led_ble(f, addr, atoi(id + 18), &row, 1);
    if (n > 0 && web_ble_iface_find(row->iface) != WEB_BLE_IF_OTHER) snprintf(iface, cap, "%s", row->iface);
    pthread_mutex_unlock(&f->lmu);
    return n > 0;
}

/* text as a request or a stored link names a finding: an anomaly's id,
 * an alert's, a MAC, or a BLE address with its type. 1 held (or, an anomaly, known to the store), 0
 * its shape is one of ours and nothing holds it (kind and id still
 * set, from the text), -1 a read failed, -2 an anomaly id collision,
 * -3 no shape of ours. */
static int resolve_ref(const web_m4_t *m, web_live_t *live, web_sdb_conn_t *c,
                       const char *text, long long now_s, ref_t *r) {
    memset(r, 0, sizeof(*r));
    if (!text || !text[0] || strlen(text) > REF_ID_MAX) return -3;
    if (frrs_anom_id_ok(text)) {
        r->kind = REF_ANOM;
        snprintf(r->id, sizeof(r->id), "%s", text);
        int g = frrs_anom_resolve(m, text, &r->an);
        if (g < 0) return g;
        if (g == 0) return 0;
        anom_label(&r->an, r->label, sizeof(r->label));
        r->held = r->an.held;
        char k[WEB_KEY_MAX + 1];
        if (web_key_mac(r->an.key, k) == 0 || web_key_ip(r->an.key, k) == 0)
            snprintf(r->key, sizeof(r->key), "%s", k);
        r->first = r->an.first;
        r->last = r->an.last;
        frrs_anom_subj(&r->an, &r->subj);
        r->has_subj = 1;
        return 1;
    }
    /* An alert's id is all alphanumeric; a MAC or a BLE address whose
     * first hex digit is d holds colons, and is looked at below. */
    int alert_shape = text[0] == 's' || text[0] == 'd';
    for (const char *p = text + 1; *p && alert_shape; p++)
        if (!isalnum((unsigned char)*p)) alert_shape = 0;
    if (alert_shape) {
        if (strlen(text) < 2 || strlen(text) > 25) return -3;
        r->kind = REF_ALERT;
        snprintf(r->id, sizeof(r->id), "%s", text);
        long long last = 0;
        int g = frrs_resolve_alert(m, live, c, text, now_s, &r->subj, &last);
        if (g < 0) return -1;
        if (g == 0) return 0;
        snprintf(r->id, sizeof(r->id), "%s", r->subj.subject);
        snprintf(r->alt, sizeof(r->alt), "%s", r->subj.alt);
        /* What it is about: the descriptor's address, else (a Wi-Fi
         * finding named by its stream handle carries none) the MAC
         * sloth.db's row of it names. Never the key's text. */
        char about[WEB_FRRS_ADDR_MAX + 1], mac[18];
        snprintf(about, sizeof(about), "%s", r->subj.addr);
        if (!about[0] && c && r->subj.finding > 0 &&
            web_adb_device(c, r->subj.finding, NULL, NULL, mac) > 0)
            snprintf(about, sizeof(about), "%s", mac);
        const web_akb_t *k = web_akb_get(r->subj.type);
        snprintf(r->label, sizeof(r->label), "%s%s%s", k && k->name ? k->name : "alert",
                 about[0] ? " " : "", about);
        snprintf(r->key, sizeof(r->key), "%s", about);
        r->first = r->subj.first;
        r->last = last > r->first ? last : r->first;
        r->held = r->has_subj = 1;
        return 1;
    }
    if (strlen(text) > 17 && text[17] == '/') {
        /* Not the anonymous address: it is every anonymous advertiser. */
        char canon[24];
        if (frrs_addr_canon(FRRS_K_BLE, text, canon, sizeof(canon)) != 0 || !strcmp(canon + 18, "255"))
            return -3;
        r->kind = REF_BLE;
        snprintf(r->id, sizeof(r->id), "%s", canon);
        r->held = ble_held(m, canon, r->iface, sizeof(r->iface));
        return r->held;
    }
    char mac[WEB_KEY_MAX + 1];
    if (strlen(text) != 17 || web_dev_canon_mac(text, mac) != 0) return -3;
    r->kind = REF_DEVICE;
    snprintf(r->id, sizeof(r->id), "%s", mac);
    snprintf(r->key, sizeof(r->key), "%s", mac);
    r->held = device_held(m, live, c, mac);
    return r->held;
}

/* ── the links of one finding ──────────────────────────────────────── */

typedef struct {
    long long link, ts;
    int       from;                     /* the finding asked about is its "from" end */
    int       kind;
    char      id[REF_ID_MAX + 1];
    char      label[WEB_REL_LABEL_MAX + 1];
    char      note[WEB_FRRS_NOTE_MAX + 1];
    char      by[WEB_FRRS_BY_MAX + 1];
    char      peer[WEB_PEER_MAX];
} link_t;

#ifdef WITH_SQLITE
/* Either end is ?1 kind and ?2 (or ?3, an alert's other name) id. */
#define END_IS(k, i) "(" k " = ?1 AND (" i " = ?2 OR (?3 <> '' AND " i " = ?3)))"

static int links_of(web_frrs_t *f, const ref_t *r, link_t *out, int max, int *more) {
    *more = 0;
    if (!f || !f->wr) return 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(f->wr,
            "SELECT id, a_kind, a_id, a_label, b_kind, b_id, b_label, note, who, peer, ts,"
            " " END_IS("a_kind", "a_id") " FROM relation WHERE " END_IS("a_kind", "a_id")
            " OR " END_IS("b_kind", "b_id") " ORDER BY id DESC LIMIT ?4", -1, &s, NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        return -1;
    }
    sqlite3_bind_int(s, 1, r->kind);
    sqlite3_bind_text(s, 2, r->id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, r->alt, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 4, max + 1);
    int n = 0, rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        if (n == max) { *more = 1; continue; }
        link_t *l = &out[n++];
        memset(l, 0, sizeof(*l));
        l->link = sqlite3_column_int64(s, 0);
        l->from = sqlite3_column_int(s, 11);
        int o = l->from ? 4 : 1;         /* the other end's columns */
        l->kind = sqlite3_column_int(s, o);
        col_text(s, o + 1, l->id, sizeof(l->id));
        col_text(s, o + 2, l->label, sizeof(l->label));
        col_text(s, 7, l->note, sizeof(l->note));
        col_text(s, 8, l->by, sizeof(l->by));
        col_text(s, 9, l->peer, sizeof(l->peer));
        l->ts = sqlite3_column_int64(s, 10);
    }
    sqlite3_finalize(s);
    return rc == SQLITE_DONE ? n : -1;
}
#else
static int links_of(web_frrs_t *f, const ref_t *r, link_t *out, int max, int *more) {
    (void)f; (void)r; (void)out; (void)max;
    *more = 0;
    return 0;
}
#endif

/* ── candidates ────────────────────────────────────────────────────── */

typedef struct {
    int       kind;
    char      id[REF_ID_MAX + 1];
    char      label[WEB_REL_LABEL_MAX + 1];
    long long first, last;
    int       overlap;
} cand_t;

/* Two spans that overlap, or lie within the window of each other. */
static int near_spans(long long a1, long long a2, long long b1, long long b2) {
    if (a2 < a1) a2 = a1;
    if (b2 < b1) b2 = b1;
    return a1 <= b2 + WEB_REL_WINDOW_S && b1 <= a2 + WEB_REL_WINDOW_S;
}

static int is_linked(const link_t *ln, int nl, int kind, const char *id, const char *alt) {
    for (int i = 0; i < nl; i++)
        if (ln[i].kind == kind && (!strcmp(ln[i].id, id) || (alt && alt[0] && !strcmp(ln[i].id, alt))))
            return 1;
    return 0;
}

static int cand_has(const cand_t *cs, int n, int kind, const char *id) {
    for (int i = 0; i < n; i++) if (cs[i].kind == kind && !strcmp(cs[i].id, id)) return 1;
    return 0;
}

static void cand_add(cand_t *cs, int *n, int kind, const char *id, const char *label,
                     long long first, long long last, const ref_t *of) {
    if (*n >= WEB_REL_SUGGEST) return;
    cand_t *c = &cs[(*n)++];
    memset(c, 0, sizeof(*c));
    c->kind = kind;
    snprintf(c->id, sizeof(c->id), "%s", id);
    snprintf(c->label, sizeof(c->label), "%s", label);
    c->first = first;
    c->last = last > first ? last : first;
    c->overlap = of->first <= c->last && c->first <= (of->last > of->first ? of->last : of->first);
}

/* The engine's other episodes on r's subject, near r's span. */
static void cand_anomalies(const web_m4_t *m, const ref_t *r, const link_t *ln, int nl,
                           cand_t *cs, int *n) {
    if (!m->anomaly) return;
    enum { EPS = 32 };
    web_anom_ep_t *eps = calloc(EPS, sizeof(*eps));
    if (!eps) return;
    int ne = web_anomaly_key_list(m->anomaly, r->key, eps, EPS);
    for (int i = 0; i < ne; i++) {
        char tid[WEB_ANOM_TID_MAX + 1];
        web_anomaly_tid(eps[i].rule, eps[i].metric, eps[i].key, tid);
        if (r->kind == REF_ANOM && !strcmp(tid, r->id)) continue;
        if (!near_spans(r->first, r->last, eps[i].first_seen, eps[i].last_seen)) continue;
        if (is_linked(ln, nl, REF_ANOM, tid, NULL) || cand_has(cs, *n, REF_ANOM, tid)) continue;
        frrs_anom_t a;
        memset(&a, 0, sizeof(a));
        snprintf(a.rule, sizeof(a.rule), "%s", web_anomaly_rule(eps[i].rule));
        snprintf(a.key, sizeof(a.key), "%s", eps[i].key);
        char label[WEB_REL_LABEL_MAX + 1];
        anom_label(&a, label, sizeof(label));
        cand_add(cs, n, REF_ANOM, tid, label, eps[i].first_seen, eps[i].last_seen, r);
    }
    free(eps);
}

typedef struct {
    const ref_t *r;
    int          n;
    struct { long long rid, first, last; } it[WEB_REL_ALERT_SCAN];
} scan_t;

static int scan_item(void *ctx, const web_sdb_item_t *it) {
    scan_t *x = ctx;
    if (x->n < WEB_REL_ALERT_SCAN &&
        near_spans(x->r->first, x->r->last, it->first_seen, it->last_seen)) {
        x->it[x->n].rid = it->rid;
        x->it[x->n].first = it->first_seen;
        x->it[x->n].last = it->last_seen;
        x->n++;
    }
    return 0;
}

/* One alert id offered: resolved to its finding, so the stream's and
 * sloth.db's names of one finding are one candidate, and one already
 * linked is not offered again. */
static void cand_alert(const web_m4_t *m, web_live_t *live, web_sdb_conn_t *c, const char *id,
                       long long first, long long last, long long now_s, const ref_t *r,
                       const link_t *ln, int nl, cand_t *cs, int *n) {
    ref_t *o = calloc(1, sizeof(*o));
    if (!o) return;
    if (resolve_ref(m, live, c, id, now_s, o) == 1 && !is_linked(ln, nl, REF_ALERT, o->id, o->alt) &&
        !cand_has(cs, *n, REF_ALERT, o->id))
        cand_add(cs, n, REF_ALERT, o->id, o->label, first, last, r);
    free(o);
}

/* The alerts on an anomaly's subject near its span: the stream's
 * incidents, then sloth.db's newest WEB_REL_ALERT_SCAN naming it (the
 * walk stops inside the request's budget, web_sdb_alerts(); *reached
 * then says how far back it read). */
static void cand_alerts(const web_m4_t *m, web_live_t *live, web_sdb_conn_t *c, long long now_s,
                        const ref_t *r, int is_mac, const link_t *ln, int nl, cand_t *cs,
                        int *n, long long *reached) {
    if (live) {
        web_live_inc_t *all = calloc(WEB_LIVE_INCIDENTS + WEB_LIVE_CLOSED, sizeof(*all));
        int na = all ? web_live_incidents(live, all, WEB_LIVE_INCIDENTS + WEB_LIVE_CLOSED, NULL) : 0;
        for (int i = 0; i < na && *n < WEB_REL_SUGGEST; i++) {
            char k[WEB_KEY_MAX + 1], mac[18];
            int same = is_mac ? frrs_mac_in(all[i].key, mac) && !strcmp(mac, r->key)
                              : all[i].match_ip[0] && web_key_ip(all[i].match_ip, k) == 0 &&
                                !strcmp(k, r->key);
            if (!same || !near_spans(r->first, r->last, all[i].first_ts, all[i].last_ts)) continue;
            char id[REF_ID_MAX + 1];
            snprintf(id, sizeof(id), "s%s", all[i].hid);
            cand_alert(m, live, c, id, all[i].first_ts, all[i].last_ts, now_s, r, ln, nl, cs, n);
        }
        free(all);
    }
    if (!c) return;
    scan_t *x = calloc(1, sizeof(*x));
    if (!x) return;
    x->r = r;
    if (web_sdb_alerts(c, is_mac ? r->key : NULL, is_mac ? NULL : r->key, WEB_REL_ALERT_SCAN,
                       scan_item, x, reached) >= 0)
        for (int i = 0; i < x->n && *n < WEB_REL_SUGGEST; i++) {
            char id[REF_ID_MAX + 1];
            snprintf(id, sizeof(id), "d%lld", x->it[i].rid);
            cand_alert(m, live, c, id, x->it[i].first, x->it[i].last, now_s, r, ln, nl, cs, n);
        }
    free(x);
}

/* ── the answer ────────────────────────────────────────────────────── */

static void triage_of(web_frrs_t *f, const ref_t *o, web_jw_t *w) {
    web_tri_t t;
    web_jw_raw(w, ",\"triage\":");
    if (o->has_subj && frrs_tri_current(f, &o->subj, &t) > 0) frrs_tri_json(w, &t, 1);
    else web_jw_raw(w, "null");
}

/* {"id":..,"kind":..,...}: r, its links and its candidates, one object
 * into w (cap: the buffer's, so a list stops before it cannot fit). */
static void related_json(const web_m4_t *m, web_live_t *live, web_sdb_conn_t *c, const ref_t *r,
                         long long now_s, web_jw_t *w, size_t cap) {
    web_frrs_t *f = m->frrs;
    link_t *ln = calloc(WEB_REL_PER, sizeof(*ln));
    cand_t *cs = calloc(WEB_REL_SUGGEST, sizeof(*cs));
    ref_t *o = calloc(1, sizeof(*o));
    int more = 0, nl = ln && cs && o ? links_of(f, r, ln, WEB_REL_PER, &more) : -1;
    web_jw_raw(w, "{\"id\":");       web_jw_str(w, r->id);
    web_jw_raw(w, ",\"kind\":");     web_jw_str(w, REF_WORD[r->kind]);
    web_jw_raw(w, ",\"label\":");    web_jw_str(w, r->label);
    web_jw_raw(w, ",\"held\":");     web_jw_raw(w, r->held ? "true" : "false");
    web_jw_raw(w, ",\"store\":");    web_jw_str(w, f && f->wr ? "open" : "none");
    web_jw_raw(w, ",\"writes\":");   web_jw_raw(w, f && f->wr && f->writes ? "true" : "false");
    web_jw_raw(w, ",\"window_s\":"); web_jw_int(w, WEB_REL_WINDOW_S);
    web_jw_raw(w, ",\"links_cap\":"); web_jw_int(w, WEB_REL_PER);
    web_jw_raw(w, ",\"links\":[");
    int shown = 0;
    for (int i = 0; i < nl; i++) {
        if (w->len + 8192 >= cap) { more = 1; break; }
        const link_t *l = &ln[i];
        /* The other end as it is now: held, or gone from sloth.db or
         * the engine, when the label kept with the link is what is
         * left of it. */
        int g = l->kind >= 0 && l->kind < REF_COUNT ? resolve_ref(m, live, c, l->id, now_s, o) : -3;
        int held = g == 1 && o->held && o->kind == l->kind;
        web_jw_raw(w, shown++ ? ",{\"link\":" : "{\"link\":");
        web_jw_int(w, l->link);
        web_jw_raw(w, ",\"dir\":");   web_jw_str(w, l->from ? "to" : "from");
        web_jw_raw(w, ",\"kind\":");
        web_jw_str(w, l->kind >= 0 && l->kind < REF_COUNT ? REF_WORD[l->kind] : "?");
        web_jw_raw(w, ",\"id\":");    web_jw_str(w, l->id);
        web_jw_raw(w, ",\"label\":"); web_jw_str(w, held && o->label[0] ? o->label : l->label);
        web_jw_raw(w, ",\"held\":");  web_jw_raw(w, held ? "true" : "false");
        web_jw_raw(w, ",\"note\":");  web_jw_str(w, l->note);
        web_jw_raw(w, ",\"by\":");    web_jw_str(w, l->by);
        web_jw_raw(w, ",\"peer\":");  web_jw_str(w, l->peer);
        web_jw_raw(w, ",\"ts\":");    web_jw_int(w, l->ts);
        /* A held BLE advertiser's sensor: what its drawer is opened by. */
        if (held && o->kind == REF_BLE && o->iface[0]) {
            web_jw_raw(w, ",\"iface\":");
            web_jw_str(w, o->iface);
        }
        if (g == 1) triage_of(f, o, w);
        else web_jw_raw(w, ",\"triage\":null");
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"links_more\":");
    web_jw_raw(w, more ? "true" : "false");
    /* Candidates: only for a finding held now and about a MAC or an
     * address. Never stored: the operator's POST is what makes a link. */
    int nc = 0;
    long long reached = 0;
    char k[WEB_KEY_MAX + 1];
    int is_mac = r->key[0] && web_key_mac(r->key, k) == 0;
    if (nl >= 0 && r->held && r->key[0] && (r->kind == REF_ANOM || r->kind == REF_ALERT)) {
        cand_anomalies(m, r, ln, nl, cs, &nc);
        if (r->kind == REF_ANOM)
            cand_alerts(m, live, c, now_s, r, is_mac, ln, nl, cs, &nc, &reached);
    }
    web_jw_raw(w, ",\"suggest\":[");
    for (int i = 0; i < nc; i++) {
        char basis[96];
        if (cs[i].overlap)
            snprintf(basis, sizeof(basis), "same %s, overlapping in time", is_mac ? "device" : "address");
        else
            snprintf(basis, sizeof(basis), "same %s, within %d minutes", is_mac ? "device" : "address",
                     WEB_REL_WINDOW_S / 60);
        web_jw_raw(w, i ? ",{\"kind\":" : "{\"kind\":");
        web_jw_str(w, REF_WORD[cs[i].kind]);
        web_jw_raw(w, ",\"id\":");         web_jw_str(w, cs[i].id);
        web_jw_raw(w, ",\"label\":");      web_jw_str(w, cs[i].label);
        web_jw_raw(w, ",\"basis\":");      web_jw_str(w, basis);
        web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, cs[i].first);
        web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, cs[i].last);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"suggest_note\":");
    web_jw_str(w, NOT_ESTABLISHED);
    /* How far back sloth.db's alerts were read for them, when the
     * budget stopped the walk; null when it read them all. */
    web_jw_raw(w, ",\"alerts_reached\":");
    if (reached > 0) web_jw_int(w, reached); else web_jw_raw(w, "null");
    /* A device's own anomalies, each with its triage: what the drawer's
     * cards show, in one read (the evidence bundle's). */
    if (r->kind == REF_DEVICE) {
        enum { EPS = 8 };
        web_anom_ep_t *eps = m->anomaly ? calloc(EPS, sizeof(*eps)) : NULL;
        int ne = eps ? web_anomaly_key_list(m->anomaly, r->id, eps, EPS) : 0;
        web_jw_raw(w, ",\"anomalies\":[");
        for (int i = 0, n = 0; i < ne && o && w->len + 8192 < cap; i++) {
            char tid[WEB_ANOM_TID_MAX + 1];
            web_anomaly_tid(eps[i].rule, eps[i].metric, eps[i].key, tid);
            int dup = 0;
            for (int j = 0; j < i && !dup; j++) {
                char t2[WEB_ANOM_TID_MAX + 1];
                web_anomaly_tid(eps[j].rule, eps[j].metric, eps[j].key, t2);
                dup = !strcmp(t2, tid);
            }
            if (dup || resolve_ref(m, live, c, tid, now_s, o) != 1) continue;
            web_jw_raw(w, n++ ? ",{\"id\":" : "{\"id\":");
            web_jw_str(w, tid);
            web_jw_raw(w, ",\"label\":");   web_jw_str(w, o->label);
            web_jw_raw(w, ",\"anomaly\":"); frrs_anom_json(w, &o->an);
            triage_of(f, o, w);
            web_jw_raw(w, "}");
        }
        web_jw_raw(w, "]");
        free(eps);
    }
    web_jw_raw(w, "}");
    free(ln);
    free(cs);
    free(o);
}

static int open_sdb(const web_m4_t *m, web_sdb_conn_t *c, long long now_s) {
    char err[200];
    return m->sdb && m->sdb->configured &&
           web_slothdb_open(m->sdb, c, WEB_SDB_HTTP_MS, now_s, err, sizeof(err)) == 0;
}

int frrs_related_get(const web_m4_t *m, web_live_t *live, const char *query, long long now_s,
                     char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[1] = { { "id", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen) return frrs_error(400, "missing_id", NULL, body, cap, len, status);
    ref_t *r = calloc(1, sizeof(*r));
    if (!r) return -1;
    web_sdb_conn_t c;
    int have_c = open_sdb(m, &c, now_s);
    int g = resolve_ref(m, live, have_c ? &c : NULL, ps[0].val, now_s, r);
    int rc;
    if (g == -3) rc = frrs_error(400, "bad_id", NULL, body, cap, len, status);
    else if (g == -2) rc = frrs_error(409, "id_collision", NULL, body, cap, len, status);
    else if (g == -1) rc = frrs_error(503, "read_failed", NULL, body, cap, len, status);
    else {
        /* An id nothing holds still answers: its links, if it has any,
         * are what is left of it. */
        web_jw_t w;
        web_jw_init(&w, body, cap);
        related_json(m, live, have_c ? &c : NULL, r, now_s, &w, cap);
        web_jw_raw(&w, "\n");
        rc = w.overflow ? -1 : 0;
        if (rc == 0) { *len = w.len; *status = 200; }
    }
    if (have_c) web_slothdb_close(&c);
    free(r);
    return rc;
}

/* ── the write ─────────────────────────────────────────────────────── */

#ifdef WITH_SQLITE
static const char *gone_word(int kind) {
    return kind == REF_ANOM ? "no_such_anomaly" : kind == REF_ALERT ? "no_such_alert"
         : kind == REF_BLE ? "no_such_ble" : "no_such_device";
}

/* What may be linked: anything to an anomaly, and an alert to a device
 * or a BLE advertiser, in either order; nothing to itself. Alert to
 * alert and device to device are not: an alert's page already lists
 * its other alerts by the device they name, and no view lists a
 * device's devices. */
static int pair_ok(const ref_t *a, const ref_t *b) {
    if (a->kind == b->kind && !strcmp(a->id, b->id)) return 0;
    if (a->kind == REF_ANOM || b->kind == REF_ANOM) return 1;
    int da = a->kind == REF_DEVICE || a->kind == REF_BLE;
    int db = b->kind == REF_DEVICE || b->kind == REF_BLE;
    return (a->kind == REF_ALERT && db) || (da && b->kind == REF_ALERT);
}

static long long end_count(web_frrs_t *f, const ref_t *r) {
    sqlite3_stmt *s = NULL;
    long long n = -1;
    if (sqlite3_prepare_v2(f->wr, "SELECT COUNT(*) FROM relation WHERE " END_IS("a_kind", "a_id")
                           " OR " END_IS("b_kind", "b_id"), -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_int(s, 1, r->kind);
        sqlite3_bind_text(s, 2, r->id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 3, r->alt, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(s) == SQLITE_ROW) n = sqlite3_column_int64(s, 0);
    }
    sqlite3_finalize(s);
    return n;
}

/* One link from a to b in one transaction: 0 made (*link), 2 already
 * there in either direction (*link), 1 refused (*why), -1. */
static int link_add(web_frrs_t *f, const ref_t *a, const ref_t *b, const char *note,
                    const char *by, const char *peer, long long now_s, long long *link,
                    const char **why) {
    if (sqlite3_exec(f->wr, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        *why = "store_busy";
        return -1;
    }
    sqlite3_stmt *s = NULL;
    int rc = -1;
    *why = "store_error";
    for (int e = 0; e < 2; e++) {
        const ref_t *x = e ? b : a;
        if (x->kind != REF_ANOM) continue;
        int g = frrs_anom_register(f, &x->an, now_s, why);
        if (g != 0) { rc = g; goto out; }
    }
    if (sqlite3_prepare_v2(f->wr,
            "SELECT id FROM relation WHERE (a_kind = ?1 AND a_id = ?2 AND b_kind = ?3 AND b_id = ?4)"
            " OR (a_kind = ?3 AND a_id = ?4 AND b_kind = ?1 AND b_id = ?2)", -1, &s, NULL) != SQLITE_OK)
        goto out;
    sqlite3_bind_int(s, 1, a->kind);
    sqlite3_bind_text(s, 2, a->id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 3, b->kind);
    sqlite3_bind_text(s, 4, b->id, -1, SQLITE_TRANSIENT);
    int st = sqlite3_step(s);
    if (st == SQLITE_ROW) { *link = sqlite3_column_int64(s, 0); rc = 2; goto out; }
    if (st != SQLITE_DONE) goto out;
    sqlite3_finalize(s);
    s = NULL;
    long long total = count_of(f, "SELECT COUNT(*) FROM relation");
    long long na = end_count(f, a), nb = end_count(f, b);
    if (total < 0 || na < 0 || nb < 0) goto out;
    if (total >= WEB_REL_CAP || na >= WEB_REL_PER || nb >= WEB_REL_PER) {
        *why = "links_full";
        rc = 1;
        goto out;
    }
    if (sqlite3_prepare_v2(f->wr,
            "INSERT INTO relation (a_kind, a_id, a_label, b_kind, b_id, b_label, note, who, peer, ts)"
            " VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)", -1, &s, NULL) != SQLITE_OK)
        goto out;
    sqlite3_bind_int(s, 1, a->kind);
    sqlite3_bind_text(s, 2, a->id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, a->label, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 4, b->kind);
    sqlite3_bind_text(s, 5, b->id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 6, b->label, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 7, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 8, by, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 9, peer, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 10, now_s);
    if (sqlite3_step(s) != SQLITE_DONE) goto out;
    *link = sqlite3_last_insert_rowid(f->wr);
    rc = 0;
out:
    sqlite3_finalize(s);
    if ((rc == 0 || rc == 2) && sqlite3_exec(f->wr, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        *why = "store_error";
        rc = -1;
    }
    if (rc != 0 && rc != 2) sqlite3_exec(f->wr, "ROLLBACK", NULL, NULL, NULL);
    return rc;
}

/* The link numbered link, when r is one of its ends: 1 removed, 0 no
 * such link of r's, -1. */
static int link_remove(web_frrs_t *f, const ref_t *r, long long link) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(f->wr, "DELETE FROM relation WHERE id = ?4 AND (" END_IS("a_kind", "a_id")
                           " OR " END_IS("b_kind", "b_id") ")", -1, &s, NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        return -1;
    }
    sqlite3_bind_int(s, 1, r->kind);
    sqlite3_bind_text(s, 2, r->id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, r->alt, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 4, link);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) return -1;
    return sqlite3_changes(f->wr) > 0;
}

int frrs_relate_post(const web_m4_t *m, web_live_t *live, const web_jrec_t *r, const char *peer,
                     long long now_s, char *body, size_t cap, size_t *len, int *status) {
    static const char *const MEMBERS[] = { "op", "from", "to", "note", "by", "link", NULL };
    const char *bad = NULL, *why = NULL;
    if (!frrs_members_ok(r, MEMBERS, &bad))
        return frrs_error(400, "unknown_member", bad, body, cap, len, status);
    char op[12], from[REF_ID_MAX + 1], to[REF_ID_MAX + 1];
    char note[WEB_FRRS_NOTE_MAX + 1], by[WEB_FRRS_BY_MAX + 1];
    if (!frrs_text(r, "op", sizeof(op) - 1, op, &why))
        return frrs_error(400, why, "op", body, cap, len, status);
    if (!frrs_text(r, "from", REF_ID_MAX, from, &why))
        return frrs_error(400, why, "from", body, cap, len, status);
    if (!frrs_text(r, "to", REF_ID_MAX, to, &why))
        return frrs_error(400, why, "to", body, cap, len, status);
    if (!frrs_text(r, "note", WEB_FRRS_NOTE_MAX, note, &why))
        return frrs_text_refused(r, "note", WEB_FRRS_NOTE_MAX, why, body, cap, len, status);
    if (!frrs_text(r, "by", WEB_FRRS_BY_MAX, by, &why))
        return frrs_text_refused(r, "by", WEB_FRRS_BY_MAX, why, body, cap, len, status);
    int add = !strcmp(op, "add"), rem = !strcmp(op, "remove");
    if (!add && !rem) return frrs_error(400, "bad_op", "op", body, cap, len, status);
    if (!from[0]) return frrs_error(400, "missing_from", "from", body, cap, len, status);
    web_frrs_t *f = m->frrs;
    ref_t *a = calloc(1, sizeof(*a)), *b = calloc(1, sizeof(*b));
    if (!a || !b) { free(a); free(b); return -1; }
    web_sdb_conn_t c;
    int have_c = open_sdb(m, &c, now_s);
    web_sdb_conn_t *cp = have_c ? &c : NULL;
    long long link = 0;
    /* rc stays NONE until an answer is written: a refusal, or at the
     * end the listing. */
    enum { NONE = -2 };
    int unchanged = 0, rc = NONE;
    int ga = resolve_ref(m, live, cp, from, now_s, a);
    if (ga == -3) rc = frrs_error(400, "bad_id", "from", body, cap, len, status);
    else if (ga == -2) rc = frrs_error(409, "id_collision", "from", body, cap, len, status);
    else if (ga == -1) rc = frrs_error(503, "read_failed", NULL, body, cap, len, status);
    if (rc == NONE && add) {
        /* Both ends exist now: a link to nothing is never written. */
        int gb = to[0] ? resolve_ref(m, live, cp, to, now_s, b) : -3;
        if (gb == -3) rc = frrs_error(400, to[0] ? "bad_id" : "missing_to", "to", body, cap, len, status);
        else if (gb == -2) rc = frrs_error(409, "id_collision", "to", body, cap, len, status);
        else if (gb == -1) rc = frrs_error(503, "read_failed", NULL, body, cap, len, status);
        else if (ga == 0) rc = frrs_error(404, gone_word(a->kind), "from", body, cap, len, status);
        else if (gb == 0) rc = frrs_error(404, gone_word(b->kind), "to", body, cap, len, status);
        else if (!pair_ok(a, b))
            rc = frrs_error(400, "bad_pair", "to", body, cap, len, status);
        else {
            int g = link_add(f, a, b, note, by, peer, now_s, &link, &why);
            if (g == 2) {
                unchanged = 1;
            } else if (g != 0) {
                if (g < 0) frrs_stat_inc(f, &f->st.write_errors);
                rc = frrs_error(g > 0 ? 507 : !strcmp(why, "store_busy") ? 503 : 500, why, NULL,
                                body, cap, len, status);
            } else {
                frrs_stat_inc(f, &f->st.writes);
                frrs_stat_inc(f, &f->st.links_made);
            }
        }
    } else if (rc == NONE) {
        /* A removal names the link and one of its ends, held or not: a
         * link whose end is gone can still be taken away. */
        const web_jfield_t *lf = web_jl_get(r, "link");
        link = web_jl_int(r, "link", 0);
        int g = lf && lf->kind == WEB_J_INT && link > 0 ? link_remove(f, a, link) : -2;
        if (g == -2) {
            rc = frrs_error(400, "bad_link", "link", body, cap, len, status);
        } else if (g < 0) {
            frrs_stat_inc(f, &f->st.write_errors);
            rc = frrs_error(500, "store_error", NULL, body, cap, len, status);
        } else if (g == 0) {
            rc = frrs_error(404, "no_such_link", "link", body, cap, len, status);
        } else {
            frrs_stat_inc(f, &f->st.writes);
            frrs_stat_inc(f, &f->st.links_removed);
        }
    }
    if (rc == NONE) {
        /* The answer is the store's, read again: the page redraws from
         * it, never from what it sent. */
        web_jw_t w;
        web_jw_init(&w, body, cap);
        web_jw_raw(&w, "{\"ok\":true,\"unchanged\":");
        web_jw_raw(&w, unchanged ? "true" : "false");
        web_jw_raw(&w, ",\"link\":");
        web_jw_int(&w, link);
        web_jw_raw(&w, ",\"related\":");
        related_json(m, live, cp, a, now_s, &w, cap);
        web_jw_raw(&w, "}\n");
        rc = w.overflow ? -1 : 0;
        if (rc == 0) { *len = w.len; *status = 200; }
    }
    if (have_c) web_slothdb_close(&c);
    free(a);
    free(b);
    return rc;
}
#else
int frrs_relate_post(const web_m4_t *m, web_live_t *live, const web_jrec_t *r, const char *peer,
                     long long now_s, char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)live; (void)r; (void)peer; (void)now_s;
    return frrs_error(503, "no_store", NULL, body, cap, len, status);
}
#endif
