/* Many alerts triaged as one incident (web_incident.h, #198). The write
 * path, its gate and its text rules are web_frrs.c's, and so is an
 * alert's resolution: this file is the two tables, what a member reads
 * as, and the three routes. */
#include "web_incident.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_alertkb.h"
#include "web_devices.h"
#include "web_frrs_int.h"
#include "web_metrics.h"
#include "web_series.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

/* An incident's state is a decision: never "untriaged". */
static int decided_of(const char *w) {
    for (int s = WEB_TRI_FALSE; s < WEB_TRI_COUNT; s++)
        if (!strcmp(w, web_frrs_state_word(s))) return s;
    return -1;
}

static void type_json(web_jw_t *w, int type) {
    const web_akb_t *k = type >= 0 ? web_akb_get(type) : NULL;
    frrs_str_or_null(w, k ? k->name : NULL);
}

#ifdef WITH_SQLITE

/* One incident as the two rows (the open and, when closed, the close)
 * hold it, and its live member counts. */
typedef struct {
    long long id, ts;
    int       state, via;
    char      title[WEB_INC_TITLE_MAX + 1];
    char      note[WEB_FRRS_NOTE_MAX + 1], who[WEB_FRRS_BY_MAX + 1], peer[WEB_PEER_MAX];
    int       closed, cstate, cvia;
    long long cts;
    char      cnote[WEB_FRRS_NOTE_MAX + 1], cwho[WEB_FRRS_BY_MAX + 1], cpeer[WEB_PEER_MAX];
    long long nalerts, nfilters;
} inc_t;

/* A member row nothing has taken back. */
#define LIVE(t) " NOT EXISTS (SELECT 1 FROM incident_member r WHERE r.removes = " t "id) "
#define INC_SEL "SELECT i.id, i.title, i.state, i.note, i.who, i.peer, i.via, i.ts," \
                " c.id, c.state, c.note, c.who, c.peer, c.via, c.ts"
/* The member predicate every read of one alert shares: the triage
 * table's own (web_frrs.c's TRI_MATCH), so a member is the same alert
 * its triage rows are, through a handle's aging out and a rebuild. */
#define MEMBER_MATCH(t) \
    " (" t "subject = ?1 OR (?2 <> '' AND " t "subject = ?2) OR (?3 > 0 AND " t "finding = ?3)" \
    " OR (?4 >= 0 AND " t "finding IS NULL AND " t "type = ?4 AND " t "addr = ?5 AND " \
    t "port = ?6 AND " t "first_seen = ?7)) "

static void col_text(sqlite3_stmt *s, int i, char *out, size_t cap) {
    const unsigned char *t = sqlite3_column_text(s, i);
    web_utf8_copy(out, cap - 1, t ? (const char *)t : "");
}

static int state_col(sqlite3_stmt *s, int i) {
    int v = sqlite3_column_int(s, i);
    return v > WEB_TRI_UNTRIAGED && v < WEB_TRI_COUNT ? v : WEB_TRI_INCIDENT;
}

/* INC_SEL's fifteen columns into *o. */
static void inc_cols(sqlite3_stmt *s, inc_t *o) {
    memset(o, 0, sizeof(*o));
    o->id = sqlite3_column_int64(s, 0);
    col_text(s, 1, o->title, sizeof(o->title));
    o->state = state_col(s, 2);
    col_text(s, 3, o->note, sizeof(o->note));
    col_text(s, 4, o->who, sizeof(o->who));
    col_text(s, 5, o->peer, sizeof(o->peer));
    o->via = sqlite3_column_int(s, 6);
    o->ts = sqlite3_column_int64(s, 7);
    o->closed = sqlite3_column_type(s, 8) != SQLITE_NULL;
    if (o->closed) {
        o->cstate = state_col(s, 9);
        col_text(s, 10, o->cnote, sizeof(o->cnote));
        col_text(s, 11, o->cwho, sizeof(o->cwho));
        col_text(s, 12, o->cpeer, sizeof(o->cpeer));
        o->cvia = sqlite3_column_int(s, 13);
        o->cts = sqlite3_column_int64(s, 14);
    }
}

/* The incident's decision: its close when it has one, else its open. */
static int dec_state(const inc_t *i) { return i->closed ? i->cstate : i->state; }
static long long dec_ts(const inc_t *i) { return i->closed ? i->cts : i->ts; }

static void bind_subj(sqlite3_stmt *st, const tri_subj_t *q) {
    sqlite3_bind_text(st, 1, q->subject, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, q->alt, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, q->finding);
    sqlite3_bind_int(st, 4, q->type);
    sqlite3_bind_text(st, 5, q->addr, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, q->port);
    sqlite3_bind_int64(st, 7, q->first);
}

/* ── what a member reads as ────────────────────────────────────────── */

typedef struct {
    inc_t     i;
    long long mts;                   /* the member row's ts */
    int       filter;
} hit_t;

/* The newest-decided incident holding s by one of the two kinds of
 * member: 1 with *h, 0 none, -1. */
static int hit_find(web_frrs_t *f, const tri_subj_t *s, int filter, hit_t *h) {
    static const char HEAD[] = INC_SEL ", m.ts FROM incident_member m JOIN incident i ON"
        " i.id = m.incident AND i.closes = 0 LEFT JOIN incident c ON c.closes = i.id"
        " WHERE m.removes = 0 AND" LIVE("m.") "AND ";
    static const char ORDER[] = " ORDER BY COALESCE(c.ts, i.ts) DESC, i.id DESC LIMIT 1";
    /* A filter takes an alert by its type, its address and when it
     * began; after the close, none that began later. */
    static const char BY_FILTER[] = "m.kind = 1 AND (m.type < 0 OR m.type = ?4) AND"
        " (m.addr = '' OR m.addr = ?5) AND ?7 >= m.t_from AND (m.t_to = 0 OR ?7 <= m.t_to) AND"
        " (c.id IS NULL OR ?7 <= c.ts)";
    static const char BY_ID[] = "m.kind = 0 AND" MEMBER_MATCH("m.");
    char sql[1536];
    snprintf(sql, sizeof(sql), "%s%s%s", HEAD, filter ? BY_FILTER : BY_ID, ORDER);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(f->wr, sql, -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    bind_subj(st, s);
    int rc = sqlite3_step(st), got = 0;
    if (rc == SQLITE_ROW) {
        inc_cols(st, &h->i);
        h->mts = sqlite3_column_int64(st, 15);
        h->filter = filter;
        got = 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? got : -1;
}

int frrs_inc_overlay(web_frrs_t *f, const tri_subj_t *s, web_tri_t *t) {
    if (!f || !f->wr || s->anom) return 0;
    hit_t a, b;
    int ga = hit_find(f, s, 0, &a);
    int gb = ga < 0 ? -1 : hit_find(f, s, 1, &b);
    if (ga < 0 || gb < 0) return -1;
    if (!ga && !gb) return 0;
    /* The incident decided last (then the higher id); the same one by
     * both kinds is its explicit membership. */
    const hit_t *h = !gb ? &a : !ga ? &b
                   : (dec_ts(&b.i) > dec_ts(&a.i) ||
                      (dec_ts(&b.i) == dec_ts(&a.i) && b.i.id > a.i.id)) ? &b : &a;
    t->inc_id = h->i.id;
    t->inc_state = dec_state(&h->i);
    t->inc_filter = h->filter;
    t->inc_auto = h->filter && s->first > h->mts;
    snprintf(t->inc_title, sizeof(t->inc_title), "%s", h->i.title);
    /* The precedence (web_incident.h): the alert's own decision at or
     * after the incident's stands. */
    if (t->state != WEB_TRI_UNTRIAGED && t->ts >= dec_ts(&h->i)) {
        t->inc_governs = 0;
        return 1;
    }
    t->inc_governs = 1;
    t->prev_state = t->state;
    t->state = t->inc_state;
    t->ts = dec_ts(&h->i);
    t->via = h->i.closed ? h->i.cvia : h->i.via;
    if (t->via < 0 || t->via >= WEB_TRI_VIA_COUNT) t->via = WEB_TRI_VIA_MANUAL;
    snprintf(t->note, sizeof(t->note), "%s", h->i.closed && h->i.cnote[0] ? h->i.cnote : h->i.note);
    snprintf(t->by, sizeof(t->by), "%s", h->i.closed ? h->i.cwho : h->i.who);
    snprintf(t->peer, sizeof(t->peer), "%s", h->i.closed ? h->i.cpeer : h->i.peer);
    t->basis[0] = t->claim_by[0] = t->claim_peer[0] = '\0';
    return 1;
}

/* ── the tables ────────────────────────────────────────────────────── */

/* One number of a statement with up to two integer parameters, or -1. */
static long long num_q(web_frrs_t *f, const char *sql, long long a, long long b) {
    sqlite3_stmt *s = NULL;
    long long n = -1;
    if (sqlite3_prepare_v2(f->wr, sql, -1, &s, NULL) == SQLITE_OK) {
        if (sqlite3_bind_parameter_count(s) >= 1) sqlite3_bind_int64(s, 1, a);
        if (sqlite3_bind_parameter_count(s) >= 2) sqlite3_bind_int64(s, 2, b);
        if (sqlite3_step(s) == SQLITE_ROW) n = sqlite3_column_int64(s, 0);
    }
    sqlite3_finalize(s);
    return n;
}

long long web_incident_rows(web_frrs_t *f) {
    return f && f->wr ? num_q(f, "SELECT COUNT(*) FROM incident WHERE closes = 0", 0, 0) : -1;
}

/* Incident id with its counts: 1, 0 none, -1. */
static int inc_get(web_frrs_t *f, long long id, inc_t *o) {
    static const char SQL[] = INC_SEL ","
        " (SELECT COUNT(*) FROM incident_member m WHERE m.incident = i.id AND m.kind = 0 AND"
        "  m.removes = 0 AND" LIVE("m.") "),"
        " (SELECT COUNT(*) FROM incident_member m WHERE m.incident = i.id AND m.kind = 1 AND"
        "  m.removes = 0 AND" LIVE("m.") ")"
        " FROM incident i LEFT JOIN incident c ON c.closes = i.id"
        " WHERE i.id = ?1 AND i.closes = 0";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(f->wr, SQL, -1, &s, NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        return -1;
    }
    sqlite3_bind_int64(s, 1, id);
    int rc = sqlite3_step(s), got = 0;
    if (rc == SQLITE_ROW) {
        inc_cols(s, o);
        o->nalerts = sqlite3_column_int64(s, 15);
        o->nfilters = sqlite3_column_int64(s, 16);
        got = 1;
    }
    sqlite3_finalize(s);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? got : -1;
}

static void inc_json(web_jw_t *w, const inc_t *i) {
    web_jw_raw(w, "{\"id\":");        web_jw_int(w, i->id);
    web_jw_raw(w, ",\"title\":");     web_jw_str(w, i->title);
    web_jw_raw(w, ",\"state\":");     web_jw_str(w, web_frrs_state_word(dec_state(i)));
    web_jw_raw(w, ",\"open\":");      web_jw_raw(w, i->closed ? "false" : "true");
    web_jw_raw(w, ",\"decided\":");   web_jw_int(w, dec_ts(i));
    web_jw_raw(w, ",\"ts\":");        web_jw_int(w, i->ts);
    web_jw_raw(w, ",\"opened_state\":"); web_jw_str(w, web_frrs_state_word(i->state));
    web_jw_raw(w, ",\"note\":");      web_jw_str(w, i->note);
    web_jw_raw(w, ",\"by\":");        web_jw_str(w, i->who);
    web_jw_raw(w, ",\"peer\":");      web_jw_str(w, i->peer);
    web_jw_raw(w, ",\"via\":");       web_jw_str(w, web_frrs_via_word(i->via));
    web_jw_raw(w, ",\"closed\":");
    if (i->closed) {
        web_jw_raw(w, "{\"ts\":");    web_jw_int(w, i->cts);
        web_jw_raw(w, ",\"state\":"); web_jw_str(w, web_frrs_state_word(i->cstate));
        web_jw_raw(w, ",\"note\":");  web_jw_str(w, i->cnote);
        web_jw_raw(w, ",\"by\":");    web_jw_str(w, i->cwho);
        web_jw_raw(w, ",\"peer\":");  web_jw_str(w, i->cpeer);
        web_jw_raw(w, ",\"via\":");   web_jw_str(w, web_frrs_via_word(i->cvia));
        web_jw_raw(w, "}");
    } else {
        web_jw_raw(w, "null");
    }
    web_jw_raw(w, ",\"alerts\":");    web_jw_int(w, i->nalerts);
    web_jw_raw(w, ",\"filters\":");   web_jw_int(w, i->nfilters);
    web_jw_raw(w, "}");
}

/* A standing filter as a request names one. */
typedef struct {
    int       has, type;
    char      addr[WEB_FRRS_ADDR_MAX + 1];
    long long from, to;
} filt_t;

static int insert_member(web_frrs_t *f, long long inc, int kind, const tri_subj_t *s,
                         const filt_t *ft, long long removes, const char *by, const char *peer,
                         int via, long long now_s, long long *mid) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(f->wr, "INSERT INTO incident_member (incident, kind, subject, finding,"
            " type, addr, port, first_seen, t_from, t_to, who, peer, via, removes, ts) VALUES"
            " (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_bind_int64(st, 1, inc);
    sqlite3_bind_int(st, 2, kind);
    sqlite3_bind_text(st, 3, s ? s->subject : "", -1, SQLITE_TRANSIENT);
    if (s && s->finding > 0) sqlite3_bind_int64(st, 4, s->finding); else sqlite3_bind_null(st, 4);
    sqlite3_bind_int(st, 5, s ? s->type : ft ? ft->type : -1);
    sqlite3_bind_text(st, 6, s ? s->addr : ft ? ft->addr : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, s ? s->port : 0);
    sqlite3_bind_int64(st, 8, s ? s->first : 0);
    sqlite3_bind_int64(st, 9, ft ? ft->from : 0);
    sqlite3_bind_int64(st, 10, ft ? ft->to : 0);
    sqlite3_bind_text(st, 11, by, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, peer, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 13, via);
    sqlite3_bind_int64(st, 14, removes);
    sqlite3_bind_int64(st, 15, now_s);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    if (mid) *mid = sqlite3_last_insert_rowid(f->wr);
    return 0;
}

/* Room for one more member row on incident inc: 0, 1 full, -1. */
static int member_room(web_frrs_t *f, long long inc) {
    long long per = num_q(f, "SELECT COUNT(*) FROM incident_member WHERE incident = ?1", inc, 0);
    long long all = num_q(f, "SELECT COUNT(*) FROM incident_member", 0, 0);
    if (per < 0 || all < 0) return -1;
    return per >= WEB_INC_PER || all >= WEB_INC_MEMBER_CAP;
}

/* One requested alert: its id, and once resolved its subject or the
 * refusal (status and word) that is its entry in "results". */
typedef struct {
    char        id[32];
    int         st, unchanged;
    const char *why;
    long long   member;
    tri_subj_t  s;
} req_id_t;

/* The ids resolved before the transaction (sloth.db's reads are never
 * made while slothweb.db's write lock is held). */
static void resolve_ids(const web_m4_t *m, web_live_t *live, req_id_t *q, int n,
                        long long now_s) {
    web_sdb_conn_t c;
    int have_c = frrs_sdb_open(m, now_s, &c);
    for (int i = 0; i < n; i++) {
        if (frrs_anom_id_ok(q[i].id)) { q[i].st = 400; q[i].why = "not_an_alert"; continue; }
        int r = frrs_resolve_alert(m, live, have_c ? &c : NULL, q[i].id, now_s, &q[i].s, NULL);
        if (r < 0) { q[i].st = 503; q[i].why = "read_failed"; }
        else if (r == 0) { q[i].st = 404; q[i].why = "no_such_alert"; }
    }
    if (have_c) web_slothdb_close(&c);
}

/* The resolved ids filed as members of inc, inside the caller's
 * transaction: one already a live member is "unchanged", one past a
 * bound is refused, 507 members_full, and the rest go on. 0, -1. */
static int add_ids(web_frrs_t *f, long long inc, req_id_t *q, int n, const char *by,
                   const char *peer, int via, long long now_s) {
    sqlite3_stmt *dup = NULL;
    if (sqlite3_prepare_v2(f->wr, "SELECT m.id FROM incident_member m WHERE m.incident = ?8 AND"
            " m.kind = 0 AND m.removes = 0 AND" LIVE("m.") "AND" MEMBER_MATCH("m.") "LIMIT 1",
            -1, &dup, NULL) != SQLITE_OK) {
        sqlite3_finalize(dup);
        return -1;
    }
    int rc = 0;
    for (int i = 0; i < n && rc == 0; i++) {
        if (q[i].st) continue;
        bind_subj(dup, &q[i].s);
        sqlite3_bind_int64(dup, 8, inc);
        int r = sqlite3_step(dup);
        if (r == SQLITE_ROW) {
            q[i].unchanged = 1;
            q[i].member = sqlite3_column_int64(dup, 0);
        }
        sqlite3_reset(dup);
        sqlite3_clear_bindings(dup);
        if (r == SQLITE_ROW) continue;
        if (r != SQLITE_DONE) { rc = -1; break; }
        int room = member_room(f, inc);
        if (room < 0) { rc = -1; break; }
        if (room) { q[i].st = 507; q[i].why = "members_full"; continue; }
        if (insert_member(f, inc, 0, &q[i].s, NULL, 0, by, peer, via, now_s, &q[i].member) != 0)
            rc = -1;
    }
    sqlite3_finalize(dup);
    return rc;
}

/* The filter filed on inc, inside the caller's transaction: 0 written
 * (*mid), 2 the same filter is already live (*mid that one), 1 refused
 * (*why), -1. */
static int add_filter(web_frrs_t *f, long long inc, const filt_t *ft, const char *by,
                      const char *peer, int via, long long now_s, long long *mid,
                      const char **why) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(f->wr, "SELECT m.id FROM incident_member m WHERE m.incident = ?1 AND"
            " m.kind = 1 AND m.removes = 0 AND" LIVE("m.") "AND m.type = ?2 AND m.addr = ?3 AND"
            " m.t_from = ?4 AND m.t_to = ?5 LIMIT 1", -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_bind_int64(st, 1, inc);
    sqlite3_bind_int(st, 2, ft->type);
    sqlite3_bind_text(st, 3, ft->addr, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, ft->from);
    sqlite3_bind_int64(st, 5, ft->to);
    int r = sqlite3_step(st);
    if (r == SQLITE_ROW) *mid = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (r == SQLITE_ROW) return 2;
    if (r != SQLITE_DONE) return -1;
    long long live = num_q(f, "SELECT COUNT(*) FROM incident_member m WHERE m.incident = ?1 AND"
                              " m.kind = 1 AND m.removes = 0 AND" LIVE("m."), inc, 0);
    if (live < 0) return -1;
    if (live >= WEB_INC_FILTERS) { *why = "filters_full"; return 1; }
    int room = member_room(f, inc);
    if (room < 0) return -1;
    if (room) { *why = "members_full"; return 1; }
    return insert_member(f, inc, 1, NULL, ft, 0, by, peer, via, now_s, mid);
}

/* ── the answers ───────────────────────────────────────────────────── */

static void results_json(web_jw_t *w, const req_id_t *q, int n) {
    web_jw_raw(w, ",\"results\":[");
    for (int i = 0; i < n; i++) {
        web_jw_raw(w, i ? ",{\"id\":" : "{\"id\":");
        web_jw_str(w, q[i].id);
        if (q[i].st) {
            web_jw_raw(w, ",\"ok\":false,\"status\":"); web_jw_int(w, q[i].st);
            web_jw_raw(w, ",\"error\":");               web_jw_str(w, q[i].why);
        } else {
            web_jw_raw(w, ",\"ok\":true,\"unchanged\":");
            web_jw_raw(w, q[i].unchanged ? "true" : "false");
            web_jw_raw(w, ",\"member\":");              web_jw_int(w, q[i].member);
        }
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "]");
}

/* The live members of inc, newest first, at most WEB_INC_SHOWN, then
 * "more" and the count of rows that took one back. */
static void members_json(web_frrs_t *f, long long inc, web_jw_t *w) {
    sqlite3_stmt *st = NULL;
    int k = 0, more = 0;
    web_jw_raw(w, ",\"members\":[");
    if (sqlite3_prepare_v2(f->wr, "SELECT m.id, m.kind, m.subject, m.type, m.addr, m.port,"
            " m.first_seen, m.t_from, m.t_to, m.who, m.peer, m.via, m.ts FROM incident_member m"
            " WHERE m.incident = ?1 AND m.removes = 0 AND" LIVE("m.") "ORDER BY m.id DESC",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, inc);
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (k >= WEB_INC_SHOWN) { more = 1; break; }
            char t[WEB_FRRS_ADDR_MAX + 64];
            int kind = sqlite3_column_int(st, 1);
            web_jw_raw(w, k++ ? ",{\"member\":" : "{\"member\":");
            web_jw_int(w, sqlite3_column_int64(st, 0));
            web_jw_raw(w, ",\"kind\":");  web_jw_str(w, kind ? "filter" : "alert");
            if (!kind) {
                col_text(st, 2, t, sizeof(t));
                web_jw_raw(w, ",\"id\":");  web_jw_str(w, t);
            }
            web_jw_raw(w, ",\"type\":");    type_json(w, sqlite3_column_int(st, 3));
            col_text(st, 4, t, sizeof(t));
            web_jw_raw(w, ",\"addr\":");    web_jw_str(w, t);
            if (kind) {
                web_jw_raw(w, ",\"from\":"); web_jw_int(w, sqlite3_column_int64(st, 7));
                web_jw_raw(w, ",\"to\":");   web_jw_int(w, sqlite3_column_int64(st, 8));
            } else {
                web_jw_raw(w, ",\"port\":");       web_jw_int(w, sqlite3_column_int(st, 5));
                web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, sqlite3_column_int64(st, 6));
            }
            col_text(st, 9, t, sizeof(t));
            web_jw_raw(w, ",\"by\":");      web_jw_str(w, t);
            col_text(st, 10, t, sizeof(t));
            web_jw_raw(w, ",\"peer\":");    web_jw_str(w, t);
            web_jw_raw(w, ",\"via\":");     web_jw_str(w, web_frrs_via_word(sqlite3_column_int(st, 11)));
            web_jw_raw(w, ",\"ts\":");      web_jw_int(w, sqlite3_column_int64(st, 12));
            web_jw_raw(w, "}");
        }
    }
    sqlite3_finalize(st);
    web_jw_raw(w, "],\"more\":");
    web_jw_raw(w, more ? "true" : "false");
    web_jw_raw(w, ",\"removed\":");
    long long rm = num_q(f, "SELECT COUNT(*) FROM incident_member WHERE incident = ?1 AND removes > 0",
                         inc, 0);
    if (rm < 0) web_jw_raw(w, "null"); else web_jw_int(w, rm);
}

static int answer(web_jw_t *w, char *body, size_t *len, int *status) {
    (void)body;
    if (w->overflow) return -1;
    *len = w->len;
    *status = 200;
    return 0;
}

/* ── the routes ────────────────────────────────────────────────────── */

/* An integer member: absent (1, *present 0), a whole number >= lo (1),
 * else 0. */
static int int_member(const web_jrec_t *r, const char *name, long long lo, long long *v,
                      int *present) {
    const web_jfield_t *fd = web_jl_get(r, name);
    *present = 0;
    *v = 0;
    if (!fd || fd->kind == WEB_J_NULL) return 1;
    if (fd->kind != WEB_J_INT || fd->i < lo) return 0;
    *v = fd->i;
    *present = 1;
    return 1;
}

/* The filter members of r into *ft (ft->has 0 when it names none): 0,
 * or -1 with the refusal's word and member. */
static int filter_of(const web_jrec_t *r, filt_t *ft, const char **why, const char **member) {
    char tw[48], ip[64], mac[24];
    memset(ft, 0, sizeof(*ft));
    ft->type = -1;
    *member = "type";
    if (!frrs_text(r, "type", sizeof(tw) - 1, tw, why)) return -1;
    *member = "ip";
    if (!frrs_text(r, "ip", sizeof(ip) - 1, ip, why)) return -1;
    *member = "mac";
    if (!frrs_text(r, "mac", sizeof(mac) - 1, mac, why)) return -1;
    int pf = 0, pt = 0;
    *member = "from";
    *why = "bad_from";
    if (!int_member(r, "from", 0, &ft->from, &pf)) return -1;
    *member = "to";
    *why = "bad_to";
    if (!int_member(r, "to", 0, &ft->to, &pt)) return -1;
    if (tw[0] && (ft->type = web_akb_find(tw)) < 0) { *why = "bad_type"; *member = "type"; return -1; }
    if (ip[0] && mac[0]) { *why = "one_address"; *member = "mac"; return -1; }
    if (ip[0]) {
        char k[WEB_KEY_MAX + 1];
        if (web_key_ip(ip, k) != 0) { *why = "bad_ip"; *member = "ip"; return -1; }
        snprintf(ft->addr, sizeof(ft->addr), "%.45s", k);
    }
    if (mac[0]) {
        char k[WEB_KEY_MAX + 1];
        if (web_dev_canon_mac(mac, k) != 0) { *why = "bad_mac"; *member = "mac"; return -1; }
        snprintf(ft->addr, sizeof(ft->addr), "%.17s", k);
    }
    if (ft->to > 0 && ft->from > ft->to) { *why = "bad_window"; *member = "to"; return -1; }
    ft->has = ft->type >= 0 || ft->addr[0] || ft->from > 0 || ft->to > 0;
    *why = NULL;
    *member = NULL;
    return 0;
}

static int begin(web_frrs_t *f) {
    return sqlite3_exec(f->wr, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}
static int commit(web_frrs_t *f, int ok) {
    if (ok && sqlite3_exec(f->wr, "COMMIT", NULL, NULL, NULL) == SQLITE_OK) return 0;
    sqlite3_exec(f->wr, "ROLLBACK", NULL, NULL, NULL);
    return -1;
}

/* A write's failure on the store: counted, and its answer. */
static int store_failed(web_frrs_t *f, int busy, char *body, size_t cap, size_t *len,
                        int *status) {
    frrs_stat_inc(f, &f->st.write_errors);
    return frrs_error(busy ? 503 : 500, busy ? "store_busy" : "store_error", NULL, body, cap,
                      len, status);
}

int web_incident_post(const web_m4_t *m, web_live_t *live, const web_jrec_t *r, const char *peer,
                      int via, long long now_s, char *body, size_t cap, size_t *len, int *status) {
    static const char *const MEMBERS[] = { "op", "title", "state", "note", "by", "incident", "ids",
                                           "type", "ip", "mac", "from", "to", "remove", NULL };
    const char *bad = NULL, *why = NULL, *member = NULL;
    if (!frrs_members_ok(r, MEMBERS, &bad))
        return frrs_error(400, "unknown_member", bad, body, cap, len, status);
    char op[12], title[WEB_INC_TITLE_MAX + 1], sw[16], note[WEB_FRRS_NOTE_MAX + 1];
    char by[WEB_FRRS_BY_MAX + 1], list[WEB_FRRS_BULK_IDS_LEN + 1];
    if (!frrs_text(r, "op", sizeof(op) - 1, op, &why))
        return frrs_error(400, why, "op", body, cap, len, status);
    if (!frrs_text(r, "title", WEB_INC_TITLE_MAX, title, &why))
        return frrs_text_refused(r, "title", WEB_INC_TITLE_MAX, why, body, cap, len, status);
    if (!frrs_text(r, "state", sizeof(sw) - 1, sw, &why))
        return frrs_error(400, why, "state", body, cap, len, status);
    if (!frrs_text(r, "note", WEB_FRRS_NOTE_MAX, note, &why))
        return frrs_text_refused(r, "note", WEB_FRRS_NOTE_MAX, why, body, cap, len, status);
    if (!frrs_text(r, "by", WEB_FRRS_BY_MAX, by, &why))
        return frrs_text_refused(r, "by", WEB_FRRS_BY_MAX, why, body, cap, len, status);
    if (!frrs_text(r, "ids", WEB_FRRS_BULK_IDS_LEN, list, &why))
        return frrs_text_refused(r, "ids", WEB_FRRS_BULK_IDS_LEN, why, body, cap, len, status);
    long long inc = 0, rm = 0;
    int has_inc = 0, has_rm = 0;
    if (!int_member(r, "incident", 1, &inc, &has_inc))
        return frrs_error(400, "bad_incident", "incident", body, cap, len, status);
    if (!int_member(r, "remove", 1, &rm, &has_rm))
        return frrs_error(400, "bad_remove", "remove", body, cap, len, status);
    filt_t ft;
    if (filter_of(r, &ft, &why, &member) != 0)
        return frrs_error(400, why, member, body, cap, len, status);
    int add = !strcmp(op, "add"), mem = !strcmp(op, "member"), cls = !strcmp(op, "close");
    if (!add && !mem && !cls) return frrs_error(400, op[0] ? "bad_op" : "missing_op", "op", body, cap, len, status);
    /* What each op does not take is refused by name, never ignored. */
    const char *extra = add ? (has_inc ? "incident" : has_rm ? "remove" : NULL)
                      : mem ? (title[0] ? "title" : sw[0] ? "state" : note[0] ? "note" : NULL)
                      : (title[0] ? "title" : list[0] ? "ids" : has_rm ? "remove"
                         : ft.has ? "type" : NULL);
    if (cls && !extra && (web_jl_get(r, "ip") || web_jl_get(r, "mac") || web_jl_get(r, "from") ||
                          web_jl_get(r, "to")))
        extra = web_jl_get(r, "ip") ? "ip" : web_jl_get(r, "mac") ? "mac" :
                web_jl_get(r, "from") ? "from" : "to";
    if (extra) return frrs_error(400, "unknown_member", extra, body, cap, len, status);
    int state = -1;
    if (sw[0] && (state = decided_of(sw)) < 0)
        return frrs_error(400, "bad_state", "state", body, cap, len, status);
    if (add && !title[0]) return frrs_error(400, "missing_title", "title", body, cap, len, status);
    if (add && state < 0) return frrs_error(400, "missing_state", "state", body, cap, len, status);
    if ((mem || cls) && !has_inc)
        return frrs_error(400, "missing_incident", "incident", body, cap, len, status);
    if (mem && (!!list[0] + ft.has + has_rm) != 1)
        return frrs_error(400, "one_change", NULL, body, cap, len, status);
    /* The ids, checked whole before anything is resolved or written. */
    req_id_t *q = NULL;
    int n = 0;
    if (list[0]) {
        char (*ids)[32] = malloc(sizeof(char[WEB_FRRS_BULK_MAX][32]));
        if (!ids) return -1;
        int pr = frrs_ids_parse(list, ids, WEB_FRRS_BULK_MAX, &n);
        if (pr == 0 && !(q = calloc((size_t)n, sizeof(*q)))) pr = -3;
        for (int i = 0; pr == 0 && i < n; i++) memcpy(q[i].id, ids[i], 32);
        free(ids);
        if (pr == -3) return -1;
        if (pr != 0)
            return frrs_error(400, pr == -2 ? "too_many_ids" : "bad_ids", "ids", body, cap, len, status);
        resolve_ids(m, live, q, n, now_s);
    }
    web_frrs_t *f = m->frrs;
    inc_t cur;
    int unchanged = 0;
    long long mid = 0;
    if (begin(f) != 0) { free(q); return store_failed(f, 1, body, cap, len, status); }
    if (add) {
        long long opens = num_q(f, "SELECT COUNT(*) FROM incident WHERE closes = 0", 0, 0);
        if (opens < 0) goto fail;
        if (opens >= WEB_INC_CAP) {
            commit(f, 0);
            free(q);
            return frrs_error(507, "incidents_full", NULL, body, cap, len, status);
        }
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(f->wr, "INSERT INTO incident (closes, title, state, note, who, peer,"
                               " via, ts) VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6, ?7)", -1, &st,
                               NULL) != SQLITE_OK) {
            sqlite3_finalize(st);
            goto fail;
        }
        sqlite3_bind_text(st, 1, title, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, state);
        sqlite3_bind_text(st, 3, note, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, by, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, peer, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, via);
        sqlite3_bind_int64(st, 7, now_s);
        int sr = sqlite3_step(st);
        sqlite3_finalize(st);
        if (sr != SQLITE_DONE) goto fail;
        inc = sqlite3_last_insert_rowid(f->wr);
        /* A new incident has room for its first filter and ids. */
        if (ft.has && add_filter(f, inc, &ft, by, peer, via, now_s, &mid, &why) < 0) goto fail;
        if (n && add_ids(f, inc, q, n, by, peer, via, now_s) != 0) goto fail;
    } else {
        int g = inc_get(f, inc, &cur);
        if (g < 0) goto fail;
        if (g == 0) {
            commit(f, 0);
            free(q);
            return frrs_error(404, "no_such_incident", "incident", body, cap, len, status);
        }
        if (cls) {
            /* Whose incident it is decides first, as note_retract()
             * asks whose note before "already taken back". */
            if (via == WEB_TRI_VIA_AGENT && cur.via != WEB_TRI_VIA_AGENT) {
                commit(f, 0);
                free(q);
                return frrs_error(403, "not_agent_incident", "incident", body, cap, len, status);
            }
            if (cur.closed) {
                unchanged = 1;
            } else {
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(f->wr, "INSERT INTO incident (closes, title, state, note,"
                                       " who, peer, via, ts) VALUES (?1, '', ?2, ?3, ?4, ?5, ?6, ?7)",
                                       -1, &st, NULL) != SQLITE_OK) {
                    sqlite3_finalize(st);
                    goto fail;
                }
                sqlite3_bind_int64(st, 1, inc);
                sqlite3_bind_int(st, 2, state >= 0 ? state : cur.state);
                sqlite3_bind_text(st, 3, note, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 4, by, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 5, peer, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(st, 6, via);
                sqlite3_bind_int64(st, 7, now_s);
                int sr = sqlite3_step(st);
                sqlite3_finalize(st);
                if (sr != SQLITE_DONE) goto fail;
            }
        } else if (cur.closed) {
            commit(f, 0);
            free(q);
            return frrs_error(409, "incident_closed", "incident", body, cap, len, status);
        } else if (has_rm) {
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(f->wr, "SELECT m.via, m.kind, NOT" LIVE("m.") "FROM"
                                   " incident_member m WHERE m.id = ?1 AND m.incident = ?2 AND"
                                   " m.removes = 0", -1, &st, NULL) != SQLITE_OK) {
                sqlite3_finalize(st);
                goto fail;
            }
            sqlite3_bind_int64(st, 1, rm);
            sqlite3_bind_int64(st, 2, inc);
            int sr = sqlite3_step(st);
            int mvia = sr == SQLITE_ROW ? sqlite3_column_int(st, 0) : 0;
            int mkind = sr == SQLITE_ROW ? sqlite3_column_int(st, 1) : 0;
            int gone = sr == SQLITE_ROW ? sqlite3_column_int(st, 2) : 0;
            sqlite3_finalize(st);
            if (sr != SQLITE_ROW && sr != SQLITE_DONE) goto fail;
            if (sr == SQLITE_DONE) {
                commit(f, 0);
                free(q);
                return frrs_error(404, "no_such_member", "remove", body, cap, len, status);
            }
            if (via == WEB_TRI_VIA_AGENT && mvia != WEB_TRI_VIA_AGENT) {
                commit(f, 0);
                free(q);
                return frrs_error(403, "not_agent_member", "remove", body, cap, len, status);
            }
            mid = rm;
            if (gone) unchanged = 1;
            /* A removal is never refused for room: it is a row, as a
             * triage clear is, and it ends a member. */
            else if (insert_member(f, inc, mkind, NULL, NULL, rm, by, peer, via, now_s, NULL) != 0)
                goto fail;
        } else if (ft.has) {
            int g2 = add_filter(f, inc, &ft, by, peer, via, now_s, &mid, &why);
            if (g2 < 0) goto fail;
            if (g2 == 1) {
                commit(f, 0);
                free(q);
                return frrs_error(507, why, NULL, body, cap, len, status);
            }
            unchanged = g2 == 2;
        } else if (add_ids(f, inc, q, n, by, peer, via, now_s) != 0) {
            goto fail;
        }
    }
    if (commit(f, 1) != 0) {
        free(q);
        return store_failed(f, 0, body, cap, len, status);
    }
    {
        int wrote = add || !unchanged;
        for (int i = 0; i < n && !wrote; i++) wrote = !q[i].st && !q[i].unchanged;
        if (wrote) frrs_stat_inc(f, &f->st.writes);
        if (add) frrs_stat_inc(f, &f->st.incidents_opened);
        if (cls && !unchanged) frrs_stat_inc(f, &f->st.incidents_closed);
    }
    /* The answer is the store's, read again. */
    if (inc_get(f, inc, &cur) <= 0) {
        free(q);
        return frrs_error(500, "store_error", NULL, body, cap, len, status);
    }
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"ok\":true,\"op\":");  web_jw_str(&w, op);
    web_jw_raw(&w, ",\"unchanged\":");       web_jw_raw(&w, unchanged ? "true" : "false");
    if (mid > 0) {
        web_jw_raw(&w, ",\"member\":");
        web_jw_int(&w, mid);
    }
    web_jw_raw(&w, ",\"incident\":");
    inc_json(&w, &cur);
    if (q) results_json(&w, q, n);
    web_jw_raw(&w, "}\n");
    free(q);
    return answer(&w, body, len, status);
fail:
    commit(f, 0);
    free(q);
    return store_failed(f, 0, body, cap, len, status);
}

int web_incident_list(const web_m4_t *m, const char *query, char *body, size_t cap,
                      size_t *len, int *status) {
    web_param_t ps[1] = { { "state", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    int want = 0;                    /* 0 all, 1 open, 2 closed */
    if (ps[0].seen) {
        if (!strcmp(ps[0].val, "open")) want = 1;
        else if (!strcmp(ps[0].val, "closed")) want = 2;
        else if (strcmp(ps[0].val, "all")) return frrs_error(400, "bad_state", NULL, body, cap, len, status);
    }
    web_frrs_t *f = m->frrs;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"store\":");  web_jw_str(&w, f && f->wr ? "open" : "none");
    web_jw_raw(&w, ",\"writes\":"); web_jw_raw(&w, f && f->wr && f->writes ? "true" : "false");
    web_jw_raw(&w, ",\"cap\":");    web_jw_int(&w, WEB_INC_CAP);
    web_jw_raw(&w, ",\"title_max\":"); web_jw_int(&w, WEB_INC_TITLE_MAX);
    web_jw_raw(&w, ",\"ids_max\":"); web_jw_int(&w, WEB_FRRS_BULK_MAX);
    web_jw_raw(&w, ",\"incidents\":[");
    int k = 0, more = 0;
    sqlite3_stmt *st = NULL;
    if (f && f->wr && sqlite3_prepare_v2(f->wr, "SELECT i.id FROM incident i WHERE i.closes = 0 AND"
            " (?1 = 0 OR (?1 = 1) = NOT EXISTS (SELECT 1 FROM incident c WHERE c.closes = i.id))"
            " ORDER BY i.id DESC", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, want);
        long long ids[WEB_INC_LIST];
        int nid = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (nid >= WEB_INC_LIST) { more = 1; break; }
            ids[nid++] = sqlite3_column_int64(st, 0);
        }
        sqlite3_finalize(st);
        st = NULL;
        for (int i = 0; i < nid; i++) {
            inc_t one;
            if (inc_get(f, ids[i], &one) <= 0) continue;
            if (k++) web_jw_raw(&w, ",");
            inc_json(&w, &one);
        }
    }
    sqlite3_finalize(st);
    web_jw_raw(&w, "],\"more\":");
    web_jw_raw(&w, more ? "true" : "false");
    web_jw_raw(&w, "}\n");
    return answer(&w, body, len, status);
}

int web_incident_get(const web_m4_t *m, const char *query, char *body, size_t cap,
                     size_t *len, int *status) {
    web_param_t ps[1] = { { "id", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    long long id = 0;
    const char *p = ps[0].val;
    size_t n = strlen(p);
    if (!ps[0].seen || n == 0 || n > 15 || p[0] == '0') n = 0;
    for (size_t i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') { n = 0; break; }
        id = id * 10 + (p[i] - '0');
    }
    if (!n) return frrs_error(400, "bad_id", NULL, body, cap, len, status);
    web_frrs_t *f = m->frrs;
    if (!f || !f->wr) return frrs_error(503, "no_store", NULL, body, cap, len, status);
    inc_t one;
    int g = inc_get(f, id, &one);
    if (g < 0) return frrs_error(500, "store_error", NULL, body, cap, len, status);
    if (g == 0) return frrs_error(404, "no_such_incident", NULL, body, cap, len, status);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"store\":\"open\",\"writes\":");
    web_jw_raw(&w, f->writes ? "true" : "false");
    web_jw_raw(&w, ",\"incident\":");
    inc_json(&w, &one);
    members_json(f, id, &w);
    web_jw_raw(&w, "}\n");
    return answer(&w, body, len, status);
}

#else

int frrs_inc_overlay(web_frrs_t *f, const tri_subj_t *s, web_tri_t *t) {
    (void)f; (void)s; (void)t;
    return 0;
}

long long web_incident_rows(web_frrs_t *f) { (void)f; return -1; }

int web_incident_post(const web_m4_t *m, web_live_t *live, const web_jrec_t *r, const char *peer,
                      int via, long long now_s, char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)live; (void)r; (void)peer; (void)via; (void)now_s;
    (void)decided_of; (void)type_json;
    return frrs_error(503, "no_store", NULL, body, cap, len, status);
}

int web_incident_list(const web_m4_t *m, const char *query, char *body, size_t cap,
                      size_t *len, int *status) {
    (void)m;
    web_param_t ps[1] = { { "state", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    if (ps[0].seen && strcmp(ps[0].val, "open") && strcmp(ps[0].val, "closed") &&
        strcmp(ps[0].val, "all"))
        return frrs_error(400, "bad_state", NULL, body, cap, len, status);
    int n = snprintf(body, cap, "{\"store\":\"none\",\"writes\":false,\"cap\":%d,\"title_max\":%d,"
                     "\"ids_max\":%d,\"incidents\":[],\"more\":false}\n", WEB_INC_CAP,
                     WEB_INC_TITLE_MAX, WEB_FRRS_BULK_MAX);
    if (n < 0 || (size_t)n >= cap) return -1;
    *len = (size_t)n;
    *status = 200;
    return 0;
}

int web_incident_get(const web_m4_t *m, const char *query, char *body, size_t cap,
                     size_t *len, int *status) {
    (void)m; (void)query;
    return frrs_error(503, "no_store", NULL, body, cap, len, status);
}

#endif
