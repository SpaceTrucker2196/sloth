/* Plain notes on devices, BLE advertisers, SSIDs, satellites, aircraft
 * and APRS stations (web_notes.h). The write path, its gate and its
 * text rules are web_frrs.c's; this file is the subject's id, the note
 * table and the three routes. */
#include "web_notes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_adsb.h"
#include "web_aprs.h"
#include "web_frrs_int.h"
#include "web_gnss.h"
#include "web_series.h"
#include "web_ssid.h"
#include "web_ssidview.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

static const char *const KIND_WORD[WEB_NOTE_KINDS] = {
    "device", "ble", "ssid", "gnss", "aircraft", "aprs",
};
#ifdef WITH_SQLITE
static const char *const GONE_WORD[WEB_NOTE_KINDS] = {
    "no_such_device", "no_such_ble", "no_such_ssid", "no_such_satellite",
    "no_such_aircraft", "no_such_station",
};
#endif

const char *web_note_kind_word(int kind) {
    return kind >= 0 && kind < WEB_NOTE_KINDS ? KIND_WORD[kind] : "?";
}

int web_note_kind_find(const char *word) {
    for (int k = 0; word && k < WEB_NOTE_KINDS; k++)
        if (!strcmp(word, KIND_WORD[k])) return k;
    return -1;
}

/* ── the subject's id ──────────────────────────────────────────────── */

/* A decimal of 1..digits digits with no leading zero (but "0"), at most
 * hi; the characters used, or 0. */
static size_t dec_in(const char *s, int digits, long hi, long *out) {
    size_t n = 0;
    long v = 0;
    while (s[n] >= '0' && s[n] <= '9' && n < (size_t)digits) v = v * 10 + (s[n++] - '0');
    if (n == 0 || (s[n] >= '0' && s[n] <= '9') || (n > 1 && s[0] == '0') || v > hi) return 0;
    *out = v;
    return n;
}

static int gnss_parts(const char *id, long *gnssid, long *prn) {
    size_t a = dec_in(id, 3, 127, gnssid);
    if (!a || id[a] != '.') return -1;
    size_t b = dec_in(id + a + 1, 5, 32767, prn);
    return b && id[a + 1 + b] == '\0' ? 0 : -1;
}

int web_note_canon(int kind, const char *in, char *out) {
    out[0] = '\0';
    if (!in || !in[0] || strlen(in) > WEB_NOTE_ID_MAX) return -1;
    switch (kind) {
    case WEB_NOTE_DEVICE: {
        char mac[WEB_KEY_MAX + 1];
        if (web_dev_canon_mac(in, mac) != 0) return -1;
        snprintf(out, WEB_NOTE_ID_MAX + 1, "%.17s", mac);
        return 0;
    }
    case WEB_NOTE_BLE: {
        char canon[24];
        if (frrs_addr_canon(FRRS_K_BLE, in, canon, sizeof(canon)) != 0 || !strcmp(canon + 18, "255"))
            return -1;
        snprintf(out, WEB_NOTE_ID_MAX + 1, "%s", canon);
        return 0;
    }
    case WEB_NOTE_SSID: {
        /* The parameter is canonical or refused, so what was sent is
         * the one spelling of those octets. */
        char oct[WEB_SSID_OCTETS + 1];
        if (web_ssid_param(in, oct) <= 0) return -1;
        snprintf(out, WEB_NOTE_ID_MAX + 1, "%s", in);
        return 0;
    }
    case WEB_NOTE_GNSS: {
        long g, p;
        if (gnss_parts(in, &g, &p) != 0) return -1;
        snprintf(out, WEB_NOTE_ID_MAX + 1, "%ld.%ld", g, p);
        return 0;
    }
    case WEB_NOTE_AIRCRAFT: {
        const char *h = in[0] == '~' ? in + 1 : in;
        if (strlen(h) != 6) return -1;
        char *o = out;
        if (in[0] == '~') *o++ = '~';
        for (int i = 0; i < 6; i++) {
            char c = h[i];
            if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { out[0] = '\0'; return -1; }
            *o++ = c;
        }
        *o = '\0';
        return 0;
    }
    case WEB_NOTE_APRS:
        if (!web_aprs_call_ok(in)) return -1;
        snprintf(out, WEB_NOTE_ID_MAX + 1, "%s", in);
        return 0;
    default:
        return -1;
    }
}

/* ── is the subject one slothweb holds? ────────────────────────────── */

#ifdef WITH_SQLITE
/* 1 when sloth.db's beacon or probe tables name the SSID, 0 when none
 * does, -1 when it could not be asked. A table an older sloth.db lacks
 * is one that does not name it. */
static int ssid_in_db(const web_m4_t *m, const char *id, long long now_s) {
    if (!m->sdb || !m->sdb->configured) return -1;
    char oct[WEB_SSID_OCTETS + 1], err[200];
    if (web_ssid_param(id, oct) <= 0) return 0;
    web_sdb_conn_t c;
    if (web_slothdb_open(m->sdb, &c, WEB_SDB_HTTP_MS, now_s, err, sizeof(err)) != 0) {
        web_slothdb_close(&c);
        return -1;
    }
    static const char *const SQL[] = {
        "SELECT 1 FROM beacon_aps WHERE ssid = ?1 LIMIT 1",
        "SELECT 1 FROM beacon_ap_ssids WHERE ssid = ?1 LIMIT 1",
        "SELECT 1 FROM pnl_ssids WHERE ssid = ?1 LIMIT 1",
    };
    int held = 0;
    for (size_t i = 0; i < sizeof(SQL) / sizeof(SQL[0]) && !held; i++) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(c.db, SQL[i], -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, oct, -1, SQLITE_TRANSIENT);
            held = sqlite3_step(st) == SQLITE_ROW;
        }
        sqlite3_finalize(st);
    }
    int failed = c.timed_out;
    web_slothdb_close(&c);
    return held ? 1 : failed ? -1 : 0;
}

static int device_in_any(const web_m4_t *m, web_live_t *live, const char *mac, long long now_s) {
    web_sdb_conn_t c;
    char err[200];
    int have = m->sdb && m->sdb->configured &&
               web_slothdb_open(m->sdb, &c, WEB_SDB_HTTP_MS, now_s, err, sizeof(err)) == 0;
    int held = frrs_device_held(m, live, have ? &c : NULL, mac);
    if (m->sdb && m->sdb->configured) web_slothdb_close(&c);
    return held;
}
#else
static int ssid_in_db(const web_m4_t *m, const char *id, long long now_s) {
    (void)m; (void)id; (void)now_s;
    return -1;
}
static int device_in_any(const web_m4_t *m, web_live_t *live, const char *mac, long long now_s) {
    (void)now_s;
    return frrs_device_held(m, live, NULL, mac);
}
#endif

/* 1 held now, 0 not, -1 nothing here can say (no sloth.db for an SSID,
 * no panel for a satellite, aircraft or station). */
static int note_held(const web_m4_t *m, web_live_t *live, int kind, const char *id,
                     long long now_s) {
    switch (kind) {
    case WEB_NOTE_DEVICE:   return device_in_any(m, live, id, now_s);
    case WEB_NOTE_BLE:      return frrs_ble_held(m, id);
    case WEB_NOTE_SSID:     return ssid_in_db(m, id, now_s);
    case WEB_NOTE_GNSS: {
        long g, p;
        if (!m->gnss) return -1;
        if (gnss_parts(id, &g, &p) != 0) return 0;
        /* The table folds a constellation sloth does not name to 8. */
        return web_gnss_has(m->gnss, g > 7 ? 8 : (int)g, (int)p);
    }
    case WEB_NOTE_AIRCRAFT: return m->adsb ? web_adsb_has(m->adsb, id) : -1;
    case WEB_NOTE_APRS:     return m->aprs ? web_aprs_has(m->aprs, id) : -1;
    default:                return -1;
    }
}

/* ── the table ─────────────────────────────────────────────────────── */

#ifdef WITH_SQLITE

static long long note_cap(const web_frrs_t *f) { return f->note_cap > 0 ? f->note_cap : WEB_NOTE_CAP; }
static long long note_per(const web_frrs_t *f) { return f->note_per > 0 ? f->note_per : WEB_NOTE_PER; }

static void col_text(sqlite3_stmt *s, int i, char *out, size_t cap) {
    const unsigned char *t = sqlite3_column_text(s, i);
    web_utf8_copy(out, cap - 1, t ? (const char *)t : "");
}

/* One number of a statement that binds a kind and a subject (either may
 * be unused by the text), or -1. */
static long long count_q(web_frrs_t *f, const char *sql, int kind, const char *subject) {
    sqlite3_stmt *s = NULL;
    long long n = -1;
    if (sqlite3_prepare_v2(f->wr, sql, -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_int(s, 1, kind);
        sqlite3_bind_text(s, 2, subject ? subject : "", -1, SQLITE_TRANSIENT);
        if (sqlite3_step(s) == SQLITE_ROW) n = (long long)sqlite3_column_double(s, 0);
    }
    sqlite3_finalize(s);
    return n;
}

#define SUBJ_ROWS "SELECT COUNT(*) FROM note WHERE kind = ?1 AND subject = ?2"
#define ALL_ROWS  "SELECT COUNT(*) FROM note"
/* A note (not a retraction) that no row takes back. */
#define LIVE(t) t "retracts = 0 AND NOT EXISTS (SELECT 1 FROM note r WHERE r.kind = " t "kind" \
                " AND r.subject = " t "subject AND r.retracts = " t "id)"

long long web_notes_rows(web_frrs_t *f) {
    return f && f->wr ? count_q(f, ALL_ROWS, 0, "") : -1;
}

/* Up to max retracted notes folded, oldest first, each with the row
 * that took it back: of one subject (all 0) or of the whole table. A
 * note nothing took back is never a candidate. The count each pair
 * carried goes, with the pair's own rows, to the subject's oldest row
 * left (lost when none is). The rows deleted, or -1. Inside the
 * caller's transaction. */
#define NOTE_FOLD_MAX 256
static long long fold_retracted(web_frrs_t *f, int all, int kind, const char *subject,
                                long long max) {
    typedef struct { long long id; int kind; char subject[WEB_NOTE_ID_MAX + 1]; } cand_t;
    if (max <= 0) return 0;
    if (max > NOTE_FOLD_MAX) max = NOTE_FOLD_MAX;
    cand_t *c = calloc((size_t)max, sizeof(*c));
    if (!c) return -1;
    sqlite3_stmt *st = NULL, *sum = NULL, *del = NULL, *add = NULL;
    long long k = 0, gone = -1;
    int rc = SQLITE_ERROR;
    if (sqlite3_prepare_v2(f->wr,
            "SELECT n.id, n.kind, n.subject FROM note n WHERE n.retracts = 0 AND"
            " (?1 <> 0 OR (n.kind = ?2 AND n.subject = ?3)) AND EXISTS (SELECT 1 FROM note r"
            " WHERE r.kind = n.kind AND r.subject = n.subject AND r.retracts = n.id)"
            " ORDER BY n.id LIMIT ?4", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, all);
        sqlite3_bind_int(st, 2, kind);
        sqlite3_bind_text(st, 3, subject ? subject : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, max);
        while ((rc = sqlite3_step(st)) == SQLITE_ROW && k < max) {
            c[k].id = sqlite3_column_int64(st, 0);
            c[k].kind = sqlite3_column_int(st, 1);
            col_text(st, 2, c[k].subject, sizeof(c[k].subject));
            k++;
        }
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) goto out;
#define PAIR " kind = ?2 AND subject = ?3 AND (id = ?1 OR retracts = ?1)"
    if (sqlite3_prepare_v2(f->wr, "SELECT TOTAL(folded) FROM note WHERE" PAIR, -1, &sum, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(f->wr, "DELETE FROM note WHERE" PAIR, -1, &del, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(f->wr, "UPDATE note SET folded = folded + ?1 WHERE id = (SELECT MIN(id)"
                           " FROM note WHERE kind = ?2 AND subject = ?3)", -1, &add, NULL) != SQLITE_OK)
        goto out;
#undef PAIR
    /* Collected first, deleted after: never a delete under an open read. */
    gone = 0;
    for (long long i = 0; i < k; i++) {
        long long carried = 0;
        sqlite3_stmt *two[2] = { sum, del };
        for (int q = 0; q < 2; q++) {
            sqlite3_bind_int64(two[q], 1, c[i].id);
            sqlite3_bind_int(two[q], 2, c[i].kind);
            sqlite3_bind_text(two[q], 3, c[i].subject, -1, SQLITE_TRANSIENT);
            int r = sqlite3_step(two[q]);
            if (q == 0 && r == SQLITE_ROW) carried = (long long)sqlite3_column_double(sum, 0);
            sqlite3_reset(two[q]);
            if (r != (q ? SQLITE_DONE : SQLITE_ROW)) { gone = -1; goto out; }
        }
        long long n = sqlite3_changes(f->wr);
        sqlite3_bind_int64(add, 1, n + carried);
        sqlite3_bind_int(add, 2, c[i].kind);
        sqlite3_bind_text(add, 3, c[i].subject, -1, SQLITE_TRANSIENT);
        int r = sqlite3_step(add);
        sqlite3_reset(add);
        if (r != SQLITE_DONE) { gone = -1; goto out; }
        gone += n;
    }
out:
    sqlite3_finalize(sum);
    sqlite3_finalize(del);
    sqlite3_finalize(add);
    free(c);
    return gone;
}

static int note_insert(web_frrs_t *f, int kind, const char *subject, const char *text,
                       const char *by, const char *peer, int via, long long retracts,
                       long long now_s, long long *nid) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(f->wr, "INSERT INTO note (kind, subject, text, who, peer, via, retracts, ts)"
                           " VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", -1, &s, NULL) != SQLITE_OK) {
        sqlite3_finalize(s);
        return -1;
    }
    sqlite3_bind_int(s, 1, kind);
    sqlite3_bind_text(s, 2, subject, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, text, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, by, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, peer, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 6, via);
    sqlite3_bind_int64(s, 7, retracts);
    sqlite3_bind_int64(s, 8, now_s);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) return -1;
    *nid = sqlite3_last_insert_rowid(f->wr);
    return 0;
}

static void folded_stat(web_frrs_t *f, long long n) {
    if (n <= 0) return;
    pthread_mutex_lock(&f->lmu);
    f->st.notes_folded += (unsigned long)n;
    pthread_mutex_unlock(&f->lmu);
}

/* One note in one transaction: 0 written (*nid), 1 refused (*why), -1. */
static int note_add(web_frrs_t *f, int kind, const char *subject, const char *text,
                    const char *by, const char *peer, int via, long long now_s,
                    long long *nid, const char **why) {
    if (sqlite3_exec(f->wr, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        *why = "store_busy";
        return -1;
    }
    int rc = -1;
    long long folded = 0, k;
    *why = "store_error";
    long long per = count_q(f, SUBJ_ROWS, kind, subject);
    if (per < 0) goto out;
    if (per >= note_per(f)) {
        /* A retracted note and its retraction are two rows: one pair
         * makes the room one note needs. */
        if ((k = fold_retracted(f, 0, kind, subject, per - note_per(f) + 1)) < 0) goto out;
        folded += k;
        if ((per = count_q(f, SUBJ_ROWS, kind, subject)) < 0) goto out;
    }
    if (per >= note_per(f)) { *why = "notes_full"; rc = 1; goto out; }
    long long total = count_q(f, ALL_ROWS, 0, "");
    if (total < 0) goto out;
    if (total >= note_cap(f)) {
        long long batch = note_cap(f) / WEB_NOTE_FOLD_DIV;
        if ((k = fold_retracted(f, 1, 0, NULL, batch > 0 ? batch : 1)) < 0) goto out;
        folded += k;
        if ((total = count_q(f, ALL_ROWS, 0, "")) < 0) goto out;
    }
    if (total >= note_cap(f)) { *why = "notes_full"; rc = 1; goto out; }
    if (note_insert(f, kind, subject, text, by, peer, via, 0, now_s, nid) != 0) goto out;
    rc = 0;
out:
    if (rc == 0 && sqlite3_exec(f->wr, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) rc = -1;
    if (rc != 0) sqlite3_exec(f->wr, "ROLLBACK", NULL, NULL, NULL);
    else folded_stat(f, folded);
    return rc;
}

/* Note nid of the subject taken back, by a row: 0 written, 2 it already
 * was, 3 the subject has no such note, -1. Never refused for room: past
 * a cap, the oldest retracted pairs fold at once, this one among them. */
static int note_retract(web_frrs_t *f, int kind, const char *subject, long long nid,
                        const char *reason, const char *by, const char *peer, int via,
                        long long now_s, const char **why) {
    if (sqlite3_exec(f->wr, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        *why = "store_busy";
        return -1;
    }
    int rc = -1;
    long long folded = 0, k, rid = 0;
    *why = "store_error";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(f->wr,
            "SELECT EXISTS (SELECT 1 FROM note r WHERE r.kind = n.kind AND r.subject = n.subject"
            " AND r.retracts = n.id) FROM note n WHERE n.id = ?3 AND n.kind = ?1 AND"
            " n.subject = ?2 AND n.retracts = 0", -1, &s, NULL) != SQLITE_OK)
        goto out;
    sqlite3_bind_int(s, 1, kind);
    sqlite3_bind_text(s, 2, subject, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 3, nid);
    int st = sqlite3_step(s);
    if (st == SQLITE_DONE) { rc = 3; goto out; }
    if (st != SQLITE_ROW) goto out;
    if (sqlite3_column_int(s, 0)) { rc = 2; goto out; }
    sqlite3_finalize(s);
    s = NULL;
    if (note_insert(f, kind, subject, reason, by, peer, via, nid, now_s, &rid) != 0) goto out;
    long long per = count_q(f, SUBJ_ROWS, kind, subject);
    if (per < 0) goto out;
    if (per > note_per(f)) {
        if ((k = fold_retracted(f, 0, kind, subject, (per - note_per(f) + 1) / 2)) < 0) goto out;
        folded += k;
    }
    long long total = count_q(f, ALL_ROWS, 0, "");
    if (total < 0) goto out;
    if (total > note_cap(f)) {
        if ((k = fold_retracted(f, 1, 0, NULL, (total - note_cap(f) + 1) / 2)) < 0) goto out;
        folded += k;
    }
    rc = 0;
out:
    sqlite3_finalize(s);
    if ((rc == 0 || rc == 2) && sqlite3_exec(f->wr, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) rc = -1;
    if (rc != 0 && rc != 2) sqlite3_exec(f->wr, "ROLLBACK", NULL, NULL, NULL);
    else folded_stat(f, folded);
    return rc;
}

/* The subject's notes, newest first, each with the row that took it
 * back; those below `before` when it is not 0. The list stops before a
 * row that might not fit ("more", and "next" to continue from). */
static void rows_json(web_frrs_t *f, int kind, const char *subject, long long before,
                      web_jw_t *w, size_t cap) {
    sqlite3_stmt *st = NULL;
    int more = 0;
    long long next = 0;
    web_jw_raw(w, ",\"notes\":[");
    if (f && f->wr && sqlite3_prepare_v2(f->wr,
            "SELECT n.id, n.text, n.who, n.peer, n.via, n.ts, r.id, r.text, r.who, r.peer,"
            " r.via, r.ts FROM note n LEFT JOIN note r ON r.kind = n.kind AND"
            " r.subject = n.subject AND r.retracts = n.id WHERE n.kind = ?1 AND n.subject = ?2"
            " AND n.retracts = 0 AND (?3 = 0 OR n.id < ?3) ORDER BY n.id DESC, r.id",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, kind);
        sqlite3_bind_text(st, 2, subject, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, before);
        int k = 0;
        long long last = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            long long id = sqlite3_column_int64(st, 0);
            if (id == last) continue;        /* one retraction is shown */
            if (w->len + WEB_NOTE_ROW_MAX + 512 >= cap) { more = 1; next = last; break; }
            last = id;
            char t[WEB_FRRS_NOTE_MAX + 1];
            web_jw_raw(w, k++ ? ",{\"note\":" : "{\"note\":");
            web_jw_int(w, id);
            web_jw_raw(w, ",\"ts\":");   web_jw_int(w, sqlite3_column_int64(st, 5));
            col_text(st, 1, t, sizeof(t));
            web_jw_raw(w, ",\"text\":"); web_jw_str(w, t);
            col_text(st, 2, t, sizeof(t));
            web_jw_raw(w, ",\"by\":");   web_jw_str(w, t);
            col_text(st, 3, t, sizeof(t));
            web_jw_raw(w, ",\"peer\":"); web_jw_str(w, t);
            web_jw_raw(w, ",\"via\":");  web_jw_str(w, web_frrs_via_word(sqlite3_column_int(st, 4)));
            web_jw_raw(w, ",\"retracted\":");
            if (sqlite3_column_type(st, 6) == SQLITE_NULL) {
                web_jw_raw(w, "null}");
                continue;
            }
            web_jw_raw(w, "{\"ts\":");     web_jw_int(w, sqlite3_column_int64(st, 11));
            col_text(st, 7, t, sizeof(t));
            web_jw_raw(w, ",\"reason\":"); web_jw_str(w, t);
            col_text(st, 8, t, sizeof(t));
            web_jw_raw(w, ",\"by\":");     web_jw_str(w, t);
            col_text(st, 9, t, sizeof(t));
            web_jw_raw(w, ",\"peer\":");   web_jw_str(w, t);
            web_jw_raw(w, ",\"via\":");    web_jw_str(w, web_frrs_via_word(sqlite3_column_int(st, 10)));
            web_jw_raw(w, "}}");
        }
    }
    sqlite3_finalize(st);
    web_jw_raw(w, "],\"more\":");
    web_jw_raw(w, more ? "true" : "false");
    web_jw_raw(w, ",\"next\":");
    if (more) web_jw_int(w, next); else web_jw_raw(w, "null");
}

static void counts_json(web_frrs_t *f, int kind, const char *subject, web_jw_t *w) {
    static const char *const K[] = { ",\"rows\":", ",\"live\":", ",\"folded\":" };
    static const char *const SQL[] = {
        SUBJ_ROWS,
        "SELECT COUNT(*) FROM note n WHERE n.kind = ?1 AND n.subject = ?2 AND " LIVE("n."),
        "SELECT TOTAL(folded) FROM note WHERE kind = ?1 AND subject = ?2",
    };
    for (int i = 0; i < 3; i++) {
        long long n = f && f->wr ? count_q(f, SQL[i], kind, subject) : -1;
        web_jw_raw(w, K[i]);
        if (n < 0) web_jw_raw(w, "null"); else web_jw_int(w, n);
    }
}

#else

long long web_notes_rows(web_frrs_t *f) { (void)f; return -1; }

static void rows_json(web_frrs_t *f, int kind, const char *subject, long long before,
                      web_jw_t *w, size_t cap) {
    (void)f; (void)kind; (void)subject; (void)before; (void)cap;
    web_jw_raw(w, ",\"notes\":[],\"more\":false,\"next\":null");
}

static void counts_json(web_frrs_t *f, int kind, const char *subject, web_jw_t *w) {
    (void)f; (void)kind; (void)subject;
    web_jw_raw(w, ",\"rows\":null,\"live\":null,\"folded\":null");
}

#endif

/* ── the answers ───────────────────────────────────────────────────── */

/* {"kind":..,"id":..,...}: the subject and its notes, one object. */
static void notes_json(const web_m4_t *m, web_live_t *live, int kind, const char *id,
                       long long before, long long now_s, web_jw_t *w, size_t cap) {
    web_frrs_t *f = m->frrs;
    int held = note_held(m, live, kind, id, now_s);
    web_jw_raw(w, "{\"kind\":");    web_jw_str(w, KIND_WORD[kind]);
    web_jw_raw(w, ",\"id\":");      web_jw_str(w, id);
    if (kind == WEB_NOTE_SSID) {
        /* The display form of the octets the id spells, made here and
         * never stored: what the page and an agent show for it. */
        char oct[WEB_SSID_OCTETS + 1];
        if (web_ssid_param(id, oct) > 0) {
            web_jw_raw(w, ",\"ssid\":");
            web_jw_ssid(w, oct);
            web_jw_ssid_meta(w, "ssid", oct);
        }
    }
    web_jw_raw(w, ",\"held\":");
    web_jw_raw(w, held < 0 ? "null" : held ? "true" : "false");
    web_jw_raw(w, ",\"store\":");   web_jw_str(w, f && f->wr ? "open" : "none");
    web_jw_raw(w, ",\"writes\":");  web_jw_raw(w, f && f->wr && f->writes ? "true" : "false");
    web_jw_raw(w, ",\"cap\":");     web_jw_int(w, f && f->note_per > 0 ? f->note_per : WEB_NOTE_PER);
    web_jw_raw(w, ",\"text_max\":"); web_jw_int(w, WEB_FRRS_NOTE_MAX);
    counts_json(f, kind, id, w);
    rows_json(f, kind, id, before, w, cap);
    web_jw_raw(w, "}");
}

int web_notes_get(const web_m4_t *m, web_live_t *live, const char *query, long long now_s,
                  char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[3] = { { "kind", "", 0 }, { "id", "", 0 }, { "before", "", 0 } };
    char err[48], id[WEB_NOTE_ID_MAX + 1];
    if (web_params_parse(query, ps, 3, err, sizeof(err)) != 0)
        return frrs_error(400, err, NULL, body, cap, len, status);
    int kind = ps[0].seen ? web_note_kind_find(ps[0].val) : -1;
    if (kind < 0) return frrs_error(400, ps[0].seen ? "bad_kind" : "missing_kind", NULL, body, cap, len, status);
    if (!ps[1].seen) return frrs_error(400, "missing_id", NULL, body, cap, len, status);
    if (web_note_canon(kind, ps[1].val, id) != 0)
        return frrs_error(400, "bad_id", NULL, body, cap, len, status);
    long long before = 0;
    if (ps[2].seen) {
        const char *p = ps[2].val;
        size_t n = strlen(p);
        if (n > 15 || p[0] == '0') n = 0;
        for (size_t i = 0; i < n; i++) {
            if (p[i] < '0' || p[i] > '9') { n = 0; break; }
            before = before * 10 + (p[i] - '0');
        }
        if (!n) return frrs_error(400, "bad_before", NULL, body, cap, len, status);
    }
    web_jw_t w;
    web_jw_init(&w, body, cap);
    notes_json(m, live, kind, id, before, now_s, &w, cap);
    web_jw_raw(&w, "\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

int web_notes_marks(const web_m4_t *m, const char *query, char *body, size_t cap,
                    size_t *len, int *status) {
    /* kind=<word>&ids=a,b,c: the ids as they are, never percent-encoded
     * (every kind's alphabet is legal in a query), so a table's page of
     * rows fits the query's bound. */
    char kw[16];
    const char *amp = strchr(query, '&');
    if (strncmp(query, "kind=", 5) || !amp || (size_t)(amp - query - 5) >= sizeof(kw) ||
        strncmp(amp + 1, "ids=", 4))
        return frrs_error(400, "bad_query", NULL, body, cap, len, status);
    memcpy(kw, query + 5, (size_t)(amp - query - 5));
    kw[amp - query - 5] = '\0';
    int kind = web_note_kind_find(kw);
    if (kind < 0) return frrs_error(400, "bad_kind", NULL, body, cap, len, status);
    char ids[WEB_NOTE_MARK_IDS][WEB_NOTE_ID_MAX + 1];
    int n = 0;
    for (const char *p = amp + 5; ; ) {
        size_t l = strcspn(p, ",&%");
        char raw[WEB_NOTE_ID_MAX + 1];
        if (l == 0 || l > WEB_NOTE_ID_MAX || n >= WEB_NOTE_MARK_IDS || p[l] == '&' || p[l] == '%')
            return frrs_error(400, "bad_ids", NULL, body, cap, len, status);
        memcpy(raw, p, l);
        raw[l] = '\0';
        if (web_note_canon(kind, raw, ids[n]) != 0)
            return frrs_error(400, "bad_ids", NULL, body, cap, len, status);
        n++;
        if (!p[l]) break;
        p += l + 1;
    }
    web_frrs_t *f = m->frrs;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"kind\":");   web_jw_str(&w, KIND_WORD[kind]);
    web_jw_raw(&w, ",\"store\":");  web_jw_str(&w, f && f->wr ? "open" : "none");
    web_jw_raw(&w, ",\"marks\":{");
#ifdef WITH_SQLITE
    sqlite3_stmt *st = NULL;
    if (f && f->wr && sqlite3_prepare_v2(f->wr,
            "SELECT COUNT(*), TOTAL(n.via = 3), MAX(n.ts) FROM note n WHERE n.kind = ?1 AND"
            " n.subject = ?2 AND " LIVE("n."), -1, &st, NULL) == SQLITE_OK) {
        for (int i = 0, k = 0; i < n; i++) {
            int dup = 0;
            for (int j = 0; j < i && !dup; j++) dup = !strcmp(ids[j], ids[i]);
            if (dup) continue;
            sqlite3_bind_int(st, 1, kind);
            sqlite3_bind_text(st, 2, ids[i], -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int64(st, 0) > 0) {
                if (k++) web_jw_raw(&w, ",");
                web_jw_key(&w, ids[i]);
                web_jw_raw(&w, "{\"n\":");     web_jw_int(&w, sqlite3_column_int64(st, 0));
                web_jw_raw(&w, ",\"agent\":"); web_jw_int(&w, (long long)sqlite3_column_double(st, 1));
                web_jw_raw(&w, ",\"ts\":");    web_jw_int(&w, sqlite3_column_int64(st, 2));
                web_jw_raw(&w, "}");
            }
            sqlite3_reset(st);
        }
    }
    sqlite3_finalize(st);
#endif
    web_jw_raw(&w, "}}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

#ifdef WITH_SQLITE
int web_notes_post(const web_m4_t *m, web_live_t *live, const web_jrec_t *r, const char *peer,
                   int via, long long now_s, char *body, size_t cap, size_t *len, int *status) {
    static const char *const MEMBERS[] = { "op", "kind", "id", "text", "by", "note", NULL };
    const char *bad = NULL, *why = NULL;
    if (!frrs_members_ok(r, MEMBERS, &bad))
        return frrs_error(400, "unknown_member", bad, body, cap, len, status);
    char op[12], kw[16], raw[WEB_NOTE_ID_MAX + 1], id[WEB_NOTE_ID_MAX + 1];
    char text[WEB_FRRS_NOTE_MAX + 1], by[WEB_FRRS_BY_MAX + 1];
    if (!frrs_text(r, "op", sizeof(op) - 1, op, &why))
        return frrs_error(400, why, "op", body, cap, len, status);
    if (!frrs_text(r, "kind", sizeof(kw) - 1, kw, &why))
        return frrs_error(400, why, "kind", body, cap, len, status);
    if (!frrs_text(r, "id", WEB_NOTE_ID_MAX, raw, &why))
        return frrs_error(400, why, "id", body, cap, len, status);
    if (!frrs_text(r, "text", WEB_FRRS_NOTE_MAX, text, &why))
        return frrs_text_refused(r, "text", WEB_FRRS_NOTE_MAX, why, body, cap, len, status);
    if (!frrs_text(r, "by", WEB_FRRS_BY_MAX, by, &why))
        return frrs_text_refused(r, "by", WEB_FRRS_BY_MAX, why, body, cap, len, status);
    int add = !strcmp(op, "add"), ret = !strcmp(op, "retract");
    if (!add && !ret) return frrs_error(400, "bad_op", "op", body, cap, len, status);
    int kind = web_note_kind_find(kw);
    if (kind < 0) return frrs_error(400, kw[0] ? "bad_kind" : "missing_kind", "kind", body, cap, len, status);
    if (!raw[0]) return frrs_error(400, "missing_id", "id", body, cap, len, status);
    if (web_note_canon(kind, raw, id) != 0)
        return frrs_error(400, "bad_id", "id", body, cap, len, status);
    web_frrs_t *f = m->frrs;
    long long nid = 0;
    int unchanged = 0;
    if (add) {
        /* A note says something: an empty one is not a note. */
        if (!text[0]) return frrs_error(400, "missing_text", "text", body, cap, len, status);
        if (web_jl_get(r, "note")) return frrs_error(400, "unknown_member", "note", body, cap, len, status);
        /* The subject is held now: a note on nothing is never written. */
        int held = note_held(m, live, kind, id, now_s);
        if (held < 0)
            return frrs_error(503, kind == WEB_NOTE_SSID ? "no_sloth_db" : "no_holder", NULL, body,
                              cap, len, status);
        if (held == 0) return frrs_error(404, GONE_WORD[kind], "id", body, cap, len, status);
        int g = note_add(f, kind, id, text, by, peer, via, now_s, &nid, &why);
        if (g != 0) {
            if (g < 0) frrs_stat_inc(f, &f->st.write_errors);
            return frrs_error(g > 0 ? 507 : !strcmp(why, "store_busy") ? 503 : 500, why, NULL, body,
                              cap, len, status);
        }
        frrs_stat_inc(f, &f->st.writes);
        frrs_stat_inc(f, &f->st.notes_added);
    } else {
        const web_jfield_t *nf = web_jl_get(r, "note");
        nid = web_jl_int(r, "note", 0);
        if (!nf || nf->kind != WEB_J_INT || nid <= 0)
            return frrs_error(400, "bad_note", "note", body, cap, len, status);
        int g = note_retract(f, kind, id, nid, text, by, peer, via, now_s, &why);
        if (g == 3) return frrs_error(404, "no_such_note", "note", body, cap, len, status);
        if (g < 0) {
            frrs_stat_inc(f, &f->st.write_errors);
            return frrs_error(!strcmp(why, "store_busy") ? 503 : 500, why, NULL, body, cap, len, status);
        }
        unchanged = g == 2;
        if (!unchanged) {
            frrs_stat_inc(f, &f->st.writes);
            frrs_stat_inc(f, &f->st.notes_retracted);
        }
    }
    /* The answer is the store's, read again: the page redraws from it,
     * never from what it sent. */
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"ok\":true,\"unchanged\":");
    web_jw_raw(&w, unchanged ? "true" : "false");
    web_jw_raw(&w, ",\"note\":");
    web_jw_int(&w, nid);
    web_jw_raw(&w, ",\"notes\":");
    notes_json(m, live, kind, id, 0, now_s, &w, cap);
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}
#else
int web_notes_post(const web_m4_t *m, web_live_t *live, const web_jrec_t *r, const char *peer,
                   int via, long long now_s, char *body, size_t cap, size_t *len, int *status) {
    (void)m; (void)live; (void)r; (void)peer; (void)via; (void)now_s;
    return frrs_error(503, "no_store", NULL, body, cap, len, status);
}
#endif
