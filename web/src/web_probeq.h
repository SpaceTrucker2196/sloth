/* What the SSID detail (web_ssidview.c) and the Probes routes
 * (web_probes.c) share: the error answer, the bounds of a decimal
 * parameter, and the few lines every sloth.db read of theirs repeats.
 * Private to those two files; each function is static inline so a file
 * that uses only some of them builds without a warning. */
#ifndef SLOTHWEB_PROBEQ_H
#define SLOTHWEB_PROBEQ_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "web_devices.h"
#include "web_json.h"
#include "web_oui.h"
#include "web_slothdb.h"
#include "web_ssid.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif


static inline int answer_error(int status, const char *reason, const char *detail,
                        char *body, size_t cap, size_t *len, int *st) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"error\":");
    web_jw_str(&w, reason);
    if (detail) {
        web_jw_raw(&w, ",\"detail\":");
        web_jw_strn(&w, detail, strnlen(detail, 240));
    }
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *st = status;
    return 0;
}

static inline int no_db(const web_m4_t *m) {
    return !m || !m->sdb || !m->sdb->configured || !web_slothdb_available();
}

#define NO_DB_ANSWER() \
    answer_error(503, "no_sloth_db", \
                 "start slothweb with --sloth-db PATH (a WITH_SQLITE build)", \
                 body, cap, len, status)

static inline int decimal(const char *s, long long lo, long long hi, long long *out) {
    size_t n = strlen(s);
    if (n == 0 || n > 6) return -1;
    long long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

#ifdef WITH_SQLITE


static inline void jw_bool(web_jw_t *w, int v) { web_jw_raw(w, v ? "true" : "false"); }

static inline void jw_text_or_null(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s);
    else web_jw_raw(w, "null");
}

static inline void jw_signal(web_jw_t *w, int has, long long v) {
    if (has) web_jw_int(w, v < -200 ? -200 : v > 50 ? 50 : v);
    else web_jw_raw(w, "null");
}

/* A canonical MAC's locally administered bit: a randomised or software
 * address (IEEE 802-2014 8.2.2). */
static inline int mac_random(const char *mac) {
    char c = mac[1];
    int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : 0;
    return (v & 2) != 0;
}

/* "mac", "random" and "vendor" (the OUI table's, null for none and for
 * a randomised address, which no registry assigned). */
static inline void jw_mac(web_jw_t *w, const web_m4_t *m, const char *mac) {
    web_jw_raw(w, "{\"mac\":");      web_jw_str(w, mac);
    web_jw_raw(w, ",\"random\":");   jw_bool(w, mac_random(mac));
    web_jw_raw(w, ",\"vendor\":");
    uint8_t b[6];
    web_oui_hit_t hit;
    if (m->oui && !mac_random(mac) && web_oui_mac_bytes(mac, b) == 0 &&
        web_oui_lookup(m->oui, b, &hit))
        web_jw_str(w, hit.name);
    else
        web_jw_raw(w, "null");
}

static inline void jw_ssid_obj(web_jw_t *w, const char *ssid) {
    web_jw_raw(w, "{\"ssid\":");
    web_jw_ssid(w, ssid);
    web_jw_ssid_meta(w, "ssid", ssid);
}

static inline sqlite3_stmt *prep(web_sdb_conn_t *c, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return NULL;
    }
    return st;
}

static inline void bind_t(sqlite3_stmt *st, int i, const char *s) {
    sqlite3_bind_text(st, i, s, -1, SQLITE_TRANSIENT);
}

static inline void ctext(sqlite3_stmt *st, int col, char *out, size_t max) {
    const unsigned char *v = sqlite3_column_text(st, col);
    web_utf8_copy(out, max, v ? (const char *)v : "");
}

/* A MAC column as the routes spell one, or 0: a row whose address is
 * not one (a file something else wrote) is not shown. */
static inline int cmac(sqlite3_stmt *st, int col, char *out) {
    char raw[WEB_SDB_TEXT_MAX + 1];
    ctext(st, col, raw, sizeof(raw) - 1);
    return web_dev_canon_mac(raw, out) == 0;
}

/* One count: the statement's first column, -1 when it could not run. */
static inline long long one_count(web_sdb_conn_t *c, const char *sql, const char *a,
                           int has_i, long long i2) {
    sqlite3_stmt *st = prep(c, sql);
    if (!st) return -1;
    int k = 1;
    if (a) bind_t(st, k++, a);
    if (has_i) sqlite3_bind_int64(st, k, i2);
    long long v = sqlite3_step(st) == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    return v;
}

static inline int open_db(const web_m4_t *m, web_sdb_conn_t *conn, long long now_s,
                   char *body, size_t cap, size_t *len, int *status) {
    char oerr[WEB_SDB_ERR_MAX];
    if (web_slothdb_open(m->sdb, conn, WEB_SDB_HTTP_MS, now_s, oerr,
                         sizeof(oerr)) == 0) {
        conn->scope = m->sc ? m->sc->scope : WEB_SCOPE_HYBRID;
        conn->sc = m->sc;
        conn->ru = m->tsdb ? m->tsdb->ru : NULL;
        return 0;
    }
    web_slothdb_close(conn);
    web_sdb_stats_t st;
    web_slothdb_stats(m->sdb, &st);
    char r[48];
    snprintf(r, sizeof(r), "sloth_db_%s", web_slothdb_state_word(st.state));
    answer_error(503, r, oerr, body, cap, len, status);
    return -1;
}

static inline int db_failed(web_sdb_conn_t *conn, char *body, size_t cap, size_t *len,
                     int *status) {
    int to = conn->timed_out;
    web_slothdb_close(conn);
    return answer_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                        body, cap, len, status);
}

#endif /* WITH_SQLITE */

#endif
