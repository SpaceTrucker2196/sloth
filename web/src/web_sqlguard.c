/* The SQL box's guard (#163): the text rules, the authorizer, the
 * limits and the runner (web_sqlbox.h). No state, no thread and no
 * opener of its own, so a fuzz harness can drive it over any
 * connection (tests/fuzz/fuzz_web_sqlbox.c). */
#include "web_sqlbox.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "web_json.h"
#include "web_ssid.h"

/* ── the text (pure) ──────────────────────────────────────────────────── */

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int web_sqlbox_param(const char *query, char *sql, size_t cap, size_t *len,
                     const char **why) {
    *len = 0;
    if (cap) sql[0] = '\0';
    if (!query || !query[0]) { *why = "missing_sql"; return -1; }
    int seen = 0;
    const char *p = query;
    for (;;) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', seg);
        if (!seg || !eq || eq == p) { *why = "bad_query"; return -1; }
        if ((size_t)(eq - p) != 3 || memcmp(p, "sql", 3) != 0) {
            *why = "unknown_parameter";
            return -1;
        }
        if (seen++) { *why = "repeated_parameter"; return -1; }
        size_t o = 0;
        for (const char *v = eq + 1; v < p + seg; v++) {
            int c = (unsigned char)*v;
            if (c == '%') {
                if ((size_t)(p + seg - v) < 3) { *why = "bad_escape"; return -1; }
                int h = hexv((unsigned char)v[1]), l = hexv((unsigned char)v[2]);
                if (h < 0 || l < 0) { *why = "bad_escape"; return -1; }
                c = h * 16 + l;
                v += 2;
            } else if (c == '+') {
                c = ' ';
            }
            if (o + 1 >= cap || o >= WEB_SQL_MAX_BYTES) {
                *why = "too_long";
                return -1;
            }
            sql[o++] = (char)c;
        }
        sql[o] = '\0';
        if (!o) { *why = "empty_value"; return -1; }
        *len = o;
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

static int blank_byte(int c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
           c == '\v';
}

/* Past the blanks and comments at p; SQLite's own rules: "--" runs to
 * the end of the line, an unterminated block comment to the end. */
static size_t skip_blank(const char *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        if (blank_byte((unsigned char)p[i])) { i++; continue; }
        if (p[i] == '-' && i + 1 < n && p[i + 1] == '-') {
            while (i < n && p[i] != '\n') i++;
            continue;
        }
        if (p[i] == '/' && i + 1 < n && p[i + 1] == '*') {
            i += 2;
            while (i + 1 < n && !(p[i] == '*' && p[i + 1] == '/')) i++;
            i = i + 1 < n ? i + 2 : n;
            continue;
        }
        break;
    }
    return i;
}

int web_sqlbox_blank(const char *p, size_t n) {
    return skip_blank(p, n) == n;
}

static int ident_byte(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '$' || c >= 0x80;
}

/* Does the keyword kw (upper case) start at p, followed by a byte that
 * cannot continue an identifier? */
static int keyword_at(const char *p, size_t n, const char *kw) {
    size_t k = strlen(kw);
    if (n < k) return 0;
    for (size_t i = 0; i < k; i++) {
        int c = (unsigned char)p[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c != kw[i]) return 0;
    }
    return n == k || !ident_byte((unsigned char)p[k]);
}

int web_sqlbox_precheck(const char *sql, size_t len, const char **why) {
    if (len == 0) { *why = "empty_value"; return -1; }
    if (len > WEB_SQL_MAX_BYTES) { *why = "too_long"; return -1; }
    for (size_t i = 0; i < len;) {
        unsigned cp;
        size_t l = web_utf8_seq((const unsigned char *)sql + i, len - i, &cp);
        if (l == 0) { *why = "bad_utf8"; return -1; }
        if ((cp < 0x20 && cp != '\t' && cp != '\n' && cp != '\r') ||
            cp == 0x7f) {
            *why = "control_byte";
            return -1;
        }
        i += l;
    }
    size_t s = skip_blank(sql, len);
    if (!keyword_at(sql + s, len - s, "SELECT") &&
        !keyword_at(sql + s, len - s, "WITH")) {
        *why = "not_select";
        return -1;
    }
    return 0;
}

size_t web_sqlbox_error(char *out, size_t cap, const char *why,
                        const char *detail) {
    web_jw_t w;
    web_jw_init(&w, out, cap);
    web_jw_raw(&w, "{\"error\":");
    web_jw_str(&w, why);
    if (detail && detail[0]) {
        web_jw_raw(&w, ",\"detail\":");
        web_jw_strn(&w, detail, strnlen(detail, 300));
    }
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}

#ifdef WITH_SQLITE

#include <sqlite3.h>

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Everything a recipe in docs/wiki/sqlite-schema.md calls, and the
 * plain scalar and aggregate functions an operator writes beside them.
 * Nothing that reads a file, loads code, makes a blob of a chosen size
 * or reaches past the statement. */
static const char *const FUNCS[] = {
    "count", "sum", "total", "avg", "min", "max", "group_concat",
    "coalesce", "ifnull", "nullif", "iif", "length", "lower", "upper",
    "substr", "substring", "instr", "trim", "ltrim", "rtrim", "replace",
    "abs", "round", "like", "glob", "date", "time", "datetime", "strftime",
    "julianday", "unixepoch", "typeof", "printf", "format", NULL
};

/* Tables no statement in the box may read at all: raw pages, sampled
 * index keys, and the page and cell statistics (dbstat's payload, ncell
 * and unused of a table or an index holding a withheld column, less its
 * readable siblings, are the withheld value's length; sqlite_dbdata
 * and sqlite_dbptr, the recovery extension's, are the same and are in
 * no stock library, so no test reaches them). */
static int denied_table(const char *t) {
    static const char *const T[] = { "sqlite_dbpage", "sqlite_stat3",
                                     "sqlite_stat4", "dbstat",
                                     "sqlite_dbdata", "sqlite_dbptr", NULL };
    for (int i = 0; T[i]; i++) if (!sqlite3_stricmp(t, T[i])) return 1;
    return !sqlite3_strnicmp(t, "pragma_", 7);
}

typedef struct {
    char t[64], c[64];
} deny_t;

typedef struct {
    deny_t    d[WEB_SQL_DENY_MAX];
    int       n, deny_all;
    char      denied[160];
    long long deadline;
    int       timed_out;
} box_t;

static const char *action_word(int a) {
    switch (a) {
    case SQLITE_INSERT:      return "INSERT";
    case SQLITE_UPDATE:      return "UPDATE";
    case SQLITE_DELETE:      return "DELETE";
    case SQLITE_PRAGMA:      return "PRAGMA";
    case SQLITE_ATTACH:      return "ATTACH";
    case SQLITE_DETACH:      return "DETACH";
    case SQLITE_TRANSACTION: return "a transaction";
    case SQLITE_RECURSIVE:   return "a recursive CTE";
    case SQLITE_ANALYZE:     return "ANALYZE";
    case SQLITE_SAVEPOINT:   return "SAVEPOINT";
    case SQLITE_REINDEX:     return "REINDEX";
    case SQLITE_FUNCTION:    return "the function";
    default:                 return "DDL or another write";
    }
}

static int deny(box_t *x, const char *what, const char *a, const char *b) {
    if (!x->denied[0])
        snprintf(x->denied, sizeof(x->denied), "%s%s%s%s%s", what,
                 a ? " " : "", a ? a : "", b && b[0] ? "." : "",
                 b && b[0] ? b : "");
    return SQLITE_DENY;
}

static int box_authz(void *ud, int action, const char *a1, const char *a2,
                     const char *dbn, const char *trig) {
    box_t *x = ud;
    (void)trig;
    switch (action) {
    case SQLITE_SELECT:
        return SQLITE_OK;
    case SQLITE_READ:
        if (!a1) return deny(x, "read of", "?", NULL);
        if (x->deny_all) return deny(x, "withheld:", a1, a2);
        if (dbn && sqlite3_stricmp(dbn, "main") != 0)
            return deny(x, "not main:", dbn, NULL);
        if (denied_table(a1)) return deny(x, "withheld:", a1, NULL);
        if (a2 && a2[0]) {
            if (web_sdb_is_secret(a1, a2, NULL))
                return deny(x, "withheld:", a1, a2);
            for (int i = 0; i < x->n; i++)
                if (!sqlite3_stricmp(x->d[i].t, a1) &&
                    !sqlite3_stricmp(x->d[i].c, a2))
                    return deny(x, "withheld:", a1, a2);
        }
        return SQLITE_OK;
    case SQLITE_FUNCTION:
        for (int i = 0; a2 && FUNCS[i]; i++)
            if (!sqlite3_stricmp(FUNCS[i], a2)) return SQLITE_OK;
        return deny(x, "not allowed: the function", a2 ? a2 : "?", NULL);
    default:
        return deny(x, "not allowed:", action_word(action), NULL);
    }
}

static int box_progress(void *ud) {
    box_t *x = ud;
    if (mono_ms() > x->deadline) {
        x->timed_out = 1;
        return 1;
    }
    return 0;
}

/* Every TEXT or BLOB column of the file named for a secret, found on
 * the file itself (so a column a later sloth adds is withheld the day
 * it appears), with no authorizer in the way: this statement is ours.
 * 0, or -1 (then every read is refused). */
static int learn_columns(sqlite3 *db, box_t *x) {
    sqlite3_set_authorizer(db, NULL, NULL);
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT m.name, c.name, c.type FROM sqlite_schema m,"
        " pragma_table_info(m.name) c WHERE m.type = 'table'", -1, &st, NULL);
    if (rc != SQLITE_OK) { sqlite3_finalize(st); return -1; }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        const char *c = (const char *)sqlite3_column_text(st, 1);
        const char *ty = (const char *)sqlite3_column_text(st, 2);
        if (!t || !c || !web_sdb_is_secret(t, c, ty ? ty : "")) continue;
        if (x->n >= WEB_SQL_DENY_MAX || strlen(t) >= sizeof(x->d[0].t) ||
            strlen(c) >= sizeof(x->d[0].c)) {
            x->deny_all = 1;
            continue;
        }
        snprintf(x->d[x->n].t, sizeof(x->d[0].t), "%s", t);
        snprintf(x->d[x->n].c, sizeof(x->d[0].c), "%s", c);
        x->n++;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void guard(sqlite3 *db, box_t *x, int timeout_ms) {
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, WEB_SQL_VALUE_MAX);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, WEB_SQL_MAX_BYTES + 1);
    sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 100);
    sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH, 100);
    sqlite3_limit(db, SQLITE_LIMIT_COMPOUND_SELECT, 20);
    sqlite3_limit(db, SQLITE_LIMIT_FUNCTION_ARG, 8);
    sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 0);
    sqlite3_limit(db, SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 256);
    sqlite3_limit(db, SQLITE_LIMIT_VARIABLE_NUMBER, 0);
    sqlite3_limit(db, SQLITE_LIMIT_WORKER_THREADS, 0);
    sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, (int *)NULL);
    sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, (int *)NULL);
    sqlite3_db_config(db, SQLITE_DBCONFIG_DQS_DML, 0, (int *)NULL);
    x->deadline = mono_ms() + timeout_ms;
    sqlite3_progress_handler(db, 1000, box_progress, x);
    sqlite3_set_authorizer(db, box_authz, x);
}

static void hexblob(web_jw_t *w, const unsigned char *p, int n) {
    static const char hx[] = "0123456789abcdef";
    char buf[129];
    web_jw_raw(w, "{\"blob\":\"");
    for (int i = 0; i < n && !w->overflow;) {
        int k = 0;
        while (i < n && k < 128) {
            buf[k++] = hx[p[i] >> 4];
            buf[k++] = hx[p[i] & 15];
            i++;
        }
        buf[k] = '\0';
        web_jw_raw(w, buf);
    }
    web_jw_raw(w, "\"}");
}

static int holds(const char *nm, const char *w) {
    size_t n = strlen(w);
    for (const char *p = nm; p && *p; p++) {
        size_t i = 0;
        while (i < n && p[i] && (p[i] | 32) == w[i]) i++;
        if (i == n) return 1;
    }
    return 0;
}

/* A result column whose name holds "ssid" or "title" (any case): its
 * text cells are SSIDs, or alert titles sloth wrote an SSID into as it
 * came (src/alerts/rules_twin.c), sent in their display form
 * (web_ssid.h), never raw. */
static int ssid_column(const char *nm) {
    return holds(nm, "ssid") || holds(nm, "title");
}

static void ssid_text(web_jw_t *w, const char *t, size_t n) {
    char small[256 * WEB_SSID_EXPAND + 1];
    char *d = n <= 256 ? small : malloc(n * WEB_SSID_EXPAND + 1);
    if (!d) { web_jw_raw(w, "null"); return; }
    size_t l = web_ssid_escape(t, n, d, n * WEB_SSID_EXPAND + 1, NULL);
    web_jw_strn(w, d, l);
    if (d != small) free(d);
}

static void value(web_jw_t *w, sqlite3_stmt *st, int i, int ssid) {
    switch (sqlite3_column_type(st, i)) {
    case SQLITE_INTEGER:
        web_jw_int(w, (long long)sqlite3_column_int64(st, i));
        break;
    case SQLITE_FLOAT: {
        double d = sqlite3_column_double(st, i);
        char b[40];
        if (!isfinite(d)) { web_jw_raw(w, "null"); break; }
        snprintf(b, sizeof(b), "%.17g", d);
        /* Kept a REAL in the JSON too: 5.0 is not written as 5. */
        if (!strpbrk(b, ".eE")) strcat(b, ".0");
        web_jw_raw(w, b);
        break;
    }
    case SQLITE_TEXT: {
        const char *t = (const char *)sqlite3_column_text(st, i);
        size_t n = (size_t)sqlite3_column_bytes(st, i);
        if (ssid) ssid_text(w, t ? t : "", t ? n : 0);
        else web_jw_strn(w, t ? t : "", n);
        break;
    }
    case SQLITE_BLOB:
        hexblob(w, sqlite3_column_blob(st, i), sqlite3_column_bytes(st, i));
        break;
    default:
        web_jw_raw(w, "null");
    }
}

/* What the tail of the answer needs, whatever was cut before it. */
#define TAIL 512

size_t web_sqlbox_run_db(sqlite3 *db, const char *sql, size_t len,
                         const web_sqlbox_lim_t *lim, char *out, size_t cap,
                         web_sqlbox_res_t *res) {
    memset(res, 0, sizeof(*res));
    res->status = 400;
    long long t0 = mono_ms();
    const char *why;
    if (web_sqlbox_precheck(sql, len, &why) != 0) {
        res->why = why;
        return web_sqlbox_error(out, cap, why, NULL);
    }
    box_t *x = calloc(1, sizeof(*x));
    if (!x) { res->status = 503; return web_sqlbox_error(out, cap, "no_memory", NULL); }
    if (learn_columns(db, x) != 0) x->deny_all = 1;
    guard(db, x, lim->timeout_ms);
    sqlite3_stmt *st = NULL;
    const char *tail = NULL;
    int rc = sqlite3_prepare_v2(db, sql, (int)len, &st, &tail);
    size_t bl = 0;
    if (rc != SQLITE_OK) {
        int auth = x->denied[0] != 0;
        res->why = auth ? "denied" : "sql_error";
        snprintf(res->denied, sizeof(res->denied), "%s", x->denied);
        bl = web_sqlbox_error(out, cap, res->why, auth ? x->denied : sqlite3_errmsg(db));
        goto done;
    }
    if (!st) {
        res->why = "empty";
        bl = web_sqlbox_error(out, cap, "empty", NULL);
        goto done;
    }
    if (tail && !web_sqlbox_blank(tail, len - (size_t)(tail - sql))) {
        res->why = "one_statement_only";
        bl = web_sqlbox_error(out, cap, res->why, "everything after the first "
                        "statement must be blank or a comment");
        goto done;
    }
    if (!sqlite3_stmt_readonly(st) || sqlite3_stmt_isexplain(st)) {
        res->why = "not_read_only";
        bl = web_sqlbox_error(out, cap, res->why, NULL);
        goto done;
    }
    {
        web_jw_t w;
        web_jw_init(&w, out, cap > TAIL ? cap - TAIL : 0);
        int nc = sqlite3_column_count(st);
        unsigned char *ssid = calloc((size_t)(nc > 0 ? nc : 1), 1);
        if (!ssid) {
            res->status = 503;
            bl = web_sqlbox_error(out, cap, "no_memory", NULL);
            goto done;
        }
        web_jw_raw(&w, "{\"columns\":[");
        for (int i = 0; i < nc; i++) {
            if (i) web_jw_raw(&w, ",");
            const char *nm = sqlite3_column_name(st, i);
            web_jw_str(&w, nm ? nm : "");
            ssid[i] = (unsigned char)ssid_column(nm);
        }
        web_jw_raw(&w, "],\"rows\":[");
        if (w.overflow) { free(ssid); bl = 0; goto done; }
        long long rows = 0;
        int cut = 0;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            if (rows >= lim->row_cap) { cut = 1; break; }
            size_t mark = w.len;
            web_jw_raw(&w, rows ? ",[" : "[");
            for (int i = 0; i < nc; i++) {
                if (i) web_jw_raw(&w, ",");
                value(&w, st, i, ssid[i]);
            }
            web_jw_raw(&w, "]");
            if (w.overflow || w.len > lim->out_cap) {
                w.overflow = 0;
                w.len = mark;
                w.buf[mark] = '\0';
                cut = 2;
                break;
            }
            rows++;
        }
        free(ssid);
        if (!cut && rc == SQLITE_INTERRUPT && x->timed_out) cut = 3;
        if (!cut && rc != SQLITE_DONE &&
            (sqlite3_extended_errcode(db) & 0xff) == SQLITE_CANTOPEN) {
            /* The only file a running statement opens is a temporary
             * one, which the box's VFS refuses (web_sqlbox.h). */
            res->why = "temp_space";
            bl = web_sqlbox_error(out, cap, res->why, "the statement needs more "
                                  "sort or temporary space than the box keeps in "
                                  "memory; temporary files are refused");
            goto done;
        }
        if (!cut && rc != SQLITE_DONE) {
            int busy = rc == SQLITE_BUSY || rc == SQLITE_LOCKED;
            res->status = busy ? 503 : 400;
            res->why = busy ? "sloth_db_busy" : "sql_error";
            bl = web_sqlbox_error(out, cap, res->why, sqlite3_errmsg(db));
            goto done;
        }
        res->rows = rows;
        res->truncated = cut;
        res->elapsed_ms = mono_ms() - t0;
        static const char *const CUT[] = { NULL, "rows", "bytes", "timeout" };
        w.cap = cap;   /* the tail's room back */
        web_jw_raw(&w, "],\"row_count\":");   web_jw_int(&w, rows);
        web_jw_raw(&w, ",\"truncated\":");    web_jw_raw(&w, cut ? "true" : "false");
        web_jw_raw(&w, ",\"truncated_by\":");
        if (cut) web_jw_str(&w, CUT[cut]); else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"row_cap\":");      web_jw_int(&w, lim->row_cap);
        web_jw_raw(&w, ",\"timeout_ms\":");   web_jw_int(&w, lim->timeout_ms);
        web_jw_raw(&w, ",\"elapsed_ms\":");   web_jw_int(&w, res->elapsed_ms);
        web_jw_raw(&w, "}\n");
        res->status = 200;
        bl = w.overflow ? 0 : w.len;
    }
done:
    sqlite3_finalize(st);
    sqlite3_set_authorizer(db, NULL, NULL);
    sqlite3_progress_handler(db, 0, NULL, NULL);
    free(x);
    return bl;
}

#endif /* WITH_SQLITE */
