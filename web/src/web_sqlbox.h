/* slothweb's SQL box (#163, M5): docs/web-ui-spec.md §7's /api/query
 * and §8.10's box, as the rulings header keeps it: behind
 * --web-allow-sql, default off, read-only, 5 s, 10,000 rows.
 *
 *   /api/query?sql=STATEMENT
 *       only with --web-allow-sql (a 404 otherwise, as any unknown
 *       path, and the page never shows the box); GET only (HEAD is a
 *       405: there is nothing to answer without running it). One
 *       statement against sloth.db through the M4 reader's opener
 *       (web_slothdb.h: read-only, no-follow, no side file, DEFENSIVE,
 *       query_only, the no-create VFS), then this module's own guard
 *       on that connection:
 *
 *   - the text: percent-decoded ('+' a space, as a form sends it), at
 *     most WEB_SQL_MAX_BYTES, valid UTF-8 with no control byte but tab,
 *     CR and LF, and its first keyword after blanks and comments SELECT
 *     or WITH;
 *   - one statement: the prepare's tail must hold nothing but blanks
 *     and comments ("SELECT 1; DROP TABLE x" is refused whole, never
 *     run in part);
 *   - an authorizer that answers SQLITE_OK to SQLITE_SELECT, to
 *     SQLITE_READ, and to SQLITE_FUNCTION for the few functions in
 *     web_sqlbox.c, and denies every other action: every write, every
 *     DDL including a temporary table or view, PRAGMA, ATTACH, DETACH,
 *     a transaction, ANALYZE, a recursive CTE (SQLITE_RECURSIVE). A
 *     CTE with a DML tail is a DELETE/INSERT/UPDATE and is denied;
 *   - SQLITE_READ itself is denied for the withheld columns
 *     (web_slothdb.h's web_sdb_is_secret(): sloth's credential-bearing
 *     columns and every TEXT/BLOB column named for a secret, the same
 *     list M4's allow-list is held to), for sqlite_dbpage (raw pages
 *     would carry a withheld column's bytes), sqlite_stat3/4 (sampled
 *     index keys), dbstat, sqlite_dbdata and sqlite_dbptr (per-table and
 *     per-index payload sizes and cell bytes: the length of a withheld
 *     value, from its readable siblings') and every pragma_* table-valued
 *     function. A query
 *     naming a withheld column, in its result or anywhere else, does
 *     not prepare, and the answer names the column;
 *   - sqlite3_stmt_readonly() must hold as well (a second, independent
 *     check), and EXPLAIN is refused by the first-keyword rule;
 *   - limits: SQLITE_LIMIT_ATTACHED 0, a value at most
 *     WEB_SQL_VALUE_MAX bytes, a bounded expression depth, compound
 *     select and column count, no bound parameters; trusted_schema off,
 *     no extension loading;
 *   - a progress handler stops the statement at WEB_SQL_TIMEOUT_MS
 *     (what came back so far is answered, "truncated_by":"timeout");
 *     at most WEB_SQL_ROW_CAP rows ("rows") and WEB_SQL_OUT_MAX bytes of
 *     answer ("bytes"); every value is JSON (web_json.h's escaping, a
 *     BLOB as {"blob":"<hex>"}).
 *
 * One query at a time. The statement runs on this module's own thread,
 * so the server's poll loop keeps serving the page, the stream and the
 * other routes for the 5 s a statement may take. From the submit until
 * its answer has been written (or its client is gone) the box is busy,
 * and every other /api/query is a 503 "busy". The answer is held in the
 * box's buffer while it is sent, which is what bounds slothweb's memory
 * for it to one WEB_SQL_OUT_MAX buffer.
 *
 * The rest: a statement that kept sloth.db open for t ms (t at most the
 * timeout) is followed by t ms in which the box holds no connection to
 * it; a statement submitted then waits (queued, so the box is busy) and
 * runs when the rest is over. A box reader holds a WAL read mark while
 * it runs, and sloth can restart its WAL only when no reader holds one:
 * without the rest, a client sending statements back to back kept one
 * held for as long as it looped, and sloth.db-wal grew at sloth's whole
 * write rate (to 14.7 MB in 40 s against a 4.2 MB control, and left at
 * that size). With it, at most half of any stretch is a box reader's.
 * The server's deadline for an asked-for answer is therefore its own
 * timeout plus twice the box's (the rest, then the statement).
 *
 * Temporary files: the box's connection is opened through a VFS that
 * refuses every file but sloth.db, its journal and its -wal
 * (web_slothdb_open_box()), with temp_store FILE, so a sort or a
 * temporary b-tree that outgrows the page cache fails ("temp_space", a
 * 400) instead of writing gigabytes to the temporary directory, which
 * on a sensor is the filesystem sloth.db lives on.
 *
 * --strict refuses --web-allow-sql (exit 2), and --web-allow-sql with
 * --web-allow-remote is announced on stderr naming the exposure
 * (web_config.h). The recipes the box offers are docs/wiki/
 * sqlite-schema.md's, extracted at build time by web/tools/recipes.c
 * (web_recipes.h). Built without SQLite there is no box: the flag is
 * refused. */
#ifndef SLOTHWEB_SQLBOX_H
#define SLOTHWEB_SQLBOX_H

#include <pthread.h>
#include <stddef.h>

#include "web_slothdb.h"

#define WEB_SQL_MAX_BYTES  4096
#define WEB_SQL_TIMEOUT_MS 5000
#define WEB_SQL_ROW_CAP    10000
#define WEB_SQL_VALUE_MAX  65536
#define WEB_SQL_OUT_MAX    (4u << 20)
/* Room kept in front of the body for the response header. */
#define WEB_SQL_HDR        1024
/* Withheld columns the open finds by name and type, at most. More is a
 * refusal of every statement, not a box that reads past the list. */
#define WEB_SQL_DENY_MAX   256

enum { WEB_SQLB_IDLE = 0, WEB_SQLB_QUEUED, WEB_SQLB_RUNNING, WEB_SQLB_DONE };

typedef struct {
    unsigned long queries, refused, busy, timeouts, truncated, errors;
} web_sqlbox_stats_t;

typedef struct web_sqlbox {
    int             enabled;
    web_slothdb_t  *sdb;
    int             timeout_ms, row_cap;
    size_t          out_max;
    pthread_mutex_t mu;            /* guards everything below */
    pthread_cond_t  cv;
    pthread_t       th;
    int             running, stop;
    int             state;         /* WEB_SQLB_* */
    char            sql[WEB_SQL_MAX_BYTES + 1];
    size_t          sql_len;
    long long       now_s;
    char           *out;           /* WEB_SQL_HDR + out_max bytes */
    size_t          resp_off, resp_len;
    int             status;
    int             notify[2];     /* the worker writes a byte when DONE */
    web_sqlbox_stats_t st;
} web_sqlbox_t;

/* enabled 0: every /api/query is a 404 and nothing is allocated. 0, or
 * -1 (memory, or a pipe). */
int  web_sqlbox_init(web_sqlbox_t *b, web_slothdb_t *sdb, int enabled);
int  web_sqlbox_start(web_sqlbox_t *b, char *err, size_t errsz);
void web_sqlbox_stop(web_sqlbox_t *b);
void web_sqlbox_destroy(web_sqlbox_t *b);

/* The query string of /api/query: exactly one sql= parameter, decoded
 * into sql (cap bytes, NUL-terminated). 0, or -1 with *why a reason
 * word ("missing_sql", "unknown_parameter", "repeated_parameter",
 * "bad_escape", "too_long", "empty_value"). */
int  web_sqlbox_param(const char *query, char *sql, size_t cap, size_t *len,
                      const char **why);
/* The text rules: 0, or -1 with *why ("too_long", "bad_utf8",
 * "control_byte", "not_select"). Pure. */
int  web_sqlbox_precheck(const char *sql, size_t len, const char **why);
/* Blanks and comments only from p for n bytes? Pure. */
int  web_sqlbox_blank(const char *p, size_t n);
/* {"error":why[,"detail":detail]} into out. Its length, 0 if it did
 * not fit. */
size_t web_sqlbox_error(char *out, size_t cap, const char *why,
                        const char *detail);

typedef struct {
    int       timeout_ms, row_cap;
    size_t    out_cap;             /* bytes the body may take */
} web_sqlbox_lim_t;

typedef struct {
    int       status;              /* 200 or 400 */
    const char *why;               /* the refusal word, or NULL */
    char      denied[160];         /* "table.column" or the action */
    long long rows;
    int       truncated;           /* 0, or 1 rows, 2 bytes, 3 timeout */
    long long elapsed_ms;
} web_sqlbox_res_t;

struct sqlite3;

/* Check and run sql on db (any connection: sloth.db's from the M4
 * opener, or the fuzz harness's own) under the box's authorizer,
 * limits and progress handler, all left installed. The JSON body (a
 * result or {"error":...}) into out. Returns the body length, 0 when
 * even an error did not fit. SQLite builds only. */
size_t web_sqlbox_run_db(struct sqlite3 *db, const char *sql, size_t len,
                         const web_sqlbox_lim_t *lim, char *out, size_t cap,
                         web_sqlbox_res_t *res);

/* The whole query on b's sloth.db, synchronously: open, run, close.
 * The complete HTTP response (header and body) at out + *off; returns
 * its length (0 when it did not fit) and sets *status. The worker's
 * job, and the tests'. */
size_t web_sqlbox_query(web_sqlbox_t *b, const char *sql, size_t len,
                        long long now_s, char *out, size_t cap, size_t *off,
                        int *status);

/* For the server loop. submit: 0 queued, 1 busy. take: 1 with the
 * finished response (held until release), 0 none ready. */
int  web_sqlbox_submit(web_sqlbox_t *b, const char *sql, size_t len,
                       long long now_s);
int  web_sqlbox_fd(const web_sqlbox_t *b);
int  web_sqlbox_take(web_sqlbox_t *b, const unsigned char **resp, size_t *len,
                     int *status);
void web_sqlbox_release(web_sqlbox_t *b);
int  web_sqlbox_busy(web_sqlbox_t *b);
void web_sqlbox_stats(web_sqlbox_t *b, web_sqlbox_stats_t *out);

#endif
