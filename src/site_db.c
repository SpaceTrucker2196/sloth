#include "site_db.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "db.h"
#include "preflight.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

void site_db_iso(time_t t, char *out, size_t n) {
    struct tm tm;
    if (t <= 0 || !gmtime_r(&t, &tm)) { snprintf(out, n, "-"); return; }
    strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* Two to four digits at p, exactly `len` of them, as a number. */
static int digits(const char *p, int len, int *v) {
    int x = 0;
    for (int i = 0; i < len; i++) {
        if (!isdigit((unsigned char)p[i])) return 0;
        x = x * 10 + (p[i] - '0');
    }
    *v = x;
    return 1;
}

/* *span: the seconds the form names past *out (a day, a minute or one
 * second), so an end bound can include them. */
static int parse_time(const char *s, time_t *out, long *span) {
    if (!s || !s[0] || !out) return -1;
    *span = 0;
    size_t n = strlen(s);
    int all_digits = 1;
    for (size_t i = 0; i < n; i++)
        if (!isdigit((unsigned char)s[i])) { all_digits = 0; break; }
    if (all_digits) {
        if (n > 12) return -1;          /* past year 33658: a typo */
        errno = 0;
        long long v = strtoll(s, NULL, 10);
        if (errno) return -1;
        *out = (time_t)v;
        return 0;
    }
    if (n < 10) return -1;
    char day[11];
    memcpy(day, s, 10);
    day[10] = '\0';
    long d = pf_date_days(day);
    if (d < 0) return -1;
    int hh = 0, mm = 0, ss = 0;
    const char *p = s + 10;
    *span = 86399;
    if (*p == 'T') {
        *span = 59;
        if (!digits(p + 1, 2, &hh) || p[3] != ':' || !digits(p + 4, 2, &mm))
            return -1;
        p += 6;
        if (*p == ':') {
            if (!digits(p + 1, 2, &ss)) return -1;
            p += 3;
            *span = 0;
        }
        if (hh > 23 || mm > 59 || ss > 60) return -1;
    }
    if (*p == 'Z') p++;
    if (*p) return -1;
    *out = (time_t)d * 86400 + hh * 3600 + mm * 60 + ss;
    return 0;
}

int site_db_parse_time(const char *s, time_t *out) {
    long span;
    return parse_time(s, out, &span);
}

int site_db_parse_time_end(const char *s, time_t *out) {
    long span;
    time_t t;
    if (parse_time(s, &t, &span) != 0) return -1;
    *out = t + (time_t)span;
    return 0;
}

#ifdef WITH_SQLITE

int site_db_open(site_db_t *d, const char *path, char *err, size_t errsz) {
    memset(d, 0, sizeof(*d));
    if (err && errsz) err[0] = '\0';
    if (!path || !path[0]) {
        snprintf(err, errsz, "no --db named");
        return -1;
    }
    struct stat sb;
    if (lstat(path, &sb) != 0) {
        snprintf(err, errsz, "%.200s: %s", path, strerror(errno));
        return -1;
    }
    if (!S_ISREG(sb.st_mode)) {
        snprintf(err, errsz, "%.200s: not a regular file", path);
        return -1;
    }
    char wal[4200];
    snprintf(wal, sizeof(wal), "%s-wal", path);
    struct stat wb;
    d->wal = lstat(wal, &wb) == 0 && S_ISREG(wb.st_mode) && wb.st_size > 0;

    char uri[8192];
    if (!db_file_uri(path, !d->wal, uri, sizeof(uri))) {
        snprintf(err, errsz, "%.200s: path too long", path);
        return -1;
    }
    sqlite3 *h = NULL;
    if (sqlite3_open_v2(uri, &h, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW |
                        SQLITE_OPEN_URI, NULL) != SQLITE_OK) {
        snprintf(err, errsz, "%.200s: %s", path, h ? sqlite3_errmsg(h) : "cannot open");
        sqlite3_close(h);
        return -1;
    }
    int defensive = -1;
    sqlite3_db_config(h, SQLITE_DBCONFIG_DEFENSIVE, 1, &defensive);
    sqlite3_busy_timeout(h, DB_BUSY_MS);
    d->h = h;
    if (defensive != 1) {
        snprintf(err, errsz, "%.200s: DEFENSIVE refused", path);
        site_db_close(d);
        return -1;
    }
    if (!site_db_has_table(d, "meta")) {
        snprintf(err, errsz, "%.200s: no meta table: not a sloth database", path);
        site_db_close(d);
        return -1;
    }
    d->version = (int)site_db_scalar(d, "SELECT CAST(value AS INTEGER) FROM meta"
                                     " WHERE key='schema_version'", -1);
    if (d->version > DB_SCHEMA_VERSION) {
        snprintf(err, errsz, "%.200s: schema v%d is newer than this build's v%d",
                 path, d->version, DB_SCHEMA_VERSION);
        site_db_close(d);
        return -1;
    }
    if (d->version < SITE_DB_MIN_VERSION) {
        snprintf(err, errsz, "%.200s: schema v%d; the exports read v%d to v%d"
                 " (open it once with this build's --db to migrate it)",
                 path, d->version, SITE_DB_MIN_VERSION, DB_SCHEMA_VERSION);
        site_db_close(d);
        return -1;
    }
    /* One read transaction for everything an export reads, so its files
     * agree with each other while a running daemon writes the file. */
    if (sqlite3_exec(d->h, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(err, errsz, "%.200s: %s", path, sqlite3_errmsg(d->h));
        site_db_close(d);
        return -1;
    }
    return 0;
}

void site_db_close(site_db_t *d) {
    if (!d || !d->h) return;
    if (!sqlite3_get_autocommit(d->h))
        sqlite3_exec(d->h, "ROLLBACK", NULL, NULL, NULL);
    sqlite3_close(d->h);
    d->h = NULL;
}

long long site_db_scalar(const site_db_t *d, const char *sql, long long dflt) {
    sqlite3_stmt *st = NULL;
    long long v = dflt;
    if (d && d->h && sqlite3_prepare_v2(d->h, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL)
        v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

int site_db_has_table(const site_db_t *d, const char *name) {
    sqlite3_stmt *st = NULL;
    int has = 0;
    if (d && d->h && sqlite3_prepare_v2(d->h, "SELECT 1 FROM sqlite_master"
                                        " WHERE type='table' AND name=?1",
                                        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
        has = sqlite3_step(st) == SQLITE_ROW;
    }
    sqlite3_finalize(st);
    return has;
}

#else /* !WITH_SQLITE */

int site_db_open(site_db_t *d, const char *path, char *err, size_t errsz) {
    (void)path;
    memset(d, 0, sizeof(*d));
    snprintf(err, errsz, "built without SQLite");
    return -1;
}
void site_db_close(site_db_t *d) { (void)d; }
int site_db_has_table(const site_db_t *d, const char *name) {
    (void)d; (void)name;
    return 0;
}
long long site_db_scalar(const site_db_t *d, const char *sql, long long dflt) {
    (void)d; (void)sql;
    return dflt;
}

#endif /* WITH_SQLITE */
