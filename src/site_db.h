#ifndef SLOTH_SITE_DB_H
#define SLOTH_SITE_DB_H

#include <stddef.h>
#include <time.h>

/* sloth.db opened read-only for the offline exports (#250): the
 * handoff packet (src/handoff.h) and the interference report
 * (src/interference.h). Neither writes the file, migrates it or
 * starts the writer; they run beside a daemon that has it open.
 *
 * HOW IT IS OPENED. When "<path>-wal" holds frames (a daemon has the
 * file open now, or one stopped uncleanly), the open is "?mode=ro": a
 * read-only connection that reads those frames, as the sqlite3 CLI or
 * slothweb would, and may leave a -shm beside the file when none is
 * there. Otherwise it is "?mode=ro&immutable=1", as --preflight and
 * --db-compact-alerts read a file: no lock, nothing created. The main
 * file alone would miss everything the running daemon wrote since its
 * last checkpoint, which on a live sensor is the last minutes of every
 * table; reading it immutable while a writer checkpoints into it could
 * read a torn page. Either way nothing in the file changes: the
 * connection is SQLITE_OPEN_READONLY, SQLITE_OPEN_NOFOLLOW and
 * DEFENSIVE.
 *
 * WHICH FILES. A file whose meta row says a newer schema than this
 * build's is refused, as db_open() refuses it; one older than
 * SITE_DB_MIN_VERSION (11, the first with alert_incidents, which both
 * exports read) is refused with the version it holds. A table an
 * export reads that the file does not have (coverage_intervals before
 * v18) is reported as absent by that export, never as empty. */

#define SITE_DB_MIN_VERSION 11

struct sqlite3;

typedef struct {
    struct sqlite3 *h;
    int  version;     /* meta schema_version */
    int  wal;         /* 1: opened to read a -wal that holds frames */
} site_db_t;

/* 0 and `d` open, or -1 with the reason in err. */
int  site_db_open(site_db_t *d, const char *path, char *err, size_t errsz);
void site_db_close(site_db_t *d);

/* 1 when the file has the table, 0 not. */
int  site_db_has_table(const site_db_t *d, const char *name);

/* One integer from a query with no parameters; `dflt` on no row, a
 * NULL or an error. */
long long site_db_scalar(const site_db_t *d, const char *sql, long long dflt);

/* "2026-11-20T14:02:11Z" for a wall second, "-" for 0 or less. */
void site_db_iso(time_t t, char *out, size_t n);

/* A time as the command line gives it: whole seconds since the epoch,
 * or UTC "YYYY-MM-DD", "YYYY-MM-DDTHH:MM", "YYYY-MM-DDTHH:MM:SS" with
 * an optional trailing 'Z'. 0 and *out, or -1. */
int  site_db_parse_time(const char *s, time_t *out);

#endif /* SLOTH_SITE_DB_H */
