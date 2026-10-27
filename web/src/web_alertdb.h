/* sloth.db's alerts table for the Alerts page and the alert detail page
 * (owner request 2026-10-23..26), read through the M4 reader and its
 * allow-list (web_slothdb.h): every statement opens on a connection
 * from web_slothdb_open(), names its columns, and binds every value.
 *
 * alerts.key stays predicate-only. sloth before schema v8 upserted one
 * row per (key, first_seen), and on the owner's host about 114 rows
 * share a key (#170, 868k rows); a v8 file keeps one row per finding,
 * but the rows recorded before it stay as they were. Repeated rows of a
 * key are one finding, so these
 * reads GROUP BY key and match on it, with pred_ok set around their
 * prepare, and no result column of any of them is the key or computed
 * from it. A group is named by the rowid of its newest row ("d<rowid>"
 * on the wire): a number sloth's upsert keeps (ON CONFLICT DO UPDATE)
 * and its incremental vacuum does not renumber, which names nothing.
 * A stream incident's key (web_live.h) is bound the same way, as a
 * predicate.
 *
 * alerts.detail is read by one statement only, with detail_ok set, and
 * only as CASE WHEN web_detail_ok(type) THEN detail END: the SQL
 * function asks web_alert_detail_ok(), so the detail of a type whose
 * format is not audited (web_alertfmt.h) never leaves SQLite.
 *
 * Bounded. Each list reads at most scan_cap rows that its filters
 * match, newest last_seen first, through idx_alerts_last_seen
 * (WEB_ADB_SCAN_CAP by default), and says when it stopped there and how
 * far back that reached; a key's incidents are read through the
 * primary key's index, at most WEB_ADB_INCIDENTS of them. Every
 * statement runs under the request's budget (WEB_SDB_HTTP_MS).
 *
 * On a v8 file (#170) a row is a finding: every incident of its key
 * while the row is kept, 1 + reopens of them, count summed over them.
 * Earlier files hold a row per incident, and every row is one. */
#ifndef SLOTHWEB_ALERTDB_H
#define SLOTHWEB_ALERTDB_H

#include "web_slothdb.h"

#define WEB_ADB_SCAN_CAP   20000
#define WEB_ADB_INCIDENTS  2000
#define WEB_ADB_TYPES      96
#define WEB_ADB_EXCLUDE    320       /* stream keys left out of a list */
#define WEB_ADB_Q_MAX      64

typedef struct {
    long long since, until;          /* last_seen in [since, until] */
    unsigned  sev_mask;              /* bit per severity; 0 all */
    int       types[WEB_ADB_TYPES];  /* type filter; ntypes 0 all */
    int       ntypes;
    char      q[WEB_ADB_Q_MAX + 1];  /* title or match_ip, a substring */
    int       qtypes[WEB_ADB_TYPES]; /* types whose name matches q */
    int       nqtypes;
    const char *exclude[WEB_ADB_EXCLUDE];   /* keys left out (bound) */
    int       nexclude;
    long long scan_cap;
} web_adb_filter_t;

typedef struct {
    long long rid;                   /* the newest row's rowid */
    int       type, sev;             /* sev: the highest in the group */
    char      title[WEB_SDB_TEXT_MAX + 1];
    char      ip[WEB_SDB_TEXT_MAX + 1];
    int       port;                  /* -1 none */
    char      technique[24];
    long long first_seen, last_seen; /* of the rows read */
    long long count;                 /* the sum of their counts */
    long long rows;                  /* rows of the key read */
} web_adb_group_t;

typedef int (*web_adb_group_fn)(void *ctx, const web_adb_group_t *g);

typedef struct {
    long long scanned;               /* matching rows read, at most scan_cap */
    int       capped;                /* stopped at scan_cap */
    long long oldest;                /* the oldest last_seen read */
    long long groups;                /* groups in the rows read */
    int       ntypes;                /* the facets: groups per type */
    int       facet_type[WEB_ADB_TYPES];
    long long facet_n[WEB_ADB_TYPES];
} web_adb_stats_t;

/* The groups f matches, newest first, at most limit from offset, each to
 * fn; and, when st is not NULL, how many rows were read and the groups
 * per type (the type filter left out, so a dropdown shows them all).
 * Rows given, or -1; 0 when the file has no alerts table to read. */
int web_adb_groups(web_sdb_conn_t *c, const web_adb_filter_t *f,
                   long long limit, long long offset, web_adb_group_fn fn,
                   void *ctx, web_adb_stats_t *st);

/* A key's totals over every row of it, by a rowid of it or by the key
 * itself (exactly one of the two). 1 found, 0 none, -1. */
typedef struct {
    long long rows;                  /* its rows */
    long long incidents;             /* sum(1 + reopens) on v8, else rows */
    long long count;                 /* sum(count) */
    long long first_seen;            /* the earliest */
    long long newest_rid;            /* its newest row's rowid */
} web_adb_totals_t;
int web_adb_key_totals(web_sdb_conn_t *c, long long rid, const char *key,
                       web_adb_totals_t *t);

typedef struct {
    long long rid;
    int       type, sev;
    char      title[WEB_SDB_TEXT_MAX + 1];
    char      ip[WEB_SDB_TEXT_MAX + 1];
    int       port;
    char      technique[24];
    long long count, first_seen, last_seen;
    int       has_detail;            /* the type's detail is audited */
    char      detail[324];           /* sloth's ALERT_DETAIL_LEN, cut */
} web_adb_row_t;

/* One row by rowid: 1, 0 none, -1. */
int web_adb_row(web_sdb_conn_t *c, long long rid, web_adb_row_t *out);

/* Every row of one key (by a rowid of it, or the key itself), newest
 * first_seen first, at most max (WEB_ADB_INCIDENTS) to fn. Rows, or -1. */
typedef int (*web_adb_row_fn)(void *ctx, const web_adb_row_t *r);
int web_adb_incidents(web_sdb_conn_t *c, long long rid, const char *key,
                      int max, web_adb_row_fn fn, void *ctx);

/* The device an alert names: a devices row whose MAC is in the key (by
 * rowid or the key itself), else one whose ip is ip. 1 (mac filled), 0,
 * -1. */
int web_adb_device(web_sdb_conn_t *c, long long rid, const char *key,
                   const char *ip, char mac[18]);

#endif
