/* slothweb's sloth.db reader (#162, M4): docs/web-ui-spec.md §4.1's
 * "reader : sloth.db RO". slothweb never writes, migrates or creates
 * anything beside sloth.db (the spec's §13.7, confirmed by the owner):
 * sloth owns that file.
 *
 * Opening. Every use opens its own connection and closes it after,
 * so no read snapshot outlives a request or a minute pass and none can
 * pin sloth's WAL past one statement: each statement runs in its own
 * implicit read transaction, ended by its reset. The path is checked
 * with lstat() first (a symlink, a directory or a device is refused)
 * and opened with SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW, never
 * READWRITE or CREATE (web_slothdb_open_flags(); a test asserts what
 * was passed). The lessons of slothweb.db's identify (web_store.h)
 * hold here too, harder, since this file is never ours:
 *
 *   - a read-only connection never checkpoints, so the WAL sloth has
 *     not flushed is never written into the file;
 *   - a WAL-mode file with no -wal, or with a -wal and no -shm, is
 *     opened as an immutable URI (mode=ro&immutable=1), which makes no
 *     side file: an ordinary read-only open would create an empty -wal
 *     and a 32 KB -shm beside sloth.db. With no -shm no sloth is
 *     running, so nothing is checkpointing either; such a read sees the
 *     file as of sloth's last checkpoint, and says so ("db_mode":
 *     "immutable");
 *   - with both present it is a WAL reader ("wal") opened
 *     mode=ro&readonly_shm=1: the -shm is opened read-only and never
 *     initialised here. With sloth running that is a reader on sloth's
 *     index; after a crash (both left, nobody holding the -shm) SQLite
 *     reads the WAL into a private index rather than run recovery on
 *     the shared one, which would fail a sloth starting at that moment
 *     with SQLITE_BUSY_RECOVERY;
 *   - every open goes through a VFS that never creates a named file
 *     (web_slothdb.c), so a sloth closing cleanly between the lstat()s
 *     and the first read fails that read instead of leaving a -wal;
 *   - a rollback-journal file is read with a shared lock per statement
 *     ("rollback"); a hot journal is not rolled back (read-only cannot)
 *     and the read fails, WEB_SDB_ERROR, until sloth opens it.
 *     WEB_SDB_REFUSED is kept for a file of the wrong shape.
 *
 * Each connection gets SQLITE_DBCONFIG_DEFENSIVE, query_only, a busy
 * timeout (WEB_SDB_BUSY_MS) and a progress handler that interrupts a
 * statement past the caller's budget, so a slow read costs slothweb a
 * 503, never sloth a stall. Then the file is identified: sloth's meta
 * (key, value) must carry a schema_version within
 * WEB_SDB_SCHEMA_MIN..WEB_SDB_SCHEMA_MAX. A newer one is refused with
 * a message (this build does not know its columns); an older one is
 * read by probing its columns (PRAGMA table_info), so a column a
 * version lacks reads as NULL and a table it lacks as no rows.
 *
 * The column allow-list. Every statement here names its columns, and
 * an authorizer on every connection denies a read of any (table,
 * column) not on web_sdb_allow[], any function but a few, any pragma
 * but table_info, and every statement that is not a SELECT: a query
 * that names another column fails to prepare. So no credential-bearing
 * column (cleartext_creds, eapol_events, rogue_radius.last_identity,
 * mqtt_flows.last_username, ...) can ever be served, whatever a later
 * change to a statement says. web/tests/test_slothdb.c holds the list
 * against tests/test_db.c's secret-column guardrail and sloth's live
 * schema.
 *
 * One listed column carries a remote string too: alerts.key, which for
 * a cleartext credential names the username (rule_cleartext_cred's
 * akey_remote()). It is predicate-only (web_sdb_col_t.pred): the
 * authorizer denies it, in a result column or a WHERE alike, to every
 * statement but the two that set pred_ok around their prepare, whose
 * result columns are constant text (web_query_row_select()'s, and
 * web_sdb_alerts()'s) and match it against a canonical MAC only. The
 * suite seeds a key in that format and holds the username out of every
 * read and every body.
 *
 * Built without SQLite every open fails ("unbuilt"). */
#ifndef SLOTHWEB_SLOTHDB_H
#define SLOTHWEB_SLOTHDB_H

#include <pthread.h>
#include <stddef.h>

#include "web_oui.h"
#include "web_query.h"
#include "web_rollup.h"

#define WEB_SDB_SCHEMA_MIN 1
#define WEB_SDB_SCHEMA_MAX 7
#define WEB_SDB_BUSY_MS    100
#define WEB_SDB_HTTP_MS    250       /* a request's budget */
#define WEB_SDB_PASS_MS    200       /* a minute pass's (A2) */
#define WEB_SDB_ERR_MAX    200
#define WEB_SDB_TEXT_MAX   63

enum {
    WEB_SDB_NONE = 0,     /* no --sloth-db */
    WEB_SDB_OPEN,         /* last open identified it */
    WEB_SDB_MISSING,      /* no file there (sloth has not made it yet) */
    WEB_SDB_REFUSED,      /* not a sloth.db, a newer schema, a symlink */
    WEB_SDB_ERROR,        /* SQLite said no (busy, corrupt, a hot journal) */
    WEB_SDB_UNBUILT       /* a build without SQLite */
};

typedef struct {
    const char *table, *column;
    int         since;    /* the first sloth schema with it */
    int         optional; /* read as NULL when the file lacks it */
    int         pred;     /* predicate-only: readable by the statements
                             that set web_sdb_conn_t.pred_ok alone */
} web_sdb_col_t;

extern const web_sdb_col_t web_sdb_allow[];
extern const size_t        web_sdb_allow_n;

struct web_anomaly;
struct web_ptr;

/* What the SQL functions a device statement uses read: web_vendor(mac)
 * (oui), web_z(mac) and web_anoms(mac, kind) (an), web_ptr(ip) (ptr).
 * Any may be NULL: the function then answers NULL or 0. */
typedef struct {
    const web_oui_tab_t *oui;
    struct web_anomaly  *an;
    struct web_ptr      *ptr;
} web_sdb_fns_t;

typedef struct {
    int           state;
    int           schema;            /* 0 unknown */
    long long     rows;              /* devices rows at the last check; -1 */
    char          mode[12];          /* "wal", "immutable", "rollback", "" */
    char          err[WEB_SDB_ERR_MAX];
    unsigned long opens, refusals, errors, timeouts;
} web_sdb_stats_t;

typedef struct web_slothdb {
    char            path[4096];
    int             configured;
    web_sdb_fns_t   fns;
    pthread_mutex_t mu;              /* guards st */
    web_sdb_stats_t st;
} web_slothdb_t;

typedef struct {
    struct sqlite3 *db;
    web_slothdb_t  *s;
    int             schema;
    unsigned        feats;           /* WEB_QF_* */
    unsigned        opt;             /* WEB_SDB_OPT_* */
    long long       deadline_ms;
    long long       now_s;
    int             timed_out;
    int             pred_ok;         /* a predicate-only column may be read */
} web_sdb_conn_t;

enum {
    WEB_SDB_OPT_CLASS = 1 << 0,      /* devices.device_class, camera_* (v6) */
    WEB_SDB_OPT_VCI   = 1 << 1       /* devices.dhcp_vci (v7) */
};

int  web_slothdb_available(void);
/* path NULL or "": not configured (every open answers WEB_SDB_NONE). */
void web_slothdb_init(web_slothdb_t *s, const char *path,
                      const web_sdb_fns_t *fns);
void web_slothdb_destroy(web_slothdb_t *s);

/* The flags every open passes to sqlite3_open_v2(): read-only and
 * no-follow, never read-write or create. */
int  web_slothdb_open_flags(void);

/* Open, configure and identify. budget_ms bounds every statement on c
 * (from now); now_s is the wall clock the SQL functions use. 0, or -1
 * with the state and the reason recorded (web_slothdb_stats) and in
 * err. web_slothdb_close() either way. */
int  web_slothdb_open(web_slothdb_t *s, web_sdb_conn_t *c, int budget_ms,
                      long long now_s, char *err, size_t errsz);
void web_slothdb_close(web_sdb_conn_t *c);

/* Open, count devices, close: the health check. The state. */
int  web_slothdb_check(web_slothdb_t *s, long long now_s);
void web_slothdb_stats(web_slothdb_t *s, web_sdb_stats_t *out);
const char *web_slothdb_state_word(int state);

/* ── reads, each one statement, every value bound ──────────────────── */

typedef struct {
    char      mac[WEB_KEY_MAX + 1];
    char      ip[WEB_KEY_MAX + 1];
    char      hostname[WEB_SDB_TEXT_MAX + 1];
    char      vendor[WEB_SDB_TEXT_MAX + 1];
    char      ssid[WEB_SDB_TEXT_MAX + 1];
    int       has_signal, signal_dbm;
    long long sources, risk_signals, risk;
    long long first_seen, last_seen;
    int       is_ap;
    char      dhcp_name[WEB_SDB_TEXT_MAX + 1];
    char      mdns_name[WEB_SDB_TEXT_MAX + 1];
    char      nbns_name[WEB_SDB_TEXT_MAX + 1];
    /* the drawer's, v6 and v7 only */
    long long device_class;
    char      camera_vendor[WEB_SDB_TEXT_MAX + 1];
    char      camera_model[WEB_SDB_TEXT_MAX + 1];
    char      dhcp_vci[WEB_SDB_TEXT_MAX + 1];
} web_sdb_dev_t;

typedef int (*web_sdb_dev_fn)(void *ctx, const web_sdb_dev_t *d);

/* The devices q matches, sorted, at most limit from offset, each to fn
 * (which returns nonzero to stop). Rows given, or -1 (*why "timeout" or
 * "error"). */
int  web_sdb_devices(web_sdb_conn_t *c, const web_query_t *q, int sort,
                     long long limit, long long offset, web_sdb_dev_fn fn,
                     void *ctx, const char **why);

/* One device by MAC, with the drawer's columns: 1, 0 none, -1. */
int  web_sdb_device(web_sdb_conn_t *c, const char *mac, web_sdb_dev_t *out);

typedef struct {
    char      a[WEB_SDB_TEXT_MAX + 1];   /* ssid / bssid / ip / mac / name */
    char      b[WEB_SDB_TEXT_MAX + 1];   /* assoc ssid; name source */
    long long n1, n2;                    /* assoc source, channel; alert
                                            type, sev; nbns suffix */
    int       has_n3;
    long long n3;                        /* assoc signal; alert count */
    long long first_seen, last_seen;
} web_sdb_item_t;

typedef int (*web_sdb_item_fn)(void *ctx, const web_sdb_item_t *it);

/* PNL SSIDs of mac (a = ssid), newest first. */
int  web_sdb_ssids(web_sdb_conn_t *c, const char *mac, int max,
                   web_sdb_item_fn fn, void *ctx);
/* Associations with mac as the station (a = bssid, b = ssid, n1 =
 * source, n2 = channel, n3 = signal). */
int  web_sdb_assocs(web_sdb_conn_t *c, const char *mac, int max,
                    web_sdb_item_fn fn, void *ctx);
/* ARP bindings: of mac (a = ip), or of ip (a = mac). */
int  web_sdb_arp_mac(web_sdb_conn_t *c, const char *mac, int max,
                     web_sdb_item_fn fn, void *ctx);
int  web_sdb_arp_ip(web_sdb_conn_t *c, const char *ip, int max,
                    web_sdb_item_fn fn, void *ctx);
/* Passive names of ip from sloth.db: a = name, b = "dhcp", "mdns",
 * "mdns-instance" or "nbns". */
int  web_sdb_names(web_sdb_conn_t *c, const char *ip, int max,
                   web_sdb_item_fn fn, void *ctx);
/* Alerts naming mac (in their key) or ip (match_ip): a = title, n1 =
 * type, n2 = sev, n3 = count. Newest first. */
int  web_sdb_alerts(web_sdb_conn_t *c, const char *mac, const char *ip,
                    int max, web_sdb_item_fn fn, void *ctx);

/* A2 (web_anomaly.c): the earliest first_seen sloth.db holds for mac
 * in devices, probe_clients, pnl_clients and assocs. 1 (in *fs), 0 none
 * there, -1. */
int  web_sdb_first_seen(web_sdb_conn_t *c, const char *mac, long long *fs);
/* Globally administered MACs whose devices.first_seen is at or after
 * since, newest first (a locally administered one never fills a slot). */
typedef struct {
    char      mac[WEB_KEY_MAX + 1];
    long long first_seen;
} web_sdb_new_t;
int  web_sdb_new_macs(web_sdb_conn_t *c, long long since, web_sdb_new_t *out,
                      int max);

/* Test seams: the flags and the URI mode of the last open
 * (web/tests/test_slothdb.c). */
extern int web_slothdb_test_flags;
extern int web_slothdb_test_immutable;
/* Called, when set, between the choice of open and sqlite3_open_v2(). */
extern void (*web_slothdb_test_before_open)(void);

#endif
