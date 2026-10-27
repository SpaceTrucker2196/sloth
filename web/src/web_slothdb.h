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
#include "web_secret.h"

#define WEB_SDB_SCHEMA_MIN 1
#define WEB_SDB_SCHEMA_MAX 8
#define WEB_SDB_BUSY_MS    100
#define WEB_SDB_HTTP_MS    250       /* a request's budget */
/* /api/history/overview's alone. It counts every device and alert
 * episode begun in up to 400 days, where every other route reads a
 * page of rows. On the owner's 254 MB snapshot (867,748 alerts, every
 * one inside the last 30 days, no first_seen index) the count took
 * 253 ms as one GROUP BY, past WEB_SDB_HTTP_MS. As web_sdb_overview()
 * reads it now that file takes the scan plan: 123-246 ms on an idle
 * desktop core with the file in the page cache, 0.3-1.1 s with the
 * same host at load average 17 (SQLite 3.45.1 and 3.53.4 alike); with
 * sloth's idx_alerts_first_seen, 32-320 ms over the same span. Those
 * are best-case figures for a desktop: 1500 ms is 6-12 times the idle
 * scan but only 1.3-5 times the loaded one. A sensor-class host (a
 * Raspberry Pi 4, several times slower a core, an SD card cold) is the
 * case the budget is for and was not measured; a 503 names the plan
 * that ran out, so a slow scan of a file sloth has not reindexed is
 * told apart from a slow index count. 1500 ms is also the longest the
 * single HTTP thread stalls, once per WEB_SDB_OVC_TTL_MS per file
 * state given the cache below. test_history.c holds a generated file
 * of the snapshot's shape to it (test_overview_on_the_owners_shape). */
#define WEB_SDB_OVERVIEW_MS 1500
#define WEB_SDB_PASS_MS    200       /* a minute pass's (A2) */
#define WEB_SDB_ERR_MAX    200
#define WEB_SDB_TEXT_MAX   63

/* sloth.db freshness (#168). The DB-backed views are as old as the file
 * they read, which with a --sloth-db snapshot is however long ago it was
 * taken. Past WEB_SDB_STALE_S, while the stream is current (a record in
 * the last WEB_SDB_STREAM_CURRENT_S), the page says the database is
 * stale: the rest of the page updating is what makes an old table look
 * live. sloth commits every --db-interval-secs (1 s in the shipped unit),
 * so a live sloth.db is seconds old. */
#define WEB_SDB_STALE_S          600
#define WEB_SDB_STREAM_CURRENT_S 60

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
    int         pred;     /* 1 predicate-only: readable by the statements
                             that set web_sdb_conn_t.pred_ok alone; 2
                             typed-detail: by those that set detail_ok
                             alone (alerts.detail, web_alertdb.h) */
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
    struct web_live_s   *live;   /* web_inpass(mac): the latest pass */
} web_sdb_fns_t;

typedef struct {
    int           state;
    int           schema;            /* 0 unknown */
    long long     rows;              /* devices rows at the last check; -1 */
    char          mode[12];          /* "wal", "immutable", "rollback", "" */
    long long     mtime;             /* what the last check read is as of,
                                        unix s (web_slothdb_data_mtime);
                                        0 unknown */
    char          err[WEB_SDB_ERR_MAX];
    unsigned long opens, refusals, errors, timeouts;
    unsigned long ovw_hits, ovw_misses;  /* the overview cache's */
} web_sdb_stats_t;

struct web_sdb_ovc;

typedef struct web_slothdb {
    char            path[4096];
    int             configured;
    web_sdb_fns_t   fns;
    pthread_mutex_t mu;              /* guards st and ovc */
    web_sdb_stats_t st;
    struct web_sdb_ovc *ovc;         /* the overview cache, made on first use */
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
    /* The progress handler's calls, one per 1000 VM steps: the work a
     * read did, which the tests compare where a clock would be flaky. */
    unsigned long   ticks;
    /* What web_sdb_overview() was reading ("devices", "alerts") and
     * the rows it had counted, for a timeout's answer; and how it read
     * each table (WEB_SDB_PLAN_*: [0] devices, [1] alerts). */
    const char     *what;
    long long       rows_read;
    int             plan[2];
    int             detail_ok;       /* alerts.detail may be read (web_alertdb.h) */
} web_sdb_conn_t;

/* How web_sdb_overview() counted a table. */
enum {
    WEB_SDB_PLAN_NONE = 0,
    WEB_SDB_PLAN_INDEX,              /* per cell over idx_<t>_first_seen */
    WEB_SDB_PLAN_BOUND,              /* the rows with last_seen >= from,
                                        by idx_<t>_last_seen */
    WEB_SDB_PLAN_SCAN,               /* every row */
    WEB_SDB_PLAN_EMPTY               /* max(last_seen) < from: none */
};

enum {
    WEB_SDB_OPT_CLASS = 1 << 0,      /* devices.device_class, camera_* (v6) */
    WEB_SDB_OPT_VCI   = 1 << 1,      /* devices.dhcp_vci (v7) */
    WEB_SDB_OPT_INC   = 1 << 2       /* alerts.incident_first_seen, reopens (v8) */
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
/* The same open for the SQL box (web_sqlbox.h): its VFS refuses every
 * temporary file and its temp_store is FILE, so a statement's sorts and
 * temporary b-trees are bounded by the page cache. */
int  web_slothdb_open_box(web_slothdb_t *s, web_sdb_conn_t *c, int budget_ms,
                          long long now_s, char *err, size_t errsz);
void web_slothdb_close(web_sdb_conn_t *c);

/* Open, count devices, close: the health check. The state. It also
 * records the data's mtime (web_slothdb_data_mtime) in the stats. */
int  web_slothdb_check(web_slothdb_t *s, long long now_s);

/* The mtime, unix seconds, of the data a read of path in mode sees:
 * a WAL reader ("wal") reads sloth's -wal as well as the main file, and
 * sloth's commits land in the -wal until a checkpoint, so it is the newer
 * of the two; "immutable" and "rollback" read the main file alone (an
 * immutable open ignores a -wal). 0 when the file is not a regular one.
 * lstat(), so a symlink is never followed. */
long long web_slothdb_data_mtime(const char *path, const char *mode);

/* 1 when a database age_s old should be called stale: older than
 * WEB_SDB_STALE_S while the live stream is current. A stream that is not
 * current is its own message (the socket state); an unknown age (< 0) is
 * not stale. */
int  web_sdb_is_stale(long long age_s, int stream_current);
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
    long long rid, rows;                 /* an alert key's newest rowid and
                                            its rows read (web_alertdb.h) */
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
/* Alerts naming mac (in their key) or ip (match_ip), one item per key
 * (its rows collapsed: rid the key's newest rowid, rows its incidents,
 * 1 + reopens a v8 row): a = title, n1 = type, n2 = the highest sev,
 * n3 = the sum of count. Newest first, at most max; returns one more
 * than given when there were more. The walk goes back through the
 * table newest first a slice at a time while the request's budget has
 * more than WEB_SDB_ALERT_RESERVE_MS left; *reached is 0 when it read
 * the whole table, else the last_seen it reached back to (the figures
 * then count the rows read). */
#define WEB_SDB_ALERT_SCAN 20000
#define WEB_SDB_ALERT_RESERVE_MS 80
int  web_sdb_alerts(web_sdb_conn_t *c, const char *mac, const char *ip,
                    int max, web_sdb_item_fn fn, void *ctx,
                    long long *reached);

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

/* ── M5 reads (#163): the WiFi and History views ─────────────────────── */

/* sloth's ALERT_TYPE_DEAUTH_FLOOD (include/sloth_alerts.def row order;
 * web/tests/test_wifi.c holds it to sloth's enum). */
#define WEB_ALERT_DEAUTH_FLOOD 1

typedef struct {
    char      bssid[WEB_KEY_MAX + 1];
    char      ssid[WEB_SDB_TEXT_MAX + 1];
    char      enc[WEB_SDB_TEXT_MAX + 1];
    char      akm[WEB_SDB_TEXT_MAX + 1];
    char      vendor[WEB_SDB_TEXT_MAX + 1];
    char      phy[WEB_SDB_TEXT_MAX + 1];
    int       has_signal, signal_dbm;
    long long channel, akm_bits, mfp, downgrade, has_wps;
    long long first_seen, last_seen;
    long long ssid_count;            /* beacon_ap_ssids rows */
    int       has_karma;             /* a karma_candidates row */
    long long k_score, k_ssids, k_overlap, k_ie_uniform;
} web_sdb_ap_t;

typedef int (*web_sdb_ap_fn)(void *ctx, const web_sdb_ap_t *a);

enum { WEB_AP_SORT_LAST = 0, WEB_AP_SORT_SSIDS, WEB_AP_SORT_KARMA,
       WEB_AP_SORT_BSSID, WEB_AP_SORT_SSID, WEB_AP_SORT_CHANNEL,
       WEB_AP_SORT_SIGNAL, WEB_AP_SORT_ENC, WEB_AP_SORT_MFP,
       WEB_AP_SORT_DOWNGRADE, WEB_AP_SORT_FIRST, WEB_AP_SORT_COUNT };

/* beacon_aps with each one's SSID count and KARMA score, sorted, at
 * most limit from offset. Rows given, or -1; 0 when the file has no
 * beacon_aps with the columns read. */
int  web_sdb_aps(web_sdb_conn_t *c, int sort, long long limit,
                 long long offset, web_sdb_ap_fn fn, void *ctx);
/* The SSIDs bssid has advertised (a = ssid), newest first. */
int  web_sdb_ap_ssids(web_sdb_conn_t *c, const char *bssid, int max,
                      web_sdb_item_fn fn, void *ctx);
/* The SSID beacon_aps holds for bssid, its octets as sloth stored them
 * (the channel mix's AP names: the octets the TUI colours by), into out
 * (WEB_SDB_TEXT_MAX + 1). 1, 0 none (or no such table), -1. */
int  web_sdb_ap_ssid(web_sdb_conn_t *c, const char *bssid, char *out);
/* DEAUTH_FLOOD episodes against bssid overlapping [from, to): n2 = sev,
 * n3 = count. Matched on alerts.key (predicate-only, a canonical MAC
 * bound) and the type; oldest first. */
int  web_sdb_deauth_floods(web_sdb_conn_t *c, const char *bssid,
                           long long from, long long to, int max,
                           web_sdb_item_fn fn, void *ctx);

typedef struct {
    long long id, started, ended;    /* ended -1: never recorded */
    char      label[WEB_SDB_TEXT_MAX + 1];
} web_sdb_session_t;

/* Sessions, newest first (by started, then id), at most max into out.
 * Count, or -1; 0 when the file has no sessions table. */
int  web_sdb_sessions(web_sdb_conn_t *c, web_sdb_session_t *out, int max);
/* One session by id, the one before it (sloth's "previous": of the
 * sessions recorded before it, the latest started) and the next one's
 * start (-1 none). 1 found (*has_prev set), 0 none, -1. */
int  web_sdb_session_pair(web_sdb_conn_t *c, long long id,
                          web_sdb_session_t *s, web_sdb_session_t *prev,
                          int *has_prev, long long *next_started);

enum { WEB_NEW_AP = 0, WEB_NEW_DEVICE, WEB_NEW_PROBE, WEB_NEW_KINDS };
/* --report's "New since last survey" (src/db.c db_new_since(), and
 * db_count_new_since()): the kind's rows with since <= first_seen
 * (and first_seen <= until, when until >= 0), newest first, at most max
 * (a = identity, b = label), and their count in *total. Rows, or -1. */
int  web_sdb_new_since(web_sdb_conn_t *c, int kind, long long since,
                       long long until, int max, web_sdb_item_fn fn,
                       void *ctx, long long *total);

/* Devices whose [first_seen, last_seen] overlaps [from, to], newest
 * last_seen first, at most limit from offset. */
int  web_sdb_devices_between(web_sdb_conn_t *c, long long from, long long to,
                             long long limit, long long offset,
                             web_sdb_dev_fn fn, void *ctx);
/* Alerts whose latest incident overlaps [from, to), one item per key,
 * the keys among the WEB_SDB_ALERT_SCAN newest rows of the range, each
 * key's figures over all of its rows in the range (through the primary
 * key): a = title, b = match_ip, n1 = type, n2 = the highest sev, n3 =
 * the sum of count, rid its newest rowid in the range, rows its rows
 * there (each at least one incident). Newest first. */
int  web_sdb_alerts_between(web_sdb_conn_t *c, long long from, long long to,
                            int max, web_sdb_item_fn fn, void *ctx);
/* The rows of the range web_sdb_alerts_between() took its keys from (at
 * most WEB_SDB_ALERT_SCAN) and the oldest last_seen among them. 0, -1. */
int  web_sdb_alerts_scan(web_sdb_conn_t *c, long long from, long long to,
                         long long *rows, long long *oldest);
/* Flows (ssh_flows, rdp_flows, smb_sessions, snmp_flows) overlapping
 * [from, to): a = src, b = dst, n1 = WEB_FLOW_*, n2 = their count
 * (banners, connect requests, messages, PDUs), n3 = the server port
 * (smb) or the SNMP version. Newest first. */
enum { WEB_FLOW_SSH = 0, WEB_FLOW_RDP, WEB_FLOW_SMB, WEB_FLOW_SNMP,
       WEB_FLOW_KINDS };
int  web_sdb_flows_between(web_sdb_conn_t *c, long long from, long long to,
                           int max, web_sdb_item_fn fn, void *ctx);
/* Per cell of ncell cells of cell_s seconds from from: devices first
 * seen in it (devs) and alert episodes begun in it (alerts). 0, or -1.
 *
 * Each table is counted the cheapest way the file allows (c->plan):
 * with sloth's idx_<t>_first_seen, one count per cell over that index;
 * without it (a file sloth has not opened since the index was added),
 * the first_seen of the rows in range, bucketed here rather than by a
 * GROUP BY, whose sorter was most of its cost. Those rows are found
 * through idx_<t>_last_seen when most of the table ended before from
 * (sloth stores first_seen <= last_seen, so last_seen >= from loses no
 * row: the device upsert binds both from one time and keeps MIN/MAX,
 * and write_events() clamps an alert episode the engine stamped across
 * a backward wall-clock step; a file an older sloth wrote across such a
 * step can hold an episode that the bound leaves out), and by
 * a scan otherwise: for a table that is mostly in range the index
 * costs about twice the scan per row. "Most" is estimated from
 * min(last_seen) and max(last_seen), two index probes, as a fraction
 * of that span: under 2/5 in range, the index. */
int  web_sdb_overview(web_sdb_conn_t *c, long long from, int cell_s,
                      int ncell, long long *devs, long long *alerts);

/* ── the overview cache ─────────────────────────────────────────────── *
 *
 * The overview's counts and sessions, kept per sloth.db state for at
 * most WEB_SDB_OVC_TTL_MS: an immutable snapshot is counted once a
 * minute at most, however often the page asks. The state is the main
 * file's and the -wal's device, inode, mtime and size, read before the
 * query, so a write during it misses next time; a running sloth
 * changes its -wal every tick and is in effect not cached. A request
 * matches an entry with the same state, cell and cell count whose from
 * falls in the same cell, and is answered with that entry's from and
 * to. WEB_SDB_OVC_SLOTS entries, made on first use, the oldest
 * replaced: bounded memory. Thread-safe (web_slothdb_t.mu). */
#define WEB_SDB_OVC_SLOTS    4
#define WEB_SDB_OVC_TTL_MS   60000
#define WEB_SDB_OVC_CELLS    360     /* WEB_HIST_COLS_MAX */
#define WEB_SDB_OVC_SESSIONS 200     /* WEB_HIST_SESSIONS */

typedef struct {
    long long dev, ino, mtime_s, mtime_ns, size;
} web_sdb_fstate_t;

typedef struct {
    web_sdb_fstate_t main, wal;      /* wal all 0: no -wal */
} web_sdb_ident_t;

typedef struct {
    long long         from, to;
    int               cell_s, ncell;
    long long         devs[WEB_SDB_OVC_CELLS], alerts[WEB_SDB_OVC_CELLS];
    int               ns;
    web_sdb_session_t ss[WEB_SDB_OVC_SESSIONS];
} web_sdb_ovw_t;

/* The file's state now: 0, or -1 (no file there: nothing to cache). */
int  web_sdb_ovc_ident(const web_slothdb_t *s, web_sdb_ident_t *id);
/* 1 and the entry in *out, or 0 (counted as a miss). */
int  web_sdb_ovc_get(web_slothdb_t *s, const web_sdb_ident_t *id,
                     long long from, int cell_s, int ncell, web_sdb_ovw_t *out);
void web_sdb_ovc_put(web_slothdb_t *s, const web_sdb_ident_t *id,
                     const web_sdb_ovw_t *v);
/* Test seam: added to the cache's clock, to age an entry. */
extern long long web_sdb_ovc_test_skew_ms;

/* ── M6 reads (#164): the Flows view ──────────────────────────────────── */

/* The protocol tables the Flows view reads, one per tab, in tab order.
 * The first four share WEB_FLOW_*'s numbers (History's flows).
 * mqtt_flows is not one: it holds MQTT usernames (last_username), and
 * the allow-list keeps that table whole off, as it did in M4. */
enum { WEB_FP_SSH = WEB_FLOW_SSH, WEB_FP_RDP = WEB_FLOW_RDP,
       WEB_FP_SMB = WEB_FLOW_SMB, WEB_FP_SNMP = WEB_FLOW_SNMP,
       WEB_FP_LDAP, WEB_FP_KERB, WEB_FP_BGP, WEB_FP_KINDS };
#define WEB_FP_COLS 6

typedef struct {
    const char *name;                 /* "ssh", the tab and the ?proto= */
    const char *table;
    const char *src, *dst;            /* dst NULL: a per-source table */
    const char *cols[WEB_FP_COLS + 1];/* its counters, NULL-ended */
    const char *xint;                 /* one more integer, or NULL */
    const char *xtext;                /* one more short text, or NULL */
    const char *withheld;             /* columns left off the allow-list,
                                         and why; NULL none */
} web_sdb_ftab_t;

extern const web_sdb_ftab_t web_sdb_ftab[WEB_FP_KINDS];
/* The tab's index for a name, or -1. */
int web_sdb_ftab_find(const char *name);

typedef struct {
    int       proto;
    char      src[WEB_SDB_TEXT_MAX + 1];
    char      dst[WEB_SDB_TEXT_MAX + 1];
    long long n[WEB_FP_COLS];
    int       ncols;
    long long total;                  /* the sum of n */
    int       has_xint;
    long long xint;
    char      xtext[16];
    long long first_seen, last_seen;
} web_sdb_flow_t;

typedef int (*web_sdb_flow_fn)(void *ctx, const web_sdb_flow_t *f);

enum { WEB_FLOWS_SORT_LAST = 0, WEB_FLOWS_SORT_TOTAL, WEB_FLOWS_SORT_SRC,
       WEB_FLOWS_SORT_DST, WEB_FLOWS_SORT_FIRST, WEB_FLOWS_SORT_COUNT };

/* One tab's rows overlapping [from, to), sorted, at most limit from
 * offset; ip, when not NULL, matches src or dst. *present 0 when the
 * file has no such table (or lacks a column read): no rows. *total is
 * every matching row's count. Rows given, or -1. */
int web_sdb_flows(web_sdb_conn_t *c, int proto, long long from, long long to,
                  const char *ip, int sort, long long limit, long long offset,
                  web_sdb_flow_fn fn, void *ctx, int *present,
                  long long *total);

/* The pairs of every pair table (ldap and kerb have no dst) overlapping
 * [from, to), largest total first, at most max to fn; and over all of
 * them (sums[]): rows, pairs, the sum of totals, distinct endpoints.
 * Per tab (tabs[k][0] rows, [1] sum of totals; -1 absent). 0, or -1. */
typedef struct {
    long long rows, pair_rows, flow_total, pair_total, nodes;
    long long tabs[WEB_FP_KINDS][2];
} web_sdb_fsum_t;
int web_sdb_flow_pairs(web_sdb_conn_t *c, long long from, long long to,
                       int max, web_sdb_flow_fn fn, void *ctx,
                       web_sdb_fsum_t *sum);

/* Test seams: the flags and the URI mode of the last open
 * (web/tests/test_slothdb.c). */
extern int web_slothdb_test_flags;
extern int web_slothdb_test_immutable;
/* Called, when set, between the choice of open and sqlite3_open_v2(). */
extern void (*web_slothdb_test_before_open)(void);

#endif
