#include "web_slothdb.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "web_anomaly.h"
#include "web_json.h"
#include "web_metrics.h"
#include "web_ptr.h"

/* The columns slothweb may read from sloth.db, and nothing else: the
 * authorizer below denies the rest at prepare. Credential-bearing and
 * secret columns are absent by construction and held absent by
 * test_slothdb.c, which reads tests/test_db.c's guardrail list. */
const web_sdb_col_t web_sdb_allow[] = {
    { "meta", "key", 1, 0, 0 },          { "meta", "value", 1, 0, 0 },
    { "devices", "mac", 1, 0, 0 },       { "devices", "ip", 1, 0, 0 },
    { "devices", "hostname", 1, 0, 0 },  { "devices", "vendor", 1, 0, 0 },
    { "devices", "last_ssid", 1, 0, 0 }, { "devices", "is_ap", 1, 0, 0 },
    { "devices", "signal_dbm", 1, 0, 0 },{ "devices", "sources", 1, 0, 0 },
    { "devices", "risk_signals", 1, 0, 0 }, { "devices", "risk_level", 1, 0, 0 },
    { "devices", "first_seen", 1, 0, 0 },{ "devices", "last_seen", 1, 0, 0 },
    { "devices", "device_class", 6, 1, 0 }, { "devices", "camera_vendor", 6, 1, 0 },
    { "devices", "camera_model", 6, 1, 0 }, { "devices", "dhcp_vci", 7, 1, 0 },
    { "pnl_clients", "mac", 1, 0, 0 },   { "pnl_clients", "first_seen", 1, 0, 0 },
    { "pnl_ssids", "mac", 1, 0, 0 },     { "pnl_ssids", "ssid", 1, 0, 0 },
    { "pnl_ssids", "first_seen", 1, 0, 0 }, { "pnl_ssids", "last_seen", 1, 0, 0 },
    { "probe_clients", "mac", 1, 0, 0 }, { "probe_clients", "first_seen", 1, 0, 0 },
    { "assocs", "bssid", 1, 0, 0 },      { "assocs", "sta_mac", 1, 0, 0 },
    { "assocs", "ssid", 1, 0, 0 },       { "assocs", "source", 1, 0, 0 },
    { "assocs", "channel", 1, 0, 0 },    { "assocs", "signal_dbm", 1, 0, 0 },
    { "assocs", "first_seen", 1, 0, 0 }, { "assocs", "last_seen", 1, 0, 0 },
    { "arp", "ip", 1, 0, 0 },            { "arp", "mac", 1, 0, 0 },
    { "arp", "first_seen", 1, 0, 0 },    { "arp", "last_seen", 1, 0, 0 },
    { "dhcp_leases", "ip", 1, 0, 0 },    { "dhcp_leases", "hostname", 1, 0, 0 },
    { "dhcp_leases", "first_seen", 1, 0, 0 }, { "dhcp_leases", "last_seen", 1, 0, 0 },
    { "mdns_services", "instance", 1, 0, 0 }, { "mdns_services", "host", 1, 0, 0 },
    { "mdns_services", "ip", 1, 0, 0 },  { "mdns_services", "first_seen", 1, 0, 0 },
    { "mdns_services", "last_seen", 1, 0, 0 },
    { "nbns_names", "name", 1, 0, 0 },   { "nbns_names", "suffix", 1, 0, 0 },
    { "nbns_names", "ip", 1, 0, 0 },     { "nbns_names", "first_seen", 1, 0, 0 },
    { "nbns_names", "last_seen", 1, 0, 0 },
    { "alerts", "key", 1, 0, 1 },     { "alerts", "type", 1, 0, 0 },
    { "alerts", "sev", 1, 0, 0 },        { "alerts", "title", 1, 0, 0 },
    { "alerts", "match_ip", 1, 0, 0 },   { "alerts", "count", 1, 0, 0 },
    { "alerts", "first_seen", 1, 0, 0 }, { "alerts", "last_seen", 1, 0, 0 },
    /* M5 (#163): the WiFi view's AP table and the History view. */
    { "beacon_aps", "bssid", 1, 0, 0 },  { "beacon_aps", "ssid", 1, 0, 0 },
    { "beacon_aps", "signal_dbm", 1, 0, 0 }, { "beacon_aps", "channel", 1, 0, 0 },
    { "beacon_aps", "enc", 1, 0, 0 },    { "beacon_aps", "akm", 1, 0, 0 },
    { "beacon_aps", "akm_bits", 1, 0, 0 }, { "beacon_aps", "mfp", 1, 0, 0 },
    { "beacon_aps", "downgrade_flags", 1, 0, 0 }, { "beacon_aps", "vendor", 1, 0, 0 },
    { "beacon_aps", "phy", 1, 0, 0 },    { "beacon_aps", "has_wps", 1, 0, 0 },
    { "beacon_aps", "first_seen", 1, 0, 0 }, { "beacon_aps", "last_seen", 1, 0, 0 },
    { "beacon_ap_ssids", "bssid", 1, 0, 0 }, { "beacon_ap_ssids", "ssid", 1, 0, 0 },
    { "beacon_ap_ssids", "first_seen", 1, 0, 0 },
    { "beacon_ap_ssids", "last_seen", 1, 0, 0 },
    { "karma_candidates", "bssid", 1, 0, 0 }, { "karma_candidates", "score", 1, 0, 0 },
    { "karma_candidates", "ssid_count", 1, 0, 0 },
    { "karma_candidates", "pnl_overlap", 1, 0, 0 },
    { "karma_candidates", "ie_uniform", 1, 0, 0 },
    { "sessions", "id", 1, 0, 0 },       { "sessions", "started", 1, 0, 0 },
    { "sessions", "ended", 1, 0, 0 },    { "sessions", "site_label", 1, 0, 0 },
    { "probe_clients", "ssid", 1, 0, 0 },
    { "ssh_flows", "src_ip", 1, 0, 0 },  { "ssh_flows", "dst_ip", 1, 0, 0 },
    { "ssh_flows", "banner_count", 1, 0, 0 },
    { "ssh_flows", "first_seen", 1, 0, 0 }, { "ssh_flows", "last_seen", 1, 0, 0 },
    { "rdp_flows", "src_ip", 1, 0, 0 },  { "rdp_flows", "dst_ip", 1, 0, 0 },
    { "rdp_flows", "connect_req_count", 1, 0, 0 },
    { "rdp_flows", "first_seen", 1, 0, 0 }, { "rdp_flows", "last_seen", 1, 0, 0 },
    { "smb_sessions", "client_ip", 1, 0, 0 }, { "smb_sessions", "server_ip", 1, 0, 0 },
    { "smb_sessions", "server_port", 1, 0, 0 },
    { "smb_sessions", "obs_count", 1, 0, 0 },
    { "smb_sessions", "first_seen", 1, 0, 0 }, { "smb_sessions", "last_seen", 1, 0, 0 },
    { "snmp_flows", "src_ip", 1, 0, 0 }, { "snmp_flows", "dst_ip", 1, 0, 0 },
    { "snmp_flows", "get_count", 1, 0, 0 }, { "snmp_flows", "getnext_count", 1, 0, 0 },
    { "snmp_flows", "getbulk_count", 1, 0, 0 }, { "snmp_flows", "set_count", 1, 0, 0 },
    { "snmp_flows", "response_count", 1, 0, 0 },
    { "snmp_flows", "trap_count", 1, 0, 0 }, { "snmp_flows", "version", 1, 0, 0 },
    { "snmp_flows", "first_seen", 1, 0, 0 }, { "snmp_flows", "last_seen", 1, 0, 0 },
};
const size_t web_sdb_allow_n = sizeof(web_sdb_allow) / sizeof(web_sdb_allow[0]);

int web_slothdb_test_flags = 0;
int web_slothdb_test_immutable = 0;
void (*web_slothdb_test_before_open)(void) = NULL;

const char *web_slothdb_state_word(int state) {
    switch (state) {
    case WEB_SDB_OPEN:    return "open";
    case WEB_SDB_MISSING: return "missing";
    case WEB_SDB_REFUSED: return "refused";
    case WEB_SDB_ERROR:   return "error";
    case WEB_SDB_UNBUILT: return "unbuilt";
    default:              return "none";
    }
}

void web_slothdb_init(web_slothdb_t *s, const char *path,
                      const web_sdb_fns_t *fns) {
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->mu, NULL);
    if (fns) s->fns = *fns;
    s->st.rows = -1;
    if (path && path[0] && strlen(path) < sizeof(s->path)) {
        snprintf(s->path, sizeof(s->path), "%s", path);
        s->configured = 1;
    }
}

void web_slothdb_destroy(web_slothdb_t *s) {
    pthread_mutex_destroy(&s->mu);
}

void web_slothdb_stats(web_slothdb_t *s, web_sdb_stats_t *out) {
    pthread_mutex_lock(&s->mu);
    *out = s->st;
    pthread_mutex_unlock(&s->mu);
}

#ifndef WITH_SQLITE

int web_slothdb_available(void) { return 0; }
int web_slothdb_open_flags(void) { return 0; }

int web_slothdb_open(web_slothdb_t *s, web_sdb_conn_t *c, int budget_ms,
                     long long now_s, char *err, size_t errsz) {
    (void)budget_ms; (void)now_s;
    memset(c, 0, sizeof(*c));
    c->s = s;
    pthread_mutex_lock(&s->mu);
    s->st.state = s->configured ? WEB_SDB_UNBUILT : WEB_SDB_NONE;
    pthread_mutex_unlock(&s->mu);
    snprintf(err, errsz, "slothweb was built without SQLite; no sloth.db");
    return -1;
}

int web_slothdb_open_box(web_slothdb_t *s, web_sdb_conn_t *c, int budget_ms,
                         long long now_s, char *err, size_t errsz) {
    return web_slothdb_open(s, c, budget_ms, now_s, err, errsz);
}

void web_slothdb_close(web_sdb_conn_t *c) { (void)c; }

int web_slothdb_check(web_slothdb_t *s, long long now_s) {
    web_sdb_conn_t c;
    char err[8];
    web_slothdb_open(s, &c, 0, now_s, err, sizeof(err));
    return s->st.state;
}

int web_sdb_devices(web_sdb_conn_t *c, const web_query_t *q, int sort,
                    long long limit, long long offset, web_sdb_dev_fn fn,
                    void *ctx, const char **why) {
    (void)c; (void)q; (void)sort; (void)limit; (void)offset; (void)fn; (void)ctx;
    *why = "error";
    return -1;
}
int web_sdb_device(web_sdb_conn_t *c, const char *mac, web_sdb_dev_t *out) {
    (void)c; (void)mac; (void)out;
    return -1;
}
int web_sdb_ssids(web_sdb_conn_t *c, const char *mac, int max,
                  web_sdb_item_fn fn, void *ctx) {
    (void)c; (void)mac; (void)max; (void)fn; (void)ctx;
    return -1;
}
int web_sdb_assocs(web_sdb_conn_t *c, const char *mac, int max,
                   web_sdb_item_fn fn, void *ctx) {
    (void)c; (void)mac; (void)max; (void)fn; (void)ctx;
    return -1;
}
int web_sdb_arp_mac(web_sdb_conn_t *c, const char *mac, int max,
                    web_sdb_item_fn fn, void *ctx) {
    (void)c; (void)mac; (void)max; (void)fn; (void)ctx;
    return -1;
}
int web_sdb_arp_ip(web_sdb_conn_t *c, const char *ip, int max,
                   web_sdb_item_fn fn, void *ctx) {
    (void)c; (void)ip; (void)max; (void)fn; (void)ctx;
    return -1;
}
int web_sdb_names(web_sdb_conn_t *c, const char *ip, int max,
                  web_sdb_item_fn fn, void *ctx) {
    (void)c; (void)ip; (void)max; (void)fn; (void)ctx;
    return -1;
}
int web_sdb_alerts(web_sdb_conn_t *c, const char *mac, const char *ip,
                   int max, web_sdb_item_fn fn, void *ctx) {
    (void)c; (void)mac; (void)ip; (void)max; (void)fn; (void)ctx;
    return -1;
}
int web_sdb_first_seen(web_sdb_conn_t *c, const char *mac, long long *fs) {
    (void)c; (void)mac; (void)fs;
    return -1;
}
int web_sdb_new_macs(web_sdb_conn_t *c, long long since, web_sdb_new_t *out,
                     int max) {
    (void)c; (void)since; (void)out; (void)max;
    return -1;
}
int web_sdb_aps(web_sdb_conn_t *c, int sort, long long limit,
                long long offset, web_sdb_ap_fn fn, void *ctx) {
    (void)c; (void)sort; (void)limit; (void)offset; (void)fn; (void)ctx;
    return -1;
}
int web_sdb_ap_ssids(web_sdb_conn_t *c, const char *bssid, int max,
                     web_sdb_item_fn fn, void *ctx) {
    (void)c; (void)bssid; (void)max; (void)fn; (void)ctx;
    return -1;
}
int web_sdb_deauth_floods(web_sdb_conn_t *c, const char *bssid,
                          long long from, long long to, int max,
                          web_sdb_item_fn fn, void *ctx) {
    (void)c; (void)bssid; (void)from; (void)to; (void)max; (void)fn; (void)ctx;
    return -1;
}
int web_sdb_sessions(web_sdb_conn_t *c, web_sdb_session_t *out, int max) {
    (void)c; (void)out; (void)max;
    return -1;
}
int web_sdb_session_pair(web_sdb_conn_t *c, long long id,
                         web_sdb_session_t *s, web_sdb_session_t *prev,
                         int *has_prev, long long *next_started) {
    (void)c; (void)id; (void)s; (void)prev;
    *has_prev = 0;
    *next_started = -1;
    return -1;
}
int web_sdb_new_since(web_sdb_conn_t *c, int kind, long long since,
                      long long until, int max, web_sdb_item_fn fn,
                      void *ctx, long long *total) {
    (void)c; (void)kind; (void)since; (void)until; (void)max; (void)fn;
    (void)ctx;
    *total = 0;
    return -1;
}
int web_sdb_devices_between(web_sdb_conn_t *c, long long from, long long to,
                            long long limit, long long offset,
                            web_sdb_dev_fn fn, void *ctx) {
    (void)c; (void)from; (void)to; (void)limit; (void)offset; (void)fn;
    (void)ctx;
    return -1;
}
int web_sdb_alerts_between(web_sdb_conn_t *c, long long from, long long to,
                           int max, web_sdb_item_fn fn, void *ctx) {
    (void)c; (void)from; (void)to; (void)max; (void)fn; (void)ctx;
    return -1;
}
int web_sdb_flows_between(web_sdb_conn_t *c, long long from, long long to,
                          int max, web_sdb_item_fn fn, void *ctx) {
    (void)c; (void)from; (void)to; (void)max; (void)fn; (void)ctx;
    return -1;
}
int web_sdb_overview(web_sdb_conn_t *c, long long from, int cell_s,
                     int ncell, long long *devs, long long *alerts) {
    (void)c; (void)from; (void)cell_s; (void)ncell; (void)devs; (void)alerts;
    return -1;
}


#else

#include <sqlite3.h>

int web_slothdb_available(void) { return 1; }

int web_slothdb_open_flags(void) {
    return SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW;
}

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* pred_ok: whether a predicate-only column may be read. */
static int allowed_col(const char *table, const char *col, int pred_ok) {
    if (!table || !col) return 0;
    /* A withheld column is predicate-only at most, whatever the list
     * says: the two lists cannot disagree in the open direction. */
    if (col[0] && web_sdb_is_secret(table, col, NULL) && !pred_ok) return 0;
    for (size_t i = 0; i < web_sdb_allow_n; i++)
        if (!strcmp(web_sdb_allow[i].table, table) &&
            (!col[0] || !strcmp(web_sdb_allow[i].column, col)))
            return !col[0] || !web_sdb_allow[i].pred || pred_ok;
    return 0;
}

static int allowed_table(const char *table) {
    return table && allowed_col(table, "", 0);
}

/* Everything a device statement may call; nullif for --report's own
 * labels (web_sdb_new_since()). */
static const char *const FUNCS[] = {
    "like", "coalesce", "substr", "instr", "min", "max", "count", "nullif",
    "web_vendor", "web_z", "web_anoms", "web_ptr", NULL
};

static int authz(void *ud, int action, const char *a1, const char *a2,
                 const char *db, const char *trig) {
    const web_sdb_conn_t *c = ud;
    (void)db; (void)trig;
    switch (action) {
    case SQLITE_SELECT:
        return SQLITE_OK;
    case SQLITE_READ:
        /* a1 table, a2 column ("" when a table is read for no column,
         * count(*)). */
        return allowed_col(a1, a2 ? a2 : "", c->pred_ok) ? SQLITE_OK : SQLITE_DENY;
    case SQLITE_FUNCTION:
        for (int i = 0; FUNCS[i]; i++)
            if (a2 && !strcmp(FUNCS[i], a2)) return SQLITE_OK;
        return SQLITE_DENY;
    case SQLITE_PRAGMA:
        return a1 && !strcmp(a1, "table_info") && allowed_table(a2)
               ? SQLITE_OK : SQLITE_DENY;
    default:
        return SQLITE_DENY;
    }
}

static int progress(void *ud) {
    web_sdb_conn_t *c = ud;
    if (mono_ms() > c->deadline_ms) {
        c->timed_out = 1;
        return 1;
    }
    return 0;
}

/* ── SQL functions ────────────────────────────────────────────────── */

static void fn_vendor(sqlite3_context *cx, int n, sqlite3_value **v) {
    (void)n;
    web_sdb_conn_t *c = sqlite3_user_data(cx);
    const unsigned char *m = sqlite3_value_text(v[0]);
    uint8_t mac[6];
    web_oui_hit_t hit;
    if (!m || !c->s->fns.oui || web_oui_mac_bytes((const char *)m, mac) != 0 ||
        !web_oui_lookup(c->s->fns.oui, mac, &hit)) {
        sqlite3_result_null(cx);
        return;
    }
    sqlite3_result_text(cx, hit.name, -1, SQLITE_TRANSIENT);
}

static void fn_z(sqlite3_context *cx, int n, sqlite3_value **v) {
    (void)n;
    web_sdb_conn_t *c = sqlite3_user_data(cx);
    const unsigned char *m = sqlite3_value_text(v[0]);
    double z;
    if (!m || !c->s->fns.an ||
        !web_anomaly_device_z(c->s->fns.an, (const char *)m, c->now_s, &z)) {
        sqlite3_result_null(cx);
        return;
    }
    sqlite3_result_double(cx, z);
}

static void fn_anoms(sqlite3_context *cx, int n, sqlite3_value **v) {
    (void)n;
    web_sdb_conn_t *c = sqlite3_user_data(cx);
    const unsigned char *m = sqlite3_value_text(v[0]);
    int kind = sqlite3_value_int(v[1]);
    sqlite3_result_int(cx, m && c->s->fns.an
        ? web_anomaly_key_count(c->s->fns.an, (const char *)m, kind) : 0);
}

static void fn_ptr(sqlite3_context *cx, int n, sqlite3_value **v) {
    (void)n;
    web_sdb_conn_t *c = sqlite3_user_data(cx);
    const unsigned char *ip = sqlite3_value_text(v[0]);
    char name[WEB_PTR_NAME_MAX + 1], k[WEB_KEY_MAX + 1];
    if (!ip || !c->s->fns.ptr || web_key_ip((const char *)ip, k) != 0 ||
        !web_ptr_get(c->s->fns.ptr, k, name, NULL)) {
        sqlite3_result_null(cx);
        return;
    }
    sqlite3_result_text(cx, name, -1, SQLITE_TRANSIENT);
}

/* ── open ─────────────────────────────────────────────────────────── */

static void note(web_slothdb_t *s, int state, const char *err) {
    pthread_mutex_lock(&s->mu);
    s->st.state = state;
    s->st.opens++;
    if (state == WEB_SDB_REFUSED) s->st.refusals++;
    if (state == WEB_SDB_ERROR) s->st.errors++;
    snprintf(s->st.err, sizeof(s->st.err), "%s", err ? err : "");
    pthread_mutex_unlock(&s->mu);
}

static int fail(web_sdb_conn_t *c, int state, char *err, size_t errsz,
                const char *fmt, const char *a) {
    snprintf(err, errsz, fmt, c->s->path, a ? a : "");
    note(c->s, state, err);
    if (c->db) sqlite3_close(c->db);
    c->db = NULL;
    return -1;
}

/* The VFS every open here goes through: the default one, but a named
 * file (sloth.db, its journal, its -wal) is never created. The choice
 * between immutable and a WAL reader is made from lstat() before the
 * open, and SQLite opens the -wal only at the first read: a sloth that
 * closes cleanly in between removes its -wal, and a plain open would
 * then make an empty one (and a -shm) beside sloth.db. Through this
 * VFS that read fails instead (SQLITE_CANTOPEN), and the next open
 * decides again. Temporary files (a sort that spills) are SQLite's own,
 * unnamed, and keep their create flag. */
static sqlite3_vfs    g_vfs, g_vfs_box;
static sqlite3_vfs   *g_base;
static int            g_vfs_ok;
static pthread_once_t g_vfs_once = PTHREAD_ONCE_INIT;
#define WEB_SDB_VFS     "slothweb-nocreate"
#define WEB_SDB_VFS_BOX "slothweb-box"
#define SDB_NAMED (SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_MAIN_JOURNAL | SQLITE_OPEN_WAL)

static int nc_open(sqlite3_vfs *v, const char *name, sqlite3_file *f,
                   int flags, int *out) {
    (void)v;
    if (flags & SDB_NAMED)
        flags &= ~SQLITE_OPEN_CREATE;
    return g_base->xOpen(g_base, name, f, flags, out);
}

/* The SQL box's (web_sqlbox.h): the same, and no temporary file at all.
 * An operator's statement whose sort or temporary b-tree outgrows the
 * page cache fails here rather than spilling to the temporary
 * directory; the connection's own reads never need one. */
static int box_open(sqlite3_vfs *v, const char *name, sqlite3_file *f,
                    int flags, int *out) {
    if (!(flags & SDB_NAMED)) {
        f->pMethods = NULL;
        return SQLITE_CANTOPEN;
    }
    return nc_open(v, name, f, flags, out);
}

static void vfs_init(void) {
    g_base = sqlite3_vfs_find(NULL);
    if (!g_base) return;
    g_vfs = *g_base;
    g_vfs.pNext = NULL;
    g_vfs.zName = WEB_SDB_VFS;
    g_vfs.xOpen = nc_open;
    g_vfs_box = g_vfs;
    g_vfs_box.zName = WEB_SDB_VFS_BOX;
    g_vfs_box.xOpen = box_open;
    g_vfs_ok = sqlite3_vfs_register(&g_vfs, 0) == SQLITE_OK &&
               sqlite3_vfs_register(&g_vfs_box, 0) == SQLITE_OK;
}

static int exists(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

/* The header's write and read versions: 2 is WAL, 1 rollback; 0 when
 * the first 20 bytes are not an SQLite header. */
static int header_mode(const char *path) {
    unsigned char h[20];
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return 0;
    ssize_t n = pread(fd, h, sizeof(h), 0);
    close(fd);
    if (n != (ssize_t)sizeof(h) || memcmp(h, "SQLite format 3", 16) != 0)
        return 0;
    return h[18] == 2 && h[19] == 2 ? 2 : 1;
}

/* path as a file: URI with the query q, every byte that could read as
 * URI syntax percent-encoded (web_store.c does the same). */
static void ro_uri(const char *path, const char *q, char *out, size_t outsz) {
    static const char hex[] = "0123456789ABCDEF";
    size_t o = (size_t)snprintf(out, outsz, "file:");
    for (size_t i = 0; path[i] && o + 4 < outsz; i++) {
        unsigned char c = (unsigned char)path[i];
        int keep = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                    c == '-' || c == '~' || c == '/') &&
                   !(i == 1 && c == '/');
        if (keep) {
            out[o++] = (char)c;
        } else {
            out[o++] = '%';
            out[o++] = hex[c >> 4];
            out[o++] = hex[c & 15];
        }
    }
    out[o] = '\0';
    snprintf(out + o, outsz - o, "%s", q);
}

static int table_cols(sqlite3 *db, const char *table, const char *const *want,
                      unsigned *have) {
    char sql[96];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    sqlite3_stmt *st = NULL;
    *have = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int any = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        any = 1;
        const unsigned char *nm = sqlite3_column_text(st, 1);
        for (int i = 0; nm && want[i]; i++)
            if (!strcmp(want[i], (const char *)nm)) *have |= 1u << i;
    }
    sqlite3_finalize(st);
    return any;
}

/* Which tables carry every column a statement here reads, and which
 * optional devices columns the file has. */
static int probe(web_sdb_conn_t *c) {
    static const struct { const char *t; unsigned feat; } T[] = {
        { "pnl_ssids", WEB_QF_PNL }, { "dhcp_leases", WEB_QF_DHCP },
        { "mdns_services", WEB_QF_MDNS }, { "nbns_names", WEB_QF_NBNS },
        { "alerts", WEB_QF_ALERTS }, { "arp", WEB_QF_ARP },
    };
    for (size_t k = 0; k < sizeof(T) / sizeof(T[0]); k++) {
        const char *want[32];
        int nw = 0;
        for (size_t i = 0; i < web_sdb_allow_n && nw < 31; i++)
            if (!strcmp(web_sdb_allow[i].table, T[k].t))
                want[nw++] = web_sdb_allow[i].column;
        want[nw] = NULL;
        unsigned have;
        if (table_cols(c->db, T[k].t, want, &have) > 0 &&
            have == (1u << nw) - 1)
            c->feats |= T[k].feat;
    }
    const char *dw[32];
    int nd = 0;
    unsigned req = 0, optbit[32];
    for (size_t i = 0; i < web_sdb_allow_n && nd < 31; i++)
        if (!strcmp(web_sdb_allow[i].table, "devices")) {
            optbit[nd] = web_sdb_allow[i].optional
                ? (!strcmp(web_sdb_allow[i].column, "dhcp_vci")
                   ? WEB_SDB_OPT_VCI : WEB_SDB_OPT_CLASS)
                : 0;
            if (!web_sdb_allow[i].optional) req |= 1u << nd;
            dw[nd++] = web_sdb_allow[i].column;
        }
    dw[nd] = NULL;
    unsigned have;
    if (table_cols(c->db, "devices", dw, &have) <= 0 ||
        (have & req) != req)
        return -1;
    unsigned cls = 1, vci = 1;
    for (int i = 0; i < nd; i++) {
        if (optbit[i] == WEB_SDB_OPT_CLASS && !(have & (1u << i))) cls = 0;
        if (optbit[i] == WEB_SDB_OPT_VCI && !(have & (1u << i))) vci = 0;
    }
    if (cls) c->opt |= WEB_SDB_OPT_CLASS;
    if (vci) c->opt |= WEB_SDB_OPT_VCI;
    /* probe_clients, pnl_clients and assocs are A2's: absent, its
     * statement leaves them out. */
    return 0;
}

static int open_conn(web_slothdb_t *s, web_sdb_conn_t *c, int budget_ms,
                     long long now_s, char *err, size_t errsz, int box) {
    memset(c, 0, sizeof(*c));
    c->s = s;
    c->now_s = now_s;
    c->deadline_ms = mono_ms() + (budget_ms > 0 ? budget_ms : WEB_SDB_HTTP_MS);
    err[0] = '\0';
    if (!s->configured) {
        snprintf(err, errsz, "no --sloth-db");
        pthread_mutex_lock(&s->mu);
        s->st.state = WEB_SDB_NONE;
        pthread_mutex_unlock(&s->mu);
        return -1;
    }
    struct stat st;
    if (lstat(s->path, &st) != 0) {
        if (errno == ENOENT)
            return fail(c, WEB_SDB_MISSING, err, errsz,
                        "%s: not there (yet): sloth makes it with --db%s", "");
        return fail(c, WEB_SDB_ERROR, err, errsz, "%s: %s", strerror(errno));
    }
    if (S_ISLNK(st.st_mode))
        return fail(c, WEB_SDB_REFUSED, err, errsz,
                    "%s: a symlink is refused%s", "");
    if (!S_ISREG(st.st_mode))
        return fail(c, WEB_SDB_REFUSED, err, errsz,
                    "%s: not a regular file%s", "");
    /* Which open makes no side file (web_slothdb.h). */
    char side[4200];
    snprintf(side, sizeof(side), "%s-wal", s->path);
    int wal = exists(side);
    snprintf(side, sizeof(side), "%s-shm", s->path);
    int shm = exists(side);
    int hm = header_mode(s->path);
    int immutable = hm == 2 && (!wal || !shm);
    const char *mode = hm == 2 ? (immutable ? "immutable" : "wal") : "rollback";
    char uri[3 * 4096 + 64];
    const char *name = s->path;
    int flags = web_slothdb_open_flags();
    if (hm == 2) {
        /* readonly_shm: sloth's -shm opened read-only, never created and
         * never initialised by this connection. With no sloth holding it
         * SQLite reads the WAL into a private index instead of running
         * recovery on the shared one, which would make a sloth starting
         * at that moment fail its first statement with
         * SQLITE_BUSY_RECOVERY. */
        ro_uri(s->path, immutable ? "?mode=ro&immutable=1"
                                  : "?mode=ro&readonly_shm=1",
               uri, sizeof(uri));
        name = uri;
        flags |= SQLITE_OPEN_URI;
    }
    /* The seams under the lock: the HTTP and store threads both open. */
    pthread_mutex_lock(&s->mu);
    web_slothdb_test_flags = flags;
    web_slothdb_test_immutable = immutable;
    pthread_mutex_unlock(&s->mu);
    if (web_slothdb_test_before_open) web_slothdb_test_before_open();
    pthread_once(&g_vfs_once, vfs_init);
    if (!g_vfs_ok)
        return fail(c, WEB_SDB_ERROR, err, errsz, "%s: %s",
                    "the no-create VFS could not be registered");
    if (sqlite3_open_v2(name, &c->db, flags, box ? WEB_SDB_VFS_BOX : WEB_SDB_VFS)
        != SQLITE_OK)
        return fail(c, WEB_SDB_ERROR, err, errsz, "%s: %s",
                    c->db ? sqlite3_errmsg(c->db) : "cannot open");
    int on = -1;
    if (sqlite3_db_config(c->db, SQLITE_DBCONFIG_DEFENSIVE, 1, &on) != SQLITE_OK ||
        on != 1)
        return fail(c, WEB_SDB_ERROR, err, errsz,
                    "%s: SQLITE_DBCONFIG_DEFENSIVE refused%s", "");
    sqlite3_busy_timeout(c->db, WEB_SDB_BUSY_MS);
    if (sqlite3_exec(c->db, "PRAGMA query_only=1", NULL, NULL, NULL) != SQLITE_OK)
        return fail(c, WEB_SDB_ERROR, err, errsz, "%s: query_only: %s",
                    sqlite3_errmsg(c->db));
    /* The box's temporary space is the page cache, a known 2 MB: temp
     * files through its VFS (refused), never memory-only ones, which
     * would grow without a bound instead. A library built always to
     * keep them in memory has no box. */
    if (box && (sqlite3_compileoption_used("TEMP_STORE=3") ||
                sqlite3_exec(c->db, "PRAGMA temp_store=FILE;"
                             "PRAGMA cache_size=-2048", NULL, NULL, NULL)
                != SQLITE_OK))
        return fail(c, WEB_SDB_ERROR, err, errsz, "%s: %s",
                    "this SQLite keeps temporary tables in memory without "
                    "a bound (TEMP_STORE=3): no SQL box");
    sqlite3_set_authorizer(c->db, authz, c);
    sqlite3_progress_handler(c->db, 1000, progress, c);
    sqlite3_create_function_v2(c->db, "web_vendor", 1,
                               SQLITE_UTF8 | SQLITE_DETERMINISTIC, c,
                               fn_vendor, NULL, NULL, NULL);
    sqlite3_create_function_v2(c->db, "web_z", 1, SQLITE_UTF8, c, fn_z, NULL,
                               NULL, NULL);
    sqlite3_create_function_v2(c->db, "web_anoms", 2, SQLITE_UTF8, c,
                               fn_anoms, NULL, NULL, NULL);
    sqlite3_create_function_v2(c->db, "web_ptr", 1, SQLITE_UTF8, c, fn_ptr,
                               NULL, NULL, NULL);

    /* Identify: sloth's meta is (key, value); slothweb.db's is (name,
     * value), and anything else has neither. */
    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(c->db, "SELECT value FROM meta WHERE"
                           " key='schema_version'", -1, &q, NULL) != SQLITE_OK) {
        /* Only a file whose shape is wrong is "not a sloth.db": not a
         * database (NOTADB), or no meta(key, value) in it (ERROR). A
         * sloth.db SQLite cannot read now (a hot journal or a WAL only
         * sloth can recover, READONLY_*; busy; locked; an I/O error) is
         * sloth's to put right, and is said to be. */
        int pc = sqlite3_extended_errcode(c->db) & 0xff;
        int shape = pc == SQLITE_NOTADB || pc == SQLITE_ERROR || pc == SQLITE_AUTH;
        char m[160];
        snprintf(m, sizeof(m), "%s", sqlite3_errmsg(c->db));
        if (shape)
            return fail(c, WEB_SDB_REFUSED, err, errsz, "%s: not a sloth.db (%s)", m);
        if (pc == SQLITE_READONLY)
            return fail(c, WEB_SDB_ERROR, err, errsz, "%s: needs recovery by "
                        "sloth, which it does when it next opens it (%s)", m);
        return fail(c, WEB_SDB_ERROR, err, errsz, "%s: %s", m);
    }
    char ver[16] = "";
    int rc = sqlite3_step(q);
    if (rc == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(q, 0);
        snprintf(ver, sizeof(ver), "%s", v ? (const char *)v : "");
    }
    sqlite3_finalize(q);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
        return fail(c, WEB_SDB_ERROR, err, errsz, "%s: %s", sqlite3_errmsg(c->db));
    size_t vl = strlen(ver);
    int v = -1;
    if (vl >= 1 && vl <= 4) {
        v = 0;
        for (size_t i = 0; i < vl; i++) {
            if (ver[i] < '0' || ver[i] > '9') { v = -1; break; }
            v = v * 10 + (ver[i] - '0');
        }
    }
    if (v < 0)
        return fail(c, WEB_SDB_REFUSED, err, errsz,
                    "%s: no schema_version in its meta: not a sloth.db%s", "");
    char vs[16];
    snprintf(vs, sizeof(vs), "%d", v);
    if (v > WEB_SDB_SCHEMA_MAX) {
        char m[96];
        snprintf(m, sizeof(m), "%d; this slothweb reads v%d..v%d", v,
                 WEB_SDB_SCHEMA_MIN, WEB_SDB_SCHEMA_MAX);
        return fail(c, WEB_SDB_REFUSED, err, errsz,
                    "%s: written by a newer sloth (schema v%s): not read; "
                    "update slothweb", m);
    }
    if (v < WEB_SDB_SCHEMA_MIN)
        return fail(c, WEB_SDB_REFUSED, err, errsz,
                    "%s: schema v%s is older than any sloth.db", vs);
    c->schema = v;
    if (probe(c) != 0)
        return fail(c, WEB_SDB_REFUSED, err, errsz,
                    "%s: no devices table with sloth's columns%s", "");
    pthread_mutex_lock(&s->mu);
    s->st.state = WEB_SDB_OPEN;
    s->st.schema = v;
    s->st.opens++;
    s->st.err[0] = '\0';
    snprintf(s->st.mode, sizeof(s->st.mode), "%s", mode);
    pthread_mutex_unlock(&s->mu);
    return 0;
}

int web_slothdb_open(web_slothdb_t *s, web_sdb_conn_t *c, int budget_ms,
                     long long now_s, char *err, size_t errsz) {
    return open_conn(s, c, budget_ms, now_s, err, errsz, 0);
}

int web_slothdb_open_box(web_slothdb_t *s, web_sdb_conn_t *c, int budget_ms,
                         long long now_s, char *err, size_t errsz) {
    return open_conn(s, c, budget_ms, now_s, err, errsz, 1);
}

void web_slothdb_close(web_sdb_conn_t *c) {
    if (c->timed_out) {
        pthread_mutex_lock(&c->s->mu);
        c->s->st.timeouts++;
        pthread_mutex_unlock(&c->s->mu);
        c->timed_out = 0;
    }
    if (c->db) sqlite3_close(c->db);
    c->db = NULL;
}

int web_slothdb_check(web_slothdb_t *s, long long now_s) {
    web_sdb_conn_t c;
    char err[WEB_SDB_ERR_MAX];
    if (web_slothdb_open(s, &c, WEB_SDB_HTTP_MS, now_s, err, sizeof(err)) == 0) {
        sqlite3_stmt *q = NULL;
        long long rows = -1;
        if (sqlite3_prepare_v2(c.db, "SELECT count(*) FROM devices", -1, &q,
                               NULL) == SQLITE_OK &&
            sqlite3_step(q) == SQLITE_ROW)
            rows = sqlite3_column_int64(q, 0);
        sqlite3_finalize(q);
        pthread_mutex_lock(&s->mu);
        s->st.rows = rows;
        pthread_mutex_unlock(&s->mu);
    } else {
        pthread_mutex_lock(&s->mu);
        s->st.rows = -1;
        s->st.mode[0] = '\0';
        pthread_mutex_unlock(&s->mu);
    }
    web_slothdb_close(&c);
    web_sdb_stats_t st;
    web_slothdb_stats(s, &st);
    return st.state;
}

/* ── reads ────────────────────────────────────────────────────────── */

static void text(sqlite3_stmt *st, int col, char *out, size_t max) {
    const unsigned char *v = sqlite3_column_text(st, col);
    web_utf8_copy(out, max, v ? (const char *)v : "");
}

static void key_text(sqlite3_stmt *st, int col, char *out) {
    text(st, col, out, WEB_KEY_MAX);
}

static void dev_row(sqlite3_stmt *st, web_sdb_dev_t *d) {
    memset(d, 0, sizeof(*d));
    key_text(st, WEB_QCOL_MAC, d->mac);
    key_text(st, WEB_QCOL_IP, d->ip);
    text(st, WEB_QCOL_HOSTNAME, d->hostname, WEB_SDB_TEXT_MAX);
    text(st, WEB_QCOL_VENDOR, d->vendor, WEB_SDB_TEXT_MAX);
    text(st, WEB_QCOL_SSID, d->ssid, WEB_SDB_TEXT_MAX);
    d->has_signal = sqlite3_column_type(st, WEB_QCOL_SIGNAL) != SQLITE_NULL;
    d->signal_dbm = sqlite3_column_int(st, WEB_QCOL_SIGNAL);
    d->sources = sqlite3_column_int64(st, WEB_QCOL_SOURCES);
    d->risk_signals = sqlite3_column_int64(st, WEB_QCOL_RISK_SIGNALS);
    d->risk = sqlite3_column_int64(st, WEB_QCOL_RISK);
    d->first_seen = sqlite3_column_int64(st, WEB_QCOL_FIRST);
    d->last_seen = sqlite3_column_int64(st, WEB_QCOL_LAST);
    d->is_ap = sqlite3_column_int(st, WEB_QCOL_IS_AP) != 0;
    text(st, WEB_QCOL_DHCP_NAME, d->dhcp_name, WEB_SDB_TEXT_MAX);
    text(st, WEB_QCOL_MDNS_NAME, d->mdns_name, WEB_SDB_TEXT_MAX);
    text(st, WEB_QCOL_NBNS_NAME, d->nbns_name, WEB_SDB_TEXT_MAX);
}

static void bind_all(sqlite3_stmt *st, const web_qsql_t *s) {
    for (int i = 0; i < s->nb; i++) {
        const web_qbind_t *b = &s->b[i];
        if (b->type == 0) sqlite3_bind_text(st, i + 1, b->s, -1, SQLITE_TRANSIENT);
        else if (b->type == 1) sqlite3_bind_int64(st, i + 1, b->i);
        else sqlite3_bind_double(st, i + 1, b->d);
    }
}

int web_sdb_devices(web_sdb_conn_t *c, const web_query_t *q, int sort,
                    long long limit, long long offset, web_sdb_dev_fn fn,
                    void *ctx, const char **why) {
    *why = "error";
    web_qsql_t *sq = malloc(sizeof(*sq));
    if (!sq) return -1;
    int rc = -1;
    if (web_query_compile(q, c->feats, sort, limit, offset, sq) == 0) {
        sqlite3_stmt *st = NULL;
        /* has:alert matches alerts.key against d.mac; the result
         * columns are web_query_row_select()'s constant list. Until the
         * finalize: a LIKE against a bound value re-prepares the
         * statement at its first step. */
        c->pred_ok = 1;
        if (sqlite3_prepare_v2(c->db, sq->sql, -1, &st, NULL) == SQLITE_OK) {
            bind_all(st, sq);
            int n = 0, r;
            web_sdb_dev_t d;
            while ((r = sqlite3_step(st)) == SQLITE_ROW) {
                dev_row(st, &d);
                n++;
                if (fn(ctx, &d)) { r = SQLITE_DONE; break; }
            }
            if (r == SQLITE_DONE) rc = n;
        }
        if (rc < 0 && c->timed_out) *why = "timeout";
        sqlite3_finalize(st);
        c->pred_ok = 0;
    }
    free(sq);
    return rc;
}

int web_sdb_device(web_sdb_conn_t *c, const char *mac, web_sdb_dev_t *out) {
    char sql[2048];
    char extra[160];
    /* The drawer's own columns after the row's, or NULL for a version
     * that lacks them. */
    snprintf(extra, sizeof(extra), "%s, %s",
             (c->opt & WEB_SDB_OPT_CLASS)
                 ? "d.device_class, d.camera_vendor, d.camera_model"
                 : "0, NULL, NULL",
             (c->opt & WEB_SDB_OPT_VCI) ? "d.dhcp_vci" : "NULL");
    if (web_query_row_select(c->feats, extra, sql, sizeof(sql) - 32) != 0)
        return -1;
    strcat(sql, " WHERE d.mac = ?1");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int found = 0;
    if (rc == SQLITE_ROW) {
        dev_row(st, out);
        out->device_class = sqlite3_column_int64(st, WEB_QCOL_COUNT);
        text(st, WEB_QCOL_COUNT + 1, out->camera_vendor, WEB_SDB_TEXT_MAX);
        text(st, WEB_QCOL_COUNT + 2, out->camera_model, WEB_SDB_TEXT_MAX);
        text(st, WEB_QCOL_COUNT + 3, out->dhcp_vci, WEB_SDB_TEXT_MAX);
        found = 1;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) return -1;
    return found;
}

/* One statement of the item shape, one or two text parameters. */
static int items(web_sdb_conn_t *c, const char *sql, const char *p1,
                 const char *p2, int max, web_sdb_item_fn fn, void *ctx,
                 int ncols) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, p1, -1, SQLITE_TRANSIENT);
    if (p2) sqlite3_bind_text(st, 2, p2, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, p2 ? 3 : 2, max);
    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        web_sdb_item_t it;
        memset(&it, 0, sizeof(it));
        text(st, 0, it.a, WEB_SDB_TEXT_MAX);
        if (ncols > 3) text(st, 1, it.b, WEB_SDB_TEXT_MAX);
        int k = ncols > 3 ? 2 : 1;
        if (ncols > 4) {
            it.n1 = sqlite3_column_int64(st, k++);
            it.n2 = sqlite3_column_int64(st, k++);
            it.has_n3 = sqlite3_column_type(st, k) != SQLITE_NULL;
            it.n3 = sqlite3_column_int64(st, k++);
        }
        it.first_seen = sqlite3_column_int64(st, k++);
        it.last_seen = sqlite3_column_int64(st, k);
        n++;
        if (fn(ctx, &it)) { rc = SQLITE_DONE; break; }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? n : -1;
}

int web_sdb_ssids(web_sdb_conn_t *c, const char *mac, int max,
                  web_sdb_item_fn fn, void *ctx) {
    if (!(c->feats & WEB_QF_PNL)) return 0;
    return items(c, "SELECT ssid, first_seen, last_seen FROM pnl_ssids WHERE"
                    " mac = ?1 ORDER BY last_seen DESC, ssid LIMIT ?2",
                 mac, NULL, max, fn, ctx, 3);
}

int web_sdb_assocs(web_sdb_conn_t *c, const char *mac, int max,
                   web_sdb_item_fn fn, void *ctx) {
    unsigned have;
    static const char *const want[] = { "bssid", "sta_mac", "ssid", "source",
                                        "channel", "signal_dbm", "first_seen",
                                        "last_seen", NULL };
    if (table_cols(c->db, "assocs", want, &have) <= 0 || have != 0xffu)
        return 0;
    return items(c, "SELECT bssid, COALESCE(ssid,''), source, COALESCE(channel,0),"
                    " signal_dbm, first_seen, last_seen FROM assocs WHERE"
                    " sta_mac = ?1 ORDER BY last_seen DESC, bssid LIMIT ?2",
                 mac, NULL, max, fn, ctx, 7);
}

int web_sdb_arp_mac(web_sdb_conn_t *c, const char *mac, int max,
                    web_sdb_item_fn fn, void *ctx) {
    if (!(c->feats & WEB_QF_ARP)) return 0;
    return items(c, "SELECT ip, first_seen, last_seen FROM arp WHERE mac = ?1"
                    " ORDER BY last_seen DESC, ip LIMIT ?2",
                 mac, NULL, max, fn, ctx, 3);
}

int web_sdb_arp_ip(web_sdb_conn_t *c, const char *ip, int max,
                   web_sdb_item_fn fn, void *ctx) {
    if (!(c->feats & WEB_QF_ARP)) return 0;
    return items(c, "SELECT mac, first_seen, last_seen FROM arp WHERE ip = ?1"
                    " ORDER BY last_seen DESC, mac LIMIT ?2",
                 ip, NULL, max, fn, ctx, 3);
}

int web_sdb_names(web_sdb_conn_t *c, const char *ip, int max,
                  web_sdb_item_fn fn, void *ctx) {
    char sql[1024] = "";
    size_t o = 0;
    const char *sep = "";
    if (c->feats & WEB_QF_DHCP) {
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%sSELECT hostname,"
            " 'dhcp', first_seen, last_seen FROM dhcp_leases WHERE ip = ?1"
            " AND COALESCE(hostname,'') <> ''", sep);
        sep = " UNION ALL ";
    }
    if (c->feats & WEB_QF_MDNS) {
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%sSELECT host, 'mdns',"
            " first_seen, last_seen FROM mdns_services WHERE ip = ?1 AND"
            " COALESCE(host,'') <> '' UNION ALL SELECT instance,"
            " 'mdns-instance', first_seen, last_seen FROM mdns_services WHERE"
            " ip = ?1 AND COALESCE(instance,'') <> ''", sep);
        sep = " UNION ALL ";
    }
    if (c->feats & WEB_QF_NBNS) {
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%sSELECT name, 'nbns',"
            " first_seen, last_seen FROM nbns_names WHERE ip = ?1 AND"
            " suffix IN (0, 32)", sep);
        sep = " UNION ALL ";
    }
    if (!sep[0]) return 0;
    snprintf(sql + o, sizeof(sql) - o, " ORDER BY 4 DESC LIMIT ?2");
    return items(c, sql, ip, NULL, max, fn, ctx, 4);
}

int web_sdb_alerts(web_sdb_conn_t *c, const char *mac, const char *ip,
                   int max, web_sdb_item_fn fn, void *ctx) {
    if (!(c->feats & WEB_QF_ALERTS)) return 0;
    /* key in the WHERE only, against a canonical MAC (the routes'). */
    c->pred_ok = 1;
    int n = items(c, "SELECT COALESCE(title,''), '', type, sev, count,"
                     " first_seen, last_seen FROM alerts WHERE"
                     " (?1 <> '' AND instr(key, ?1) > 0)"
                     " OR (?2 <> '' AND match_ip = ?2)"
                     " ORDER BY last_seen DESC LIMIT ?3",
                  mac, ip ? ip : "", max, fn, ctx, 7);
    c->pred_ok = 0;
    return n;
}

int web_sdb_first_seen(web_sdb_conn_t *c, const char *mac, long long *fs) {
    static const struct { const char *t, *col; } T[] = {
        { "devices", "mac" }, { "probe_clients", "mac" },
        { "pnl_clients", "mac" }, { "assocs", "sta_mac" },
    };
    char sql[768] = "SELECT min(f) FROM (";
    size_t o = strlen(sql);
    int any = 0;
    for (size_t i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
        const char *want[3] = { T[i].col, "first_seen", NULL };
        unsigned have;
        if (table_cols(c->db, T[i].t, want, &have) <= 0 || have != 3u) continue;
        o += (size_t)snprintf(sql + o, sizeof(sql) - o,
                              "%sSELECT min(first_seen) AS f FROM %s WHERE %s = ?1",
                              any ? " UNION ALL " : "", T[i].t, T[i].col);
        any = 1;
    }
    if (!any) return 0;
    snprintf(sql + o, sizeof(sql) - o, ")");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int found = 0;
    if (rc == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) {
        *fs = sqlite3_column_int64(st, 0);
        found = 1;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW) return -1;
    return found;
}

int web_sdb_new_macs(web_sdb_conn_t *c, long long since, web_sdb_new_t *out,
                     int max) {
    sqlite3_stmt *st = NULL;
    /* The locally administered ones are left out here, before the
     * LIMIT: A2 drops them, and a burst of newer random MACs must not
     * fill the window ahead of a new globally administered one. */
    if (sqlite3_prepare_v2(c->db, "SELECT mac, first_seen FROM devices WHERE"
                           " first_seen >= ?1 AND substr(mac,2,1) NOT IN"
                           " ('2','3','6','7','a','b','e','f')"
                           " ORDER BY first_seen DESC, mac"
                           " LIMIT ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, since);
    sqlite3_bind_int(st, 2, max);
    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW && n < max) {
        char raw[WEB_KEY_MAX + 1];
        key_text(st, 0, raw);
        if (web_key_mac(raw, out[n].mac) != 0) continue;
        out[n].first_seen = sqlite3_column_int64(st, 1);
        n++;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE || rc == SQLITE_ROW ? n : -1;
}

/* ── M5 reads (#163) ──────────────────────────────────────────────────── */

/* Does table carry every column of cols (NULL-ended, at most 31)?
 * Through PRAGMA table_info, which the authorizer allows for an
 * allow-listed table. */
static int have_all(web_sdb_conn_t *c, const char *table,
                    const char *const *cols) {
    unsigned have;
    int n = 0;
    while (cols[n]) n++;
    if (n > 31) return 0;
    return table_cols(c->db, table, cols, &have) > 0 && have == (1u << n) - 1;
}

static int karma_ok(web_sdb_conn_t *c) {
    static const char *const k[] = { "bssid", "score", "ssid_count",
                                     "pnl_overlap", "ie_uniform", NULL };
    return have_all(c, "karma_candidates", k);
}

static int ap_ssids_ok(web_sdb_conn_t *c) {
    static const char *const k[] = { "bssid", "ssid", "first_seen",
                                     "last_seen", NULL };
    return have_all(c, "beacon_ap_ssids", k);
}

int web_sdb_aps(web_sdb_conn_t *c, int sort, long long limit,
                long long offset, web_sdb_ap_fn fn, void *ctx) {
    static const char *const want[] = {
        "bssid", "ssid", "signal_dbm", "channel", "enc", "akm", "akm_bits",
        "mfp", "downgrade_flags", "vendor", "phy", "has_wps", "first_seen",
        "last_seen", NULL };
    if (!have_all(c, "beacon_aps", want)) return 0;
    static const char *const ORDER[WEB_AP_SORT_COUNT] = {
        " ORDER BY a.last_seen DESC, a.bssid",
        " ORDER BY 15 DESC, a.last_seen DESC, a.bssid",
        " ORDER BY 16 DESC, a.last_seen DESC, a.bssid",
        " ORDER BY a.bssid",
    };
    int km = karma_ok(c), ss = ap_ssids_ok(c);
    char sql[1400];
    snprintf(sql, sizeof(sql),
        "SELECT a.bssid, a.ssid, a.signal_dbm, a.channel, a.enc, a.akm,"
        " a.akm_bits, a.mfp, a.downgrade_flags, a.vendor, a.phy, a.has_wps,"
        " a.first_seen, a.last_seen, %s, %s FROM beacon_aps a%s%s LIMIT ?1"
        " OFFSET ?2",
        ss ? "(SELECT count(*) FROM beacon_ap_ssids s WHERE s.bssid = a.bssid)"
           : "0",
        km ? "k.score, k.ssid_count, k.pnl_overlap, k.ie_uniform" : "NULL, 0, 0, 0",
        km ? " LEFT JOIN karma_candidates k ON k.bssid = a.bssid" : "",
        ORDER[sort >= 0 && sort < WEB_AP_SORT_COUNT ? sort : 0]);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, limit);
    sqlite3_bind_int64(st, 2, offset);
    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        web_sdb_ap_t a;
        memset(&a, 0, sizeof(a));
        key_text(st, 0, a.bssid);
        text(st, 1, a.ssid, WEB_SDB_TEXT_MAX);
        a.has_signal = sqlite3_column_type(st, 2) != SQLITE_NULL;
        a.signal_dbm = sqlite3_column_int(st, 2);
        a.channel = sqlite3_column_int64(st, 3);
        text(st, 4, a.enc, WEB_SDB_TEXT_MAX);
        text(st, 5, a.akm, WEB_SDB_TEXT_MAX);
        a.akm_bits = sqlite3_column_int64(st, 6);
        a.mfp = sqlite3_column_int64(st, 7);
        a.downgrade = sqlite3_column_int64(st, 8);
        text(st, 9, a.vendor, WEB_SDB_TEXT_MAX);
        text(st, 10, a.phy, WEB_SDB_TEXT_MAX);
        a.has_wps = sqlite3_column_int64(st, 11);
        a.first_seen = sqlite3_column_int64(st, 12);
        a.last_seen = sqlite3_column_int64(st, 13);
        a.ssid_count = sqlite3_column_int64(st, 14);
        a.has_karma = sqlite3_column_type(st, 15) != SQLITE_NULL;
        a.k_score = sqlite3_column_int64(st, 15);
        a.k_ssids = sqlite3_column_int64(st, 16);
        a.k_overlap = sqlite3_column_int64(st, 17);
        a.k_ie_uniform = sqlite3_column_int64(st, 18);
        n++;
        if (fn(ctx, &a)) { rc = SQLITE_DONE; break; }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? n : -1;
}

int web_sdb_ap_ssids(web_sdb_conn_t *c, const char *bssid, int max,
                     web_sdb_item_fn fn, void *ctx) {
    if (!ap_ssids_ok(c)) return 0;
    return items(c, "SELECT ssid, first_seen, last_seen FROM beacon_ap_ssids"
                    " WHERE bssid = ?1 ORDER BY last_seen DESC, ssid LIMIT ?2",
                 bssid, NULL, max, fn, ctx, 3);
}

/* One statement of the seven-column item shape: ?1 a text (when p1),
 * ?2 and ?3 the range, ?4 the cap. */
static int items_range(web_sdb_conn_t *c, const char *sql, const char *p1,
                       long long from, long long to, int max,
                       web_sdb_item_fn fn, void *ctx) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (p1) sqlite3_bind_text(st, 1, p1, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, from);
    sqlite3_bind_int64(st, 3, to);
    sqlite3_bind_int(st, 4, max);
    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        web_sdb_item_t it;
        memset(&it, 0, sizeof(it));
        text(st, 0, it.a, WEB_SDB_TEXT_MAX);
        text(st, 1, it.b, WEB_SDB_TEXT_MAX);
        it.n1 = sqlite3_column_int64(st, 2);
        it.n2 = sqlite3_column_int64(st, 3);
        it.has_n3 = sqlite3_column_type(st, 4) != SQLITE_NULL;
        it.n3 = sqlite3_column_int64(st, 4);
        it.first_seen = sqlite3_column_int64(st, 5);
        it.last_seen = sqlite3_column_int64(st, 6);
        n++;
        if (fn(ctx, &it)) { rc = SQLITE_DONE; break; }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? n : -1;
}

int web_sdb_deauth_floods(web_sdb_conn_t *c, const char *bssid,
                          long long from, long long to, int max,
                          web_sdb_item_fn fn, void *ctx) {
    if (!(c->feats & WEB_QF_ALERTS)) return 0;
    char sql[400];
    /* rule_deauth_flood() keys an episode "deauth:<victim>@<bssid>". The
     * key is in the WHERE only, against the canonical MAC the route
     * bound; the result columns are constants and the episode's
     * numbers. */
    snprintf(sql, sizeof(sql),
             "SELECT '', '', type, sev, count, first_seen, last_seen FROM"
             " alerts WHERE type = %d AND instr(key, '@' || ?1) > 0 AND"
             " last_seen >= ?2 AND first_seen < ?3 ORDER BY first_seen"
             " LIMIT ?4", WEB_ALERT_DEAUTH_FLOOD);
    c->pred_ok = 1;
    int n = items_range(c, sql, bssid, from, to, max, fn, ctx);
    c->pred_ok = 0;
    return n;
}

static int sessions_ok(web_sdb_conn_t *c) {
    static const char *const k[] = { "id", "started", "ended", "site_label",
                                     NULL };
    return have_all(c, "sessions", k);
}

static void session_row(sqlite3_stmt *st, int k, web_sdb_session_t *s) {
    memset(s, 0, sizeof(*s));
    s->id = sqlite3_column_int64(st, k);
    s->started = sqlite3_column_int64(st, k + 1);
    s->ended = sqlite3_column_type(st, k + 2) == SQLITE_NULL
             ? -1 : sqlite3_column_int64(st, k + 2);
    text(st, k + 3, s->label, WEB_SDB_TEXT_MAX);
}

int web_sdb_sessions(web_sdb_conn_t *c, web_sdb_session_t *out, int max) {
    if (!sessions_ok(c)) return 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, "SELECT id, started, ended, site_label FROM"
                           " sessions ORDER BY started DESC, id DESC LIMIT ?1",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, max);
    int n = 0, rc = SQLITE_DONE;
    while (n < max && (rc = sqlite3_step(st)) == SQLITE_ROW)
        session_row(st, 0, &out[n++]);
    if (n == max) rc = SQLITE_DONE;
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? n : -1;
}

int web_sdb_session_pair(web_sdb_conn_t *c, long long id,
                         web_sdb_session_t *s, web_sdb_session_t *prev,
                         int *has_prev, long long *next_started) {
    *has_prev = 0;
    *next_started = -1;
    if (!sessions_ok(c)) return 0;
    sqlite3_stmt *st = NULL;
    /* sloth's "previous" (src/db.c db_session_begin()): before it
     * inserts its own row, the session with the latest started, so of
     * the rows inserted before this one (a smaller AUTOINCREMENT id).
     * The next one is the row inserted after it. */
    if (sqlite3_prepare_v2(c->db,
            "SELECT s.id, s.started, s.ended, s.site_label,"
            " p.id, p.started, p.ended, p.site_label,"
            " (SELECT n.started FROM sessions n WHERE n.id > s.id"
            " ORDER BY n.id LIMIT 1)"
            " FROM sessions s LEFT JOIN sessions p ON p.id = (SELECT q.id FROM"
            " sessions q WHERE q.id < s.id ORDER BY q.started DESC, q.id DESC"
            " LIMIT 1) WHERE s.id = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, id);
    int rc = sqlite3_step(st), found = 0;
    if (rc == SQLITE_ROW) {
        found = 1;
        session_row(st, 0, s);
        if (sqlite3_column_type(st, 4) != SQLITE_NULL) {
            session_row(st, 4, prev);
            *has_prev = 1;
        }
        if (sqlite3_column_type(st, 8) != SQLITE_NULL)
            *next_started = sqlite3_column_int64(st, 8);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) return -1;
    return found;
}

int web_sdb_new_since(web_sdb_conn_t *c, int kind, long long since,
                      long long until, int max, web_sdb_item_fn fn,
                      void *ctx, long long *total) {
    /* src/db.c new_since_sql(): (identity, label, first_seen) per kind,
     * the label exactly as --report builds it. */
    static const struct { const char *t, *id, *label; } K[WEB_NEW_KINDS] = {
        { "beacon_aps", "bssid", "COALESCE(NULLIF(ssid,''), '')" },
        { "devices", "mac", "COALESCE(NULLIF(hostname,''), NULLIF(vendor,''), '')" },
        { "probe_clients", "mac", "COALESCE(NULLIF(ssid,''), '')" },
    };
    *total = 0;
    if (kind < 0 || kind >= WEB_NEW_KINDS) return -1;
    const char *want[5] = { K[kind].id, "first_seen", NULL, NULL, NULL };
    if (kind == WEB_NEW_DEVICE) { want[2] = "hostname"; want[3] = "vendor"; }
    else want[2] = "ssid";
    if (!have_all(c, K[kind].t, want)) return 0;
    char sql[512];
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM %s WHERE first_seen >= ?1"
             " AND (?2 < 0 OR first_seen <= ?2)", K[kind].t);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, since);
    sqlite3_bind_int64(st, 2, until);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *total = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW) return -1;
    snprintf(sql, sizeof(sql), "SELECT %s, %s, first_seen FROM %s"
             " WHERE first_seen >= ?1 AND (?2 < 0 OR first_seen <= ?2)"
             " ORDER BY first_seen DESC LIMIT ?3", K[kind].id, K[kind].label,
             K[kind].t);
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, since);
    sqlite3_bind_int64(st, 2, until);
    sqlite3_bind_int(st, 3, max);
    int n = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        web_sdb_item_t it;
        memset(&it, 0, sizeof(it));
        text(st, 0, it.a, WEB_SDB_TEXT_MAX);
        text(st, 1, it.b, WEB_SDB_TEXT_MAX);
        it.first_seen = sqlite3_column_int64(st, 2);
        it.last_seen = it.first_seen;
        n++;
        if (fn(ctx, &it)) { rc = SQLITE_DONE; break; }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? n : -1;
}

int web_sdb_devices_between(web_sdb_conn_t *c, long long from, long long to,
                            long long limit, long long offset,
                            web_sdb_dev_fn fn, void *ctx) {
    char sql[2048];
    if (web_query_row_select(c->feats, NULL, sql, sizeof(sql) - 160) != 0)
        return -1;
    strcat(sql, " WHERE d.last_seen >= ?1 AND d.first_seen <= ?2"
                " ORDER BY d.last_seen DESC, d.mac LIMIT ?3 OFFSET ?4");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, from);
    sqlite3_bind_int64(st, 2, to);
    sqlite3_bind_int64(st, 3, limit);
    sqlite3_bind_int64(st, 4, offset);
    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        web_sdb_dev_t d;
        dev_row(st, &d);
        n++;
        if (fn(ctx, &d)) { rc = SQLITE_DONE; break; }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? n : -1;
}

int web_sdb_alerts_between(web_sdb_conn_t *c, long long from, long long to,
                           int max, web_sdb_item_fn fn, void *ctx) {
    if (!(c->feats & WEB_QF_ALERTS)) return 0;
    return items_range(c, "SELECT COALESCE(title,''), COALESCE(match_ip,''),"
                          " type, sev, count, first_seen, last_seen FROM alerts"
                          " WHERE last_seen >= ?2 AND first_seen < ?3"
                          " ORDER BY last_seen DESC, first_seen DESC LIMIT ?4",
                       NULL, from, to, max, fn, ctx);
}

int web_sdb_flows_between(web_sdb_conn_t *c, long long from, long long to,
                          int max, web_sdb_item_fn fn, void *ctx) {
    static const char *const ssh[] = { "src_ip", "dst_ip", "banner_count",
                                       "first_seen", "last_seen", NULL };
    static const char *const rdp[] = { "src_ip", "dst_ip", "connect_req_count",
                                       "first_seen", "last_seen", NULL };
    static const char *const smb[] = { "client_ip", "server_ip", "server_port",
                                       "obs_count", "first_seen", "last_seen",
                                       NULL };
    static const char *const snmp[] = { "src_ip", "dst_ip", "get_count",
                                        "getnext_count", "getbulk_count",
                                        "set_count", "response_count",
                                        "trap_count", "version", "first_seen",
                                        "last_seen", NULL };
    static const char W[] = " WHERE last_seen >= ?2 AND first_seen < ?3";
    char sql[2048] = "";
    size_t o = 0;
    const char *sep = "";
    if (have_all(c, "ssh_flows", ssh)) {
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%sSELECT src_ip, dst_ip,"
            " %d, banner_count, NULL, first_seen, last_seen FROM ssh_flows%s",
            sep, WEB_FLOW_SSH, W);
        sep = " UNION ALL ";
    }
    if (have_all(c, "rdp_flows", rdp)) {
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%sSELECT src_ip, dst_ip,"
            " %d, connect_req_count, NULL, first_seen, last_seen FROM"
            " rdp_flows%s", sep, WEB_FLOW_RDP, W);
        sep = " UNION ALL ";
    }
    if (have_all(c, "smb_sessions", smb)) {
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%sSELECT client_ip,"
            " server_ip, %d, obs_count, server_port, first_seen, last_seen FROM"
            " smb_sessions%s", sep, WEB_FLOW_SMB, W);
        sep = " UNION ALL ";
    }
    if (have_all(c, "snmp_flows", snmp)) {
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%sSELECT src_ip, dst_ip,"
            " %d, get_count + getnext_count + getbulk_count + set_count +"
            " response_count + trap_count, version, first_seen, last_seen FROM"
            " snmp_flows%s", sep, WEB_FLOW_SNMP, W);
        sep = " UNION ALL ";
    }
    if (!sep[0]) return 0;
    snprintf(sql + o, sizeof(sql) - o, " ORDER BY 7 DESC, 1, 2 LIMIT ?4");
    return items_range(c, sql, NULL, from, to, max, fn, ctx);
}

/* One grouped count per cell: (first_seen - from) / cell_s. */
static int cells_of(web_sdb_conn_t *c, const char *table, long long from,
                    int cell_s, int ncell, long long *out) {
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT (first_seen - ?1) / ?2, count(*) FROM %s"
             " WHERE first_seen >= ?1 AND first_seen < ?3 GROUP BY 1", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, from);
    sqlite3_bind_int(st, 2, cell_s);
    sqlite3_bind_int64(st, 3, from + (long long)cell_s * ncell);
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        long long k = sqlite3_column_int64(st, 0);
        if (k >= 0 && k < ncell) out[k] = sqlite3_column_int64(st, 1);
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int web_sdb_overview(web_sdb_conn_t *c, long long from, int cell_s,
                     int ncell, long long *devs, long long *alerts) {
    if (cell_s <= 0 || ncell <= 0) return -1;
    memset(devs, 0, (size_t)ncell * sizeof(*devs));
    memset(alerts, 0, (size_t)ncell * sizeof(*alerts));
    if (cells_of(c, "devices", from, cell_s, ncell, devs) != 0) return -1;
    if ((c->feats & WEB_QF_ALERTS) &&
        cells_of(c, "alerts", from, cell_s, ncell, alerts) != 0)
        return -1;
    return 0;
}

#endif /* WITH_SQLITE */
