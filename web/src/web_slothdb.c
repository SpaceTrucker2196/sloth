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
    { "meta", "key", 1, 0 },          { "meta", "value", 1, 0 },
    { "devices", "mac", 1, 0 },       { "devices", "ip", 1, 0 },
    { "devices", "hostname", 1, 0 },  { "devices", "vendor", 1, 0 },
    { "devices", "last_ssid", 1, 0 }, { "devices", "is_ap", 1, 0 },
    { "devices", "signal_dbm", 1, 0 },{ "devices", "sources", 1, 0 },
    { "devices", "risk_signals", 1, 0 }, { "devices", "risk_level", 1, 0 },
    { "devices", "first_seen", 1, 0 },{ "devices", "last_seen", 1, 0 },
    { "devices", "device_class", 6, 1 }, { "devices", "camera_vendor", 6, 1 },
    { "devices", "camera_model", 6, 1 }, { "devices", "dhcp_vci", 7, 1 },
    { "pnl_clients", "mac", 1, 0 },   { "pnl_clients", "first_seen", 1, 0 },
    { "pnl_ssids", "mac", 1, 0 },     { "pnl_ssids", "ssid", 1, 0 },
    { "pnl_ssids", "first_seen", 1, 0 }, { "pnl_ssids", "last_seen", 1, 0 },
    { "probe_clients", "mac", 1, 0 }, { "probe_clients", "first_seen", 1, 0 },
    { "assocs", "bssid", 1, 0 },      { "assocs", "sta_mac", 1, 0 },
    { "assocs", "ssid", 1, 0 },       { "assocs", "source", 1, 0 },
    { "assocs", "channel", 1, 0 },    { "assocs", "signal_dbm", 1, 0 },
    { "assocs", "first_seen", 1, 0 }, { "assocs", "last_seen", 1, 0 },
    { "arp", "ip", 1, 0 },            { "arp", "mac", 1, 0 },
    { "arp", "first_seen", 1, 0 },    { "arp", "last_seen", 1, 0 },
    { "dhcp_leases", "ip", 1, 0 },    { "dhcp_leases", "hostname", 1, 0 },
    { "dhcp_leases", "first_seen", 1, 0 }, { "dhcp_leases", "last_seen", 1, 0 },
    { "mdns_services", "instance", 1, 0 }, { "mdns_services", "host", 1, 0 },
    { "mdns_services", "ip", 1, 0 },  { "mdns_services", "first_seen", 1, 0 },
    { "mdns_services", "last_seen", 1, 0 },
    { "nbns_names", "name", 1, 0 },   { "nbns_names", "suffix", 1, 0 },
    { "nbns_names", "ip", 1, 0 },     { "nbns_names", "first_seen", 1, 0 },
    { "nbns_names", "last_seen", 1, 0 },
    { "alerts", "key", 1, 0 },        { "alerts", "type", 1, 0 },
    { "alerts", "sev", 1, 0 },        { "alerts", "title", 1, 0 },
    { "alerts", "match_ip", 1, 0 },   { "alerts", "count", 1, 0 },
    { "alerts", "first_seen", 1, 0 }, { "alerts", "last_seen", 1, 0 },
};
const size_t web_sdb_allow_n = sizeof(web_sdb_allow) / sizeof(web_sdb_allow[0]);

int web_slothdb_test_flags = 0;
int web_slothdb_test_immutable = 0;

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

static int allowed_col(const char *table, const char *col) {
    if (!table || !col) return 0;
    for (size_t i = 0; i < web_sdb_allow_n; i++)
        if (!strcmp(web_sdb_allow[i].table, table) &&
            (!col[0] || !strcmp(web_sdb_allow[i].column, col)))
            return 1;
    return 0;
}

static int allowed_table(const char *table) {
    return table && allowed_col(table, "");
}

/* Everything a device statement may call. */
static const char *const FUNCS[] = {
    "like", "coalesce", "substr", "instr", "min", "max", "count",
    "web_vendor", "web_z", "web_anoms", "web_ptr", NULL
};

static int authz(void *ud, int action, const char *a1, const char *a2,
                 const char *db, const char *trig) {
    (void)ud; (void)db; (void)trig;
    switch (action) {
    case SQLITE_SELECT:
        return SQLITE_OK;
    case SQLITE_READ:
        /* a1 table, a2 column ("" when a table is read for no column,
         * count(*)). */
        return allowed_col(a1, a2 ? a2 : "") ? SQLITE_OK : SQLITE_DENY;
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

/* path as a read-only immutable URI, every byte that could read as URI
 * syntax percent-encoded (web_store.c does the same). */
static void immutable_uri(const char *path, char *out, size_t outsz) {
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
    snprintf(out + o, outsz - o, "?mode=ro&immutable=1");
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

int web_slothdb_open(web_slothdb_t *s, web_sdb_conn_t *c, int budget_ms,
                     long long now_s, char *err, size_t errsz) {
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
    if (immutable) {
        immutable_uri(s->path, uri, sizeof(uri));
        name = uri;
        flags |= SQLITE_OPEN_URI;
    }
    /* The seams under the lock: the HTTP and store threads both open. */
    pthread_mutex_lock(&s->mu);
    web_slothdb_test_flags = flags;
    web_slothdb_test_immutable = immutable;
    pthread_mutex_unlock(&s->mu);
    if (sqlite3_open_v2(name, &c->db, flags, NULL) != SQLITE_OK)
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
        int busy = sqlite3_errcode(c->db) == SQLITE_BUSY ||
                   sqlite3_errcode(c->db) == SQLITE_LOCKED;
        char m[160];
        snprintf(m, sizeof(m), "%s", sqlite3_errmsg(c->db));
        return busy ? fail(c, WEB_SDB_ERROR, err, errsz, "%s: %s", m)
                    : fail(c, WEB_SDB_REFUSED, err, errsz,
                           "%s: not a sloth.db (%s)", m);
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
    return items(c, "SELECT COALESCE(title,''), '', type, sev, count,"
                    " first_seen, last_seen FROM alerts WHERE"
                    " (?1 <> '' AND instr(key, ?1) > 0)"
                    " OR (?2 <> '' AND match_ip = ?2)"
                    " ORDER BY last_seen DESC LIMIT ?3",
                 mac, ip ? ip : "", max, fn, ctx, 7);
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
    if (sqlite3_prepare_v2(c->db, "SELECT mac, first_seen FROM devices WHERE"
                           " first_seen >= ?1 ORDER BY first_seen DESC, mac"
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

#endif /* WITH_SQLITE */
