/* slothweb-demo (#164, M6): synthetic data to run slothweb against
 * without a sensor, for the README's five-minute walk-through, its
 * check (web/tools/quickstart_check.sh) and the screenshots.
 *
 *   slothweb-demo db PATH
 *       writes a new sloth.db at PATH from sloth's own DDL
 *       (src/db_schema.c), stamped with sloth's schema version, holding
 *       made-up devices, access points, alerts, survey sessions and
 *       protocol flows. Refuses a PATH that exists. Needs a WITH_SQLITE
 *       build.
 *   slothweb-demo feed unix:PATH [--seconds N]
 *       listens on a new unix socket at PATH (mode 0600, as sloth makes
 *       its own) and writes every client the same generated JSONL
 *       stream sloth's data socket carries: a snapshot pass a second
 *       (interfaces, top hosts, devices, probe clients, channels,
 *       flows, sensor health) and the capture thread's DNS, TLS and
 *       HTTP records between them, with an alert now and then. For N
 *       seconds, or until SIGINT or SIGTERM; the socket is removed on
 *       exit. Refuses a PATH that exists.
 *
 * Nothing in either is real or captured: addresses are the
 * documentation ranges (RFC 5737's 192.0.2.0/24, 198.51.100.0/24 and
 * 203.0.113.0/24, RFC 3849's 2001:db8::/32), every MAC is locally
 * administered (its first octet's 0x02 bit set, so no vendor's), and
 * names and SSIDs are under example. (RFC 2606) or plainly "demo".
 * The generator is seeded with a constant, so two runs write the same
 * rows apart from the clock. It never touches the network: the one
 * socket is the unix one it is told to make. */
#include <errno.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifdef WITH_SQLITE
#include <sqlite3.h>
const char *db_schema_sql(void);
const char *db_schema_meta_sql(void);
int db_schema_version(void);
#endif

#define NDEV   24
#define NCLI   16

static unsigned g_rng = 20261023u;
static unsigned rnd(unsigned n) {
    g_rng = g_rng * 1103515245u + 12345u;
    return n ? ((g_rng >> 8) & 0xffffffu) % n : 0;
}

typedef struct {
    const char *mac, *ip, *host, *ssid;
    int         is_ap, signal, sources, risk;
    int         first_days;            /* first seen this many days ago */
} demo_dev_t;

/* sources: 1 ARP, 2 DHCP, 8 beacon, 16 probe, 32 station. */
static const demo_dev_t DEV[NDEV] = {
    { "02:de:00:00:00:01", "192.0.2.1",  "gw.lan.example",       "",              1, -38, 1 | 2 | 8,  0, 29 },
    { "02:de:00:00:00:10", "192.0.2.10", "nas.lan.example",      "example-home",  0, -51, 1 | 2 | 32, 0, 28 },
    { "02:de:00:00:00:11", "192.0.2.11", "printer.lan.example",  "example-home",  0, -63, 1 | 2 | 32, 1, 27 },
    { "02:de:00:00:00:12", "192.0.2.12", "laptop-01.example",    "example-home",  0, -47, 1 | 2 | 32, 0, 21 },
    { "02:de:00:00:00:13", "192.0.2.13", "laptop-02.example",    "example-home",  0, -58, 1 | 2 | 32, 0, 14 },
    { "02:de:00:00:00:14", "192.0.2.14", "tv.lan.example",       "example-home",  0, -66, 1 | 2,      0, 26 },
    { "02:de:00:00:00:15", "192.0.2.15", "cam-entry.example",    "demo-iot",      0, -71, 1 | 2 | 32, 2, 12 },
    { "02:de:00:00:00:16", "192.0.2.16", "thermostat.example",   "demo-iot",      0, -69, 1 | 2 | 32, 0, 25 },
    { "02:de:00:00:00:17", "192.0.2.17", "plug-01.example",      "demo-iot",      0, -74, 1 | 2,      0, 9 },
    { "02:de:00:00:00:18", "192.0.2.18", "fileserver.example",   "",              0, -45, 1 | 2,      3, 30 },
    { "02:de:00:00:00:19", "192.0.2.19", "dc-01.example",        "",              0, -44, 1 | 2,      0, 30 },
    { "02:de:00:00:00:1a", "192.0.2.20", "workstation-03.example", "example-home", 0, -55, 1 | 2 | 32, 0, 6 },
    { "06:de:00:00:00:21", "192.0.2.21", "",                     "example-guest", 0, -60, 1 | 32,     0, 2 },
    { "06:de:00:00:00:22", "192.0.2.22", "phone-guest.example",  "example-guest", 0, -62, 1 | 2 | 32, 0, 1 },
    { "0a:de:00:00:00:23", "",           "",                     "",              0, -78, 16,         0, 3 },
    { "0a:de:00:00:00:24", "",           "",                     "",              0, -81, 16,         0, 0 },
    { "0e:de:00:00:00:25", "192.0.2.25", "tablet.example",       "example-home",  0, -57, 1 | 2 | 32, 0, 18 },
    { "02:de:00:00:00:26", "192.0.2.26", "speaker.lan.example",  "demo-iot",      0, -64, 1 | 2 | 32, 0, 22 },
    { "02:de:00:00:00:a1", "",           "",                     "example-home",  1, -41, 8,          0, 29 },
    { "02:de:00:00:00:a2", "",           "",                     "example-guest", 1, -43, 8,          0, 29 },
    { "02:de:00:00:00:a3", "",           "",                     "demo-iot",      1, -49, 8,          0, 20 },
    { "06:de:00:00:00:a4", "",           "",                     "FreeWiFi-demo", 1, -72, 8,          2, 0 },
    { "02:de:00:00:00:a5", "",           "",                     "neighbour-demo", 1, -80, 8,         0, 15 },
    { "02:de:00:00:00:a6", "",           "",                     "",              1, -84, 8,          0, 5 },
};

typedef struct {
    const char *bssid, *ssid, *akm, *enc;
    int         channel, akm_bits, mfp, downgrade, signal;
} ap_t;

static const ap_t AP[] = {
    { "02:de:00:00:00:a1", "example-home",   "PSK SAE", "WPA3", 6,   0x104, 1, 1, -41 },
    { "02:de:00:00:00:a2", "example-guest",  "PSK",     "WPA2", 36,  0x4,   0, 0, -43 },
    { "02:de:00:00:00:a3", "demo-iot",       "PSK",     "WPA2", 1,   0x4,   0, 0, -49 },
    { "06:de:00:00:00:a4", "FreeWiFi-demo",  "",        "OPEN", 11,  0,     0, 0, -72 },
    { "02:de:00:00:00:a5", "neighbour-demo", "SAE",     "WPA3", 149, 0x100, 2, 0, -80 },
    { "02:de:00:00:00:a6", "",               "PSK",     "WPA2", 44,  0x4,   0, 0, -84 },
};
#define NAP (int)(sizeof(AP) / sizeof(AP[0]))

/* ── the database ────────────────────────────────────────────────────── */

#ifdef WITH_SQLITE

static sqlite3 *g_db;
static int g_dbfail;

/* Run sql; after the first failure, nothing more (and the file is
 * removed at the end). */
static void raw(const char *sql) {
    if (g_dbfail) return;
    char *err = NULL;
    if (sqlite3_exec(g_db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "slothweb-demo: %s\n  in: %.200s\n", err ? err : "?", sql);
        g_dbfail = 1;
    }
    sqlite3_free(err);
}

static void ex(const char *fmt, ...) {
    char sql[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(sql, sizeof(sql), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(sql)) {
        fprintf(stderr, "slothweb-demo: a statement too long to build\n");
        g_dbfail = 1;
        return;
    }
    raw(sql);
}

static int make_db(const char *path) {
    struct stat sb;
    if (lstat(path, &sb) == 0) {
        fprintf(stderr, "slothweb-demo: %s exists; give a new path\n", path);
        return 1;
    }
    if (sqlite3_open_v2(path, &g_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        NULL) != SQLITE_OK) {
        fprintf(stderr, "slothweb-demo: %s: %s\n", path, sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        return 1;
    }
    long long now = (long long)time(NULL), D = 86400, H = 3600;
    ex("PRAGMA journal_mode=WAL");
    raw(db_schema_meta_sql());
    raw(db_schema_sql());
    ex("INSERT INTO meta (key, value) VALUES ('schema_version', '%d')",
       db_schema_version());
    ex("BEGIN");
    ex("INSERT INTO sessions (id,started,ended,site_label) VALUES"
       " (1,%lld,%lld,'demo-site'), (2,%lld,%lld,'demo-site'), (3,%lld,NULL,'demo-site')",
       now - 20 * D, now - 20 * D + 3 * H, now - 6 * D, now - 6 * D + 5 * H, now - 2 * H);
    for (int i = 0; i < NDEV; i++) {
        const demo_dev_t *d = &DEV[i];
        long long fs = now - d->first_days * D - (long long)rnd(20000);
        long long ls = now - (long long)rnd(600);
        if (i == 15) ls = now - 30 * H;      /* one gone for a day */
        ex("INSERT INTO devices (mac,ip,hostname,vendor,last_ssid,is_ap,signal_dbm,"
           "sources,risk_signals,risk_level,first_seen,last_seen) VALUES"
           " ('%s',%s%s%s,%s%s%s,NULL,%s%s%s,%d,%d,%d,%d,%d,%lld,%lld)",
           d->mac, d->ip[0] ? "'" : "", d->ip[0] ? d->ip : "NULL", d->ip[0] ? "'" : "",
           d->host[0] ? "'" : "", d->host[0] ? d->host : "NULL", d->host[0] ? "'" : "",
           d->ssid[0] ? "'" : "", d->ssid[0] ? d->ssid : "NULL", d->ssid[0] ? "'" : "",
           d->is_ap, d->signal, d->sources, d->risk ? 1 << d->risk : 0, d->risk, fs, ls);
        if (d->ip[0]) {
            ex("INSERT INTO arp (ip,mac,iface,first_seen,last_seen) VALUES"
               " ('%s','%s','eth0',%lld,%lld)", d->ip, d->mac, fs, ls);
            if (d->host[0])
                ex("INSERT INTO dhcp_leases (ip,hostname,expire,first_seen,last_seen)"
                   " VALUES ('%s','%s',%lld,%lld,%lld)", d->ip, d->host, now + D, fs, ls);
        }
        if (d->sources & 32) {
            ex("INSERT INTO pnl_clients (mac,mac_random,probe_count,first_seen,last_seen)"
               " VALUES ('%s',%d,%u,%lld,%lld)", d->mac, (d->mac[1] != '2'), 3 + rnd(40), fs, ls);
            ex("INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
               " ('%s','%s',%lld,%lld), ('%s','demo-cafe',%lld,%lld)",
               d->mac, d->ssid, fs, ls, d->mac, fs, fs + 600);
            const char *bss = !strcmp(d->ssid, "demo-iot") ? AP[2].bssid
                            : !strcmp(d->ssid, "example-guest") ? AP[1].bssid : AP[0].bssid;
            int ch = !strcmp(d->ssid, "demo-iot") ? 1 : !strcmp(d->ssid, "example-guest") ? 36 : 6;
            ex("INSERT INTO assocs (bssid,sta_mac,ssid,source,channel,signal_dbm,frame_count,"
               "first_seen,last_seen) VALUES ('%s','%s','%s',1,%d,%d,%u,%lld,%lld)",
               bss, d->mac, d->ssid, ch, d->signal, 100 + rnd(5000), fs, ls);
        }
        if (d->sources & 16)
            ex("INSERT INTO probe_clients (mac,ssid,signal_dbm,channel,frame_count,presence,"
               "first_seen,last_seen) VALUES ('%s','demo-cafe',%d,6,%u,2,%lld,%lld)",
               d->mac, d->signal, 10 + rnd(90), fs, ls);
    }
    ex("INSERT INTO mdns_services (instance,service,host,ip,port,first_seen,last_seen)"
       " VALUES ('Demo NAS._smb._tcp.local','_smb._tcp','nas.local','192.0.2.10',445,%lld,%lld),"
       " ('Demo Printer._ipp._tcp.local','_ipp._tcp','printer.local','192.0.2.11',631,%lld,%lld)",
       now - 28 * D, now - 60, now - 27 * D, now - 120);
    ex("INSERT INTO nbns_names (name,suffix,ip,first_seen,last_seen) VALUES"
       " ('FILESERVER',32,'192.0.2.18',%lld,%lld), ('WORKSTATION-03',0,'192.0.2.20',%lld,%lld)",
       now - 30 * D, now - 300, now - 6 * D, now - 200);
    for (int i = 0; i < NAP; i++) {
        const ap_t *a = &AP[i];
        long long fs = now - (i == 3 ? 3 * H : (long long)(20 + i) * D);
        ex("INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,enc,akm,akm_bits,mfp,"
           "downgrade_flags,vendor,phy,has_wps,first_seen,last_seen) VALUES"
           " ('%s',%s%s%s,%d,%d,'%s','%s',%d,%d,%d,NULL,'%s',%d,%lld,%lld)",
           a->bssid, a->ssid[0] ? "'" : "", a->ssid[0] ? a->ssid : "NULL",
           a->ssid[0] ? "'" : "", a->signal, a->channel, a->enc, a->akm, a->akm_bits,
           a->mfp, a->downgrade, a->channel > 14 ? "ac" : "n", i == 2, fs, now - 5);
        if (a->ssid[0])
            ex("INSERT INTO beacon_ap_ssids (bssid,ssid,first_seen,last_seen) VALUES"
               " ('%s','%s',%lld,%lld)", a->bssid, a->ssid, fs, now - 5);
    }
    /* The open AP answers for every SSID a client asks about: KARMA. */
    ex("INSERT INTO beacon_ap_ssids (bssid,ssid,first_seen,last_seen) VALUES"
       " ('%s','demo-cafe',%lld,%lld), ('%s','example-home',%lld,%lld),"
       " ('%s','airport-demo',%lld,%lld)",
       AP[3].bssid, now - 3 * H, now - 60, AP[3].bssid, now - 2 * H, now - 90,
       AP[3].bssid, now - H, now - 30);
    ex("INSERT INTO karma_candidates (bssid,ssid_count,pnl_overlap,pnl_best,ie_uniform,"
       "score,top_ssid,first_seen,last_seen) VALUES ('%s',4,3,2,1,82,'demo-cafe',%lld,%lld)",
       AP[3].bssid, now - 3 * H, now - 30);
    /* Alert episodes, oldest first; type is sloth_alerts.def's row. */
    static const struct {
        int type, sev; const char *title, *key, *ip; long long ago, len; int count;
    } AL[] = {
        { 0,  1, "PORT_SCAN",        "scan:203.0.113.50",                         "203.0.113.50", 18 * 86400, 600, 41 },
        { 10, 2, "SMB1_USE",         "smb1:192.0.2.18",                           "192.0.2.18",   9 * 86400,  7200, 12 },
        { 2,  0, "NXDOMAIN_BURST",   "nxdomain:192.0.2.17",                       "192.0.2.17",   4 * 86400,  900, 30 },
        { 14, 1, "SSH_BRUTE_FORCE",  "sshbf:203.0.113.77",                        "192.0.2.10",   2 * 86400,  1800, 64 },
        { 1,  2, "DEAUTH_FLOOD",     "deauth:02:de:00:00:00:12@02:de:00:00:00:a1", "",            5 * 3600,   240, 380 },
        { 20, 2, "KARMA_AP",         "karma:06:de:00:00:00:a4",                   "",             3 * 3600,   10000, 9 },
        { 0,  1, "PORT_SCAN",        "scan:192.0.2.21",                           "192.0.2.21",   50 * 60,    300, 22 },
    };
    for (size_t i = 0; i < sizeof(AL) / sizeof(AL[0]); i++) {
        long long fs = now - AL[i].ago, ls = fs + AL[i].len;
        if (ls > now) ls = now - 10;
        ex("INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,technique,"
           "match_ip,match_port,count) VALUES ('%s',%lld,%lld,%d,%d,'%s','demo episode',"
           "NULL,%s%s%s,NULL,%d)", AL[i].key, fs, ls, AL[i].type, AL[i].sev, AL[i].title,
           AL[i].ip[0] ? "'" : "", AL[i].ip[0] ? AL[i].ip : "NULL", AL[i].ip[0] ? "'" : "",
           AL[i].count);
    }
    /* Protocol flows. */
    long long fs = now - 3 * D, ls = now - 120;
    static const char *const SSH[][2] = {
        { "192.0.2.12", "192.0.2.10" }, { "192.0.2.13", "192.0.2.10" },
        { "192.0.2.12", "198.51.100.20" }, { "203.0.113.77", "192.0.2.10" },
        { "192.0.2.20", "192.0.2.18" }, { "192.0.2.25", "192.0.2.10" },
    };
    for (size_t i = 0; i < sizeof(SSH) / sizeof(SSH[0]); i++)
        ex("INSERT INTO ssh_flows (src_ip,dst_ip,banner_count,server_banner,first_seen,"
           "last_seen) VALUES ('%s','%s',%u,'SSH-2.0-demo',%lld,%lld)", SSH[i][0],
           SSH[i][1], i == 3 ? 64 : 2 + rnd(30), fs + (long long)i * H, ls - (long long)i * 60);
    ex("INSERT INTO rdp_flows (src_ip,dst_ip,connect_req_count,last_cookie,proto_mask,"
       "first_seen,last_seen) VALUES ('192.0.2.20','192.0.2.19',5,'mstshash=demo-user',3,"
       "%lld,%lld), ('192.0.2.13','192.0.2.20',2,NULL,1,%lld,%lld)", fs, ls, fs, ls - 500);
    ex("INSERT INTO smb_sessions (client_ip,server_ip,server_port,dialect,obs_count,"
       "first_seen,last_seen) VALUES ('192.0.2.20','192.0.2.18',445,'SMB1',12,%lld,%lld),"
       " ('192.0.2.12','192.0.2.10',445,'SMB2',40,%lld,%lld),"
       " ('192.0.2.13','192.0.2.10',445,'SMB2',18,%lld,%lld),"
       " ('192.0.2.25','192.0.2.18',139,'SMB2',6,%lld,%lld)",
       now - 9 * D, ls, fs, ls - 30, fs, ls - 90, fs, ls - 700);
    ex("INSERT INTO snmp_flows (src_ip,dst_ip,get_count,getnext_count,getbulk_count,"
       "set_count,response_count,trap_count,version,community_count,first_seen,last_seen)"
       " VALUES ('192.0.2.10','192.0.2.11',20,40,0,0,60,0,1,1,%lld,%lld),"
       " ('192.0.2.11','192.0.2.10',0,0,0,0,0,3,0,1,%lld,%lld),"
       " ('192.0.2.10','192.0.2.1',12,0,4,0,16,0,1,1,%lld,%lld)", fs, ls, fs, ls, fs, ls);
    ex("INSERT INTO ldap_events (src_ip,bind_count,bind_anon_count,search_count,"
       "search_ref_count,first_seen,last_seen) VALUES ('192.0.2.20',8,0,40,2,%lld,%lld),"
       " ('192.0.2.13',3,1,9,0,%lld,%lld)", fs, ls, fs, ls);
    ex("INSERT INTO kerb_events (src_ip,as_req_count,as_rep_count,tgs_req_count,"
       "tgs_rep_count,preauth_required_count,preauth_failed_count,principal_unknown_count,"
       "error_other_count,first_seen,last_seen) VALUES ('192.0.2.20',6,6,14,14,2,0,0,0,%lld,%lld),"
       " ('192.0.2.13',9,4,3,3,5,5,2,0,%lld,%lld)", fs, ls, fs, ls);
    ex("INSERT INTO bgp_sessions (peer_a,peer_b,open_count,update_count,notification_count,"
       "keepalive_count,first_seen,last_seen) VALUES ('198.51.100.1','198.51.100.2',1,40,0,"
       "300,%lld,%lld)", fs, ls);
    ex("INSERT INTO mqtt_flows (src_ip,dst_ip,connect_count,connack_fail_count,"
       "subscribe_count,publish_count,proto_level,last_username,first_seen,last_seen)"
       " VALUES ('192.0.2.16','192.0.2.10',4,0,2,300,4,'demo-user',%lld,%lld)", fs, ls);
    ex("COMMIT");
    /* The last connection closing checkpoints: no -wal or -shm left. */
    sqlite3_close(g_db);
    if (g_dbfail) {
        unlink(path);
        return 1;
    }
    fprintf(stderr, "slothweb-demo: wrote %s (sloth schema v%d, synthetic)\n", path,
            db_schema_version());
    return 0;
}

#else

static int make_db(const char *path) {
    (void)path;
    fprintf(stderr, "slothweb-demo: built without SQLite (WITH_SQLITE=0); no db\n");
    return 1;
}

#endif

/* ── the stream ──────────────────────────────────────────────────────── */

#define MAXC 8
static int g_cl[MAXC];
static volatile sig_atomic_t g_stop;
static void on_sig(int s) { (void)s; g_stop = 1; }

static char g_buf[1 << 16];
static size_t g_len;

static void line(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(g_buf + g_len, sizeof(g_buf) - g_len - 1, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(g_buf) - g_len - 1) return;
    g_len += (size_t)n;
    g_buf[g_len++] = '\n';
}

static void flush(void) {
    for (int i = 0; i < MAXC; i++) {
        if (g_cl[i] < 0) continue;
        size_t o = 0;
        while (o < g_len) {
            ssize_t w = send(g_cl[i], g_buf + o, g_len - o, MSG_NOSIGNAL);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                close(g_cl[i]);
                g_cl[i] = -1;
                break;
            }
            o += (size_t)w;
        }
    }
    g_len = 0;
}

static const char *const QN[] = {
    "www.example.com", "api.example.net", "cdn.example.org", "time.example.com",
    "updates.example.net", "mail.example.org", "files.example.com", "demo.test",
};

/* One snapshot pass at t (sloth's order: interfaces first, sensor
 * health last), with the capture thread's records before it. */
static void pass(long long t, long long start, unsigned long k) {
    double ph = (double)(t % 600) / 600.0 * 6.283185307;
    for (unsigned i = 0, n = 2 + rnd(5); i < n; i++) {
        const demo_dev_t *d = &DEV[1 + rnd(12)];
        const char *q = QN[rnd(8)];
        int nx = !strcmp(q, "demo.test") || rnd(30) == 0;
        line("{\"type\":\"dns\",\"ts\":%lld,\"src\":\"%s\",\"qname\":\"%s\",\"qtype\":\"A\","
             "\"answer\":\"\",\"is_resp\":0}", t, d->ip, q);
        line("{\"type\":\"dns\",\"ts\":%lld,\"src\":\"192.0.2.1\",\"qname\":\"%s\",\"qtype\":\"A\","
             "\"answer\":\"%s\",\"is_resp\":1}", t, q, nx ? "NXDOMAIN" : "203.0.113.80");
    }
    for (unsigned i = 0, n = rnd(4); i < n; i++)
        line("{\"type\":\"tls\",\"ts\":%lld,\"src\":\"%s\",\"dst\":\"203.0.113.%u\","
             "\"host\":\"%s\",\"ver\":\"TLS1.3\",\"ja3\":\"\"}", t, DEV[1 + rnd(12)].ip,
             10 + rnd(80), QN[rnd(7)]);
    if (rnd(3) == 0)
        line("{\"type\":\"http\",\"ts\":%lld,\"src\":\"%s\",\"host\":\"demo.test\","
             "\"method\":\"GET\",\"path\":\"/status\"}", t, DEV[7].ip);
    if (k % 45 == 7)
        line("{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"demo-%lu\","
             "\"title\":\"PORT_SCAN\",\"detail\":\"203.0.113.50 probed 40 ports on 192.0.2.10"
             " (demo)\",\"sev\":1,\"ty\":0,\"match_ip\":\"203.0.113.50\",\"match_port\":0}", t, k);
    if (k % 120 == 30)
        line("{\"type\":\"alert.create\",\"ts\":%lld,\"incident_id\":\"demo-smb1-%lu\","
             "\"title\":\"SMB1_USE\",\"detail\":\"192.0.2.20 negotiated SMB1 with 192.0.2.18"
             " (demo)\",\"sev\":2,\"ty\":10,\"match_ip\":\"192.0.2.20\",\"match_port\":445}", t, k);
    /* sloth's order (src/jsonl.c): the connections of the tick just
     * before its interfaces, then ARP, DHCP, top hosts, and the device
     * table as one run (slothweb counts devices by the run). */
    unsigned conns = 12 + rnd(10);
    for (unsigned i = 0; i < conns; i++)
        line("{\"type\":\"connections\",\"ts\":%lld,\"src\":\"%s\",\"dst\":\"203.0.113.%u\","
             "\"proto\":\"tcp\",\"state\":\"ESTABLISHED\"}", t, DEV[1 + i % 12].ip, 10 + i);
    double rx = 180000 + 120000 * sin(ph) + (double)rnd(40000);
    if (k % 300 > 280) rx *= 4;               /* a burst now and then */
    line("{\"type\":\"iface\",\"ts\":%lld,\"name\":\"eth0\",\"rx_bytes\":%lld,\"tx_bytes\":%lld,"
         "\"rx_rate\":%.0f,\"tx_rate\":%.0f,\"mtu\":1500,\"speed_mbps\":1000}",
         t, (long long)k * 200000, (long long)k * 50000, rx, rx / 4 + rnd(9000));
    line("{\"type\":\"iface\",\"ts\":%lld,\"name\":\"wlan0mon\",\"rx_bytes\":%lld,\"tx_bytes\":0,"
         "\"rx_rate\":%u,\"tx_rate\":0,\"mtu\":2304,\"speed_mbps\":0}", t,
         (long long)k * 30000, 20000 + rnd(20000));
    for (int i = 0; i < NDEV; i++)
        if (DEV[i].ip[0] && i != 15)
            line("{\"type\":\"arp\",\"ts\":%lld,\"ip\":\"%s\",\"mac\":\"%s\",\"iface\":\"eth0\"}",
                 t, DEV[i].ip, DEV[i].mac);
    for (int i = 1; i < 14; i++)
        if (DEV[i].host[0] && DEV[i].ip[0])
            line("{\"type\":\"dhcp_lease\",\"ts\":%lld,\"ip\":\"%s\",\"hostname\":\"%s\","
                 "\"expire\":%lld}", t, DEV[i].ip, DEV[i].host, t + 86400);
    for (int i = 0; i < 5; i++)
        line("{\"type\":\"top_host\",\"ts\":%lld,\"ip\":\"%s\",\"hostname\":\"%s\","
             "\"first_seen\":%lld,\"last_seen\":%lld,\"conn_count\":%u,\"rx_rate\":%u,"
             "\"tx_rate\":%u}", t, DEV[1 + i].ip, DEV[1 + i].host, start, t, 1 + rnd(9),
             (5 - i) * 20000 + rnd(9000), (5 - i) * 4000 + rnd(2000));
    for (int i = 0; i < NDEV; i++) {
        const demo_dev_t *d = &DEV[i];
        if (i == 15) continue;                /* gone */
        static const char *const RISK[] = { "none", "low", "medium", "high" };
        line("{\"type\":\"device\",\"ts\":%lld,\"mac\":\"%s\",\"ip\":\"%s\",\"hostname\":\"%s\","
             "\"vendor\":\"\",\"last_ssid\":\"%s\",\"is_ap\":%d,\"signal_dbm\":%d,"
             "\"probe_count\":0,\"sources\":%d,\"last_seen\":%lld,\"risk\":\"%s\","
             "\"risk_signals\":%d}", t, d->mac, d->ip, d->host, d->ssid, d->is_ap,
             d->signal + (int)rnd(5) - 2, d->sources, t, RISK[d->risk & 3],
             d->risk ? 1 << d->risk : 0);
    }
    /* A deauth burst against the home AP for a minute in every ten. */
    if (k % 600 >= 300 && k % 600 < 360)
        line("{\"type\":\"deauth\",\"ts\":%lld,\"src\":\"%s\",\"dst\":\"%s\",\"bssid\":\"%s\","
             "\"reason\":7,\"subtype\":12,\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"count\":%lu,\"flood\":1}", t, AP[0].bssid, DEV[3].mac, AP[0].bssid,
             start, t, (k % 600 - 299) * 12);
    line("{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":\"%s\",\"ssid\":\"demo-cafe\","
         "\"signal_dbm\":%d,\"channel\":6,\"first_seen\":%lld,\"last_seen\":%lld,"
         "\"frame_count\":%lu}", t, DEV[14].mac, DEV[14].signal, start, t, k / 3);
    if (k % 600 < 400)
        line("{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":\"0a:de:00:00:01:%02lx\","
             "\"ssid\":\"\",\"signal_dbm\":-83,\"channel\":11,\"first_seen\":%lld,"
             "\"last_seen\":%lld,\"frame_count\":%lu}", t, (k / 60) % 200, t - (long long)(k % 60),
             t, k % 60);
    static const struct { int ch; const char *band; } CH[] = {
        { 1, "2.4 GHz" }, { 6, "2.4 GHz" }, { 11, "2.4 GHz" }, { 36, "5 GHz" },
        { 44, "5 GHz" }, { 149, "5 GHz" }, { 37, "6 GHz" },
    };
    for (size_t i = 0; i < sizeof(CH) / sizeof(CH[0]); i++) {
        int aps = 0;
        for (int a = 0; a < NAP; a++) if (AP[a].channel == CH[i].ch) aps++;
        if (CH[i].ch == 6) aps += 2;
        line("{\"type\":\"channel_summary\",\"ts\":%lld,\"channel\":%d,\"band\":\"%s\","
             "\"ap_count\":%d,\"assoc_count\":%d,\"best_signal\":-45,\"top_ssid\":\"\","
             "\"ctrl_total\":%lu}", t, CH[i].ch, CH[i].band, aps, aps * 2,
             k * (unsigned long)(10 + 7 * i) + rnd(30));
    }
    for (int i = 0; i < NDEV; i++)
        if (DEV[i].sources & 32)
            line("{\"type\":\"assoc\",\"ts\":%lld,\"bssid\":\"%s\",\"sta_mac\":\"%s\","
                 "\"ssid\":\"%s\",\"first_seen\":%lld,\"last_seen\":%lld,\"frame_count\":%lu}",
                 t, AP[0].bssid, DEV[i].mac, DEV[i].ssid, start, t, k * 3);
    line("{\"type\":\"ssh_flow\",\"ts\":%lld,\"src_ip\":\"192.0.2.12\",\"dst_ip\":\"192.0.2.10\","
         "\"banner_count\":%lu,\"first_seen\":%lld,\"last_seen\":%lld}", t, 1 + k / 30, start, t);
    line("{\"type\":\"smb_session\",\"ts\":%lld,\"client_ip\":\"192.0.2.12\","
         "\"server_ip\":\"192.0.2.10\",\"server_port\":445,\"dialect\":\"SMB2\",\"count\":%lu,"
         "\"first_seen\":%lld,\"last_seen\":%lld}", t, 1 + k / 10, start, t);
    line("{\"type\":\"sensor_health\",\"ts\":%lld,\"capture_iface\":\"eth0\","
         "\"monitor_iface\":\"wlan0mon\",\"capture_open\":1,\"capture_running\":1,"
         "\"monitor_open\":1,\"monitor_running\":1,\"scope\":\"demo\","
         "\"scope_not_enforced\":0}", t);
}

static int feed(const char *spec, long long seconds) {
    if (strncmp(spec, "unix:", 5) != 0 || !spec[5]) {
        fprintf(stderr, "slothweb-demo: feed wants unix:PATH\n");
        return 2;
    }
    const char *path = spec + 5;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(sa.sun_path)) {
        fprintf(stderr, "slothweb-demo: %s: path too long for a unix socket\n", path);
        return 2;
    }
    struct stat sb;
    if (lstat(path, &sb) == 0) {
        fprintf(stderr, "slothweb-demo: %s exists; give a new path\n", path);
        return 1;
    }
    memcpy(sa.sun_path, path, strlen(path) + 1);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0) { perror("slothweb-demo: socket"); return 1; }
    mode_t old = umask(077);
    int b = bind(ls, (struct sockaddr *)&sa, sizeof(sa));
    umask(old);
    if (b != 0 || listen(ls, 4) != 0) {
        fprintf(stderr, "slothweb-demo: %s: %s\n", path, strerror(errno));
        close(ls);
        return 1;
    }
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = on_sig;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    signal(SIGPIPE, SIG_IGN);
    for (int i = 0; i < MAXC; i++) g_cl[i] = -1;
    fprintf(stderr, "slothweb-demo: serving a synthetic stream on unix:%s%s\n", path,
            seconds > 0 ? "" : " until SIGINT");
    long long start = (long long)time(NULL), next = start;
    unsigned long k = 0;
    while (!g_stop && (seconds <= 0 || (long long)time(NULL) - start < seconds)) {
        struct pollfd p = { ls, POLLIN, 0 };
        long long now = (long long)time(NULL);
        int wait = next > now ? (int)(next - now) * 1000 : 0;
        if (poll(&p, 1, wait > 1000 ? 1000 : wait) > 0 && (p.revents & POLLIN)) {
            int c = accept(ls, NULL, NULL);
            int slot = -1;
            for (int i = 0; c >= 0 && i < MAXC; i++) if (g_cl[i] < 0) { slot = i; break; }
            if (slot >= 0) g_cl[slot] = c;
            else if (c >= 0) close(c);
        }
        now = (long long)time(NULL);
        if (now >= next) {
            pass(now, start, k++);
            flush();
            next = now + 1;
        }
    }
    for (int i = 0; i < MAXC; i++) if (g_cl[i] >= 0) close(g_cl[i]);
    close(ls);
    unlink(path);
    fprintf(stderr, "slothweb-demo: stopped after %lu passes\n", k);
    return 0;
}

static void usage(FILE *o) {
    fprintf(o, "usage: slothweb-demo db PATH\n"
               "       slothweb-demo feed unix:PATH [--seconds N]\n"
               "Synthetic data only: documentation addresses, locally administered\n"
               "MACs, example names. See web/README.md.\n");
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "db")) return make_db(argv[2]);
    if ((argc == 3 || argc == 5) && !strcmp(argv[1], "feed")) {
        long long secs = 0;
        if (argc == 5) {
            char *end = NULL;
            secs = strtoll(argv[4], &end, 10);
            if (strcmp(argv[3], "--seconds") || !end || *end || secs <= 0) {
                usage(stderr);
                return 2;
            }
        }
        return feed(argv[2], secs);
    }
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
        usage(stdout);
        return 0;
    }
    usage(stderr);
    return 2;
}
