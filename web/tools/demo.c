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

#include "../tools/sha256.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
const char *db_schema_sql(void);
const char *db_schema_meta_sql(void);
int db_schema_version(void);
#endif

#define NDEV   24
#define NCLI   16

static unsigned g_rng = 20261023u;
/* The clock: time(NULL), or the one a test set (demo_now). */
static long long g_now_fixed;
static long long now_s(void) { return g_now_fixed ? g_now_fixed : (long long)time(NULL); }
static unsigned rnd(unsigned n) {
    g_rng = g_rng * 1103515245u + 12345u;
    return n ? ((g_rng >> 8) & 0xffffffu) % n : 0;
}

typedef struct {
    const char *mac, *ip, *host, *ssid;
    int         is_ap, signal, sources, risk;
    int         first_days;            /* first seen this many days ago */
} demo_dev_t;

/* The signals that score a demo device's level under sloth's formula
 * (web_scope_risk_level()): unknown vendor is MED, an alert naming the
 * device HIGH, that and a cleartext credential CRIT. slothweb scores the
 * level from these and does not read the stored one. */
static const int RISK_SIG[4] = { 0, 2, 32, 16 | 32 };

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
    /* The SSID as sloth's stream carries it (src/jsonl.c json_escape():
     * an octet that is not UTF-8 becomes U+FFFD); NULL: as ssid. */
    const char *stream_ssid;
    int         six;                  /* channel_source 3: a 6 GHz channel */
} ap_t;

static const ap_t AP[] = {
    { "02:de:00:00:00:a1", "example-home",   "PSK SAE", "WPA3", 6,   0x104, 1, 1, -41, NULL, 0 },
    { "02:de:00:00:00:a2", "example-guest",  "PSK",     "WPA2", 36,  0x4,   0, 0, -43, NULL, 0 },
    { "02:de:00:00:00:a3", "demo-iot",       "PSK",     "WPA2", 1,   0x4,   0, 0, -49, NULL, 0 },
    { "06:de:00:00:00:a4", "FreeWiFi-demo",  "",        "OPEN", 11,  0,     0, 0, -72, NULL, 0 },
    { "02:de:00:00:00:a5", "neighbour-demo", "SAE",     "WPA3", 149, 0x100, 2, 0, -80, NULL, 0 },
    { "02:de:00:00:00:a6", "",               "PSK",     "WPA2", 44,  0x4,   0, 0, -84, NULL, 0 },
    /* An SSID that is not UTF-8, as an old or misconfigured AP sends
     * one: sloth.db keeps its octets, the stream carries U+FFFD for
     * them, and the page shows both escaped (web/src/web_ssid.h). */
    { "02:de:00:00:00:a7", "demo-\xff\xfe-legacy", "PSK", "WPA2", 11, 0x4, 0, 0, -77,
      "demo-\\ufffd\\ufffd-legacy", 0 },
    { "02:de:00:00:00:a8", "example-6e",     "SAE",     "WPA3", 37,  0x100, 2, 0, -58,
      NULL, 1 },
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
    long long now = now_s(), D = 86400, H = 3600;
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
           d->is_ap, d->signal, d->sources, RISK_SIG[d->risk & 3], d->risk, fs, ls);
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
    /* The FRRS record's parametrics and posture (docs/web-frrs-spec.md
     * §4): the columns sloth fills from a beacon, a client's
     * association request, a BTM steer, a sequence-counter trail and the
     * multi-radio merge. No rnd() here: the passes the suite replays
     * draw the same numbers as before this block existed. */
    ex("UPDATE beacon_aps SET beacon_ms=100, frame_count=4200,"
       " pairwise=CASE WHEN enc='OPEN' THEN NULL ELSE 'CCMP' END,"
       " group_ciph=CASE WHEN enc='OPEN' THEN NULL ELSE 'CCMP' END");
    /* A second SSID from the home AP's radio: a virtual BSSID one up
     * from it, on its channel (the TACDB's S3 suggestion). */
    ex("INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,enc,akm,akm_bits,mfp,"
       "downgrade_flags,phy,has_wps,first_seen,last_seen) VALUES ('02:de:00:00:00:a9',"
       "'example-home-iot',-42,6,'WPA2','PSK',4,0,0,'n',0,%lld,%lld)", now - 29 * D, now - 5);
    ex("UPDATE beacon_aps SET has_qbss=1, qbss_stations=7, qbss_chan_util=88"
       " WHERE bssid='%s'", AP[0].bssid);
    ex("UPDATE beacon_aps SET wps_state=2, wps_locked=0 WHERE bssid='%s'", AP[2].bssid);
    ex("INSERT INTO ssid_akm_history (ssid,bssid,akm_bits,first_seen,last_seen) VALUES"
       " ('example-home','%s',%d,%lld,%lld), ('neighbour-demo','%s',4,%lld,%lld),"
       " ('neighbour-demo','%s',256,%lld,%lld)", AP[0].bssid, 0x104, now - 29 * D, now - 5,
       AP[4].bssid, now - 15 * D, now - 9 * D, AP[4].bssid, now - 9 * D, now - 5);
    ex("INSERT INTO assoc_reqs (bssid,sta_mac,requested_ssid,listen_interval,akm_bits,"
       "pairwise_bits,requested_mfp,supported_rates,phy,vendor_ie_hash,first_seen,last_seen)"
       " VALUES ('%s','%s','example-home',10,256,16,1,4095,'HE',1311768467294899695,%lld,%lld)",
       AP[0].bssid, DEV[3].mac, now - 21 * D, now - 40);
    ex("INSERT INTO btm_requests (bssid,sta_mac,req_count,imminent_count,first_seen,last_seen)"
       " VALUES ('%s','%s',3,0,%lld,%lld)", AP[0].bssid, DEV[4].mac, now - 2 * D, now - 3 * H);
    ex("UPDATE pnl_clients SET os_fp='Apple', phy='HE', phy_confirmed=1 WHERE mac='%s'",
       DEV[3].mac);
    ex("INSERT INTO seqnum_correlations (mac_a,mac_b,mac_a_random,mac_b_random,gap,dt_ms,"
       "a_count,b_count,first_seen,last_seen) VALUES ('%s','%s',1,1,3,4200,40,38,%lld,%lld)",
       DEV[14].mac, DEV[15].mac, now - 3 * D, now - 2 * H);
    ex("INSERT INTO wifi_merged (entity,sensor_mask,seen_by,best_rssi,best_sensor,channel,"
       "observations,first_seen,last_seen) VALUES ('%s',3,2,-39,0,6,900,%lld,%lld),"
       " ('%s',1,1,-46,0,6,410,%lld,%lld)", AP[0].bssid, now - 29 * D, now - 5,
       DEV[3].mac, now - 21 * D, now - 40);
    /* The host's own card is a station of the home AP too: the TACDB's
     * S6 suggestion (one emitter heard in both scopes). */
    ex("INSERT INTO wifi_stas (mac,signal_dbm,tx_rate_kbps,rx_rate_kbps,connected_secs,"
       "inactive_ms,tx_bytes,rx_bytes,first_seen,last_seen) VALUES"
       " ('%s',-55,866700,780000,5400,120,48000000,910000000,%lld,%lld)",
       DEV[11].mac, now - 6 * D, now - 20);
    /* Alert episodes, oldest first; type is sloth_alerts.def's row, the
     * detail in the format the rule writes (src/alerts/). sloth upserts
     * one row per (key, first_seen), so a finding that comes and goes is
     * many rows of one key: runs is how many incidents, every gap apart,
     * the Alerts page collapses them into one row. */
    static const struct {
        int type, sev; const char *title, *key, *ip; int port;
        long long ago, len; int count, runs; long long gap; const char *detail;
    } AL[] = {
        { 0,  1, "PORT_SCAN",       "scan:203.0.113.50",                          "203.0.113.50", 0,
          18 * 86400, 600, 41, 24, 6 * 3600, "203.0.113.50 scanned 41 distinct ports" },
        { 10, 2, "SMB1_USE",        "smb1:192.0.2.20->192.0.2.18:445",            "192.0.2.18", 445,
          9 * 86400, 7200, 12, 3, 86400,
          "SMBv1 traffic 192.0.2.20 -> 192.0.2.18:445 (count=12). SMBv1 has been deprecated"
          " since 2017 (EternalBlue / WannaCry); the endpoint serving v1 should be patched"
          " or v1 disabled." },
        { 2,  0, "NXDOMAIN_BURST",  "nxdomain:192.0.2.17",                        "192.0.2.17", 53,
          4 * 86400, 900, 30, 1, 0, "192.0.2.17 saw 30 NXDOMAIN responses in 60s" },
        { 14, 1, "SSH_BRUTE_FORCE", "sshbf:203.0.113.77->192.0.2.10",             "203.0.113.77", 22,
          2 * 86400, 1800, 64, 2, 1200, "203.0.113.77->192.0.2.10: 64 SSH banners (brute-force; SSH-2.0-demo)" },
        { 1,  2, "DEAUTH_FLOOD",    "deauth:02:de:00:00:00:12@02:de:00:00:00:a1", NULL, 0,
          5 * 3600, 240, 380, 6, 3 * 3600,
          "victim=02:de:00:00:00:12 bssid=02:de:00:00:00:a1 observed 380 frames, peak 41 in 5s,"
          " reason=7, 1 stream; sender unverified, disruption not confirmed" },
        { 20, 2, "KARMA_AP",        "karma:06:de:00:00:00:a4",                    NULL, 0,
          3 * 3600, 10000, 9, 1, 0, "KARMA BSSID 06:de:00:00:00:a4: 4 SSIDs, conf 82%" },
        { 27, 1, "CLEARTEXT_CRED",  "cred:192.0.2.16:192.0.2.10:21:FTP:demo-user:00c0ffee00c0ffee",
          "192.0.2.16", 21, 26 * 3600, 600, 2, 1, 0,
          "FTP user demo-user in the clear on FTP -> 192.0.2.10:21" },
        { 0,  1, "PORT_SCAN",       "scan:192.0.2.21",                            "192.0.2.21", 0,
          50 * 60, 300, 22, 1, 0, "192.0.2.21 scanned 22 distinct ports" },
        /* A posture finding (no ATT&CK technique): what the FRRS
         * record's SCS group lists for the emitter. */
        { 80, 0, "COUNTRY_ABSENT",  "countryabsent:02:de:00:00:00:a5",            NULL, 0,
          7 * 3600, 3600, 1, 1, 0,
          "02:de:00:00:00:a5 (neighbour-demo) beacons on 5 GHz channel 149 with no Country element" },
    };
    for (size_t i = 0; i < sizeof(AL) / sizeof(AL[0]); i++) {
        for (int r = AL[i].runs - 1; r >= 0; r--) {
            long long fs = now - AL[i].ago - (long long)r * (AL[i].len + AL[i].gap), ls = fs + AL[i].len;
            if (ls > now) ls = now - 10;
            ex("INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,technique,"
               "match_ip,match_port,count) VALUES ('%s',%lld,%lld,%d,%d,'%s','%s',NULL,%s%s%s,%d,%d)",
               AL[i].key, fs, ls, AL[i].type, AL[i].sev, AL[i].title, AL[i].detail,
               AL[i].ip ? "'" : "", AL[i].ip ? AL[i].ip : "NULL", AL[i].ip ? "'" : "",
               AL[i].port, AL[i].count);
        }
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

/* One lifecycle record (src/jsonl.c jsonl_emit_alert_event()). */
static void alert_ev(const char *ev, long long t, const char *id, int ty, int sev,
                     const char *title, const char *key, const char *detail,
                     const char *ip, int port, long long first, long long count,
                     const char *extra) {
    line("{\"type\":\"%s\",\"ts\":%lld,\"event_id\":\"%s-0001\",\"incident_id\":\"%s\","
         "\"key\":\"%s\",\"title\":\"%s\",\"detail\":\"%s\",\"sev\":%d,\"ty\":%d,"
         "\"observations\":%lld,\"evaluations\":%lld,\"count\":%lld,\"first_detected\":%lld,"
         "\"last_observed\":%lld%s%s%s%s}", ev, t, id, id, key, title, detail, sev, ty,
         count, count, count, first, t, ip ? ",\"match_ip\":\"" : "", ip ? ip : "",
         ip ? "\"" : "", extra);
    (void)port;
}

/* The demo's incidents: a port scan that opens and closes every 45
 * passes, an SMB1 session that escalates, a deauth flood with its pcap
 * during the burst, and two that stay open: a KARMA AP (sloth.db has
 * its key too) and a cleartext credential, whose detail and key carry a
 * username slothweb never shows. */
static void lifecycle(long long t, unsigned long k) {
    char id[32], d[200];
    unsigned long n = k / 45, p = k % 45;
    snprintf(id, sizeof(id), "d0000000000a%04lx", n & 0xffff);
    snprintf(d, sizeof(d), "203.0.113.50 scanned %lu distinct ports", 8 + p);
    if (p == 7)
        alert_ev("alert.create", t, id, 0, 1, "PORT_SCAN", "scan:203.0.113.50", d,
                 "203.0.113.50", 0, t, 1, ",\"match_port\":0");
    if (p == 20)
        alert_ev("alert.update", t, id, 0, 1, "PORT_SCAN", "scan:203.0.113.50", d,
                 "203.0.113.50", 0, t - 13, 14, ",\"match_port\":0");
    if (p == 40)
        alert_ev("alert.resolve", t, id, 0, 1, "PORT_SCAN", "scan:203.0.113.50", d,
                 "203.0.113.50", 0, t - 33, 34, ",\"match_port\":0,\"reason\":\"expired\"");
    n = k / 120;
    p = k % 120;
    snprintf(id, sizeof(id), "d0000000000b%04lx", n & 0xffff);
    static const char SMB[] = "SMBv1 traffic 192.0.2.20 -> 192.0.2.18:445 (count=4). SMBv1 has"
                              " been deprecated since 2017 (EternalBlue / WannaCry); the endpoint"
                              " serving v1 should be patched or v1 disabled.";
    if (p == 30)
        alert_ev("alert.create", t, id, 10, 1, "SMB1_USE", "smb1:192.0.2.20->192.0.2.18:445",
                 SMB, "192.0.2.18", 445, t, 1, ",\"match_port\":445");
    if (p == 36)
        alert_ev("alert.escalate", t, id, 10, 2, "SMB1_USE", "smb1:192.0.2.20->192.0.2.18:445",
                 SMB, "192.0.2.18", 445, t - 6, 7, ",\"match_port\":445,\"prev_sev\":1,"
                 "\"pcap_path\":\"/var/lib/sloth/pcap/alert_20261027_120000_SMB1_USE.pcap\"");
    if (p == 100)
        alert_ev("alert.resolve", t, id, 10, 2, "SMB1_USE", "smb1:192.0.2.20->192.0.2.18:445",
                 SMB, "192.0.2.18", 445, t - 70, 71, ",\"match_port\":445,\"reason\":\"expired\"");
    n = k / 600;
    p = k % 600;
    snprintf(id, sizeof(id), "d0000000000c%04lx", n & 0xffff);
    snprintf(d, sizeof(d), "victim=02:de:00:00:00:12 bssid=02:de:00:00:00:a1 observed %lu frames,"
             " peak 41 in 5s, reason=7, 1 stream; sender unverified, disruption not confirmed",
             p >= 300 ? (p - 299) * 12 : 0);
    static const char DK[] = "deauth:02:de:00:00:00:12@02:de:00:00:00:a1";
    if (p == 302)
        alert_ev("alert.create", t, id, 1, 1, "DEAUTH_FLOOD", DK, d, NULL, 0, t, 1, "");
    if (p == 310)
        alert_ev("alert.escalate", t, id, 1, 2, "DEAUTH_FLOOD", DK, d, NULL, 0, t - 8, 9,
                 ",\"prev_sev\":1,\"pcap_path\":\"/var/lib/sloth/pcap/demo-deauth.pcap\"");
    if (p == 400)
        alert_ev("alert.resolve", t, id, 1, 2, "DEAUTH_FLOOD", DK, d, NULL, 0, t - 98, 99,
                 ",\"pcap_path\":\"/var/lib/sloth/pcap/demo-deauth.pcap\",\"reason\":\"expired\"");
    if (k == 2)
        alert_ev("alert.create", t, "d000000000000001", 20, 2, "KARMA_AP",
                 "karma:06:de:00:00:00:a4", "KARMA BSSID 06:de:00:00:00:a4: 4 SSIDs, conf 82%",
                 NULL, 0, t - 3 * 3600, 9, "");
    if (k == 3)
        alert_ev("alert.create", t, "d000000000000002", 27, 1, "CLEARTEXT_CRED",
                 "cred:192.0.2.16:192.0.2.10:21:FTP:demo-user:00c0ffee00c0ffee",
                 "FTP user demo-user in the clear on FTP -> 192.0.2.10:21", "192.0.2.16", 21,
                 t - 26 * 3600, 2, ",\"match_port\":21");
}

/* The BLE advertisers (src/jsonl.c jsonl_emit_ble_devices(), one row
 * per advertiser as one sensor heard it), and the one finding. Six
 * rows: a public-address beacon with a complete name and a service
 * (the stream's distance estimate on it), an Apple-style random address
 * with Continuity manufacturer data, a keyboard (HID appearance 0x03C1
 * and the 0x1812 service: the TUI's bright row), a random address that
 * rotates every fifteen minutes, an extended advertiser on LE Coded,
 * and an anonymous (type 255) extended advertisement; two of them heard
 * by an Ubertooth as well (sampled rows of the same addresses). Every
 * address is locally administered (0x02 bit of the first octet set) or
 * random, every name under demo; nothing is captured. sloth's records
 * are change-only with a 300 s heartbeat: these go out on the first
 * pass, every 300th pass, and when a signed field changes (a rotation,
 * a band change). */
/* sloth's own table (s->ble_device_count, sensor_health ble_devices)
 * keys a row per address as one sensor heard it, so the two Ubertooth
 * rows count: six advertisers, eight rows, and the FRRS record's three
 * (pass(): the watch, the beacon and the keyboard, heard by the host
 * controller) make eleven. */
#define NBLE 11
static const int BLE_CO_DEMO = 0xffff;   /* the SIG's reserved "internal use" id */

static void ble_dev(long long t, long long start, unsigned long k, const char *addr,
                    int type, const char *iface, int adapter, int sampled,
                    int channel, const char *pdu, int pdu_mask, const char *name,
                    int name_complete, int uuid16, int mfr_id, int mfr_sub,
                    int svc_data, int appearance, int hid, int tx_power, int flags,
                    int rssi, int rssi_best, unsigned long adv, const char *cat,
                    int ext, int pphy, int sphy, int sid, long long first,
                    const char *est) {
    line("{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"%s\",\"addr_type\":%d,"
         "\"sensor\":\"ble\",\"iface\":\"%s\",\"adapter\":%d,\"sampled\":%d,\"channel\":%d,"
         "\"last_pdu\":\"%s\",\"pdu_mask\":%d,\"name\":\"%s\",\"name_complete\":%d,"
         "\"uuid16\":%d,\"mfr_id\":%d,\"mfr_subtype\":%d,\"svc_data_uuid16\":%d,"
         "\"appearance\":%d,\"hid\":%d,\"tx_power\":%d,\"flags\":%d,\"has_rssi\":1,"
         "\"rssi\":%d,\"rssi_best\":%d,\"adv_count\":%lu,\"watch_category\":\"%s\","
         "\"ext_adv\":%d,\"primary_phy\":%d,\"secondary_phy\":%d,\"adv_sid\":%d,"
         "\"first_seen\":%lld,\"last_seen\":%lld%s}",
         t, addr, type, iface, adapter, sampled, channel, pdu, pdu_mask, name,
         name_complete, uuid16, mfr_id, mfr_sub, svc_data, appearance, hid, tx_power,
         flags, rssi, rssi_best, adv, cat, ext, pphy, sphy, sid, first, t, est);
    (void)start; (void)k;
}

static void ble_pass(long long t, long long start, unsigned long k) {
    /* A rotating random address: a new one every 900 passes, the row's
     * first_seen the rotation's. */
    unsigned long rot = k / 900;
    char rand_addr[18];
    snprintf(rand_addr, sizeof(rand_addr), "7a:de:00:00:%02lx:%02lx", (rot >> 8) & 0xff, rot & 0xff);
    /* sloth's heartbeat is 300 s; the demo's rows go out every 15 passes
     * so a client that connects between two of them (the README's walk-
     * through, the screenshots) sees the table fill within a quarter of
     * a minute. Each record is still change-only in shape. */
    int heartbeat = k % 15 == 0;
    /* The beacon's band moves between room and near every ten minutes:
     * a signed change, so the record goes out then too. */
    int near = (k / 600) % 2;
    char est[160];
    snprintf(est, sizeof(est), ",\"est_dist_m\":%s,\"est_dist_band\":\"%s\","
             "\"est_dist_trend\":\"%s\",\"est_ptx_source\":\"ble_ad_tx_power\"",
             near ? "2.5" : "6", near ? "near" : "room",
             k % 600 < 60 ? (near ? "approaching" : "leaving") : "steady");
    if (heartbeat || k % 600 == 0) {
        ble_dev(t, start, k, "02:de:00:00:b1:01", 0, "bluetooth-monitor", 0, 0, -1, "ADV_IND",
                17, "demo-beacon", 1, 0x180f, -1, -1, 0x181c, 0x0200, 0, -8, 6,
                near ? -58 : -71, -55, 60 * k / 7 + 120, "", 0, 0, 0, -1, start, est);
        ble_dev(t, start, k, "02:de:00:00:b1:01", 0, "ubertooth", 0, 1, 37, "ADV_IND",
                1, "demo-beacon", 1, 0x180f, -1, -1, 0x181c, 0x0200, 0, -8, 6,
                near ? -64 : -77, -61, 20 * k / 7 + 40, "", 0, 0, 0, -1, start, "");
    }
    if (heartbeat) {
        ble_dev(t, start, k, "5e:de:00:00:b2:02", 1, "bluetooth-monitor", 0, 0, -1, "ADV_IND",
                17, "", 0, -1, 0x004c, 0x10, -1, -1, 0, -128, 26, -67, -62, 3 * k + 9, "",
                0, 0, 0, -1, start - 3600, "");
        ble_dev(t, start, k, "02:de:00:00:b3:03", 0, "bluetooth-monitor", 0, 0, -1, "SCAN_RSP",
                17, "demo-kbd", 1, 0x1812, BLE_CO_DEMO, -1, -1, 0x03c1, 3, 0, 5, -49, -44,
                2 * k + 30, "", 0, 0, 0, -1, start - 7200,
                ",\"est_dist_m\":1.5,\"est_dist_band\":\"near\",\"est_dist_trend\":\"steady\","
                "\"est_ptx_source\":\"ble_ad_tx_power\"");
        ble_dev(t, start, k, "02:de:00:00:b3:03", 0, "ubertooth", 0, 1, 38, "ADV_IND",
                1, "demo-kbd", 1, 0x1812, BLE_CO_DEMO, -1, -1, 0x03c1, 3, 0, 5, -55, -50,
                k / 2 + 10, "", 0, 0, 0, -1, start - 7200, "");
        ble_dev(t, start, k, "02:de:00:00:b4:04", 0, "bluetooth-monitor", 0, 0, -1, "EXT_ADV",
                32, "demo-coded-sensor", 1, 0x181a, -1, -1, -1, 0x0540, 0, -128, 6,
                -81, -79, k / 4 + 2, "", 1, 3, 3, 4, start - 600, "");
        ble_dev(t, start, k, "00:00:00:00:00:00", 255, "bluetooth-monitor", 0, 0, -1, "EXT_ADV",
                32, "", 0, -1, -1, -1, -1, -1, 0, -128, -1, -76, -70, k / 9 + 1, "",
                1, 1, 2, 7, start - 300, "");
    }
    if (heartbeat || k % 900 == 0)
        ble_dev(t, start, k, rand_addr, 1, "bluetooth-monitor", 0, 0, -1, "ADV_NONCONN_IND",
                8, "", 0, -1, 0x0006, 0x01, -1, -1, 0, -128, -1, -72, -66,
                (k % 900) / 2 + 1, "", 0, 0, 0, -1, start + (long long)rot * 900, "");
    /* A pairing-notification flood for a minute in every ten (research/
     * bluetooth/ble-spam-flood.md), from the half-minute mark: the
     * finding stands while the window passes its gates, re-emitted as
     * its closed window grows, then the alert.resolve of the same key. */
    static const char FK[] = "ble_flood:bluetooth-monitor:mfr:004c:07";
    unsigned long p = (k + 390) % 600;   /* 420 at k = 30, 630, ... */
    if (p >= 420 && p < 480 && (p == 420 || p % 10 == 0))
        line("{\"type\":\"ble_alert\",\"ts\":%lld,\"kind\":\"adv_flood\",\"alert\":\"BLE_ADV_FLOOD\","
             "\"ty\":87,\"key\":\"%s\",\"sensor\":\"ble\",\"iface\":\"bluetooth-monitor\","
             "\"sampled\":0,\"adv_type\":\"ADV_IND\",\"family\":\"mfr\",\"id\":76,\"subtype\":7,"
             "\"window\":\"previous\",\"window_s\":10,\"distinct_addrs\":%lu,\"distinct_capped\":0,"
             "\"fresh_addrs\":%lu,\"total_adv\":%lu,\"rate\":%lu.0,\"has_rssi\":1,"
             "\"median_rssi\":-61,\"spam_source\":\"ble-spam-flood.md: ECTO-1A/ble_spam.c\"}",
             t, FK, 40 + (p - 420), 38 + (p - 420), 400 + (p - 420) * 9, 40 + (p - 420));
    if (p == 420)
        alert_ev("alert.create", t, "d0000000000e0001", 87, 1, "BLE_ADV_FLOOD", FK,
                 "BLE advertisement flood: mfr 004c/07 ADV_IND, 40 fresh addresses in 10s",
                 NULL, 0, t, 1, "");
    if (p == 480)
        alert_ev("alert.resolve", t, "d0000000000e0001", 87, 1, "BLE_ADV_FLOOD", FK,
                 "BLE advertisement flood: mfr 004c/07 ADV_IND, 40 fresh addresses in 10s",
                 NULL, 0, t - 60, 7, ",\"reason\":\"expired\"");
}

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
    lifecycle(t, k);
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
             RISK_SIG[d->risk & 3]);
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
    /* Each station on its own AP's channel, at its own pace, and every
     * AP's beacons (frame_count is the beacons heard): what the WiFi
     * view's channel mix stacks. */
    for (int i = 0; i < NDEV; i++)
        if (DEV[i].sources & 32) {
            int a = !strcmp(DEV[i].ssid, "demo-iot") ? 2
                  : !strcmp(DEV[i].ssid, "example-guest") ? 1 : 0;
            line("{\"type\":\"assoc\",\"ts\":%lld,\"bssid\":\"%s\",\"sta_mac\":\"%s\","
                 "\"ssid\":\"%s\",\"channel\":%d,\"first_seen\":%lld,\"last_seen\":%lld,"
                 "\"frame_count\":%lu}", t, AP[a].bssid, DEV[i].mac, DEV[i].ssid,
                 AP[a].channel, start, t, k * (unsigned long)(1 + i % 5) + rnd(3));
        }
    for (int a = 0; a < NAP; a++)
        line("{\"type\":\"beacon\",\"ts\":%lld,\"ssid\":\"%s\",\"bssid\":\"%s\","
             "\"signal_dbm\":%d,\"channel\":%d,\"channel_source\":%d,\"enc\":\"%s\","
             "\"last_seen\":%lld,\"frame_count\":%lu,\"beacon_ms\":100,"
             "\"primary_channel\":%d,\"secondary_offset\":%d,\"operating_width\":%d,"
             "\"phy\":\"%s\",\"akm\":\"%s\",\"akm_bits\":%d,\"mfp\":%d,"
             "\"pairwise\":\"%s\",\"group\":\"%s\",\"has_wps\":%d,"
             "\"rssi_min_60s\":%d,\"rssi_max_60s\":%d,\"tbtt_jitter_us\":%d,"
             "\"tbtt_jitter_samples\":60,\"vendor_ies_hash\":%d,\"ie_order_hash\":%d,"
             "\"ie_order_count\":%d,\"est_dist_m\":%.1f,\"est_dist_band\":\"%s\","
             "\"est_dist_trend\":\"steady\",\"est_ptx_source\":\"default\"}", t,
             AP[a].stream_ssid ? AP[a].stream_ssid : AP[a].ssid, AP[a].bssid,
             AP[a].signal, AP[a].channel, AP[a].six ? 3 : 1, AP[a].enc, t,
             k * (unsigned long)(4 + 2 * a) + (k % 120 < 60 && a == 3 ? k : 0),
             AP[a].channel, AP[a].channel > 14 ? 1 : 0,
             AP[a].six ? 160 : AP[a].channel > 14 ? 80 : 20,
             AP[a].six ? "EHT" : AP[a].channel > 14 ? "VHT" : "HT", AP[a].akm,
             AP[a].akm_bits, AP[a].mfp, AP[a].enc[0] == 'O' ? "" : "CCMP",
             AP[a].enc[0] == 'O' ? "" : "CCMP", a == 2,
             AP[a].signal - 4, AP[a].signal + 3, a == 3 ? 900 : 40 + 10 * a,
             0x51a70000 + a, 0x0e0d0000 + a, 9 + a % 3,
             AP[a].signal > -50 ? 2.5 + 0.5 * a : 12.0 + 2.0 * a,
             AP[a].signal > -50 ? "near" : AP[a].signal > -75 ? "room" : "far");
    /* The records the FRRS record reads from the stream alone
     * (docs/web-frrs-spec.md §3.3): the regulatory envelope of three
     * APs (one with no Country element), one Multi-Link Device, a
     * client's association request and probe-list summary, a
     * sequence-counter trail between two randomised probers, and three
     * BLE advertisers. Fixed values, no rnd(). */
    line("{\"type\":\"wifi_regulatory\",\"ts\":%lld,\"bssid\":\"%s\","
         "\"country_present\":1,\"country\":\"US\",\"env\":\"any\",\"env_raw\":32,"
         "\"triplets_truncated\":0,\"triplets\":[{\"first_channel\":1,\"num_channels\":11,"
         "\"max_tx_power_dbm\":30}],\"power_constraint_present\":1,"
         "\"power_constraint_db\":3,\"tpc_present\":1,\"tpc_tx_power_dbm\":17,"
         "\"tpc_link_margin_db\":0,\"he6_present\":0,\"he6_reg_info\":0,"
         "\"he6_reg_info_name\":\"\",\"tpe_truncated\":0,\"tpe\":[],"
         "\"malformed_country\":0}", t, AP[0].bssid);
    line("{\"type\":\"wifi_regulatory\",\"ts\":%lld,\"bssid\":\"%s\","
         "\"country_present\":0,\"country\":\"\",\"env\":\"\",\"env_raw\":0,"
         "\"triplets_truncated\":0,\"triplets\":[],\"power_constraint_present\":0,"
         "\"power_constraint_db\":0,\"tpc_present\":0,\"tpc_tx_power_dbm\":0,"
         "\"tpc_link_margin_db\":0,\"he6_present\":0,\"he6_reg_info\":0,"
         "\"he6_reg_info_name\":\"\",\"tpe_truncated\":0,\"tpe\":[],"
         "\"malformed_country\":0}", t, AP[4].bssid);
    line("{\"type\":\"wifi_regulatory\",\"ts\":%lld,\"bssid\":\"%s\","
         "\"country_present\":1,\"country\":\"US\",\"env\":\"indoor\",\"env_raw\":73,"
         "\"triplets_truncated\":0,\"triplets\":[],\"power_constraint_present\":0,"
         "\"power_constraint_db\":0,\"tpc_present\":1,\"tpc_tx_power_dbm\":12,"
         "\"tpc_link_margin_db\":0,\"he6_present\":1,\"he6_reg_info\":0,"
         "\"he6_reg_info_name\":\"indoor_ap\",\"tpe_truncated\":0,\"tpe\":[],"
         "\"malformed_country\":0}", t, AP[7].bssid);
    line("{\"type\":\"wifi_mld\",\"ts\":%lld,\"mld_mac\":\"02:de:00:00:00:b0\","
         "\"link_count\":2,\"links_truncated\":0,\"link_0_mac\":\"%s\",\"link_0_id\":0,"
         "\"link_1_mac\":\"%s\",\"link_1_id\":1,\"first_seen\":%lld,\"last_seen\":%lld}",
         t, AP[0].bssid, AP[7].bssid, start, t);
    line("{\"type\":\"wifi_assoc_req\",\"ts\":%lld,\"bssid\":\"%s\",\"sta_mac\":\"%s\","
         "\"requested_ssid\":\"example-home\",\"is_reassoc\":0,\"listen_interval\":10,"
         "\"capability_info\":4369,\"akm_bits\":256,\"pairwise_bits\":16,"
         "\"requested_mfp\":1,\"supported_rates\":4095,\"phy\":\"HE\","
         "\"vendor_ie_hash\":1311768467294899695,\"downgrade_flags\":0,"
         "\"prev_akm_bits\":0,\"prev_mfp\":0,\"last_seen\":%lld}", t, AP[0].bssid,
         DEV[3].mac, t);
    line("{\"type\":\"pnl_client\",\"ts\":%lld,\"mac\":\"%s\",\"mac_random\":0,"
         "\"probe_count\":%lu,\"os_fp\":\"Apple\",\"phy\":\"HE\",\"phy_confirmed\":1,"
         "\"first_seen\":%lld,\"last_seen\":%lld,\"ssids\":[\"example-home\",\"demo-cafe\"]}",
         t, DEV[3].mac, 40 + k / 30, start, t);
    line("{\"type\":\"seqnum_correlation\",\"ts\":%lld,\"mac_a\":\"%s\",\"mac_b\":\"%s\","
         "\"mac_a_random\":1,\"mac_b_random\":1,\"gap\":3,\"dt_ms\":4200,\"a_count\":40,"
         "\"b_count\":38,\"fwd_gap\":3,\"confidence\":72,\"window_start\":%lld,"
         "\"window_end\":%lld,\"a_hist_n\":16,\"b_hist_n\":16,\"a_is_earlier\":1}",
         t, DEV[14].mac, DEV[15].mac, start, t);
    static const struct {
        const char *addr, *name, *watch, *pdu;
        int type, appearance, mfr, tx, rssi, adapter;
    } BLE[] = {
        { "c6:de:00:00:00:b1", "demo-watch", "smartwatch", "ADV_IND", 1, 0x00c2, 0x004c, 4, -61, 0 },
        { "d2:de:00:00:00:b2", "", "", "ADV_NONCONN_IND", 1, -1, 0x0006, -8, -77, 0 },
        { "02:de:00:00:00:b3", "demo-keyboard", "", "ADV_IND", 0, 0x03c1, 0x0059, 0, -55, 0 },
    };
    for (size_t b = 0; b < sizeof(BLE) / sizeof(BLE[0]); b++)
        line("{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"%s\",\"addr_type\":%d,"
             "\"sensor\":\"ble\",\"iface\":\"bluetooth-monitor\",\"adapter\":%d,\"sampled\":0,"
             "\"channel\":%d,\"last_pdu\":\"%s\",\"pdu_mask\":%d,\"name\":\"%s\","
             "\"name_complete\":%d,\"uuid16\":%d,\"mfr_id\":%d,\"mfr_subtype\":-1,"
             "\"svc_data_uuid16\":-1,\"appearance\":%d,\"hid\":%d,\"tx_power\":%d,"
             "\"flags\":6,\"has_rssi\":1,\"rssi\":%d,\"rssi_best\":%d,\"adv_count\":%lu,"
             "\"watch_category\":\"%s\",\"ext_adv\":%d,\"primary_phy\":1,"
             "\"secondary_phy\":%d,\"adv_sid\":%d,\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"est_dist_m\":%.1f,\"est_dist_band\":\"%s\",\"est_dist_trend\":\"steady\","
             "\"est_ptx_source\":\"%s\"}", t, BLE[b].addr, BLE[b].type, BLE[b].adapter,
             37 + (int)b, BLE[b].pdu, b == 1 ? 8 : 1, BLE[b].name, BLE[b].name[0] ? 1 : 0,
             b == 2 ? 0x1812 : -1, BLE[b].mfr, BLE[b].appearance, b == 2 ? 1 : 0, BLE[b].tx,
             BLE[b].rssi, BLE[b].rssi + 4, 10 * k + 3 * b, BLE[b].watch, b == 1,
             b == 1 ? 2 : 0, b == 1 ? 3 : -1, start, t,
             b == 1 ? 9.5 : 2.0 + (double)b, b == 1 ? "room" : "near",
             BLE[b].tx ? "ble_ad_tx_power" : "assumed");
    for (int p = 0; p < 6; p++)
        line("{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":\"0a:de:00:00:02:%02x\","
             "\"ssid\":\"\",\"signal_dbm\":-80,\"channel\":%d,\"first_seen\":%lld,"
             "\"last_seen\":%lld,\"frame_count\":%lu}", t, p, p % 3 == 0 ? 1 : p % 3 == 1 ? 36 : 149,
             start, t, k * (unsigned long)(1 + p));
    line("{\"type\":\"ssh_flow\",\"ts\":%lld,\"src_ip\":\"192.0.2.12\",\"dst_ip\":\"192.0.2.10\","
         "\"banner_count\":%lu,\"first_seen\":%lld,\"last_seen\":%lld}", t, 1 + k / 30, start, t);
    line("{\"type\":\"smb_session\",\"ts\":%lld,\"client_ip\":\"192.0.2.12\","
         "\"server_ip\":\"192.0.2.10\",\"server_port\":445,\"dialect\":\"SMB2\",\"count\":%lu,"
         "\"first_seen\":%lld,\"last_seen\":%lld}", t, 1 + k / 10, start, t);
    ble_pass(t, start, k);
    /* The Bluetooth block of sensor_health (src/jsonl.c, appended after
     * libs): a host source under --bt-monitor with a passive scan held,
     * the decode counters climbing with the advertisers below, no
     * Ubertooth, no rotation hints (the flag is off by default). */
    line("{\"type\":\"sensor_health\",\"ts\":%lld,\"capture_iface\":\"eth0\","
         "\"capture_linktype\":1,\"monitor_only\":0,\"monitor_iface\":\"wlan0mon\","
         "\"capture_open\":1,\"capture_running\":1,"
         "\"monitor_open\":1,\"monitor_running\":1,\"scope\":\"demo\","
         "\"scope_not_enforced\":0,"
         "\"btmon_iface\":\"bluetooth-monitor\",\"btmon_err\":\"\",\"btmon_open\":1,"
         "\"btmon_running\":1,\"btmon_exit\":\"none\",\"btmon_exit_detail\":\"\","
         "\"btmon_stats_valid\":0,\"btmon_recv\":0,\"btmon_drop\":0,\"btmon_ifdrop\":0,"
         "\"btmon_last_frame_ts\":%lld,\"btmon_stale_secs\":0,"
         "\"ble_controllers\":1,\"ble_devices\":%d,\"ble_records\":%lu,"
         "\"ble_adv_reports\":%lu,\"ble_multi_report_rejected\":0,"
         "\"ble_ext_adv_undecoded\":0,\"ble_ext_adv_reports\":%lu,"
         "\"ble_ext_adv_fragments\":0,\"ble_ext_adv_partial\":0,\"ble_ext_trains_evicted\":0,"
         "\"ble_records_ignored\":%lu,\"ble_records_malformed\":0,\"ble_host_commands\":3,"
         "\"ble_scan_mode\":\"passive\",\"ble_scan_filter\":\"basic\","
         "\"ble_scan_accept_list\":0,\"ble_scan_enabled\":1,\"ble_own_tx\":\"never\","
         "\"ble_own_tx_kind\":\"none\",\"ble_own_tx_count\":0,\"ble_own_tx_secs\":-1,"
         "\"ble_own_tx_on\":\"\",\"ble_own_tx_asserted\":\"\",\"ble_own_tx_baseline\":1,"
         "\"ble_index_records\":2,\"btcap_iface\":\"\",\"btcap_state\":\"off\","
         "\"evict_ble_device\":0,\"evict_bredr_lap\":0,\"evict_ble_flood\":0}",
         t, t, NBLE, k * 47 + 5, k * 44, k / 3, k);
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
    long long start = now_s(), next = start;
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

/* ── pcaps DIR: the sensor's --pcap-dir, made up ───────────────────
 * The files sloth's alert pcap sinks would write for the demo's own
 * incidents, with the manifest beside them (src/evidence_manifest.c's
 * line, its SHA-256 over each file), so the alert page's capture has
 * something to decode, check and download: SMB1_USE's CRIT escalation
 * (the --pcap-dir sink: Ethernet, snaplen 64, the packets to or from
 * match_ip 192.0.2.18), and the first DEAUTH_FLOOD's 802.11 evidence
 * (the --eapol-dir sink's shape: radiotap, whole frames). Every frame
 * is built here from its clause; documentation addresses and locally
 * administered MACs only. */
typedef struct {
    unsigned char b[16384];
    size_t        n;
} pbuf_t;

static void p32(pbuf_t *f, unsigned long v) {
    for (int i = 0; i < 4; i++) f->b[f->n++] = (unsigned char)(v >> (8 * i));
}

static void p_hdr(pbuf_t *f, unsigned long snaplen, unsigned long dlt) {
    f->n = 0;
    p32(f, 0xa1b2c3d4ul);
    f->b[f->n++] = 2; f->b[f->n++] = 0; f->b[f->n++] = 4; f->b[f->n++] = 0;
    p32(f, 0); p32(f, 0); p32(f, snaplen); p32(f, dlt);
}

static void p_rec(pbuf_t *f, long long t, unsigned long us, const unsigned char *d,
                  size_t caplen, size_t len) {
    p32(f, (unsigned long)t); p32(f, us); p32(f, caplen); p32(f, len);
    memcpy(f->b + f->n, d, caplen);
    f->n += caplen;
}

/* Ethernet II, IPv4 (IHL 5, total tot), TCP (doff 5): the 54 header
 * bytes of one packet between 192.0.2.20 and 192.0.2.18:445. */
static size_t smb_frame(unsigned char *o, int to_srv, unsigned flags, unsigned long seq,
                        unsigned tot) {
    static const unsigned char cli[6] = { 0x02, 0xde, 0, 0, 0, 0x14 }, srv[6] = { 0x02, 0xde, 0, 0, 0, 0x12 };
    size_t n = 0;
    memcpy(o + n, to_srv ? srv : cli, 6); n += 6;
    memcpy(o + n, to_srv ? cli : srv, 6); n += 6;
    o[n++] = 0x08; o[n++] = 0x00;
    unsigned char ip[20] = { 0x45, 0, (unsigned char)(tot >> 8), (unsigned char)tot, 0, 0, 0x40, 0,
                             64, 6, 0, 0, 192, 0, 2, 20, 192, 0, 2, 18 };
    if (!to_srv) { ip[15] = 18; ip[19] = 20; }
    memcpy(o + n, ip, 20); n += 20;
    unsigned sp = to_srv ? 49200 : 445, dp = to_srv ? 445 : 49200;
    unsigned char tcp[20] = { (unsigned char)(sp >> 8), (unsigned char)sp, (unsigned char)(dp >> 8),
                              (unsigned char)dp, (unsigned char)(seq >> 24), (unsigned char)(seq >> 16),
                              (unsigned char)(seq >> 8), (unsigned char)seq, 0, 0, 0, 1, 0x50,
                              (unsigned char)flags, 0xfa, 0xf0, 0, 0, 0, 0 };
    memcpy(o + n, tcp, 20); n += 20;
    return n;
}

static int write_bytes(const char *dir, const char *name, const unsigned char *b, size_t n) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "slothweb-demo: %s: %s\n", path, strerror(errno)); return -1; }
    size_t w = fwrite(b, 1, n, f);
    if (fclose(f) != 0 || w != n) { fprintf(stderr, "slothweb-demo: %s: write failed\n", path); return -1; }
    chmod(path, 0600);
    return 0;
}

/* The sloth run the manifest is of: one session for every line. */
static long long g_session;

static void manifest_add(FILE *m, int seq, const char *file, const pbuf_t *f, const char *sink,
                         const char *inc, const char *rule, long long t) {
    unsigned char d[32];
    char hex[65];
    web_sha256(f->b, f->n, d);
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", d[i]);
    struct tm tmv, s0;
    time_t tt = (time_t)t, ts0 = (time_t)g_session;
    gmtime_r(&tt, &tmv);
    gmtime_r(&ts0, &s0);
    fprintf(m, "{\"v\":1,\"session\":\"%04d%02d%02dT%02d%02d%02dZ-00000000000000de\",\"seq\":%d,"
               "\"file\":\"%s\",\"size\":%zu,\"sha256\":\"%s\",\"sink\":\"%s\","
               "\"incident_id\":\"%s\",\"rule\":\"%s\",\"reconstructed\":false,"
               "\"written_at\":\"%04d-%02d-%02dT%02d:%02d:%02dZ\",\"written_at_epoch\":%lld}\n",
            s0.tm_year + 1900, s0.tm_mon + 1, s0.tm_mday, s0.tm_hour, s0.tm_min, s0.tm_sec,
            seq, file, f->n, hex, sink, inc, rule, tmv.tm_year + 1900, tmv.tm_mon + 1,
            tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec, t);
}

static int make_pcaps(const char *dir) {
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "slothweb-demo: %s: %s\n", dir, strerror(errno));
        return 1;
    }
    long long t0 = now_s() - 600;
    g_session = t0 - 3600;
    static pbuf_t f;
    unsigned char fr[320];
    char mpath[4096];
    snprintf(mpath, sizeof(mpath), "%s/sloth-manifest-20261027T120000Z-00000000000000de.jsonl", dir);
    FILE *m = fopen(mpath, "w");
    if (!m) { fprintf(stderr, "slothweb-demo: %s: %s\n", mpath, strerror(errno)); return 1; }
    chmod(mpath, 0600);

    /* SMB1_USE: a handshake, then NetBIOS session service (RFC 1002
     * §4.3.1) carrying an SMB1 NEGOTIATE ("\xffSMB", command 0x72,
     * [MS-CIFS] §2.2.4.52), and its answer; 64 bytes of each kept. */
    p_hdr(&f, 64, 1);
    size_t n = smb_frame(fr, 1, 0x02, 1000, 40);
    p_rec(&f, t0, 1000, fr, n, 54);
    n = smb_frame(fr, 0, 0x12, 5000, 40);
    p_rec(&f, t0, 1400, fr, n, 54);
    n = smb_frame(fr, 1, 0x10, 1001, 40);
    p_rec(&f, t0, 1600, fr, n, 54);
    for (int i = 0; i < 4; i++) {
        n = smb_frame(fr, i % 2 == 0, 0x18, 1001 + (unsigned long)i * 137, 177);
        static const unsigned char neg[10] = { 0x00, 0x00, 0x00, 0x89, 0xff, 'S', 'M', 'B', 0x72, 0x00 };
        memcpy(fr + n, neg, sizeof(neg));
        if (i % 2) fr[n + 9] = 0x00;
        p_rec(&f, t0 + 1 + i, 2000 + (unsigned long)i * 50, fr, 64, 191);
    }
    const char *smb = "alert_20261027_120000_SMB1_USE.pcap";
    if (write_bytes(dir, smb, f.b, f.n) != 0) { fclose(m); return 1; }
    manifest_add(m, 1, smb, &f, "alert_pcap", "d0000000000b0000", "SMB1_USE", t0 + 6);

    /* DEAUTH_FLOOD's evidence: radiotap (version 0, Channel 2437 MHz,
     * dBm signal) + Deauthentication frames (IEEE Std 802.11-2020
     * §9.3.3.12), reason 7, from the BSSID to the victim, sequence
     * numbers stepping, whole frames. */
    p_hdr(&f, 262144, 127);
    for (int i = 0; i < 12; i++) {
        static const unsigned char rt[13] = { 0, 0, 13, 0, 0x28, 0, 0, 0, 0x85, 0x09, 0xa0, 0x00, 0xc4 };
        unsigned char *o = fr;
        memcpy(o, rt, 13);
        o[12] = (unsigned char)(0xc4 - (i % 3));
        static const unsigned char hdr[22] = { 0xc0, 0x00, 0x3a, 0x01,
            0x02, 0xde, 0, 0, 0, 0x12, 0x02, 0xde, 0, 0, 0, 0xa1, 0x02, 0xde, 0, 0, 0, 0xa1 };
        memcpy(o + 13, hdr, 22);
        unsigned sc = (unsigned)(100 + i) << 4;
        o[35] = (unsigned char)sc; o[36] = (unsigned char)(sc >> 8);
        o[37] = 0x07; o[38] = 0x00;
        p_rec(&f, t0 + 300, (unsigned long)i * 400000ul, fr, 39, 39);
    }
    const char *dea = "d0000000000c0000-1-DEAUTH_FLOOD.pcap";
    if (write_bytes(dir, dea, f.b, f.n) != 0) { fclose(m); return 1; }
    manifest_add(m, 2, dea, &f, "evidence_pcap", "d0000000000c0000", "DEAUTH_FLOOD", t0 + 305);
    if (fclose(m) != 0) return 1;
    return 0;
}

static void usage(FILE *o) {
    fprintf(o, "usage: slothweb-demo db PATH\n"
               "       slothweb-demo feed unix:PATH [--seconds N]\n"
               "       slothweb-demo pcaps DIR\n"
               "Synthetic data only: documentation addresses, locally administered\n"
               "MACs, example names. See web/README.md.\n");
}

#ifdef SLOTHWEB_DEMO_LIB
/* The test suite's door (web/tests/test_alerts.c): the same database
 * and the same passes, on a clock it sets, into a buffer it reads. */
int demo_make_db(const char *path, long long now) {
    g_now_fixed = now;
    g_rng = 20261023u;
    int rc = make_db(path);
    g_now_fixed = 0;
    return rc;
}

size_t demo_pass(long long t, long long start, unsigned long k, char *out, size_t cap) {
    g_len = 0;
    pass(t, start, k);
    /* The stream's server half is the binary's, not the test's. */
    (void)feed;
    (void)usage;
    (void)make_pcaps;
    size_t n = g_len < cap ? g_len : cap;
    memcpy(out, g_buf, n);
    g_len = 0;
    return n;
}
#else
int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "db")) return make_db(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "pcaps")) return make_pcaps(argv[2]);
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
#endif
