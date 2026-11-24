#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "runner.h"
#include "tmp_dir.h"
#include "fake_platform.h"
#include "sloth.h"
#include "db.h"
#include "handoff.h"
#include "interference.h"
#include "ownership.h"
#include "site_db.h"
#include "wifi_snapshot.h"
#include <sqlite3.h>

/* ── sloth --handoff and --interference-report (#250) ──────────────
 *
 * The database is a real sloth.db (db_open() creates it at this
 * build's schema) with rows written into it by hand, so the readers are
 * held to the schema the daemon writes and not to a copy of it. */

/* A wall second inside 2026, and the episodes around it. */
#define T0  1795000000LL
#define NOW (T0 + 3000)

/* What the withheld columns hold here. Each is a word that appears
 * nowhere else, so finding it in a packet file can only mean the
 * column was written. */
static const char *const SECRETS[] = {
    "SECRETUSERKEY", "SECRETUSERDETAIL", "SECRETUSERCRED", "SECRETUSERMQTT",
    "SECRETUSERRADIUS", "SECRETCOOKIERDP", "SECRETTITLE",
};
#define NSECRETS ((int)(sizeof(SECRETS) / sizeof(SECRETS[0])))

static int exec_sql(sqlite3 *h, const char *sql) {
    char *e = NULL;
    int rc = sqlite3_exec(h, sql, NULL, NULL, &e);
    if (rc != SQLITE_OK) fprintf(stderr, "    sql: %s\n", e ? e : "?");
    sqlite3_free(e);
    return rc;
}

static char g_sql[8192];

/* Fill a sloth.db at `path` with the episodes the tests read. */
static int seed_db(const char *path) {
    if (db_open(path) != 1) return -1;
    db_close();
    sqlite3 *h = NULL;
    if (sqlite3_open(path, &h) != SQLITE_OK) { sqlite3_close(h); return -1; }
    snprintf(g_sql, sizeof(g_sql),
        /* RF_DEGRADED on channel 6: an earlier episode, then the latest,
         * whose figures the alerts row holds. */
        "INSERT INTO alert_incidents (key,incident_id,type,first_seen,last_seen,"
        " sev,peak_sev,count,observations,closed_at,reason) VALUES"
        " ('rfdegraded:6','rf1',%d,%lld,%lld,1,1,3,1,%lld,'quiet'),"
        " ('rfdegraded:6','rf2',%d,%lld,%lld,1,1,30,4,%lld,'quiet'),"
        " ('rtsflood:02:00:00:00:00:99','rts1',%d,%lld,%lld,2,2,5,2,%lld,'quiet'),"
        " ('gnssjam','gj1',%d,%lld,%lld,1,2,9,3,NULL,NULL),"
        " ('cred:192.0.2.10:198.51.100.80:80:HTTP-Basic:SECRETUSERKEY','cc1',%d,"
        "  %lld,%lld,1,1,1,1,NULL,NULL),"
        " ('deauth:old','da1',%d,%lld,%lld,1,1,1,1,NULL,NULL);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,"
        " count,incident_id) VALUES"
        " ('rfdegraded:6',%lld,%lld,%d,1,'RF_DEGRADED',"
        "  'ch 6: 42%% retries, 3%% bad-FCS over 1200 frames - interference,"
        " hidden node or jamming SENTINELDETAIL',33,'rf2'),"
        " ('rtsflood:02:00:00:00:00:99',%lld,%lld,%d,2,'RTS_FLOOD',"
        "  '02:00:00:00:00:99 sent 600 RTS over 60s (~10/s), max NAV 32767us"
        " - above the legal maximum SENTINELDETAIL',5,'rts1'),"
        " ('gnssjam',%lld,%lld,%d,1,'GNSS_JAMMING','u-blox jamInd >= 200 for"
        " 30 s - interference or jamming SENTINELDETAIL',9,'gj1'),"
        " ('cred:192.0.2.10:198.51.100.80:80:HTTP-Basic:SECRETUSERKEY',%lld,%lld,"
        "  %d,1,'SECRETTITLE','HTTP-Basic user SECRETUSERDETAIL in the clear',1,'cc1');"
        "INSERT INTO cleartext_creds (ts,src,dst,dst_port,protocol,username,"
        " first_seen,last_seen) VALUES (%lld,'192.0.2.10','198.51.100.80',80,"
        " 'HTTP-Basic','SECRETUSERCRED',%lld,%lld);"
        "INSERT INTO mqtt_flows (src_ip,dst_ip,last_username,first_seen,last_seen)"
        " VALUES ('192.0.2.10','198.51.100.81','SECRETUSERMQTT',%lld,%lld);"
        "INSERT INTO rogue_radius (bssid,last_identity,first_seen,last_seen)"
        " VALUES ('02:00:00:00:00:77','SECRETUSERRADIUS',%lld,%lld);"
        "INSERT INTO rdp_flows (src_ip,dst_ip,last_cookie,first_seen,last_seen)"
        " VALUES ('192.0.2.10','198.51.100.82','SECRETCOOKIERDP',%lld,%lld);",
        ALERT_TYPE_RF_DEGRADED, T0 - 7200, T0 - 7000, T0 - 6700,
        ALERT_TYPE_RF_DEGRADED, T0, T0 + 299, T0 + 600,
        ALERT_TYPE_RTS_FLOOD, T0 + 1000, T0 + 1100, T0 + 1400,
        ALERT_TYPE_GNSS_JAMMING, T0 + 2000, T0 + 2100,
        ALERT_TYPE_CLEARTEXT_CRED, T0 + 2000, T0 + 2100,
        ALERT_TYPE_DEAUTH_FLOOD, T0 - 5000, T0 - 5000,
        T0 - 7200, T0 + 299, ALERT_TYPE_RF_DEGRADED,
        T0 + 1000, T0 + 1100, ALERT_TYPE_RTS_FLOOD,
        T0 + 2000, T0 + 2100, ALERT_TYPE_GNSS_JAMMING,
        T0 + 2000, T0 + 2100, ALERT_TYPE_CLEARTEXT_CRED,
        T0, T0, T0, T0, T0, T0, T0, T0, T0);
    int rc = exec_sql(h, g_sql);
    snprintf(g_sql, sizeof(g_sql),
        /* Coverage: one minute before the episode, two in it. Radio 0
         * splits each minute between channels 6 and 1. */
        "INSERT INTO coverage_intervals (start,last_seen,dur_ms,f_ctrl,f_data,chans)"
        " VALUES"
        " (%lld,%lld,60000,30,100,'[{\"radio\":0,\"ch\":6,\"freq_mhz\":2437,"
        "\"band\":\"2g4\",\"ms\":30000,\"frames\":60},{\"radio\":0,\"ch\":1,"
        "\"freq_mhz\":2412,\"band\":\"2g4\",\"ms\":30000,\"frames\":40}]'),"
        " (%lld,%lld,60000,120,600,'[{\"radio\":0,\"ch\":6,\"freq_mhz\":2437,"
        "\"band\":\"2g4\",\"ms\":30000,\"frames\":600},{\"radio\":0,\"ch\":1,"
        "\"freq_mhz\":2412,\"band\":\"2g4\",\"ms\":30000,\"frames\":100}]'),"
        " (%lld,%lld,60000,120,600,'[{\"radio\":0,\"ch\":6,\"freq_mhz\":2437,"
        "\"band\":\"2g4\",\"ms\":30000,\"frames\":600},{\"radio\":0,\"ch\":1,"
        "\"freq_mhz\":2412,\"band\":\"2g4\",\"ms\":30000,\"frames\":100}]'),"
        /* One minute in the RTS episode, all of it on channel 11. */
        " (%lld,%lld,60000,900,10,'[{\"radio\":0,\"ch\":11,\"freq_mhz\":2462,"
        "\"band\":\"2g4\",\"ms\":60000,\"frames\":910}]');"
        /* An AP on channel 6 across the episode, whose SSID carries
         * Markdown, one client in the episode and one long after. */
        "INSERT INTO beacon_aps (bssid,ssid,channel,enc,akm,mfp,has_qbss,"
        " qbss_chan_util,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:06','Cafe|Net*',6,'WPA2','PSK',1,1,200,%lld,%lld),"
        " ('02:00:00:00:00:24','Far',36,'WPA3','SAE',2,0,NULL,%lld,%lld),"
        " ('02:00:00:00:00:01','Stale',1,'OPEN',NULL,0,0,NULL,%lld,%lld);"
        "INSERT INTO assocs (bssid,sta_mac,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:06','0a:00:00:00:00:01',%lld,%lld),"
        " ('02:00:00:00:00:06','0a:00:00:00:00:02',%lld,%lld);",
        T0 - 60, T0 - 1, T0, T0 + 59, T0 + 60, T0 + 119, T0 + 1020, T0 + 1079,
        T0 - 1000, T0 + 1000, T0 - 500, T0 + 2000,
        T0 - 200000, T0 - 199000,
        T0, T0 + 10, T0 + 5000, T0 + 5001);
    if (rc == SQLITE_OK) rc = exec_sql(h, g_sql);
    sqlite3_close(h);
    return rc == SQLITE_OK ? 0 : -1;
}

/* A file's whole text, NUL-ended; NULL when it cannot be read. */
static char *slurp(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char *buf = NULL;
    size_t cap = 0, n = 0, k;
    char tmp[4096];
    while ((k = fread(tmp, 1, sizeof(tmp), f)) > 0) {
        if (n + k + 1 > cap) {
            cap = (n + k + 1) * 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); fclose(f); return NULL; }
            buf = nb;
        }
        memcpy(buf + n, tmp, k);
        n += k;
    }
    fclose(f);
    if (!buf) buf = calloc(1, 1);
    else buf[n] = '\0';
    return buf;
}

static char *report(const char *db, time_t from, time_t to) {
    site_db_t d;
    char err[256];
    if (site_db_open(&d, db, err, sizeof(err)) != 0) {
        fprintf(stderr, "    open: %s\n", err);
        return NULL;
    }
    char *buf = NULL;
    size_t len = 0;
    FILE *m = open_memstream(&buf, &len);
    if (!m) { site_db_close(&d); return NULL; }
    int n = interference_report(&d, db, from, to, (time_t)NOW, m, err, sizeof(err));
    fclose(m);
    site_db_close(&d);
    if (n < 0) { free(buf); return NULL; }
    return buf;
}

static void test_parse_time(void) {
    time_t t;
    ASSERT_EQ(site_db_parse_time("1795000000", &t), 0);
    ASSERT_EQ((long long)t, 1795000000LL);
    ASSERT_EQ(site_db_parse_time("2026-11-24", &t), 0);
    ASSERT_EQ((long long)t, 1795478400LL);
    ASSERT_EQ(site_db_parse_time("2026-11-24T01:02", &t), 0);
    ASSERT_EQ((long long)t, 1795478400LL + 3720);
    ASSERT_EQ(site_db_parse_time("2026-11-24T01:02:03Z", &t), 0);
    ASSERT_EQ((long long)t, 1795478400LL + 3723);
    ASSERT_EQ(site_db_parse_time("2026-11-24Z", &t), 0);
    ASSERT_EQ(site_db_parse_time("2026-11-24T25:00", &t), -1);
    ASSERT_EQ(site_db_parse_time("2026-13-01", &t), -1);
    ASSERT_EQ(site_db_parse_time("2026-11-24 01:02", &t), -1);
    ASSERT_EQ(site_db_parse_time("yesterday", &t), -1);
    ASSERT_EQ(site_db_parse_time("", &t), -1);
    ASSERT_EQ(site_db_parse_time("17950000001234", &t), -1);

    /* As an end bound the form's whole extent is included, so
     * --from D --to D is the day D and not its first second. */
    ASSERT_EQ(site_db_parse_time_end("2026-11-24", &t), 0);
    ASSERT_EQ((long long)t, 1795478400LL + 86399);
    ASSERT_EQ(site_db_parse_time_end("2026-11-24Z", &t), 0);
    ASSERT_EQ((long long)t, 1795478400LL + 86399);
    ASSERT_EQ(site_db_parse_time_end("2026-11-24T01:02", &t), 0);
    ASSERT_EQ((long long)t, 1795478400LL + 3720 + 59);
    ASSERT_EQ(site_db_parse_time_end("2026-11-24T01:02:03Z", &t), 0);
    ASSERT_EQ((long long)t, 1795478400LL + 3723);
    ASSERT_EQ(site_db_parse_time_end("1795000000", &t), 0);
    ASSERT_EQ((long long)t, 1795000000LL);
    ASSERT_EQ(site_db_parse_time_end("2026-11-24T25:00", &t), -1);
}

static void test_interference_report(void) {
    char dir[TEST_TMP_MAX] = "", db[TEST_TMP_MAX + 16];
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_ifr_XXXXXX")) != NULL);
    if (!dir[0]) return;
    snprintf(db, sizeof(db), "%s/s.db", dir);
    ASSERT_EQ(seed_db(db), 0);

    char *r = report(db, 0, 0);
    ASSERT(r != NULL);
    if (r) {
        ASSERT(strstr(r, "Episodes: RF_DEGRADED 2, RTS_FLOOD 1, GNSS_JAMMING 1.") != NULL);
        /* In time order: the earlier RF_DEGRADED, the later, RTS, GNSS. */
        const char *e1 = strstr(r, "## 1. RF_DEGRADED on channel 6");
        const char *e2 = strstr(r, "## 2. RF_DEGRADED on channel 6");
        const char *e3 = strstr(r, "## 3. RTS_FLOOD from 02:00:00:00:00:99");
        const char *e4 = strstr(r, "## 4. GNSS_JAMMING");
        ASSERT(e1 && e2 && e3 && e4 && e1 < e2 && e2 < e3 && e3 < e4);
        /* The earlier episode's figures were overwritten by the later's. */
        const char *nf = strstr(r, "not stored for this episode");
        ASSERT(nf && e1 && e2 && nf > e1 && nf < e2);
        /* rf_quality_observe() counts every frame type: never "data". */
        ASSERT(strstr(r, "- Retry ratio 42% and bad-FCS share 3% over 1200"
                         " frames of every type heard on the channel") != NULL);
        ASSERT(strstr(r, "data frames") == NULL);
        ASSERT(strstr(r, "- Closed 2026-") != NULL);
        /* Coverage of the later episode: two minutes, half on ch 6. */
        ASSERT(strstr(r, "- Coverage: 2 one-minute coverage intervals overlap"
                         " the episode (120 s") != NULL);
        ASSERT(strstr(r, "- Radio 0 spent 50% of that time on channel 6.") != NULL);
        ASSERT(strstr(r, "- Frames heard on channel 6 per minute of radio time:"
                         " 600 during, 60 before (the 1 interval that closed in"
                         " the 300 s before it opened).") != NULL);
        ASSERT(strstr(r, "- Control frames per minute, every channel heard:"
                         " 120 during, 30 before.") != NULL);
        /* The earlier episode had no coverage rows: said, not zeroed. */
        ASSERT(strstr(r, "no coverage interval overlaps the episode") != NULL);
        /* APs on the channel, the SSID inert, one client in the window. */
        ASSERT(strstr(r, "02:00:00:00:00:06 \"Cafe\\x7cNet\\x2a\", 1 client,"
                         " QBSS load 200") != NULL);
        ASSERT(strstr(r, "Far") == NULL);
        ASSERT(strstr(r, "0a:00:00:00:00:01") == NULL);   /* no client address */
        /* RTS: the volume, and what is not stored. */
        ASSERT(strstr(r, "- Control-frame volume: 600 RTS frames over 60 s"
                         " from one transmitter, longest NAV 32767 us, at the rule's"
                         " last evaluation.") != NULL);
        ASSERT(strstr(r, "- The radios' time in the episode, by channel: channel"
                         " 11 100%. The alert does not record the channel.") != NULL);
        ASSERT(strstr(r, "- Control frames per minute, every channel heard:"
                         " 900 during; before not covered.") != NULL);
        /* GNSS: open, its figures, the other daemon named. */
        ASSERT(strstr(r, "No close recorded in this file") != NULL);
        ASSERT(strstr(r, "- The receiver's own jamming indicator (u-blox jamInd)"
                         " stayed at or above 200 for 30 s.") != NULL);
        ASSERT(strstr(r, "In this file: Wi-Fi rows yes; GNSS fixes none.") != NULL);
        ASSERT(strstr(r, "/var/lib/sloth-rf/sloth-rf.db") != NULL);
        ASSERT(strstr(r, "the same path") == NULL);
        /* The detail's text is parsed, never copied: a word that is in
         * each of the three details and is no figure is not written.
         * Seen red with the verbatim "Figures the rule recorded" line
         * restored. */
        ASSERT(strstr(r, "SENTINELDETAIL") == NULL);
        ASSERT(strstr(r, "hidden node or jamming") == NULL);
        /* Every episode: not located. Never a word about intent. */
        int nl = 0;
        for (const char *p = r; (p = strstr(p, "- Location: not located.")); p++) nl++;
        ASSERT_EQ(nl, 4);
        ASSERT(strstr(r, "attack") == NULL);
        ASSERT(strstr(r, "attacker") == NULL);
        /* The other kinds are not read. */
        ASSERT(strstr(r, "CLEARTEXT") == NULL);
        ASSERT(strstr(r, "SECRET") == NULL);
        free(r);
    }

    /* --from after the RF episodes: RTS and GNSS only. */
    r = report(db, (time_t)(T0 + 900), 0);
    ASSERT(r != NULL);
    if (r) {
        ASSERT(strstr(r, "Episodes: RF_DEGRADED 0, RTS_FLOOD 1, GNSS_JAMMING 1.") != NULL);
        ASSERT(strstr(r, "## 1. RTS_FLOOD") != NULL);
        free(r);
    }
    /* A window holding nothing says so. */
    r = report(db, (time_t)(T0 + 100000), (time_t)(T0 + 200000));
    ASSERT(r != NULL);
    if (r) {
        ASSERT(strstr(r, "No episode of the three kinds overlaps the window.") != NULL);
        free(r);
    }
    test_rm_tree(dir);
}

/* The command: a missing database and a newer one are refused with 2,
 * and the output file is not created; "-" is stdout. */
static void test_interference_main_refusals(void) {
    char dir[TEST_TMP_MAX] = "", db[TEST_TMP_MAX + 16], out[TEST_TMP_MAX + 16];
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_ifm_XXXXXX")) != NULL);
    if (!dir[0]) return;
    snprintf(db, sizeof(db), "%s/s.db", dir);
    snprintf(out, sizeof(out), "%s/r.md", dir);
    FILE *null = fopen("/dev/null", "w");
    ASSERT_EQ(interference_main(db, out, 0, 0, null), 2);
    ASSERT(access(out, F_OK) != 0);

    ASSERT_EQ(seed_db(db), 0);
    sqlite3 *h = NULL;
    ASSERT_EQ(sqlite3_open(db, &h), SQLITE_OK);
    char sql[128];
    snprintf(sql, sizeof(sql), "UPDATE meta SET value='%d' WHERE key='schema_version'",
             DB_SCHEMA_VERSION + 1);
    ASSERT_EQ(exec_sql(h, sql), SQLITE_OK);
    sqlite3_close(h);
    ASSERT_EQ(interference_main(db, out, 0, 0, null), 2);
    ASSERT(access(out, F_OK) != 0);

    snprintf(sql, sizeof(sql), "UPDATE meta SET value='%d' WHERE key='schema_version'",
             DB_SCHEMA_VERSION);
    ASSERT_EQ(sqlite3_open(db, &h), SQLITE_OK);
    ASSERT_EQ(exec_sql(h, sql), SQLITE_OK);
    sqlite3_close(h);
    ASSERT_EQ(interference_main(db, out, 0, 0, null), 0);
    struct stat sb;
    ASSERT_EQ(stat(out, &sb), 0);
    ASSERT_EQ((int)(sb.st_mode & 0777), 0600);

    /* FILE naming the database, or its -wal while a writer holds it
     * open, is refused before anything is truncated: both keep their
     * size. Seen red with names_the_db() returning 0. */
    struct stat b0, b1;
    ASSERT_EQ(stat(db, &b0), 0);
    ASSERT_EQ(interference_main(db, db, 0, 0, null), 2);
    ASSERT_EQ(stat(db, &b1), 0);
    ASSERT_EQ((long long)b1.st_size, (long long)b0.st_size);
    ASSERT(b0.st_size > 0);
    char viadot[TEST_TMP_MAX + 32];
    snprintf(viadot, sizeof(viadot), "%s/./s.db", dir);
    ASSERT_EQ(interference_main(db, viadot, 0, 0, null), 2);
    ASSERT_EQ(stat(db, &b1), 0);
    ASSERT_EQ((long long)b1.st_size, (long long)b0.st_size);

    sqlite3 *w = NULL;
    ASSERT_EQ(sqlite3_open(db, &w), SQLITE_OK);
    ASSERT_EQ(exec_sql(w, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"
                          " INSERT INTO meta (key,value) VALUES ('t','1');"),
              SQLITE_OK);
    char walp[TEST_TMP_MAX + 32];
    snprintf(walp, sizeof(walp), "%s-wal", db);
    ASSERT_EQ(stat(walp, &b0), 0);
    ASSERT(b0.st_size > 0);
    ASSERT_EQ(interference_main(db, walp, 0, 0, null), 2);
    ASSERT_EQ(stat(walp, &b1), 0);
    ASSERT_EQ((long long)b1.st_size, (long long)b0.st_size);
    sqlite3_close(w);
    fclose(null);
    test_rm_tree(dir);
}

/* What the seeded fixture does not reach. An episode shorter than the
 * interval it falls in: that interval is "during" only, so "before"
 * is not the same row read twice (seen red with the before window
 * matching by overlap: it printed the during rate again). A channel
 * number heard on two bands is said to be (the key has no band). GNSS
 * rows in a sloth.db are counted with their newest time and no owner
 * is claimed (a pre-cutover file keeps sloth-wifi's own). More
 * episodes than IFR_MAX_EPISODES: the latest are written and the rest
 * counted (seen red with the LIMIT removed). */
static void test_interference_edges(void) {
    char dir[TEST_TMP_MAX] = "", db[TEST_TMP_MAX + 16];
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_ife_XXXXXX")) != NULL);
    if (!dir[0]) return;
    snprintf(db, sizeof(db), "%s/s.db", dir);
    ASSERT_EQ(db_open(db), 1);
    db_close();
    sqlite3 *h = NULL;
    ASSERT_EQ(sqlite3_open(db, &h), SQLITE_OK);
    snprintf(g_sql, sizeof(g_sql),
        "INSERT INTO alert_incidents (key,incident_id,type,first_seen,last_seen,"
        " sev,peak_sev,count,observations,closed_at,reason) VALUES"
        " ('rfdegraded:3','m1',%d,%lld,%lld,1,1,3,1,%lld,'quiet'),"
        " ('rfdegraded:1','b1',%d,%lld,%lld,1,1,3,1,%lld,'quiet');"
        "INSERT INTO coverage_intervals (start,last_seen,dur_ms,f_ctrl,f_data,chans)"
        " VALUES"
        " (%lld,%lld,60000,10,500,'[{\"radio\":0,\"ch\":3,\"freq_mhz\":2422,"
        "\"band\":\"2g4\",\"ms\":60000,\"frames\":510}]'),"
        " (%lld,%lld,60000,10,500,'[{\"radio\":0,\"ch\":1,\"freq_mhz\":2412,"
        "\"band\":\"2g4\",\"ms\":30000,\"frames\":300},{\"radio\":0,\"ch\":1,"
        "\"freq_mhz\":5955,\"band\":\"6g\",\"ms\":30000,\"frames\":210}]');"
        "INSERT INTO gnss_fixes (last_seen,src,mode) VALUES (%lld,'gpsd',3);"
        "WITH RECURSIVE i(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM i"
        " WHERE n < %d)"
        " INSERT INTO alert_incidents (key,incident_id,type,first_seen,last_seen,"
        " sev,peak_sev,count,observations) SELECT"
        " printf('rtsflood:02:00:00:00:%%02x:%%02x', n / 256, n %% 256),"
        " 'r' || n, %d, %lld + n * 100, %lld + n * 100 + 10, 1, 1, 1, 1 FROM i;",
        ALERT_TYPE_RF_DEGRADED, T0 + 30, T0 + 50, T0 + 60,
        ALERT_TYPE_RF_DEGRADED, T0 + 10010, T0 + 10030, T0 + 10100,
        T0, T0 + 59, T0 + 10000, T0 + 10059,
        T0 - 86400,
        IFR_MAX_EPISODES + 4,
        ALERT_TYPE_RTS_FLOOD, T0 + 20000, T0 + 20000);
    ASSERT_EQ(exec_sql(h, g_sql), SQLITE_OK);
    sqlite3_close(h);

    char *r = report(db, 0, (time_t)(T0 + 15000));
    ASSERT(r != NULL);
    if (r) {
        const char *m = strstr(r, "## 1. RF_DEGRADED on channel 3");
        const char *b = strstr(r, "## 2. RF_DEGRADED on channel 1");
        ASSERT(m != NULL && b != NULL && m < b);
        ASSERT(strstr(r, "- Frames heard on channel 3 per minute of radio time:"
                         " 510 during; no coverage interval closed in the 21 s"
                         " before it opened.") != NULL);
        ASSERT(strstr(r, "510 during, 510 before") == NULL);
        ASSERT(strstr(r, "- Control frames per minute, every channel heard:"
                         " 10 during; before not covered.") != NULL);
        ASSERT(strstr(r, "- Channel 1 was heard on more than one band in these"
                         " intervals (2g4, 6g).") != NULL);
        ASSERT(strstr(r, "- Channel 3 was heard on more than one band") == NULL);
        ASSERT(strstr(r, "GNSS fixes 1, the newest 2026-") != NULL);
        ASSERT(strstr(r, "both daemons") == NULL);
        ASSERT(strstr(r, "episodes overlap the window; the latest") == NULL);
        free(r);
    }

    r = report(db, 0, 0);
    ASSERT(r != NULL);
    if (r) {
        char want[160];
        snprintf(want, sizeof(want), "%d episodes overlap the window; the latest"
                 " %d are written below.", IFR_MAX_EPISODES + 7, IFR_MAX_EPISODES);
        ASSERT(strstr(r, want) != NULL);
        int nh = 0;
        for (const char *p = r; (p = strstr(p, "\n## ")); p++) nh++;
        ASSERT_EQ(nh, IFR_MAX_EPISODES);
        /* The latest are kept: the RF episodes and the first RTS go. */
        ASSERT(strstr(r, "RF_DEGRADED on channel") == NULL);
        ASSERT(strstr(r, "from 02:00:00:00:00:00") == NULL);
        snprintf(want, sizeof(want), "from 02:00:00:00:00:%02x,",
                 IFR_MAX_EPISODES + 4);
        ASSERT(strstr(r, want) != NULL);
        free(r);
    }
    test_rm_tree(dir);
}

/* ── The handoff packet ─────────────────────────────────────────── */

static int ho_reg(char a2[3]) { a2[0] = 'D'; a2[1] = 'E'; a2[2] = '\0'; return 1; }
static int ho_iftypes(int phy, unsigned *mask) { (void)phy; *mask = 1u << 6; return 1; }
static int ho_gpsd(const char *h, int p, int t, char *d, size_t n) {
    (void)h; (void)p; (void)t; snprintf(d, n, "fake"); return 1;
}
static int ho_sync(int *s) { *s = 1; return 0; }
static const pf_ops_t g_ho_ops = { ho_reg, ho_iftypes, ho_gpsd, ho_sync };

static pf_config_t g_pf;
static handoff_cfg_t g_hc;
static char *g_argv[] = { "sloth", "--headless", "--db", "x.db", NULL };

static void base_cfg(const char *out, const char *db) {
    memset(&g_pf, 0, sizeof(g_pf));
    g_pf.have_pcap = g_pf.have_wifi = g_pf.have_sqlite = 1;
    g_pf.db = db;
    memset(&g_hc, 0, sizeof(g_hc));
    g_hc.out_dir    = out;
    g_hc.argc       = 4;
    g_hc.argv       = g_argv;
    g_hc.db         = db;
    g_hc.site_label = "lab";
    g_hc.pf         = &g_pf;
    g_hc.ops        = &g_ho_ops;
    g_hc.now        = (time_t)NOW;
}

static const char *const PACKET[] = {
    "README.txt", "config.json", "preflight.txt", "preflight.json",
    "networks.tsv", "snapshot.tsv", "findings_open.tsv",
    "findings_closed_30d.tsv", "interference.md", "false_positives.txt",
};
#define NPACKET ((int)(sizeof(PACKET) / sizeof(PACKET[0])))

static char *packet_file(const char *dir, const char *name) {
    char p[TEST_TMP_MAX + 64];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    return slurp(p);
}

static void test_handoff_packet(void) {
    char dir[TEST_TMP_MAX] = "", db[TEST_TMP_MAX + 16], out[TEST_TMP_MAX + 16];
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_ho_XXXXXX")) != NULL);
    if (!dir[0]) return;
    snprintf(db, sizeof(db), "%s/s.db", dir);
    snprintf(out, sizeof(out), "%s/pk", dir);
    ASSERT_EQ(seed_db(db), 0);
    ownership_clear();
    ASSERT(ownership_add_ssid("Cafe|Net*"));
    ASSERT(ownership_add_bssid("02:00:00:00:00:06"));
    ASSERT(ownership_add_known_mac("0a:00:00:00:00:01"));

    base_cfg(out, db);
    fake_net_reset();
    FILE *null = fopen("/dev/null", "w");
    ASSERT_EQ(handoff_write(&g_hc, null), 0);

    struct stat sb;
    ASSERT_EQ(stat(out, &sb), 0);
    ASSERT_EQ((int)(sb.st_mode & 0777), 0700);
    int files = 0;
    DIR *dp = opendir(out);
    struct dirent *e;
    while (dp && (e = readdir(dp)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        files++;
        char p[TEST_TMP_MAX + 16 + 260];
        snprintf(p, sizeof(p), "%s/%s", out, e->d_name);
        ASSERT_EQ(stat(p, &sb), 0);
        ASSERT_EQ((int)(sb.st_mode & 0777), 0600);
        /* WITHHELD: no column sloth.db's readers withhold reaches any
         * file. Seen red with write_open() writing alert_incidents.key
         * in place of incident_id (SECRETUSERKEY in
         * findings_open.tsv), and with interference.c's KINDS[] given
         * ALERT_TYPE_CLEARTEXT_CRED (its key and detail in
         * interference.md). */
        char *t = slurp(p);
        ASSERT(t != NULL);
        for (int k = 0; t && k < NSECRETS; k++) {
            if (strstr(t, SECRETS[k]))
                fprintf(stderr, "    %s holds %s\n", e->d_name, SECRETS[k]);
            ASSERT(strstr(t, SECRETS[k]) == NULL);
        }
        free(t);
    }
    if (dp) closedir(dp);
    ASSERT_EQ(files, NPACKET);
    for (int i = 0; i < NPACKET; i++) {
        char *t = packet_file(out, PACKET[i]);
        if (!t) fprintf(stderr, "    missing %s\n", PACKET[i]);
        ASSERT(t != NULL);
        free(t);
    }

    /* The finding the secrets belong to is listed, so the absence above
     * is of the columns and not of the row. */
    char *t = packet_file(out, "findings_open.tsv");
    ASSERT(t != NULL);
    if (t) {
        ASSERT(strstr(t, "CLEARTEXT_CRED\tWARN\tWARN\topen\t") != NULL);
        ASSERT(strstr(t, "\tcc1\n") != NULL);
        ASSERT(strstr(t, "GNSS_JAMMING\tWARN\tCRIT\topen\t") != NULL);
        /* Last evaluated long before the file's newest write. */
        ASSERT(strstr(t, "DEAUTH_FLOOD\tWARN\tWARN\tunclosed\t") != NULL);
        ASSERT(strstr(t, "RF_DEGRADED") == NULL);
        free(t);
    }
    t = packet_file(out, "findings_closed_30d.tsv");
    ASSERT(t != NULL);
    if (t) {
        ASSERT(strstr(t, "RF_DEGRADED\t2\t0\t2\t0\n") != NULL);
        ASSERT(strstr(t, "RTS_FLOOD\t1\t1\t0\t0\n") != NULL);
        ASSERT(strstr(t, "GNSS_JAMMING") == NULL);
        free(t);
    }
    t = packet_file(out, "networks.tsv");
    ASSERT(t != NULL);
    if (t) {
        ASSERT(strstr(t, "my-ssid\tCafe|Net*\n") != NULL);
        ASSERT(strstr(t, "my-bssid\t02:00:00:00:00:06\n") != NULL);
        ASSERT(strstr(t, "known-mac\t0a:00:00:00:00:01\n") != NULL);
        free(t);
    }
    t = packet_file(out, "config.json");
    ASSERT(t != NULL);
    if (t) {
        ASSERT(strstr(t, "\"argv\":[\"sloth\",\"--headless\",\"--db\",\"x.db\"]") != NULL);
        ASSERT(strstr(t, "\"designations\":{\"ssids\":1,\"bssids\":1,\"roster\":1}") != NULL);
        ASSERT(strstr(t, "\"intel_pack\":{\"version\":") != NULL);
        char want[64];
        snprintf(want, sizeof(want), "\"schema\":%d", DB_SCHEMA_VERSION);
        ASSERT(strstr(t, want) != NULL);
        free(t);
    }
    t = packet_file(out, "preflight.json");
    ASSERT(t != NULL);
    if (t) {
        ASSERT(strstr(t, "\"rules\":{\"assessed\":true") != NULL);
        free(t);
    }
    t = packet_file(out, "README.txt");
    ASSERT(t != NULL);
    if (t) {
        ASSERT(strstr(t, "observable,") != NULL);
        ASSERT(strstr(t, "[absent] no --baseline-in named") != NULL);
        ASSERT(strstr(t, "interference.md") != NULL);
        free(t);
    }
    t = packet_file(out, "false_positives.txt");
    ASSERT(t != NULL);
    if (t) { ASSERT(strstr(t, "sloth-mesh") != NULL); free(t); }

    /* The snapshot: the APs heard within a day of the newest ("Stale"
     * was last heard two days before), and it imports: --baseline-in's
     * reader finds no drift against the same APs. */
    t = packet_file(out, "snapshot.tsv");
    ASSERT(t != NULL);
    if (t) {
        ASSERT(strncmp(t, "# sloth-snapshot v1\n# label\tlab\n", 31) == 0);
        ASSERT(strstr(t, "02:00:00:00:00:06\tCafe|Net*\tWPA2\t6\tPSK\t1\t-\n") != NULL);
        ASSERT(strstr(t, "02:00:00:00:00:24\tFar\tWPA3\t36\tSAE\t2\t-\n") != NULL);
        ASSERT(strstr(t, "Stale") == NULL);
        free(t);
    }
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    beacon_ap_t *a = &s.beacon_aps[0];
    ASSERT_EQ(ownership_parse_mac("02:00:00:00:00:06", a->bssid), 1);
    snprintf(a->ssid, sizeof(a->ssid), "Cafe|Net*");
    snprintf(a->enc, sizeof(a->enc), "WPA2");
    a->channel = 6; a->mfp = 1;
    a = &s.beacon_aps[1];
    ASSERT_EQ(ownership_parse_mac("02:00:00:00:00:24", a->bssid), 1);
    snprintf(a->ssid, sizeof(a->ssid), "Far");
    snprintf(a->enc, sizeof(a->enc), "WPA3");
    a->channel = 36; a->mfp = 2;
    s.beacon_count = 2;
    char snap[TEST_TMP_MAX + 64];
    snprintf(snap, sizeof(snap), "%s/snapshot.tsv", out);
    ASSERT_EQ(wifi_snapshot_diff(&s, snap, null), 0);
    s.beacon_aps[1].channel = 40;
    ASSERT_EQ(wifi_snapshot_diff(&s, snap, null), 1);

    /* A second packet into the same directory is refused, and leaves
     * the first as it was. */
    ASSERT_EQ(handoff_write(&g_hc, null), 2);
    files = 0;
    dp = opendir(out);
    while (dp && (e = readdir(dp)) != NULL)
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) files++;
    if (dp) closedir(dp);
    ASSERT_EQ(files, NPACKET);

    fclose(null);
    ownership_clear();
    fake_net_reset();
    test_rm_tree(dir);
}

/* A running daemon's writes sit in the -wal until a checkpoint. The
 * packet reads them: a finding written through a connection that is
 * still open, with no checkpoint, is listed. Seen red with
 * site_db_open() opening immutable whatever the -wal holds. */
static void test_handoff_reads_the_wal(void) {
    char dir[TEST_TMP_MAX] = "", db[TEST_TMP_MAX + 16], out[TEST_TMP_MAX + 16];
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_how_XXXXXX")) != NULL);
    if (!dir[0]) return;
    snprintf(db, sizeof(db), "%s/s.db", dir);
    snprintf(out, sizeof(out), "%s/pk", dir);
    ASSERT_EQ(seed_db(db), 0);
    sqlite3 *w = NULL;
    ASSERT_EQ(sqlite3_open(db, &w), SQLITE_OK);
    ASSERT_EQ(exec_sql(w, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"),
              SQLITE_OK);
    char sql[256];
    snprintf(sql, sizeof(sql),
             "INSERT INTO alert_incidents (key,incident_id,type,first_seen,last_seen,"
             "sev,peak_sev) VALUES ('wal:1','walinc',%d,%lld,%lld,1,1)",
             ALERT_TYPE_EVIL_TWIN, T0 + 2100, T0 + 2100);
    ASSERT_EQ(exec_sql(w, sql), SQLITE_OK);
    char walp[TEST_TMP_MAX + 32];
    snprintf(walp, sizeof(walp), "%s-wal", db);
    struct stat sb;
    ASSERT_EQ(stat(walp, &sb), 0);
    ASSERT(sb.st_size > 0);

    base_cfg(out, db);
    fake_net_reset();
    FILE *null = fopen("/dev/null", "w");
    ASSERT_EQ(handoff_write(&g_hc, null), 0);
    fclose(null);
    char *t = packet_file(out, "findings_open.tsv");
    ASSERT(t != NULL);
    if (t) { ASSERT(strstr(t, "\twalinc\n") != NULL); free(t); }
    t = packet_file(out, "config.json");
    ASSERT(t != NULL);
    if (t) { ASSERT(strstr(t, "\"read_wal\":true") != NULL); free(t); }
    sqlite3_close(w);
    fake_net_reset();
    test_rm_tree(dir);
}

/* Refusals create nothing: a database that will not open stops the
 * command before the directory exists; a non-empty directory is not
 * written into. Without --db, the --snapshot-out file is the snapshot
 * when it is one, and a file that is not one is not copied. */
static void test_handoff_refusals_and_no_db(void) {
    char dir[TEST_TMP_MAX] = "", out[TEST_TMP_MAX + 16], db[TEST_TMP_MAX + 16];
    char snap[TEST_TMP_MAX + 16], base[TEST_TMP_MAX + 16];
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_hor_XXXXXX")) != NULL);
    if (!dir[0]) return;
    snprintf(out, sizeof(out), "%s/pk", dir);
    snprintf(db, sizeof(db), "%s/none.db", dir);
    snprintf(snap, sizeof(snap), "%s/snap.txt", dir);
    snprintf(base, sizeof(base), "%s/base.txt", dir);
    FILE *null = fopen("/dev/null", "w");

    base_cfg(out, db);
    ASSERT_EQ(handoff_write(&g_hc, null), 2);
    ASSERT(access(out, F_OK) != 0);

    ASSERT_EQ(mkdir(out, 0700), 0);
    char junk[TEST_TMP_MAX + 32];
    snprintf(junk, sizeof(junk), "%s/other", out);
    FILE *f = fopen(junk, "w");
    if (f) fclose(f);
    base_cfg(out, NULL);
    ASSERT_EQ(handoff_write(&g_hc, null), 2);
    char cfgp[TEST_TMP_MAX + 32];
    snprintf(cfgp, sizeof(cfgp), "%s/config.json", out);
    ASSERT(access(cfgp, F_OK) != 0);
    unlink(junk);
    rmdir(out);

    f = fopen(snap, "w");
    if (f) {
        fputs("# sloth-snapshot v1\n# label\t-\n# ts\t1\n# count\t0\n"
              "# bssid\tssid\tenc\tchannel\takm\tmfp\tvendor\n", f);
        fclose(f);
    }
    f = fopen(base, "w");
    if (f) { fputs("psk=hunter2\n", f); fclose(f); }
    base_cfg(out, NULL);
    g_hc.snapshot_out = snap;
    g_hc.baseline_in  = base;
    fake_net_reset();
    ASSERT_EQ(handoff_write(&g_hc, null), 0);
    char *t = packet_file(out, "snapshot.tsv");
    ASSERT(t != NULL);
    if (t) { ASSERT(strncmp(t, "# sloth-snapshot v1\n", 20) == 0); free(t); }
    t = packet_file(out, "baseline.tsv");
    ASSERT(t == NULL);
    free(t);
    t = packet_file(out, "findings_open.tsv");
    ASSERT(t == NULL);
    free(t);
    t = packet_file(out, "README.txt");
    ASSERT(t != NULL);
    if (t) {
        ASSERT(strstr(t, "baseline.tsv             [absent] not copied:") != NULL);
        ASSERT(strstr(t, "not a sloth snapshot") != NULL);
        ASSERT(strstr(t, "findings_open.tsv        [absent] no --db named") != NULL);
        ASSERT(strstr(t, "hunter2") == NULL);
        free(t);
    }
    fclose(null);
    fake_net_reset();
    test_rm_tree(dir);
}

void run_handoff_tests(void) {
    TEST_SUITE("sloth --handoff and --interference-report (#250)");
    RUN_TEST(test_parse_time);
    RUN_TEST(test_interference_report);
    RUN_TEST(test_interference_main_refusals);
    RUN_TEST(test_interference_edges);
    RUN_TEST(test_handoff_packet);
    RUN_TEST(test_handoff_reads_the_wal);
    RUN_TEST(test_handoff_refusals_and_no_db);
}
