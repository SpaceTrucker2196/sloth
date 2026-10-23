/* See sdb_gen.h. Not a suite: no run_ function, linked into
 * slothweb_test with the rest of web/tests/. */
#include "sdb_gen.h"

#include <stdio.h>

#ifdef WITH_SQLITE

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

/* src/db_schema.c, sloth's own DDL (src/db.h). Declared here rather
 * than by including db.h: slothweb_test links that one file of sloth's
 * and nothing it needs (db_schema_version() is in sdb_gen.h). */
const char *db_schema_sql(void);
const char *db_schema_meta_sql(void);

int sdb_exec(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    if (sqlite3_open(path, &h) != SQLITE_OK) { sqlite3_close(h); return -1; }
    char *m = NULL;
    int rc = sqlite3_exec(h, sql, NULL, NULL, &m);
    if (rc != SQLITE_OK) fprintf(stderr, "  sdb_exec: %s\n", m ? m : "?");
    sqlite3_free(m);
    sqlite3_close(h);
    return rc == SQLITE_OK ? 0 : -1;
}

/* The columns each later version added (src/db_schema.c's migration
 * steps), dropped again for an older file's shape. */
static const char DROP_V7[] =
    "ALTER TABLE devices DROP COLUMN cam_score;"
    "ALTER TABLE devices DROP COLUMN cam_evidence;"
    "ALTER TABLE devices DROP COLUMN cam_vetoes;"
    "ALTER TABLE devices DROP COLUMN cam_conflict;"
    "ALTER TABLE devices DROP COLUMN dhcp_prl;"
    "ALTER TABLE devices DROP COLUMN dhcp_vci;";
static const char DROP_V6[] =
    "ALTER TABLE devices DROP COLUMN device_class;"
    "ALTER TABLE devices DROP COLUMN camera_vendor;"
    "ALTER TABLE devices DROP COLUMN camera_model;"
    "ALTER TABLE devices DROP COLUMN setup_mode;"
    "ALTER TABLE devices DROP COLUMN cam_signals;";

int sdb_make(const char *path, int version, int wal) {
    sqlite3 *h = NULL;
    if (sqlite3_open(path, &h) != SQLITE_OK) { sqlite3_close(h); return -1; }
    char stamp[160];
    snprintf(stamp, sizeof(stamp), "INSERT INTO meta (key, value) VALUES "
             "('schema_version', '%d');", version);
    int rc = SQLITE_OK;
    if (wal) rc = sqlite3_exec(h, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    if (rc == SQLITE_OK) rc = sqlite3_exec(h, db_schema_meta_sql(), NULL, NULL, NULL);
    if (rc == SQLITE_OK) rc = sqlite3_exec(h, db_schema_sql(), NULL, NULL, NULL);
    if (rc == SQLITE_OK && version < 7) rc = sqlite3_exec(h, DROP_V7, NULL, NULL, NULL);
    if (rc == SQLITE_OK && version < 6) rc = sqlite3_exec(h, DROP_V6, NULL, NULL, NULL);
    if (rc == SQLITE_OK) rc = sqlite3_exec(h, stamp, NULL, NULL, NULL);
    if (rc != SQLITE_OK) fprintf(stderr, "  sdb_make: %s\n", sqlite3_errmsg(h));
    /* The last connection closing checkpoints and removes the -wal and
     * -shm: a cleanly closed WAL-mode file, as sloth leaves one. */
    sqlite3_close(h);
    return rc == SQLITE_OK ? 0 : -1;
}

/* The scenario, against SDB_NOW (rows named in test_slothdb.c):
 *   D1 da:a1:19:00:00:01 random, "Apple", seen 1 h ago      matches
 *   D2 da:a1:19:00:00:02 random, "Apple", seen 30 h ago     too old
 *   D3 00:03:93:00:00:03 Apple's own OUI, not random        not random
 *   D4 da:a1:19:00:00:04 random, "Samsung"                  not Apple
 *   D5 3e:00:00:00:00:05 random, no vendor                  not Apple
 *   D6 f2:11:22:00:00:06 random, "Apple Inc", seen 23 h ago matches
 *   D7 da:a1:19:00:00:07 random, "apple", seen exactly 24 h ago:
 *      "less than 24 h" excludes it
 *   D8 70:b3:d5:f2:a1:23 an MA-S block sloth's table misses (vendor NULL)
 *   D9 00:11:22:33:44:55 a hostname holding markup; DHCP, mDNS and NBNS
 *      names for its IP; an alert naming that IP, keyed as sloth keys a
 *      cleartext credential (its key carries the username)
 * D3 also has an alert naming it only in its key (no match_ip); and, in
 * a table no statement may read, the credential exposure itself. The
 * username must never be served. */
int sdb_seed(const char *path) {
    char sql[8192];
    const long long N = SDB_NOW, H = 3600, D = 86400;
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,ip,hostname,vendor,last_ssid,is_ap,signal_dbm,"
        "probe_count,sources,risk_signals,risk_level,first_seen,last_seen) VALUES"
        " ('da:a1:19:00:00:01','10.0.1.11',NULL,'Apple','HomeNet',0,-48,3,48,1,1,%lld,%lld),"
        " ('da:a1:19:00:00:02',NULL,NULL,'Apple',NULL,0,-70,1,16,1,0,%lld,%lld),"
        " ('00:03:93:00:00:03','10.0.1.13','macbook','Apple',NULL,0,NULL,0,3,0,0,%lld,%lld),"
        " ('da:a1:19:00:00:04',NULL,NULL,'Samsung',NULL,0,-60,2,16,1,1,%lld,%lld),"
        " ('3e:00:00:00:00:05',NULL,NULL,NULL,NULL,0,NULL,0,16,1,0,%lld,%lld),"
        " ('f2:11:22:00:00:06','10.0.1.16',NULL,'Apple Inc','CorpWiFi',0,-55,5,16,1,2,%lld,%lld),"
        " ('da:a1:19:00:00:07',NULL,NULL,'apple',NULL,0,NULL,0,16,1,0,%lld,%lld),"
        " ('70:b3:d5:f2:a1:23','10.0.1.18',NULL,NULL,NULL,0,NULL,0,1,2,1,%lld,%lld),"
        " ('00:11:22:33:44:55','10.0.1.5','<b>nas</b>','Generic',NULL,0,NULL,0,7,0,0,%lld,%lld);"
        "INSERT INTO dhcp_leases (ip,hostname,expire,first_seen,last_seen) VALUES"
        " ('10.0.1.5','nas-dhcp',0,%lld,%lld),"
        " ('10.0.1.13','macbook-dhcp',0,%lld,%lld);"
        "INSERT INTO mdns_services (instance,service,host,ip,port,first_seen,last_seen)"
        " VALUES ('NAS._smb._tcp.local','_smb._tcp','nas.local','10.0.1.5',445,%lld,%lld);"
        "INSERT INTO nbns_names (name,suffix,ip,first_seen,last_seen) VALUES"
        " ('NAS',0,'10.0.1.5',%lld,%lld), ('WORKGROUP',30,'10.0.1.5',%lld,%lld);"
        "INSERT INTO arp (ip,mac,iface,first_seen,last_seen) VALUES"
        " ('10.0.1.5','00:11:22:33:44:55','eth0',%lld,%lld),"
        " ('10.0.9.9','00:03:93:00:00:03','eth0',%lld,%lld);"
        "INSERT INTO pnl_clients (mac,mac_random,probe_count,first_seen,last_seen)"
        " VALUES ('da:a1:19:00:00:01',1,3,%lld,%lld);"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
        " ('da:a1:19:00:00:01','HomeNet',%lld,%lld),"
        " ('da:a1:19:00:00:01','CafeFree',%lld,%lld);"
        "INSERT INTO probe_clients (mac,ssid,signal_dbm,channel,frame_count,"
        "presence,first_seen,last_seen) VALUES"
        " ('da:a1:19:00:00:01','HomeNet',-48,6,10,0,%lld,%lld);"
        "INSERT INTO assocs (bssid,sta_mac,ssid,sta_random,source,channel,"
        "signal_dbm,frame_count,first_seen,last_seen) VALUES"
        " ('aa:bb:cc:dd:ee:ff','da:a1:19:00:00:01','HomeNet',1,1,6,-50,10,%lld,%lld);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,"
        "technique,match_ip,match_port,count) VALUES"
        " ('cred:10.0.1.5:10.0.1.1:21:ftp:alice-secret-user:0123456789abcdef',"
        "%lld,%lld,12,2,'FTP login in cleartext',"
        "'user=alice-detail','T1040','10.0.1.5',21,3),"
        " ('evil_twin:00:03:93:00:00:03',%lld,%lld,3,1,'Evil twin',NULL,"
        "'T1557',NULL,NULL,1);"
        "INSERT INTO cleartext_creds (ts,src,dst,dst_port,protocol,username,"
        "pw_observed,first_seen,last_seen) VALUES"
        " (%lld,'10.0.1.5','10.0.1.1',21,'ftp','alice-secret-user',1,%lld,%lld);",
        N - 10 * D, N - H, N - 5 * D, N - 30 * H, N - 20 * D, N - 60,
        N - D, N - 60, N - 2 * H, N - 120, N - 30 * H, N - 23 * H,
        N - 2 * D, N - D, N - H, N - 300, N - 40 * D, N - 10,
        N - 40 * D, N - 10, N - 20 * D, N - 60,
        N - 40 * D, N - 10,
        N - 40 * D, N - 10, N - 40 * D, N - 5,     /* WORKGROUP the newer */
        N - 40 * D, N - 10, N - 20 * D, N - 60,
        N - 10 * D, N - H,
        N - 10 * D, N - H, N - 9 * D, N - 2 * D,
        N - 12 * D, N - H,
        N - 11 * D, N - H,
        N - 100, N - 50, N - 200, N - 150,
        N - 100, N - 100, N - 100);
    return sdb_exec(path, sql);
}

size_t sdb_slurp(const char *path, unsigned char *buf, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

void sdb_listing(const char *dir, char *out, size_t cap) {
    char *names[64] = { NULL };
    int n = 0;
    out[0] = '\0';
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) && n < 64) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        names[n] = malloc(strlen(e->d_name) + 1);
        if (!names[n]) break;
        strcpy(names[n], e->d_name);
        n++;
    }
    closedir(d);
    qsort(names, (size_t)n, sizeof(names[0]), cmp_str);
    size_t o = 0;
    for (int i = 0; i < n; i++) {
        int w = snprintf(out + o, cap - o, "%s ", names[i]);
        if (w > 0 && (size_t)w < cap - o) o += (size_t)w;
        free(names[i]);
    }
}

#endif /* WITH_SQLITE */

int sdb_oui(oui_build_t *b, const char *dir) {
    char p[160];
    snprintf(p, sizeof(p), "%s/oui-test.csv", dir);
    FILE *f = fopen(p, "wb");
    if (!f) return -1;
    fputs("Registry,Assignment,Organization Name,Organization Address\n"
          "MA-L,000393,\"Apple, Inc.\",Cupertino US\n"
          "MA-L,001122,Generic Corp,x\n"
          "MA-L,70B3D5,IEEE Registration Authority,Piscataway US\n"
          "MA-S,70B3D5F2A,Small Vendor Ltd,Leeds GB\n", f);
    fclose(f);
    oui_build_init(b);
    int rc = oui_build_csv(b, p) == 0 && oui_build_finish(b, "ieee") == 0 ? 0 : -1;
    remove(p);
    return rc;
}


/* Never empty, whatever the build. */
typedef int sdb_gen_build_t;
