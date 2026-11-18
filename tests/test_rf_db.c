#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include "rf_scenario.h"

/*
 * sloth-rf's database (#213): sloth's own DDL and DB_SCHEMA_VERSION,
 * written by the same src/db.c from a state only the RF stages fill.
 * The canned run of tests/rf_scenario.h is persisted once under
 * sloth-rf's poll table and once under `sloth`'s, the control.
 *
 * Owner ruling 2026-11-15 (ADR 0010): both daemons write
 * sensor_positions, each to its own file; device_positions is the
 * capture daemon's, because only it has devices.
 */

static char g_db[TEST_TMP_MAX];

static void tmp_db(void) {
    g_db[0] = '\0';
    int fd = mkstemp(test_tmp_tpl(g_db, sizeof(g_db), "sloth_rfdb_XXXXXX"));
    if (fd >= 0) close(fd);
    remove(g_db);
}

/* A scalar integer query against the file; -1 on any error, so a
 * misspelt table is a failed assertion and not a quiet zero. */
static long long q_int(const char *sql) {
    sqlite3 *h = NULL;
    long long v = -1;
    /* Read-write, as tests/test_db.c opens its file: the last
     * connection to close a WAL database checkpoints it and removes the
     * -wal and -shm files, which a read-only one cannot. */
    if (sqlite3_open(g_db, &h) == SQLITE_OK) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    sqlite3_close(h);
    return v;
}

/* The file and whatever SQLite left beside it. */
static void rm_db(void) {
    static const char *const sfx[] = { "", "-wal", "-shm", "-journal" };
    for (size_t i = 0; i < sizeof(sfx) / sizeof(sfx[0]); i++) {
        char p[TEST_TMP_MAX + 16];
        snprintf(p, sizeof(p), "%s%s", g_db, sfx[i]);
        unlink(p);
    }
}

static long long rows(const char *table) {
    char sql[96];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    return q_int(sql);
}

/* The file sloth-rf writes is a sloth database: the same schema
 * version, every table of the DDL present, and the RF tables filled
 * from the canned inputs - with the sensor's own track among them. */
static void test_rf_db_has_sloths_schema_and_the_rf_rows(void) {
    tmp_db();
    rfs_run(&g_poll_rf, 1, NULL, g_db);

    ASSERT_EQ(q_int("SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'"),
              DB_SCHEMA_VERSION);
    /* slothweb's probe needs the devices table to exist (empty is a
     * healthy sloth-rf.db; docs/wiki/architecture-rf-split.md 6.3). */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND "
                    "name IN ('devices','beacon_aps','device_positions',"
                    "'sensor_positions','gnss_fixes','adsb_aircraft','aprs_stations')"), 7);

    ASSERT_GE(rows("gnss_fixes"), 1);
    ASSERT_GE(rows("gnss_sightings"), 3);
    ASSERT_EQ(rows("adsb_aircraft"), 2);
    ASSERT_GE(rows("adsb_sightings"), 2);
    ASSERT_EQ(rows("aprs_stations"), 2);
    ASSERT_EQ(rows("aprs_packets"), 2);
    /* sloth-va's file: one device, one write of its readings. */
    ASSERT_EQ(rows("victron_devices"), 1);
    ASSERT_GE(rows("victron_readings"), 1);
    ASSERT_EQ(rows("sensors"), 5);
    ASSERT_EQ(rows("sessions"), 1);
    /* The 7700 squawk, as an alert row with its incident. */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts WHERE title='ADSB_EMERGENCY'"), 1);
    ASSERT_GE(rows("alert_incidents"), 1);

    /* The sensor's own track: the fix moved about 110 m a tick. */
    ASSERT_GE(rows("sensor_positions"), 2);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM sensor_positions WHERE loc_src='gps'"),
              rows("sensor_positions"));
    rm_db();
}

/* Nothing of the capture's is in it. The host the scenario reports has
 * an interface and an associated station, which under `sloth` become a
 * devices row and - the sensor moving - a device_positions row; under
 * sloth-rf's table no stage reads the platform or builds a device, so
 * both stay empty, and so does every other capture table.
 *
 * SENSOR_UNDERVOLT is absent from its alerts table for the reason
 * tests/test_rf_rules.c gives, with the alarm reading 1 throughout.
 *
 * (Seen red - devices, device_positions, wifi_stas and the undervolt
 * row - with the one binary's table and services passed in sloth-rf's
 * place, #213.) */
static void test_rf_db_has_no_capture_rows(void) {
    tmp_db();
    rfs_run(&g_poll_rf, 1, NULL, g_db);
    static const char *const empty[] = {
        "devices", "device_positions", "wifi_aps", "wifi_stas", "wifi_merged",
        "beacon_aps", "probe_clients", "pnl_clients", "arp", "dhcp_leases",
        "deauth_events", "eapol_events", "top_hosts", "scan_entries",
        "twin_episodes", "cleartext_creds",
    };
    for (size_t i = 0; i < sizeof(empty) / sizeof(empty[0]); i++) {
        long long n = rows(empty[i]);
        if (n != 0) fprintf(stderr, "    %s has %lld row(s)\n", empty[i], n);
        ASSERT_EQ(n, 0);
    }
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts WHERE title='SENSOR_UNDERVOLT'"), 0);
    ASSERT_GE(rows("sensor_positions"), 2);     /* not empty for want of a fix */
    rm_db();

    /* The control: the same run as sloth-wifi. */
    tmp_db();
    rfs_run(&g_poll_wifi, 0, NULL, g_db);
    ASSERT_GE(rows("devices"), 1);
    ASSERT_GE(rows("device_positions"), 1);
    ASSERT_GE(rows("wifi_stas"), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts WHERE title='SENSOR_UNDERVOLT'"), 1);
    /* And sloth-wifi writes the track too: both daemons do. */
    ASSERT_GE(rows("sensor_positions"), 2);
    rm_db();
}

/* The other daemon's file, from the same inputs (#216): sloth-wifi,
 * with a receiver that has a fix and three decoder files on disk,
 * writes none of the receiver's records' tables and none of the
 * decoders' - gnss_fixes, gnss_sightings, adsb_*, aprs_*, victron_* are
 * sloth-rf's alone - and no GNSS or ADS-B alert. What it keeps, it
 * keeps: the sensor's own track and the devices' (both daemons write
 * sensor_positions, owner ruling 2026-11-15), the receiver in its
 * sensors table, and the loc_* stamp on the alert it does open.
 *
 * The control for every zero is the first test of this file: the same
 * run as sloth-rf fills each of these tables.
 *
 * Seen red (2026-11-15): with `if (g_rf_side)` taken off the four
 * writers in db_tick(), gnss_fixes and gnss_sightings fill (the
 * receiver's state is in this daemon); with health_rf put back in
 * wifi_stages[] as well, adsb_aircraft, aprs_stations, victron_devices
 * and victron_readings do (the Victron pair seen on 2026-11-15, #216's
 * review, once the scenario fed sloth-va's file: until then those two
 * zeros had nothing to be non-zero from). */
static void test_wifi_db_has_no_rf_rows_and_keeps_the_track(void) {
    tmp_db();
    rfs_run(&g_poll_wifi, 0, NULL, g_db);
    static const char *const empty[] = {
        "gnss_fixes", "gnss_sightings", "adsb_aircraft", "adsb_sightings",
        "aprs_stations", "aprs_packets", "victron_devices", "victron_readings",
    };
    for (size_t i = 0; i < sizeof(empty) / sizeof(empty[0]); i++) {
        long long n = rows(empty[i]);
        if (n != 0) fprintf(stderr, "    sloth-wifi wrote %lld row(s) of %s\n", n, empty[i]);
        ASSERT_EQ(n, 0);
    }
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts WHERE title LIKE 'GNSS_%'"), 0);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts WHERE title='ADSB_EMERGENCY'"), 0);

    /* Kept. The fix moved about 110 m a tick. */
    ASSERT_GE(rows("sensor_positions"), 2);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM sensor_positions WHERE loc_src='gps'"),
              rows("sensor_positions"));
    ASSERT_GE(rows("device_positions"), 1);
    /* The receiver is one of this daemon's sensors, and no decoder is. */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM sensors WHERE name='GNSS receiver'"), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM sensors WHERE name IN "
                    "('ADS-B decoder','APRS decoder','rtl_433 decoder',"
                    "'Victron (sloth-va)')"), 0);
    /* The location stamp: the undervolt incident opened with a fix. */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts WHERE title='SENSOR_UNDERVOLT' "
                    "AND loc_src='gps'"), 1);
    rm_db();
}

void run_rf_db_tests(void) {
    TEST_SUITE("sloth-rf: its database (#213)");
    RUN_TEST(test_rf_db_has_sloths_schema_and_the_rf_rows);
    RUN_TEST(test_rf_db_has_no_capture_rows);
    RUN_TEST(test_wifi_db_has_no_rf_rows_and_keeps_the_track);
}
