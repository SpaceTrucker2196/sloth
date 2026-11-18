#ifndef SLOTH_TEST_RF_SCENARIO_H
#define SLOTH_TEST_RF_SCENARIO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "runner.h"
#include "tmp_dir.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "reset_all.h"
#include "fake_platform.h"
#include "capture_side.h"
#include "rf_profile.h"
#include "poll.h"
#include "jsonl.h"
#include "db.h"
#include "gps.h"
#include "adsb.h"
#include "aprs.h"
#include "rtl433.h"
#include "victron.h"
#include "capture/adsb_reader.h"
#include "capture/aprs_reader.h"
#include "capture/rtl433_reader.h"
#include "capture/victron_reader.h"

/*
 * One canned run of the five RF inputs, for the sloth-rf tests (#213;
 * Victron's added on #216's review, so that "sloth-wifi writes no
 * Victron record or row" is said of a run that has one to write).
 *
 * The inputs are the files and the stream the decoders write, built by
 * hand from each format's own documentation, as tests/test_adsb.c,
 * test_aprs.c, test_rtl433.c and test_gps.c build theirs: readsb's
 * aircraft.json (README-json.md), Dire Wolf's packet log (its User
 * Guide's "Log files" columns), rtl_433's -F json lines
 * (docs/DATA_FORMAT.md), sloth-va's victron.jsonl (docs/wiki/victron.md)
 * and gpsd's TPV / SKY objects (gpsd_json(5)).
 * Callsigns, models, ids and addresses are invented; the position is a
 * point in the open Atlantic. No line came off a receiver and no parser
 * output is fed back in.
 *
 * They go in the way they arrive: the four files are read by the
 * readers' own poll step (*_reader_poll_once(), the body of each
 * worker's loop, on a file under the test's temporary directory), and
 * the gpsd objects through the reader's line framer. No device, serial
 * port or socket is opened, and the worker threads are never started,
 * so a run is a function of its inputs and of the pinned clocks.
 *
 * rfs_run() does the same run under any poll table, with the shared
 * services in the shape the daemon that passes that table has:
 * sloth-wifi with its capture side (g_poll_wifi), or sloth-rf with its
 * own (g_poll_rf). The two are then compared: since the cutover (#216)
 * for what each has that the other must not.
 */

#define RFS_WALL0 ((time_t)1800000000)   /* 2027-01-15T08:00:00Z */

static time_t   rfs_wall;
static uint64_t rfs_mono;
static time_t   rfs_wall_fn(void) { return rfs_wall; }
static uint64_t rfs_mono_fn(void) { return rfs_mono; }

static char rfs_dir[TEST_TMP_MAX];

static inline void rfs_append(const char *name, const char *text) {
    char p[TEST_TMP_MAX + 40];
    snprintf(p, sizeof(p), "%s/%s", rfs_dir, name);
    FILE *fp = fopen(p, "a");
    ASSERT(fp != NULL);
    if (!fp) return;
    fputs(text, fp);
    fclose(fp);
}

/* Replace a file whole, by rename, as readsb does aircraft.json. */
static inline void rfs_replace(const char *name, const char *text) {
    char p[TEST_TMP_MAX + 40], t[TEST_TMP_MAX + 48];
    snprintf(p, sizeof(p), "%s/%s", rfs_dir, name);
    snprintf(t, sizeof(t), "%s.tmp", p);
    FILE *fp = fopen(t, "w");
    ASSERT(fp != NULL);
    if (!fp) return;
    fputs(text, fp);
    fclose(fp);
    ASSERT_EQ(rename(t, p), 0);
}

#define RFS_APRS_HDR \
    "chan,utime,isotime,source,heard,level,error,dti,name,symbol," \
    "latitude,longitude,speed,course,altitude,frequency,offset,tone," \
    "system,status,telemetry,comment\n"
#define RFS_APRS_OLD \
    "0,1799990000,2027-01-15T05:13:20Z,N0OLD-1,N0OLD-1,50(14/14),0,!," \
    "N0OLD-1,/#,10.000000,-20.000000,,,,,,,\"DireWolf, WB2OSZ\",,,before start\n"
#define RFS_APRS_FIXED \
    "0,1800000001,2027-01-15T08:00:01Z,N0TEST-5,N0TEST-5,50(14/14),0,!," \
    "N0TEST-5,/#,10.000000,-20.000000,,,,,,,\"DireWolf, WB2OSZ\",,,Test station\n"
#define RFS_APRS_MOVING \
    "0,1800000002,2027-01-15T08:00:02Z,N0TEST-9,N0TEST-9,50(14/14),0,=," \
    "N0TEST-9,/>,10.205667,-20.535000,45.0,90.0,376.1,,,," \
    "\"Generic, (obsolete. Digis should use APNxxx instead)\",,, moving\n"

#define RFS_RTL_OLD \
    "{\"time\":\"2027-01-15 05:13:20\",\"model\":\"Testco-OLD\",\"id\":1," \
    "\"temperature_C\":1.000,\"mod\":\"ASK\",\"freq\":433.900}\n"
#define RFS_RTL_TPMS \
    "{\"time\":\"2027-01-15 08:00:01\",\"protocol\":60,\"model\":\"Testco-TP01\"," \
    "\"type\":\"TPMS\",\"id\":\"1a2b3c\",\"state\":\"closed\",\"flags\":3," \
    "\"pressure_kPa\":241.400,\"temperature_C\":21.000,\"code\":\"0f1e2d\"," \
    "\"mic\":\"CHECKSUM\",\"mod\":\"FSK\",\"freq1\":433.918,\"freq2\":433.952," \
    "\"rssi\":-0.158,\"snr\":22.431,\"noise\":-22.589}\n"
#define RFS_RTL_WX \
    "{\"time\":\"2027-01-15 08:00:02\",\"protocol\":12,\"model\":\"Testco-WX9\"," \
    "\"id\":205,\"channel\":2,\"battery_ok\":1.000,\"temperature_C\":-4.500," \
    "\"humidity\":63.000,\"pressure_hPa\":1013.200,\"mic\":\"CRC\"," \
    "\"mod\":\"ASK\",\"freq\":433.942,\"rssi\":-11.100,\"snr\":9.800," \
    "\"noise\":-20.900}\n"

/* sloth-va's file: a line from before the start, then one instant
 * readout of a battery monitor. The address is locally administered
 * and the serial is not a Victron one. */
#define RFS_VIC_OLD \
    "{\"type\":\"victron\",\"t\":1799990000,\"source\":\"readout\"," \
    "\"mac\":\"02:00:5e:00:53:0a\",\"serial\":\"TESTOLD0001\"," \
    "\"model_id\":\"0xa381\",\"model\":\"BMV-712 Smart\"," \
    "\"record\":\"battery_monitor\",\"rssi\":-70," \
    "\"values\":{\"voltage_v\":12.000}}\n"
#define RFS_VIC_BMV \
    "{\"type\":\"victron\",\"t\":1800000001,\"source\":\"readout\"," \
    "\"mac\":\"02:00:5e:00:53:0b\",\"serial\":\"TESTBMV0001\"," \
    "\"model_id\":\"0xa381\",\"model\":\"BMV-712 Smart\"," \
    "\"record\":\"battery_monitor\",\"rssi\":-71," \
    "\"values\":{\"voltage_v\":13.200,\"current_a\":-1.500,\"soc_pct\":87.500}}\n"

/* One ordinary aircraft; then the same with a second one squawking
 * 7700, which is ADSB_EMERGENCY. */
#define RFS_ADSB_1 \
    "{\"now\":1800000000.5,\"messages\":50," \
    "\"aircraft\":[{\"hex\":\"a0b1c2\",\"flight\":\"SYN100  \",\"alt_baro\":35000," \
    "\"gs\":440.0,\"track\":90.0,\"lat\":10.5,\"lon\":-20.5,\"squawk\":\"1200\"," \
    "\"seen\":0.5,\"seen_pos\":0.5,\"messages\":40,\"rssi\":-12.5}]}"
#define RFS_ADSB_2 \
    "{\"now\":1800000002.5,\"messages\":90," \
    "\"aircraft\":[{\"hex\":\"a0b1c2\",\"flight\":\"SYN100  \",\"alt_baro\":35025," \
    "\"gs\":441.0,\"track\":90.0,\"lat\":10.5,\"lon\":-20.4,\"squawk\":\"1200\"," \
    "\"seen\":0.3,\"seen_pos\":0.3,\"messages\":70,\"rssi\":-12.0}," \
    "{\"hex\":\"a1b2c3\",\"flight\":\"SYN7700 \",\"alt_baro\":12000," \
    "\"lat\":10.2,\"lon\":-20.2,\"squawk\":\"7700\",\"seen\":0.2," \
    "\"seen_pos\":0.2,\"messages\":12,\"rssi\":-20.0}]}"

#define RFS_GPSD_SKY \
    "{\"class\":\"SKY\",\"device\":\"/dev/ttyTEST\",\"hdop\":0.9,\"nSat\":3,\"uSat\":2," \
    "\"satellites\":[" \
    "{\"PRN\":5,\"gnssid\":0,\"svid\":5,\"el\":45.0,\"az\":120.0,\"ss\":40.0,\"used\":true}," \
    "{\"PRN\":7,\"gnssid\":0,\"svid\":7,\"el\":30.0,\"az\":200.0,\"ss\":36.0,\"used\":true}," \
    "{\"PRN\":66,\"gnssid\":6,\"svid\":2,\"el\":10.0,\"az\":300.0,\"ss\":21.0,\"used\":false}]}\n"

static gps_lines_t rfs_gpsd;

/* A 3D fix at `lat`, stamped with the pinned wall clock's second. */
static inline void rfs_feed_tpv(double lat) {
    char line[400];
    struct tm tm;
    time_t w = rfs_wall;
    gmtime_r(&w, &tm);
    snprintf(line, sizeof(line),
             "{\"class\":\"TPV\",\"device\":\"/dev/ttyTEST\",\"mode\":3,"
             "\"time\":\"%04d-%02d-%02dT%02d:%02d:%02d.000Z\","
             "\"lat\":%.5f,\"lon\":-20.00000,\"altMSL\":12.0,\"eph\":3.0,"
             "\"epv\":5.0,\"speed\":0.0,\"track\":0.0,\"leapseconds\":18}\n",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, lat);
    gps_lines_feed(&rfs_gpsd, (const uint8_t *)line, strlen(line), rfs_wall);
}

static inline void rfs_readers_poll(void) {
    (void)adsb_reader_poll_once(rfs_wall, rfs_mono);
    (void)aprs_reader_poll_once(rfs_wall, rfs_mono);
    (void)rtl433_reader_poll_once(rfs_wall);
    (void)victron_reader_poll_once(rfs_wall);
}

static inline void rfs_tick(const poll_table_t *t, sloth_state_t *s) {
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    poll_tick(t, s, &ctx);
}

/* The run. `as_rf` puts the shared services in sloth-rf's shape;
 * otherwise they are sloth-wifi's. `jsonl` and `dbp` are sink paths, either
 * may be NULL. Leaves both sinks closed and everything reset. The host
 * the fake platform reports has one interface, one associated Wi-Fi
 * station and a hwmon supply alarm reading 1 - things a daemon with a
 * capture reports and one without must not. */
static inline void rfs_run(const poll_table_t *t, int as_rf,
                           const char *jsonl, const char *dbp) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    sloth_reset_all();
    fake_net_reset();
    capture_side_install();
    if (as_rf) rf_profile_select();
    rfs_wall = RFS_WALL0;
    rfs_mono = 7000000;
    sloth_clock_test_set(rfs_mono_fn, rfs_wall_fn);

    snprintf(g_fake_net.ifaces[0].name, sizeof(g_fake_net.ifaces[0].name), "eth0");
    g_fake_net.iface_count = 1;
    snprintf(g_fake_net.wifi_stas[0].mac, sizeof(g_fake_net.wifi_stas[0].mac),
             "02:00:5e:00:53:21");
    g_fake_net.wifi_stas[0].signal_dbm = -50;
    g_fake_net.wifi_sta_count = 1;
    fake_sys_put("/sys/class/hwmon/hwmon1/name", "rpi_volt\n");
    fake_sys_put("/sys/class/hwmon/hwmon1/in0_lcrit_alarm", "1\n");

    /* One fixed name under the run's temporary directory, emptied
     * first: the readers' labels (`src`, the sensor's `iface`) carry the
     * path, so two runs that are to be compared must read the same one. */
    ASSERT_EQ(test_tmp_path(rfs_dir, sizeof(rfs_dir), "sloth_rfs"), 0);
    test_rm_tree(rfs_dir);
    ASSERT_EQ(mkdir(rfs_dir, 0700), 0);
    /* What the decoders had already written before the daemon started:
     * the two tailed logs are read from their end, so none of it is a
     * record. */
    rfs_append("aprs.log", RFS_APRS_HDR RFS_APRS_OLD);
    rfs_append("events.jsonl", RFS_RTL_OLD);
    rfs_append("victron.jsonl", RFS_VIC_OLD);
    rfs_replace("aircraft.json", RFS_ADSB_1);

    char spec[TEST_TMP_MAX + 64], err[200];
    snprintf(spec, sizeof(spec), "file://%s/aircraft.json", rfs_dir);
    ASSERT_EQ(adsb_reader_configure(spec, err, sizeof(err)), 0);
    snprintf(spec, sizeof(spec), "%s/aprs.log", rfs_dir);
    ASSERT_EQ(aprs_reader_configure(spec, err, sizeof(err)), 0);
    snprintf(spec, sizeof(spec), "%s/events.jsonl", rfs_dir);
    ASSERT_EQ(rtl433_reader_configure(spec, err, sizeof(err)), 0);
    snprintf(spec, sizeof(spec), "%s/victron.jsonl", rfs_dir);
    ASSERT_EQ(victron_reader_configure(spec, err, sizeof(err)), 0);
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    gps_lines_init(&rfs_gpsd, GPS_FEED_GPSD);

    if (jsonl) { unlink(jsonl); ASSERT(jsonl_open(jsonl)); }
    if (dbp) {
        unlink(dbp);
        ASSERT_EQ(db_open(dbp), 1);
        db_session_begin("rf scenario", rfs_wall);
    }

    /* Tick 1: the receiver's first fix and sky, the first aircraft.json;
     * the two logs are at their end. */
    rfs_feed_tpv(10.00000);
    gps_lines_feed(&rfs_gpsd, (const uint8_t *)RFS_GPSD_SKY,
                   strlen(RFS_GPSD_SKY), rfs_wall);
    rfs_readers_poll();
    rfs_tick(t, &s);

    /* Tick 2: a packet and a decode arrive. */
    rfs_wall += 1; rfs_mono += 1000;
    rfs_append("aprs.log", RFS_APRS_FIXED);
    rfs_append("events.jsonl", RFS_RTL_TPMS);
    rfs_append("victron.jsonl", RFS_VIC_BMV);
    rfs_feed_tpv(10.00000);
    rfs_readers_poll();
    rfs_tick(t, &s);

    /* Tick 3: more of both, and an aircraft squawking 7700. */
    rfs_wall += 1; rfs_mono += 1000;
    rfs_append("aprs.log", RFS_APRS_MOVING);
    rfs_append("events.jsonl", RFS_RTL_WX);
    rfs_replace("aircraft.json", RFS_ADSB_2);
    rfs_feed_tpv(10.00100);                 /* about 110 m north: a move */
    rfs_readers_poll();
    rfs_tick(t, &s);

    /* Ticks 4 to 15: nothing new arrives; the sensor keeps moving, so
     * the track is sampled, and a sys_status sample falls due. */
    for (int i = 0; i < 12; i++) {
        rfs_wall += 1; rfs_mono += 1000;
        rfs_feed_tpv(10.00100 + 0.001 * (i + 1));
        rfs_readers_poll();
        rfs_tick(t, &s);
    }

    if (dbp) { db_session_end(rfs_wall); db_close(); }
    if (jsonl) jsonl_close();
    adsb_reader_stop();
    aprs_reader_stop();
    rtl433_reader_stop();
    victron_reader_stop();
    test_rm_tree(rfs_dir);
    sloth_reset_all();
    fake_net_reset();
    capture_side_install();
    sloth_clock_test_set(NULL, NULL);
}

/* The whole of a file, NUL-terminated; the caller frees. "" when it is
 * not there. */
static inline char *rfs_slurp(const char *path) {
    FILE *fp = fopen(path, "r");
    size_t cap = 1 << 20, n = 0;
    char *b = malloc(cap);
    if (!b) return NULL;
    if (fp) {
        n = fread(b, 1, cap - 1, fp);
        fclose(fp);
    }
    b[n] = '\0';
    return b;
}

#endif /* SLOTH_TEST_RF_SCENARIO_H */
