#ifndef SLOTH_GPS_H
#define SLOTH_GPS_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* ── Sensor position: --location and --gps (2026-10-27) ───────────
 *
 * Two opt-in, receive-only sources of where the sensor is:
 *
 *   --location LAT,LON[,ALT]   a fixed sensor (WGS84 decimal degrees,
 *                              altitude in metres above mean sea level)
 *   --gps /dev/ttyXXX          NMEA 0183 sentences off a serial device,
 *                              read only: sloth never writes a byte to it
 *   --gps gpsd://[HOST[:PORT]] gpsd's JSON WATCH stream over TCP
 *                              (default 127.0.0.1:2947). gpsd has no
 *                              Unix-socket data transport (its -F socket
 *                              takes device add/remove commands only), so
 *                              this is network use: loopback by default,
 *                              a routable host refused without
 *                              --gps-allow-remote, and sloth SENDS exactly
 *                              one ?WATCH line before reading.
 *
 * This file is the pure half: the NMEA and gpsd parsers over bytes, the
 * spec parser, and the arbitration state the reader (src/capture/
 * gps_reader.c) feeds and the engine, views and exports read. Nothing
 * here does I/O.
 *
 * Arbitration (gps_location_current): a GPS fix younger than
 * gps.max_fix_age_s wins; otherwise the fixed --location, if given;
 * otherwise nothing (LOC_SRC_NONE), and every consumer omits the
 * stamp. A stale fix is reported as such in sensor_health.
 *
 * Sources: NMEA 0183 as gpsd documents it
 * (https://gpsd.gitlab.io/gpsd/NMEA.html): "$TTSSS,fields*hh\r\n", at
 * most 82 bytes with the "$" and CRLF, the checksum the XOR of every
 * byte between "$" and "*", GGA/RMC/GSA field numbering per that page;
 * gpsd's JSON (https://gpsd.gitlab.io/gpsd/gpsd_json.html): TPV mode
 * 0..3 with only class and mode guaranteed, SKY's hdop and uSat. */

/* ── NMEA 0183 ─────────────────────────────────────────────────── */

#define NMEA_MAX_LINE 82        /* "$" .. CRLF inclusive, per the spec */

/* The receiver's state as GGA, RMC and GSA sentences merge into it.
 * -1 means "no sentence has said". A GGA or RMC with empty position
 * fields, an RMC with status V, or a GGA with quality 0 clears
 * valid_lat_lon: the receiver is telling us it has no fix. A GSA never
 * clears it: from NMEA 4.10 a multi-GNSS receiver sends one GSA per
 * constellation, and a constellation contributing nothing says mode 1
 * while the combined fix stands. */
typedef struct {
    int      valid_lat_lon;
    double   lat, lon;          /* decimal degrees, N and E positive */
    int      has_alt;
    double   alt_m;             /* GGA field 9, MSL */
    int      quality;           /* GGA field 6: 0 none, 1 GPS, 2 DGPS, 3 PPS,
                                 * 4 RTK, 5 float RTK, 6 estimated, 7 manual,
                                 * 8 simulation; -1 no GGA yet */
    int      sats;              /* GGA field 7; -1 unknown */
    int      has_hdop;
    double   hdop;              /* GGA field 8 or GSA field 16 */
    int      rmc_status;        /* 'A' valid, 'V' warning, 0 no RMC yet */
    int      gsa_mode;          /* GSA field 2: 1 none, 2 2D, 3 3D; 0 no GSA */
    long     utc_hms;           /* hhmmss of the newest GGA/RMC, -1 unknown */
    long     utc_dmy;           /* ddmmyy of the newest RMC, -1 unknown */
    int      pos_new;           /* 1 when the sentence last merged carried a
                                 * position itself (GGA quality > 0 or RMC A
                                 * with coordinates); a GSA never does, so it
                                 * cannot re-stamp an older GGA/RMC position */
} nmea_fix_t;

void nmea_fix_init(nmea_fix_t *f);

/* 1 when line[0..n) is "$...*hh" with a correct checksum (a trailing
 * CR/LF is ignored), 0 otherwise. */
int  nmea_checksum_ok(const char *line, size_t n);

/* Merge one sentence into *f. 1 for a GGA, RMC or GSA that merged, 0 for
 * a well-formed sentence of another type (ignored), -1 for a malformed
 * one: no "$", no "*hh", a bad checksum, over NMEA_MAX_LINE bytes, or a
 * position field that does not parse. Talker is ignored (GP, GN, GL,
 * GA, GB, BD, GQ, GI all match on the three-letter type). Never calls
 * strtod: the digit walk is locale-free. */
int  nmea_parse(const char *line, size_t n, nmea_fix_t *f);

/* 1 when *f is a position sloth may stamp: a valid lat/lon and a fix
 * quality 1..5 (6 estimated / dead reckoning, 7 manual and 8 simulation
 * are reported but never a fix), or, with no GGA seen, an RMC status A
 * or a GSA 2D/3D mode. */
int  nmea_fix_usable(const nmea_fix_t *f);

/* Horizontal error estimate from HDOP: HDOP x 5 m, the usual UERE
 * figure for a civilian receiver. An estimate, documented as such. */
double nmea_acc_m(double hdop);

/* ── gpsd JSON ─────────────────────────────────────────────────── */

#define GPSD_MAX_LINE 10240

enum { GPSD_CLS_OTHER = 0, GPSD_CLS_TPV, GPSD_CLS_SKY, GPSD_CLS_VERSION,
       GPSD_CLS_GST };

/* One entry of SKY's satellites[] (2026-11-02). PRN is the only member
 * gpsd always writes; -1 / has_* 0 mark the rest absent. */
#define GPSD_MAX_SATS GNSS_MAX_SATS
typedef struct {
    int     prn, gnssid, svid, sigid, health;
    double  el, az, cn0;
    uint8_t used, has_el, has_az, has_cn0;
} gpsd_sat_t;

typedef struct {
    int    cls;                 /* GPSD_CLS_* */
    int    mode;                /* TPV: 0 unknown, 1 none, 2 2D, 3 3D; -1 absent */
    int    has_lat, has_lon, has_alt, has_eph, has_epx, has_epy, has_hdop,
           has_usat;
    double lat, lon, alt_m;     /* alt: altMSL, else altHAE */
    double eph, epx, epy;       /* metres */
    double hdop;                /* SKY */
    int    usat;                /* SKY: satellites used */
    char   time[32];            /* TPV / SKY / GST "time", "" absent */
    /* GNSS observation (2026-11-02). TPV: */
    int    has_speed, has_track, has_climb, has_epv, has_eps;
    double speed, track, climb, epv, eps;
    int    status;              /* TPV status 0..9, -1 absent */
    int    jam;                 /* u-blox jamming indicator, -1 absent */
    int    leap;                /* leapseconds, -1 absent */
    /* SKY: */
    int    has_sats;            /* the satellites key was present (an empty
                                 * array is a sky with nothing in it, not a
                                 * DOP-only SKY) */
    int    has_nsat, nsat;
    int    has_pdop, has_vdop, has_gdop, has_tdop;
    double pdop, vdop, gdop, tdop;
    int    nsats;               /* entries kept in sats[] */
    int    sats_overflow;       /* entries past GPSD_MAX_SATS, not kept */
    gpsd_sat_t sats[GPSD_MAX_SATS];
    /* GST (error statistics): rms, the error ellipse, the sigmas; -1 absent. */
    double gst_rms, gst_major, gst_minor, gst_orient;
    double gst_lat, gst_lon, gst_alt;
} gpsd_msg_t;

/* One line of gpsd's stream. 1 for a TPV, SKY, GST or VERSION object, 0
 * for any other well-formed object (DEVICES, WATCH, ...), -1 when the
 * line is not a JSON object, is unbalanced, or is over GPSD_MAX_LINE.
 * Unknown keys are skipped; nested arrays and objects are skipped by
 * depth except SKY's satellites[], whose flat objects are read into
 * sats[] (a member of another type, or a nested value inside one, is
 * skipped the same way). Tolerant of key order. */
int  gpsd_json_parse(const char *line, size_t n, gpsd_msg_t *out);

/* gpsd's "time": strict ISO 8601 UTC, YYYY-MM-DDTHH:MM:SS[.fff]Z, digit
 * walk, no strptime and no locale. 0 with unix milliseconds in
 * *epoch_ms (the fraction truncated to ms), -1 for anything else: a
 * missing Z, an offset, a field out of range, a year outside 1970..2999. */
int  gpsd_time_parse(const char *s, int64_t *epoch_ms);

/* "GPS", "SBAS", "Galileo", "BeiDou", "IMES", "QZSS", "GLONASS", "NavIC"
 * for gpsd's gnssid 0..7; "?" otherwise (-1: an NMEA-only gpsd). */
const char *gnss_name(int gnssid);

/* ── Line framing ──────────────────────────────────────────────
 * Both sources are line-oriented (NMEA CRLF, gpsd LF). The reader hands
 * raw bytes here; each complete line is parsed, counted and fed into
 * the arbitration state below. A line longer than the source's maximum
 * is counted as a parse error and discarded up to its newline. Pure but
 * for the state feed, so the tests and the fuzz harnesses drive it with
 * hand-built bytes and no device. */

enum { GPS_FEED_NMEA = 1, GPS_FEED_GPSD };

typedef struct {
    int        kind;            /* GPS_FEED_* */
    size_t     len;
    int        overlong;        /* discarding to the next newline */
    nmea_fix_t nmea;            /* merged receiver state (NMEA only) */
    char       buf[GPSD_MAX_LINE + 1];
    gpsd_msg_t msg;             /* the parse scratch (~2.5 KB of satellites):
                                 * per framer, so two readers cannot share
                                 * one, and off the reader's stack */
} gps_lines_t;

void gps_lines_init(gps_lines_t *l, int kind);
void gps_lines_feed(gps_lines_t *l, const uint8_t *data, size_t n, time_t wall);

/* ── The --gps SPEC ────────────────────────────────────────────── */

enum { GPS_SPEC_SERIAL = 1, GPS_SPEC_GPSD };

typedef struct {
    int  kind;                  /* GPS_SPEC_* */
    char path[256];             /* serial device */
    char host[64];              /* gpsd: a numeric address, never a name */
    int  port;
} gps_spec_t;

/* "/dev/ttyUSB0" (anything starting with '/') or "gpsd://[HOST[:PORT]]".
 * HOST is a numeric literal ("127.0.0.1", "[::1]") — sloth resolves no
 * name for it — and defaults to 127.0.0.1; PORT defaults to 2947. 0, or
 * -1 with a reason in err. */
int  gps_spec_parse(const char *spec, gps_spec_t *out, char *err, size_t errsz);

/* 1 when a gpsd spec names a host other than loopback, 0 for loopback
 * or a serial spec. */
int  gps_spec_is_remote(const gps_spec_t *sp);

/* "nmea:/dev/ttyUSB0" / "gpsd:127.0.0.1:2947", as sensor_health and the
 * stamps name the source. */
void gps_spec_label(const gps_spec_t *sp, char *out, size_t outsz);

/* The startup announcement for a parsed spec, naming what is actually
 * opened or dialled (a bare "gpsd://" says 127.0.0.1:2947), not the
 * operator's spelling of it. */
void gps_spec_announce(const gps_spec_t *sp, char *out, size_t outsz);

/* ── Arbitration state ─────────────────────────────────────────── *
 * All under one mutex: the reader thread feeds, the main thread reads. */

/* Validate and set the fixed sensor position. lat in [-90,90], lon in
 * [-180,180], alt in [-1000,20000] when has_alt. 0, or -1 with err. */
int  gps_location_set_fixed(double lat, double lon, double alt_m, int has_alt,
                            char *err, size_t errsz);

/* Parse "LAT,LON[,ALT]" the way --location takes it, then set. */
int  gps_location_parse_fixed(const char *arg, char *err, size_t errsz);

/* Declare a --gps reader and its label; the state is SEARCHING until a
 * usable fix arrives. */
void gps_location_set_gps(const char *label);

/* The reader's feeds. A usable NMEA fix or a TPV with mode >= 2 and a
 * position becomes the newest fix, reported with wall time `wall` and
 * aged on sloth_mono_ms() at its receipt; anything else only moves the
 * counters and the satellite / HDOP figures. A position outside
 * -90..90 / -180..180 or not finite is ignored entirely; an accuracy
 * (eph, hypot(epx, epy), HDOP x 5) outside 0..1e5 m or an altitude
 * outside -1000..20000 m, or either not finite, is dropped from the fix
 * (has_acc / has_alt 0) rather than recorded. */
void gps_location_feed_nmea(const nmea_fix_t *f, time_t wall);
void gps_location_feed_gpsd(const gpsd_msg_t *m, time_t wall);
/* The same, with the host's wall clock in milliseconds at the moment the
 * line was framed (sloth_wall_ms()), which the clock offset is measured
 * against; gps_location_feed_gpsd() passes wall x 1000. */
void gps_location_feed_gpsd_ms(const gpsd_msg_t *m, int64_t wall_ms);

/* The reader lost its source (EOF, read error, unplugged device, gpsd
 * hung up): the fix ends now rather than after gps.max_fix_age_s. */
void gps_location_source_lost(void);
void gps_location_note(int sentences, int bad_checksum, int parse_errors,
                       int reconnects);
void gps_location_set_err(const char *err);     /* "" clears */

/* The stamp for `now`: GPS while the newest fix is at most
 * gps.max_fix_age_s old by sloth's monotonic clock (so a wall-clock
 * step cannot keep an old fix fresh), the fixed position otherwise, else
 * LOC_SRC_NONE with *out zeroed. Returns out->src. */
int  gps_location_current(loc_stamp_t *out, time_t now);

/* Fill s->gps for this tick (PH_PLATFORM, after the health polls). */
void gps_health_poll(sloth_state_t *s, time_t now);

/* Back to "nothing configured". Tests and sloth_reset_all(). */
void gps_location_reset(void);

/* ── GNSS observation (2026-11-02, docs/wiki/gnss.md) ──────────────
 * The sky and the newest fix as the module holds them, copied under the
 * lock. gps_health_poll() fills s->gnss_sky / s->gnss_fix with these. */
void gps_sky_snapshot(gnss_sky_t *out);
void gps_fix_snapshot(gnss_fix_t *out);

/* The history the GNSS rules read (gnss_hist_t, include/sloth.h): the
 * last GNSS_FIX_HIST positioned fixes and GNSS_SERIES_S one-second
 * points of (the tracked rows' median C/N0 and count, usat, nsat, jam,
 * mode). gps_health_poll() copies
 * it each poll and points s->gnss_hist at the copy; this is the same
 * copy, into the caller's buffer, for the tests. */
void gps_gnss_history(gnss_hist_t *out);

/* Change-only signatures, shared by the JSONL writer and the --db
 * writer so one bucketing rule decides when a GNSS record is news
 * (agents/AGENTS.md: a continuous value enters a signature as its
 * band, never itself). gps_gnss_fix_sig: mode, status, the used-count
 * band (gps_usat_band: 0, 1..3, 4..5, 6..7, >=8 - a solution-quality
 * band, because uSat flaps by one every few seconds on a moving or
 * urban receiver), nsat/4, the HDOP and PDOP bands (<1, <2, <5, >=5),
 * the clock-offset band as take_tpv() holds it with hysteresis (|off|
 * <500 ms, <2 s, <10 s, >=10 s, unknown; a band changes only once the
 * offset clears the edge by a quarter of it, since a 9600-baud
 * receiver's serial latency hovers around the first edge), the speed
 * band (<0.5, <2 m/s, <30, >=30), the jam band, has_pos.
 * gps_gnss_sat_sig: the row's identity, used, health, C/N0 to 6 dB,
 * elevation and azimuth to 15 degrees (absent as their own band).
 * gps_gnss_sky_sig: nsat/4, the used-count band, the DOP bands and the
 * mean-C/N0 band (<25, 25..35, >=35 dB-Hz). The per-row bands have no
 * hysteresis: a satellite sitting on a 6 dB or 15 degree edge writes a
 * line per pass until it moves off it, which is bounded (one row, one
 * line) and accepted (docs/wiki/gnss.md). */
uint64_t gps_gnss_fix_sig(const gnss_fix_t *f, const gnss_sky_t *k);
uint64_t gps_gnss_sat_sig(const gnss_sat_t *s);
uint64_t gps_gnss_sky_sig(const gnss_sky_t *k);
/* The bands themselves, for sensor_health's signature. */
int  gps_cn0_band(double cn0_mean);               /* -1 none, 0 <25, 1 <35, 2 >=35 */
int  gps_time_off_band(int has, long long off_ms); /* -1 unknown, 0..3: the raw band, no hysteresis */
int  gps_jam_band(int jam);                        /* -1 absent, 0 none, 1 light, 2, 3 */
int  gps_usat_band(int usat);                      /* -1 unknown, 0 none, 1 <4, 2 <6, 3 <8, 4 >=8 */
/* How many TPVs without `jam` keep the last reported value: gpsd
 * attaches jam only to the TPV after a UBX-MON-HW poll (one in five to
 * seven on the reference u-blox 7), so a per-TPV reading would flip
 * -1 / value every second and sign a record each tick. */
#define GNSS_JAM_HOLD_TPVS 10

/* The newest raw fix, fresh or not, for the position sampler and the
 * tests: 1 when one exists (lat/lon/acc/ts filled), 0 before any. */
int  gps_location_last_fix(loc_stamp_t *out);

/* Great-circle distance in metres (haversine on the WGS84 mean radius):
 * the position sampler's movement test. */
double gps_distance_m(double lat1, double lon1, double lat2, double lon2);

/* Initial great-circle bearing from point 1 to point 2, degrees true
 * clockwise from north in [0, 360): the direction to steer at point 1,
 * which changes along a great circle and is not the bearing back
 * reversed. Beside gps_distance_m() because the pair is what a sensor
 * needs to say where something it hears is ([^] ADS-B, 2026-11-07).
 *
 * Three degenerate cases, each a real answer rather than a failure, and
 * each pinned in tests/test_gps.c:
 *   - identical points: 0 (no direction exists; north is the
 *     convention, and atan2(0, 0) gives it without a branch);
 *   - antipodal points: every great circle between them is a shortest
 *     path, so the value is whichever one the formula picks (90 on the
 *     equator, 180 from the north pole) — not meaningless, just not
 *     unique;
 *   - a longitude difference past +/-180 (either side of the dateline)
 *     needs no normalising: sin and cos of the difference are periodic,
 *     so 179.5E -> 179.5W reads 90, due east, as it should. */
double gps_bearing_deg(double lat1, double lon1, double lat2, double lon2);

/* Fixed-point decimal of v with `decimals` places (0..9), written
 * without printf's %f, which honours LC_NUMERIC: the TUI calls
 * setlocale(LC_ALL, "") and a decimal-comma locale would corrupt every
 * JSON consumer. */
void gps_fmt_fixed(char *out, size_t outsz, double v, int decimals);

/* "gps" / "fixed" / "" for a loc_src_t. */
const char *gps_loc_src_name(int src);

/* `"loc":{"lat":..,"lon":..[,"alt_m":..][,"acc_m":..],"src":"gps"|"fixed","ts":N}`
 * into out, with no leading comma, for the JSONL alert records and the
 * evidence manifest line. Writes "" and returns 0 for LOC_SRC_NONE: an
 * unstamped record carries no `loc` key at all. Otherwise the length. */
int  gps_loc_json(const loc_stamp_t *l, char *out, size_t outsz);

/* One human line for a stamp, for the TUI's alert detail:
 * "51.5007400, -0.1246900  +/-8 m  alt 12 m  (gps, fix 3 s before)" or
 * "(fixed)" for a --location. "" for LOC_SRC_NONE. `opened` is the
 * incident's open time, which the fix's age is reported against. */
void gps_loc_text(const loc_stamp_t *l, time_t opened, char *out, size_t outsz);

/* State names for sensor_health and the strip: "none", "fixed",
 * "searching", "fix", "stale". */
const char *gps_state_name(int state);

#endif /* SLOTH_GPS_H */
