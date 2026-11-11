/* Aircraft across the owner's fleet (#192 I7; docs/wiki/fleet.md
 * "Aircraft across the sites", research/adsb/multi-receiver-verification.md):
 * each site's ADS-B receiver and the aircraft it heard, compared site
 * against site. slothweb fleet findings, not sloth alerts.
 *
 * The export (adsb=1, the whole export only; an I6 export refuses it and
 * the puller falls back for WEB_FA_NOADSB_S, as for gnss=1):
 *
 *   {"type":"adsb_rx",...}   the receiver: the decoder's source kind and
 *                            state, its aircraft and message counts and
 *                            messages/s between two summaries, and its
 *                            demonstrated coverage: every airborne
 *                            position sloth.db holds from the last
 *                            WEB_FA_COV_WINDOW_S, per 30-degree bearing
 *                            sector from the site's own position (the
 *                            header's), as the sector's reach (the median
 *                            of its hourly farthest, web_fa_cov_t) and the
 *                            farthest overall; r000 .. r330 metres, n000
 *                            .. n330 positions.
 *   {"type":"aircraft",...}  each adsb_aircraft row last seen at or after
 *                            max(since, now - WEB_FA_EXPORT_S), newest
 *                            first, at most WEB_FA_CAP_AIRCRAFT: the ICAO
 *                            address (the key), callsign, squawk,
 *                            category, emergency, the newest altitude,
 *                            ground speed, track, RSSI and messages, the
 *                            newest position of the current visit with
 *                            the bounds of its time (pos_prev, pos_ts:
 *                            web_sdb_acf_t), and first seen, the visit's
 *                            start and last seen.
 *
 * The end line then counts "aircraft" and says "truncated_aircraft",
 * which is true whenever the aircraft were not all read - cut, out of
 * budget, or not read at all (no sloth.db): an empty list is never
 * passed off as a complete one. No
 * cursor and no backfill: rows past the cap are older than the ones sent,
 * and the comparison needs the last WEB_FA_LIST_S only; a cut answer
 * makes its site undetermined over the time it covered instead.
 *
 * The store: peer_sightings kind "aircraft" (key the address, label the
 * callsign, vendor the category, extra the rest) and kind "adsb" (key
 * "receiver"); kept WEB_FA_KEEP_S and at most WEB_FA_ROWS_PER_PEER rows
 * a peer by the peer's clock; and meta "fleet.adsb.<peer>": the peer's
 * clock at its newest answer that carried aircraft, and at its newest
 * cut one. No schema step.
 *
 * The comparison (web_fa_classify()), per ICAO address over the
 * receivers, in this site's clock (a peer's less its skew):
 *   confirmed            two receivers heard it at overlapping times
 *                        (each [visit start, last seen + heartbeat]
 *                        within the window of the other's);
 *   unconfirmed          the reporting site's newest position lies inside
 *                        another receiver B's demonstrated coverage
 *                        (within WEB_FA_COV_K of B's reach in that
 *                        bearing sector, the sector held at least
 *                        WEB_FA_SECTOR_MIN positions) and inside
 *                        WEB_FA_COV_K of the radio horizon between B's
 *                        ground (no antenna height credited, B's own
 *                        altitude known) and the aircraft's altitude,
 *                        while B was answering (its data complete past
 *                        the window), not cut, and receiving other
 *                        aircraft (at least WEB_FA_HEALTH_MIN at each
 *                        end of the window), and B had not heard the
 *                        address since before the window less its
 *                        heartbeat. The window is WEB_FA_WINDOW_S about
 *                        the whole span [pos_prev, pos_ts] the
 *                        position's time may lie in;
 *   out_of_peer_coverage the same, but outside every B's coverage;
 *   undetermined         anything else, with the reason: one receiver
 *                        (single_receiver), no position, on the ground,
 *                        no altitude, B pending, cut, not receiving, B
 *                        heard it later, B with no position or no
 *                        altitude, B's rows cut short by a cap.
 * Never a false unconfirmed by construction: every reason B might have
 * heard it and the data not show it makes the address undetermined.
 * Separately, two receivers' positions for one address within
 * WEB_FA_PAIR_DT_S of each other that are further apart than the
 * aircraft could fly between them (its reported ground speed, knots, x
 * 1.25 + 30 m/s, else WEB_FA_VMAX_MS, times the longest the two times may
 * lie apart given each [pos_prev, pos_ts], plus WEB_FA_POS_TOL_M) are
 * flagged inconsistent. */
#ifndef SLOTHWEB_FLEETADSB_H
#define SLOTHWEB_FLEETADSB_H

#include "web_fleet.h"
#include "web_json.h"
#include "web_slothdb.h"

#define WEB_FA_SECTORS       12
#define WEB_FA_SECTOR_DEG    30
#define WEB_FA_COV_WINDOW_S  86400
#define WEB_FA_COV_ROWS      100000
#define WEB_FA_COV_HOURS     (WEB_FA_COV_WINDOW_S / 3600)
#define WEB_FA_EXPORT_S      (6 * 3600)
#define WEB_FA_CAP_AIRCRAFT  1000
#define WEB_FA_LIST_S        7200
#define WEB_FA_WINDOW_S      120
#define WEB_FA_HB_S          300        /* sloth's ADS-B write heartbeat (src/db.c) */
#define WEB_FA_LAG_S         30
#define WEB_FA_HEALTH_MIN    2
#define WEB_FA_SECTOR_MIN    10
#define WEB_FA_COV_K         0.8
#define WEB_FA_RX_AGL_M      10.0       /* the coverage filter only; the comparison credits none */
#define WEB_FA_ALT_CEIL_M    15240.0    /* 50,000 ft */
#define WEB_FA_POS_TOL_M     2000.0
#define WEB_FA_VMAX_MS       340.0
#define WEB_FA_PAIR_DT_S     600
#define WEB_FA_KEEP_S        (2LL * 86400)
#define WEB_FA_ROWS_PER_PEER 3000
#define WEB_FA_NOADSB_S      3600
#define WEB_FA_FRESH_S       660
#define WEB_FA_ROWS_MAX      8000
#define WEB_FA_LIMIT_DEF     100
#define WEB_FA_LIMIT_MAX     500
#define WEB_FA_SITES         (WEB_FLEET_PEERS + 1)

enum { WEB_FA_UNDETERMINED = 0, WEB_FA_CONFIRMED, WEB_FA_UNCONFIRMED,
       WEB_FA_OUT_OF_COVERAGE, WEB_FA_NVERDICT };
/* A receiver's state toward one address. */
enum { WEB_FA_B_NONE = 0, WEB_FA_B_HEARD, WEB_FA_B_SHOULD, WEB_FA_B_OUTSIDE,
       WEB_FA_B_LATER, WEB_FA_B_PENDING, WEB_FA_B_CUT, WEB_FA_B_QUIET,
       WEB_FA_B_NOPOS, WEB_FA_B_NOALT, WEB_FA_B_NOCOV, WEB_FA_B_REPORTER,
       WEB_FA_B_NOSITEALT, WEB_FA_B_NSTATE };

const char *web_fa_verdict_word(int v);
const char *web_fa_bstate_word(int s);

/* The geometry: the initial bearing from 1 to 2 (degrees, 0 north,
 * clockwise, [0, 360)), its sector (0 .. WEB_FA_SECTORS - 1), and the
 * radio horizon between two heights (metres; d = 4.12 (sqrt h1 + sqrt h2)
 * km, the 4/3-earth line-of-sight distance; a negative height is 0). */
double web_fa_bearing(double lat1, double lon1, double lat2, double lon2);
int    web_fa_sector(double bearing_deg);
double web_fa_horizon_m(double h1_m, double h2_m);

/* A receiver's demonstrated coverage. sec_m is each sector's reach: the
 * lower median, over the hours of the window that held a position in the
 * sector, of that hour's farthest - robust to a lone bad decode and to a
 * few hours of anomalous (ducted) propagation, either of which would
 * stretch a plain farthest and with it the reach a silence is judged
 * against. max_m is the plain farthest, for the plot's scale only. */
typedef struct {
    long long n;                       /* positions counted */
    int       complete;                /* the read ran to its end */
    double    max_m;
    double    sec_m[WEB_FA_SECTORS];
    long long sec_n[WEB_FA_SECTORS];
} web_fa_cov_t;
typedef struct {
    web_fa_cov_t c;                    /* n, sec_n, max_m as counted */
    double       hr_m[WEB_FA_SECTORS][WEB_FA_COV_HOURS];
} web_fa_covacc_t;
/* One position heard from a receiver at (rx_lat, rx_lon) `hour` hours
 * ago (clamped into the window): counted into its sector and hour,
 * unless not finite or beyond the horizon of an aircraft at
 * WEB_FA_ALT_CEIL_M (a decode no receiver could make). 1 counted. */
int  web_fa_cov_add(web_fa_covacc_t *a, double rx_lat, double rx_lon, double lat, double lon,
                    int hour);
void web_fa_cov_finish(const web_fa_covacc_t *a, web_fa_cov_t *out);

/* One site's view of one address, in this site's clock. */
typedef struct {
    int       present;
    long long first, visit_first, last;
    int       has_pos;
    double    lat, lon;
    long long pos_ts, pos_prev;        /* the position is from [pos_prev, pos_ts] */
    int       has_alt, alt_ft, on_ground;
    int       has_gs;
    double    gs_kt;
} web_fa_obs_t;

/* One site, as the comparison needs it. */
typedef struct {
    int             receiver;
    int             has_pos, has_alt;
    double          lat, lon, alt_m;
    long long       through;           /* its data complete through (0 none) */
    long long       cut_at;            /* its newest cut answer (0 none) */
    web_fa_cov_t    cov;
    int             nact;              /* every address it held: [vf, last] */
    const long long *act_a, *act_b;
} web_fa_site_t;

typedef struct {
    int       verdict;
    int       why;                     /* the B state that decided an undetermined */
    int       single;                  /* fewer than two receivers */
    int       ref;                     /* the site whose position was tested, -1 none */
    int       bstate[WEB_FA_SITES];
    double    dist_m[WEB_FA_SITES], sec_max_m[WEB_FA_SITES], horizon_m[WEB_FA_SITES];
    int       inconsistent, inc_a, inc_b;
    double    sep_m, allow_m;
} web_fa_verdict_t;

void web_fa_classify(const web_fa_site_t *sites, int n, const web_fa_obs_t *obs,
                     web_fa_verdict_t *out);

/* The export's receiver figures: the summary from the live stream's
 * ADS-B state (src->adsb) and the coverage from sloth.db (c, may be
 * NULL). messages/s from this summary and the one before it, when
 * 10 s .. 900 s apart. */
struct web_adsb;
typedef struct {
    int       seen;
    char      source[16], state[12];
    long long ts, aircraft, messages;
    int       has_rate;
    double    rate;
} web_fa_rx_t;
void web_fa_rx_read(struct web_adsb *a, web_fa_rx_t *o);
void web_fa_cov_read(web_sdb_conn_t *c, double rx_lat, double rx_lon, long long now_s,
                     web_fa_cov_t *o);

/* GET /api/fleet/aircraft?limit=N (100, 1..500). A heap body; 0 with
 * *status, -1 out of memory. */
int  web_fleet_aircraft_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                              long long now_s, char **body, size_t *len, int *status);
/* /api/fleet/overview's "aircraft": the receivers and the counts. */
void web_fa_overview_json(web_fleet_t *f, const web_fleet_src_t *src, long long now_s,
                          web_jw_t *w);

#endif
