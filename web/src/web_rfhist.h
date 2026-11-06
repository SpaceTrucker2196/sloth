/* slothweb's GNSS and ADS-B history (2026-11-05): what the receiver and
 * the decoder have seen over time, read from sloth.db, beside the live
 * panels web_gnss.h and web_adsb.h keep in memory.
 *
 * sloth's --db writer records one gnss_sightings row per satellite per
 * banded change or 300 s heartbeat (schema v10) and, with --adsb, one
 * adsb_aircraft inventory row per address ever listed and one
 * adsb_sightings row per meaningful change of an aircraft (schema v12,
 * the adsb_aircraft JSONL record's rule). These routes read them
 * through the M4 allow-list (web_slothdb.h), inside the request budget:
 *
 *   /api/gnss/seen?days=&limit=       one row per satellite seen in the
 *                                     window: first and last seen, the
 *                                     records, C/N0 max and mean, the
 *                                     share of records in the solution,
 *                                     the highest elevation
 *   /api/gnss/sat?gnssid=&prn=&days=  one satellite's records over the
 *                                     window (el, az, C/N0, used, health)
 *   /api/gnss/tracks?hours=           every satellite's (el, az) over the
 *                                     last hours (1..24, default 6), at
 *                                     most WEB_RFHIST_TRK_PTS a satellite:
 *                                     the sky plot's trails
 *   /api/adsb/seen?days=&limit=&offset=&q=
 *                                     the aircraft inventory rows last
 *                                     seen in the window, a page at a
 *                                     time, a hex or callsign prefix in q
 *   /api/adsb/aircraft?hex=&days=     one aircraft's inventory row and
 *                                     its sightings: its track and
 *                                     altitude profile
 *
 * days is 1..400 (default 1 for the sky, 7 for aircraft). A sloth.db
 * older than the table answers an empty list with "have":false, never
 * an error. Scope: the receiver is the host's own (every scope); the
 * decoder's SDR is a passive radio (Monitor's and Hybrid's; route_m5
 * answers Local out_of_scope with the query checked). */
#ifndef SLOTHWEB_RFHIST_H
#define SLOTHWEB_RFHIST_H

#include <stddef.h>

#include "web_devices.h"

#define WEB_RFHIST_DAYS_MAX    400
/* Every answer is built in the connection's 64 KB output buffer
 * (web_server.h WEB_SSE_MAX_UNSENT): a satellite row is some 230 bytes,
 * an aircraft row some 350 (the page walks the inventory with offset=),
 * a point some 40 (satellite) or 90 (aircraft, a compact array). */
#define WEB_RFHIST_SATS_MAX    160
#define WEB_RFHIST_AC_MAX      100
#define WEB_RFHIST_OFFSET_MAX  100000
#define WEB_RFHIST_PTS_MAX     400
/* Trails: a satellite's window in this many buckets, and a row cap
 * (some 16 bytes a point) that keeps 60-odd satellites inside 64 KB. */
#define WEB_RFHIST_TRK_PTS     32
#define WEB_RFHIST_TRK_ROWS    2400

int web_gnss_seen_route(const web_m4_t *m, const char *query, long long now_s,
                        char *body, size_t cap, size_t *len, int *status);
int web_gnss_sat_route(const web_m4_t *m, const char *query, long long now_s,
                       char *body, size_t cap, size_t *len, int *status);
int web_gnss_tracks_route(const web_m4_t *m, const char *query, long long now_s,
                          char *body, size_t cap, size_t *len, int *status);
int web_adsb_seen_route(const web_m4_t *m, const char *query, long long now_s,
                        char *body, size_t cap, size_t *len, int *status);
int web_adsb_aircraft_route(const web_m4_t *m, const char *query, long long now_s,
                            char *body, size_t cap, size_t *len, int *status);

#endif /* SLOTHWEB_RFHIST_H */
