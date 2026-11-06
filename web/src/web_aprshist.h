/* slothweb's APRS history (2026-11-05, docs/wiki/aprs.md): the stations
 * the --aprs decoder has heard over time, read from sloth.db, beside the
 * live panel web_aprs.h keeps in memory.
 *
 * sloth's --db writer records one aprs_stations inventory row per
 * source callsign ever heard and one aprs_packets row per packet
 * (schema v13). These routes read them through the M4 allow-list
 * (web_slothdb.h), inside the request budget:
 *
 *   /api/aprs/seen?days=&limit=&offset=&q=
 *                                  the inventory rows last heard in the
 *                                  window, newest first, a page at a
 *                                  time (WEB_APRSHIST_SEEN_MAX), q a
 *                                  callsign prefix of [0-9A-Za-z-]
 *   /api/aprs/station?call=&days=  one station's inventory row and its
 *                                  packets over the window, oldest
 *                                  first, the newest
 *                                  WEB_APRSHIST_PKTS_MAX, as compact
 *                                  rows named by "cols"
 *
 *   /api/aprs/tracks?hours=        the Radar's APRS entities (2026-11-06):
 *                                  stations, and objects and items as
 *                                  entities of their own keyed by name,
 *                                  heard in the last hours (1..24,
 *                                  default 24), newest first, each with
 *                                  its newest packet's time, its newest
 *                                  position, motion, status and comment,
 *                                  and for a moving one its trail of at
 *                                  most WEB_SDB_APRS_TRK_PTS bucketed
 *                                  points ([ts, lat, lon], oldest first)
 *
 * days is 1..400 (default 7). A sloth.db older than the tables answers
 * an empty list with "have":false, never an error. Scope: the decoder's
 * receiver is a passive radio (Monitor's and Hybrid's; route_m5 answers
 * Local out_of_scope with the query checked).
 *
 * Every answer is built in the connection's 64 KB output buffer
 * (web_server.h WEB_SSE_MAX_UNSENT), and an APRS row carries free text a
 * transmitter chose, each byte of which can cost a six-byte escape. So
 * the lists are budgeted in bytes as well as rows: the inventory stops
 * before a row that might not fit ("more", and the page continues from
 * offset = rows shown); a station's packets are measured from the
 * newest back and the oldest that do not fit are left out ("cut"). The
 * inventory's comment is cut to WEB_APRSHIST_SEEN_CM. */
#ifndef SLOTHWEB_APRSHIST_H
#define SLOTHWEB_APRSHIST_H

#include <stddef.h>

#include "web_devices.h"

#define WEB_APRSHIST_DAYS_MAX   400
#define WEB_APRSHIST_SEEN_MAX   100
#define WEB_APRSHIST_SEEN_CM    48
#define WEB_APRSHIST_OFFSET_MAX 100000
#define WEB_APRSHIST_PKTS_MAX   400
#define WEB_APRSHIST_Q_MAX      9
/* The largest inventory row (every text at its cap, each byte a
 * six-byte escape), and the bytes kept back for the answer's close. */
#define WEB_APRSHIST_ROW_WORST  1700
#define WEB_APRSHIST_TAIL       4096
/* /api/aprs/tracks: the entities read at most, the window's hours, and
 * the scratch an entity is measured in before it is written (its worst:
 * every text a six-byte escape, 48 points). */
#define WEB_APRSHIST_TRK_MAX    300
#define WEB_APRSHIST_TRK_HOURS  24
#define WEB_APRSHIST_TRK_POINTS 48
#define WEB_APRSHIST_TRK_WORST  6144

int web_aprs_seen_route(const web_m4_t *m, const char *query, long long now_s,
                        char *body, size_t cap, size_t *len, int *status);
int web_aprs_station_route(const web_m4_t *m, const char *query, long long now_s,
                           char *body, size_t cap, size_t *len, int *status);
/* Entities newest first while a worst-case one still fits the buffer;
 * "cut" when the read held more than WEB_APRSHIST_TRK_MAX or the budget
 * stopped the list. A stationary entity's trail is [] (its position is
 * its lat/lon). */
int web_aprs_tracks_route(const web_m4_t *m, const char *query, long long now_s,
                          char *body, size_t cap, size_t *len, int *status);

#endif /* SLOTHWEB_APRSHIST_H */
