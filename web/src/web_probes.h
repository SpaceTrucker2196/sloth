/* slothweb: the Probes view (owner request 2026-11-11: "a separate
 * probes tab that shows clients searching for ssid's. associating these
 * with clients or other devices where possible keep track of ssid's and
 * look for devices probing for the same ssids").
 *
 * Everything here is read from sloth.db through the M4 reader and its
 * column allow-list (web_slothdb.h): no column was added to it, no
 * table is written, and nothing is kept in slothweb.db, so the view is
 * whatever sloth.db retains, across restarts of either process. What
 * sloth records about a probe request, and so what these routes can
 * say:
 *
 *   probe_clients  one row a station heard probing: its latest directed
 *                  SSID, signal, channel, first and last seen, and
 *                  frame_count, every probe request sloth counted for it
 *                  (directed and wildcard together)
 *   pnl_clients    one row a station that sent a directed probe:
 *                  probe_count (directed probes only), sloth's OS and
 *                  PHY labels, first and last seen
 *   pnl_ssids      one row per (station, SSID) it asked for by name; a
 *                  wildcard probe names none and has no row
 *   assocs         an association seen for the station
 *   seqnum_correlations
 *                  two MACs whose 802.11 sequence counters ran on from
 *                  one another: sloth's hypothesis that one radio sent
 *                  both, never an identification
 *
 * sloth keeps no count of wildcard probes: frame_count and probe_count
 * are two tables' own counters with their own lifetimes, so their
 * difference is not one. The routes give both and name each.
 *
 *   /api/probes/clients?days=&sort=&limit=&offset=
 *       every station in probe_clients or pnl_clients last seen in the
 *       window: its named SSIDs (the newest WEB_PROBE_ROW_SSIDS and the
 *       count), frames and directed probes, signal, channel, first and
 *       last seen, vendor, the 24 h presence strip, whether sloth.db
 *       holds a devices row for the MAC, its newest association, and
 *       its seqnum correlations. sort is last (default), first, ssids,
 *       frames, signal or mac.
 *   /api/probes/ssids?days=&sort=&limit=&offset=
 *       every SSID asked for by name in the window: how many stations
 *       ask for it and how many of those MACs are randomised, how many
 *       BSSIDs beacon it and the strongest of them, first and last seen.
 *       sort is clients (default), last, first or ssid.
 *   /api/probes/shared?mac=&days=&min=
 *       the stations whose named SSIDs overlap mac's, ranked.
 *   /api/probes/groups?days=&min=
 *       the sets of stations linked by shared uncommon SSIDs.
 *
 * The similarity (shared and groups), over the window's rows:
 *
 *   N        the stations that sent a directed probe (pnl_clients)
 *   df(s)    the stations asking for SSID s (pnl_ssids)
 *   w(s)     ln(N / df(s)): an SSID everyone asks for weighs 0
 *   uncommon 2 <= df(s) <= U, U = N / 20 kept within 2..16
 *   sim(A,B) the sum of w over the SSIDs both ask for, over the sum of w
 *            over the SSIDs either asks for (0 when that is 0)
 *
 * and a pair counts only when it shares at least `min` (default 2,
 * 1..8) uncommon SSIDs. It says two stations probe for the same
 * networks. It does not say they have one owner: a household, an
 * office and a conference each produce it.
 *
 * days is 0 (everything sloth.db retains) or 1..400, default 30. Every
 * read runs under the request's budget (WEB_SDB_HTTP_MS); the caps are
 * the constants below, and an answer that met one says so with the
 * whole count beside the shown one. Parameters are validated whole; a
 * refusal is a 400 with a reason word of slothweb's own. The router
 * answers out_of_scope under Local: all of it is the monitor radio's. */
#ifndef SLOTHWEB_PROBES_H
#define SLOTHWEB_PROBES_H

#include <stddef.h>

#include "web_devices.h"

#define WEB_PROBE_LIMIT     50
#define WEB_PROBE_MAX       100
#define WEB_PROBE_ROW_SSIDS 16
#define WEB_PROBE_SIBLINGS  3
#define WEB_PROBE_SEQ_READ  20000
#define WEB_PROBE_DAYS      30
#define WEB_PROBE_DAYS_MAX  400

/* The similarity's bounds: the SSIDs read for one station, the
 * candidates ranked and shown, the uncommon cut's range, the minimum
 * shared; the groups' stations, uncommon SSIDs, pairs, and what one
 * answer lists. */
#define WEB_PROBE_SET       64
#define WEB_PROBE_CANDS     1024
#define WEB_PROBE_SHOWN     50
#define WEB_PROBE_U_MIN     2
#define WEB_PROBE_U_MAX     16
#define WEB_PROBE_U_SHARE   20
#define WEB_PROBE_MIN       2
#define WEB_PROBE_MIN_MAX   8
#define WEB_PROBE_G_MACS    4096
#define WEB_PROBE_G_SSIDS   8192
#define WEB_PROBE_G_PAIRS   65536
#define WEB_PROBE_G_SHOWN   40
#define WEB_PROBE_G_MEMBERS 12
#define WEB_PROBE_G_NAMES   8

/* The uncommon cut for n stations, and w(s) for df of n. */
int    web_probe_u(long long n);
double web_probe_weight(long long n, long long df);

int web_probes_clients_route(const web_m4_t *m, const char *query, long long now_s,
                             char *body, size_t cap, size_t *len, int *status);
int web_probes_ssids_route(const web_m4_t *m, const char *query, long long now_s,
                           char *body, size_t cap, size_t *len, int *status);
int web_probes_shared_route(const web_m4_t *m, const char *query, long long now_s,
                            char *body, size_t cap, size_t *len, int *status);
int web_probes_groups_route(const web_m4_t *m, const char *query, long long now_s,
                            char *body, size_t cap, size_t *len, int *status);

#endif
