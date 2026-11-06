/* slothweb's /api/radar (2026-11-06, the Radar view, docs/web-ui-spec.md
 * §8.14): the Wi-Fi and BLE distance-band census the dome draws as
 * rings. A single passive sensor has no bearing for a terrestrial
 * emitter (web_frrs_report.c, src/position_track.h), so the page draws
 * one translucent ring per band, counted, rather than a mark per
 * device; and since /api/ble?limit=1024 answers 62.8 KB with more:true
 * and /api/wifi/aps 57 KB, counting bands on the page would be a dozen
 * pages every 30 s. This route counts them on the server, in one small
 * answer:
 *
 *   {"now":N,
 *    "ble":{"total","estimated","none",
 *           "bands":{"immediate":{"n","devs":[≤8 {addr,addr_type,iface,name,rssi,last_seen}]},
 *                    "near":..,"room":..,"building":..,"far":..}} | null,
 *    "wifi":{"total","estimated","none",
 *            "bands":{..same five.. devs:[≤8 {mac,kind:"ap"|"sta",ssid,rssi,ts}]}} | null}
 *
 * total is every row the table holds, estimated the rows with one of
 * sloth's five band words (src/rf_distance.h: immediate < 1 m, near
 * < 3 m, room < 10 m, building < 30 m, far beyond), none the rows with
 * a signal reading and no estimate (the TUI's "-": never 0, never a
 * band). devs lists each band's WEB_RADAR_DEVS strongest-signal rows
 * (the panel says "8 of 31"); a row without a reading sorts last. The
 * BLE half walks web_ble_t.dev[] under its mutex (a row per advertiser
 * as one sensor heard it, as every BLE answer counts), the Wi-Fi half
 * the FRRS ledger through web_frrs_rf_census(). A name is cut to
 * WEB_RADAR_NAME_MAX octets on a code-point boundary: the dome's panel
 * is a label, and the family's own tab has the whole string. Either
 * half is null when its table is not attached.
 *
 * The receivers are passive radio, so the route is Monitor's and
 * Hybrid's; under Local the query is checked, then the one out_of_scope
 * answer (route_ble's pattern, web_routes.c). The route takes no
 * parameter: any is a 400. */
#ifndef SLOTHWEB_RADAR_H
#define SLOTHWEB_RADAR_H

#include <stddef.h>

#include "web_ble.h"
#include "web_frrs.h"

#define WEB_RADAR_DEVS      8
#define WEB_RADAR_NAME_MAX  24
#define WEB_RADAR_BANDS     5

/* The body into body (cap bytes), *status set; 0, or -1 when even an
 * error did not fit. none_here (Local): the query is checked and a 200
 * of length 0 answered, for the router's out_of_scope body. b and f
 * may each be NULL. */
int    web_radar_route(web_ble_t *b, web_frrs_t *f, const char *query, long long now_s,
                       int none_here, char *body, size_t cap, size_t *len, int *status);

/* The Local answer's body: its length, 0 when it did not fit. */
size_t web_radar_out_of_scope_json(char *body, size_t cap);

#endif
