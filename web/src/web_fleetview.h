/* The merged views (owner request 2026-11-11, "combine data from all
 * sloth hosts in the web ui make non local devices and data show in a
 * grey state"; docs/wiki/fleet.md "The merged views"): the WiFi Devices
 * list, the AP table and the BLE advertisers gain what the peers sent
 * (web_fleet.h's peer_sightings), and the device and BLE drawers answer
 * for an address only a peer heard.
 *
 *   /api/devices      kind wifi, keyed by the client's MAC
 *   /api/wifi/aps     kind ap, keyed by the BSSID
 *   /api/ble          kind ble, keyed by the address
 *   /api/device/{mac} kind wifi, then ap
 *   /api/ble/{addr}   kind ble
 *
 * A list answer's local rows are the route's own, byte for byte, and
 * one that a peer also reported gains "sites": [{site, first_seen,
 * last_seen, label}] of each peer that did (label: the site's own
 * name from peer_sites, null when it sent none). The peers' other keys follow the
 * local rows on the page that ends the local list (the one answering
 * "more": false), as rows with "remote": true, "site" (the peer that
 * heard it last) and "sites", holding only what peer_sightings holds
 * under the route's own member names: a member a peer cannot supply is
 * absent, never made up. A key this sensor holds anywhere (sloth.db's
 * devices or beacon_aps, the BLE table), whether or not this page or
 * this filter shows it, is never a remote row. At most
 * WEB_FV_REMOTE_MAX remote rows an answer, sorted by the route's own
 * sort among themselves, a column a peer cannot supply read as empty
 * (last, then by last seen); a filter's term a peer row cannot answer
 * (ip, name, risk, z, src, has, anomaly, pass) leaves the remote rows
 * out and says so. The answer's top-level "fleet" member says what was
 * done: the peers, the remote rows and whether more were cut
 * ("remote_more"), the cap, and why none were added ("remote_off").
 *
 * Remote rows are display only. They are added after the route has
 * answered and feed nothing: no risk, alert, anomaly, baseline, series,
 * triage, tile count, detail audit, and never /api/fleet/export (which
 * reads sloth.db and the BLE table, never peer_sightings, so a peer's
 * rows never echo back to it).
 *
 * The router (web_routes.c) takes fleet= out of the query before the
 * route's own parser sees it, as it does scope=: fleet=0 answers the
 * route's own bytes exactly, fleet=1 and no fleet= merge. Nothing is
 * merged without a configured --peer, under a capture scope other than
 * Hybrid (a peer row carries no capture path), or in a build without
 * SQLite (there is no store to read).
 *
 * Every peer string (label, vendor) is untrusted: it came over the
 * network from another slothweb. It is JSON-escaped on the way out by
 * web_jw_str()/web_jw_ssid() and the page sets it with textContent. */
#ifndef SLOTHWEB_FLEETVIEW_H
#define SLOTHWEB_FLEETVIEW_H

#include <stddef.h>

#include "web_scope.h"

struct web_fleet;
struct web_slothdb;
struct web_ble;

/* Remote rows an answer at most; the peer rows of a kind read, newest
 * first (more are left unread, "partial"). */
#define WEB_FV_REMOTE_MAX 100
#define WEB_FV_SCAN       4000

/* fleet= in a query: absent, fleet=1, fleet=0. */
enum { WEB_FV_DEFAULT = 0, WEB_FV_ON, WEB_FV_OFF };
/* The merged lists. */
enum { WEB_FV_DEVICES = 0, WEB_FV_APS, WEB_FV_BLE };

/* query with its fleet=... pair taken out into rest (the other pairs
 * byte for byte, as web_scope_take() leaves them), *mode set. 0, or -1
 * with a reason word in err ("repeated_parameter", "bad_fleet",
 * "empty_value", "bad_query", "query_too_long"). */
int  web_fv_take(const char *query, char *rest, size_t restsz, int *mode,
                 char *err, size_t errsz);

/* Whether an answer merges: mode not off, a peer configured, the
 * request Hybrid (sc NULL or Hybrid). */
int  web_fv_on(const struct web_fleet *f, int mode, const web_scope_ctx_t *sc);

typedef struct {
    struct web_slothdb *sdb;       /* which keys this sensor holds */
    struct web_ble     *ble;
} web_fv_src_t;

/* A list route's 200 answer (body, *len bytes of cap) with the peers'
 * rows merged in place; query is the route's own (fleet= taken out).
 * An answer it cannot read as the route's shape, or that would not fit
 * with even the "fleet" member, is left as it was. */
void web_fv_list(struct web_fleet *f, const web_fv_src_t *src, int view,
                 const char *query, long long now_s, char *body, size_t cap,
                 size_t *len);

/* A drawer's answer: /api/device/{mac} (ble 0) or /api/ble/{addr}
 * (ble 1), path_key the path's segment as it came. Where a peer
 * reported the address, a "fleet" member with each peer's row; where
 * this sensor has no record of it (device: "record" null; BLE: the
 * route's 404), "remote": true and the note "seen at NAME[, NAME...]",
 * each the host's label from peer_sites, else its --peer name; the BLE
 * 404 becomes a 200 with no local row. */
void web_fv_detail(struct web_fleet *f, int ble, const char *path_key,
                   long long now_s, char *body, size_t cap, size_t *len,
                   int *status);

#endif
