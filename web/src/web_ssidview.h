/* slothweb: one SSID's detail (owner request 2026-11-11: "on the wifi
 * tab we should be able to select any ssid and get a detail view just
 * like we do for a client").
 *
 * Read from sloth.db through the M4 reader and its column allow-list
 * (web_slothdb.h): no column was added to it, no table is written, and
 * nothing is kept in slothweb.db.
 *
 * An SSID is 0..32 octets, not text (web_ssid.h), and a route parameter
 * is 1..63 bytes of printable ASCII (web_series.h), so an SSID travels
 * as `ssid=` the base64url (RFC 4648 section 5, no padding) of its
 * octets, 1..43 characters, or `-` for the empty SSID (a hidden
 * network's). The page computes it from the display form the server
 * sent, which reads back to one octet string only. It is bound as a
 * parameter and compared with `=`; it is never a LIKE pattern and never
 * part of a statement's text.
 *
 *   /api/wifi/ssid?ssid=
 *       the SSID in its display form with its colour and non-printable
 *       flag; the BSSIDs beaconing it now (beacon_aps, the newest
 *       WEB_SSID_BSSIDS) and those that did once (beacon_ap_ssids),
 *       each with vendor, channel, security, signal, first and last
 *       seen, its KARMA score and the twin links the stream made with it
 *       (web_chain.h); the stations associated to it (assocs) and those
 *       probing for it (pnl_ssids), WEB_SSID_ITEMS of each with the
 *       whole count; its 24 h presence strip (any current BSSID
 *       present); and the alerts of the last WEB_SSID_ALERT_DAYS days
 *       whose key names one of its current BSSIDs or the SSID itself
 *       (the key as src/alert_key.c akey_remote() writes an SSID), by
 *       the alert page's opaque id, read back a slice at a time for as
 *       long as the request's budget allows ("alerts_reached").
 *       "designated" is null: sloth's --my-ssid is its own
 *       configuration and reaches neither sloth.db nor the stream.
 *
 * beacon_aps.channel carries no band, so a 6 GHz channel reads as the
 * number alone, as the AP table's does. Every read runs under the
 * request's budget (WEB_SDB_HTTP_MS). The parameter is validated whole;
 * a refusal is a 400 with a reason word of slothweb's own. The router
 * answers out_of_scope under Local: all of it is the monitor radio's. */
#ifndef SLOTHWEB_SSIDVIEW_H
#define SLOTHWEB_SSIDVIEW_H

#include <stddef.h>

#include "web_devices.h"

#define WEB_SSID_OCTETS     32
#define WEB_SSID_BSSIDS     48
#define WEB_SSID_ITEMS      24
#define WEB_SSID_ALERTS     12
#define WEB_SSID_ALERT_DAYS 30

/* The `ssid=` parameter to octets: out holds WEB_SSID_OCTETS + 1 and is
 * NUL-terminated. The octet count (0 for "-"), or -1: not base64url,
 * not canonical, more than 32 octets, or a NUL octet (sloth.db's text
 * holds none). */
int web_ssid_param(const char *val, char *out);
/* The parameter for n octets into out (48 bytes): the inverse. */
void web_ssid_param_of(const char *ssid, size_t n, char *out);

int web_ssid_route(const web_m4_t *m, const char *query, long long now_s,
                   char *body, size_t cap, size_t *len, int *status);

#endif
