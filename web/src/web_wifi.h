/* slothweb WiFi routes (#163, M5): docs/web-ui-spec.md §8.8's channel
 * waterfall, AP table and deauth timeline (§7 /api/wifi/channels,
 * /api/wifi/aps; /api/wifi/deauth is this milestone's).
 *
 *   /api/wifi/channels?metric=&from=&to=&cols=
 *       a channel x time grid of slothweb.db's wifi.ap_count (a gauge:
 *       each cell the mean of its buckets) or wifi.ctrl_total (a
 *       counter: each cell the sum), metric "ap_count" (default) or
 *       "ctrl_total". Rows are channels, 2.4 GHz first, then 5, then 6,
 *       then any sloth could not place ("?") ("band"), each band by
 *       channel number; at most WEB_WIFI_ROWS of
 *       them ("more" past that). Columns are cols (1..WEB_WIFI_COLS,
 *       default WEB_WIFI_COLS) cells of col_s seconds from from; an
 *       empty cell is null. The tier is the finest that covers the
 *       range: fine for at most 6 h inside the last 24 h, minute for at
 *       most 3 d inside --web-retain-days, hour beyond (minute and hour
 *       need the store; without it a range older than 24 h is a 400
 *       "tier_unavailable"). The keys are the rollup's and the store's
 *       for that tier and range, so a channel the rollup has evicted
 *       keeps its history.
 *   /api/wifi/deauth?from=&to=&cols=
 *       the deauth timeline: per bssid, wifi.deauth's frames summed per
 *       cell (the same grid and tiers), the WEB_WIFI_ROWS bssids with
 *       the most frames in the range first, each with the DEAUTH_FLOOD
 *       episodes sloth.db's alerts hold against it in the range
 *       ([first_seen, last_seen, sev, count], oldest first, at most
 *       WEB_WIFI_FLOODS); "db" says whether sloth.db was read.
 *   /api/wifi/aps?sort=&limit=&offset=
 *       sloth.db's beacon_aps through the M4 allow-list: SSID, channel,
 *       signal, the encryption and AKM sloth wrote and the AKM bits
 *       decoded to the 802.11 suite names (src/rsn_ie.c's), MFP, the
 *       downgrade flags decoded (include/sloth.h WPA_DG_*), WPS, the
 *       SSID history (beacon_ap_ssids, at most WEB_WIFI_SSIDS, newest
 *       first, with its count), and the KARMA score from
 *       karma_candidates where the AP is one. sort is last (default),
 *       ssids, karma or bssid; limit 1..WEB_WIFI_AP_MAX (default
 *       WEB_WIFI_AP_LIMIT) from offset; a page stops early with "more"
 *       rather than not fit.
 *
 * Parameters are validated whole, as /api/series's are (web_series.h);
 * a refusal is a 400 with a reason word of slothweb's own and never
 * echoes the value. */
#ifndef SLOTHWEB_WIFI_H
#define SLOTHWEB_WIFI_H

#include <stddef.h>

#include "web_devices.h"

#define WEB_WIFI_COLS     96
#define WEB_WIFI_ROWS     40
#define WEB_WIFI_FLOODS   8
#define WEB_WIFI_SSIDS    8
#define WEB_WIFI_AP_LIMIT 50
#define WEB_WIFI_AP_MAX   100
#define WEB_WIFI_SPAN_MAX (400LL * 86400)
/* The largest one AP row renders to: every text member at its cut
 * length escaped six-fold, every AKM name, WEB_WIFI_SSIDS SSIDs. */
#define WEB_WIFI_AP_ROW_MAX 7400

int web_wifi_channels_route(const web_m4_t *m, const char *query,
                            long long now_s, char *body, size_t cap,
                            size_t *len, int *status);
int web_wifi_deauth_route(const web_m4_t *m, const char *query,
                          long long now_s, char *body, size_t cap,
                          size_t *len, int *status);
int web_wifi_aps_route(const web_m4_t *m, const char *query, long long now_s,
                       char *body, size_t cap, size_t *len, int *status);

/* The 802.11 AKM suite name of type t (IEEE 802.11-2020 Table 9-151),
 * src/rsn_ie.c rsn_akm_name()'s, "?" when it names none. */
const char *web_akm_name(int t);
/* The name of downgrade bit b (0..3) of beacon_aps.downgrade_flags
 * (include/sloth.h WPA_DG_*), or NULL. */
const char *web_downgrade_name(int b);

/* The band word of a channel key ("6g37" "6", "36" "5", "11" "2.4",
 * and "?" for a number in neither sloth range, "20" or "180") and its
 * sort rank (the unknown last). */
const char *web_channel_band(const char *key, int *rank);

#endif
