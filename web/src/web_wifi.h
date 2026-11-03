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
#include <stdint.h>

#include "web_devices.h"
#include "web_json.h"
#include "web_series.h"

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

/* The grid the channel, deauth and mix answers share, lent to the BLE
 * Devices view (web_bledev.h) so its class grid has the same tiers,
 * bounds and cells. from, to and cols are ps[0..2]; 0, or -1 with the
 * reason word in why. */
typedef struct {
    int       tier, ncol;
    long long step, from, to, col_s;
} web_grid_t;
#define WEB_GRID_KEYS 512
int  web_grid_of(const web_m4_t *m, const web_param_t *ps, long long now,
                 web_grid_t *g, const char **why);
/* The keys of metric for the grid (the rollup's and the store's), each
 * once, into keys (WEB_GRID_KEYS of them). */
int  web_grid_keys(const web_m4_t *m, int metric, const web_grid_t *g,
                   char (*keys)[WEB_KEY_MAX + 1]);
/* metric, kind, unit, tier, step, from, to, cols and col_s, opening the
 * object; then one key's cells as a JSON array (a gauge's mean per
 * cell, a counter's sum, null for none) and its total. -1 on memory. */
void web_grid_head(web_jw_t *w, int metric, const web_grid_t *g);
int  web_grid_cells_json(const web_m4_t *m, int metric, const web_grid_t *g,
                         const char *key, web_jw_t *w, double *total);

/* The mix answer (/api/wifi/channels?mix=1), for any web_chmix_t: its
 * keys checked and ranked by key(), the store read in namespace ns
 * (web_store.h WEB_MIX_NS_*) and only the transmitter kinds in kinds (a
 * bit per WEB_TX_*), each transmitter written by tx_json, each row's
 * members after "key" by row_extra, the rows under rows_word, and tail's
 * members (at most tail_max bytes) last. use_db opens sloth.db for
 * tx_json and says "db". */
typedef struct {
    struct web_chmix *mix;
    int               ns;
    const char       *metric, *unit, *rows_word;
    unsigned          kinds;
    int               use_db;
    int  (*key)(const char *key, int *rank, long *num);
    void (*row_extra)(web_jw_t *w, const char *key, void *ctx);
    void (*tx_json)(web_jw_t *w, const web_m4_t *m, web_sdb_conn_t *conn,
                    const uint8_t mac[6], int kind, void *ctx);
    void (*tail)(web_jw_t *w, void *ctx);
    size_t            tail_max;
    void             *ctx;
} web_mix_ops_t;
int web_mix_answer(const web_m4_t *m, const web_grid_t *g, const web_mix_ops_t *ops,
                   long long now_s, char *body, size_t cap, size_t *len, int *status);

int web_wifi_channels_route(const web_m4_t *m, const char *query,
                            long long now_s, char *body, size_t cap,
                            size_t *len, int *status);
int web_wifi_deauth_route(const web_m4_t *m, const char *query,
                          long long now_s, char *body, size_t cap,
                          size_t *len, int *status);
int web_wifi_aps_route(const web_m4_t *m, const char *query, long long now_s,
                       char *body, size_t cap, size_t *len, int *status);
/* /api/wifi/local?limit=: the managed Wi-Fi card's own scan (sloth.db
 * wifi_aps, newest first, limit rows, default and most
 * WEB_WIFI_AP_MAX) and its station dump (wifi_stas, its link to the AP
 * it is associated with, at most WEB_WIFI_STA_MAX): Wi-Fi through the
 * host's own network, not the passive radio, so the WiFi view's Local
 * half (web_scope.h). The router answers out_of_scope under Monitor. */
#define WEB_WIFI_STA_MAX 32
int web_wifi_local_route(const web_m4_t *m, const char *query, long long now_s,
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
