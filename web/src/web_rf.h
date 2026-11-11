/* G2's data (docs/web-visual-spec.md §5 G2, §7; #171 slice V2): an
 * emitter's signal over the last hour, as the page's range sparkline
 * draws it, beside sloth's own distance band and trend.
 *
 * The series are the rf.rssi.* gauges (web_rollup.h) that §7 calls
 * ap.rssi and sta.rssi: the same quantity under the names they already
 * had (rf.rssi.bssid is the beacon's and the AP side of an assoc's
 * signal_dbm by BSSID, rf.rssi.sta the probe_client's by MAC), so no
 * new metric and no slothweb.db schema step. §7's other two sources for
 * sta.rssi are the AP's signal, not the station's: assoc's signal_dbm
 * is set from frames the AP sent (src/assoc_track.c), and wifi_sta's
 * is the managed card's link to the AP it is on, a different receiver.
 *
 * A row's "rf" member:
 *
 *   {"metric":"rf.rssi.bssid","from":T,"cell_s":60,
 *    "cells":[-61,null,...],          WEB_RF_CELLS means, oldest first,
 *                                     integer dBm, null where no bucket
 *                                     fell; [] when none at all
 *    "n":42,                          the cells with a value
 *    "whisker":[-70,-55]|null,        the range at the last value
 *    "whisker_src":"beacon"|"samples"|null,
 *    "band":"room"|null,"trend":"approaching"|null,
 *    "est_src":"beacon"|"probe_client"|null,
 *    "radio":"2.4 GHz"|"5 GHz"|"6 GHz"|null}
 *
 * The cells are the fine buckets in memory (web_rollup_trail()), merged
 * per minute. The whisker is the beacon's own rssi_min_60s..max_60s for
 * a BSSID whose latest beacon is in the last value's minute, else
 * that cell's own sample range, which spans the same minute. band and trend are
 * sloth's (src/rf_distance.c, through the FRRS ledger, web_frrs_rf()):
 * the page bolds an approaching emitter by sloth's trend and names
 * sloth's band, so G2 never draws a nearness of its own that could
 * disagree with the estimate the TUI and the record show. radio is the
 * band the latest beacon (or probe_client) record was heard on, in
 * ap_band_label()'s words from that record's channel and, for a beacon,
 * its channel_source: the page's S-meter reads a signal on its band's
 * scale (owner ruling 2026-11-11), and null is "band unknown", never a
 * guess. A probe_client record has no channel_source, so a 6 GHz
 * channel number in one reads as the 2.4 or 5 GHz number it shares.
 *
 * Under a scope that does not show the monitor radio (web_scope.h:
 * rf.rssi.* are Monitor's), "rf" is null. */
#ifndef SLOTHWEB_RF_H
#define SLOTHWEB_RF_H

#include "web_json.h"
#include "web_rollup.h"
#include "web_scope.h"

struct web_frrs;

#define WEB_RF_CELLS    60
#define WEB_RF_CELL_S   60
/* The longest "rf" member: every cell "-127", the fixed members and
 * the longest words. */
#define WEB_RF_JSON_MAX 580

typedef struct {
    int       metric;                 /* WM_RF_RSSI_STA or _BSSID; -1 none */
    int       n;                      /* cells with a value */
    web_agg_t cell[WEB_RF_CELLS];
} web_rf_trail_t;

/* The first cell's start for now_s: the cell now_s is in is the last. */
long long web_rf_from(long long now_s);

/* The trails of n MACs, is_ap[k] saying which series is asked first:
 * rf.rssi.bssid for an AP, rf.rssi.sta otherwise, and the other when
 * the first has no cell in the window. ru NULL or a scope that does not
 * show Monitor's: every metric -1. */
void web_rf_trails(web_rollup_t *ru, const web_scope_ctx_t *sc,
                   const char (*macs)[WEB_KEY_MAX + 1], const int *is_ap,
                   int n, long long now_s, web_rf_trail_t *out);

/* ,"rf":{...} for one MAC, or ,"rf":null when t is NULL or its metric
 * is -1. frrs may be NULL: no band, trend or beacon whisker. */
void web_rf_json(web_jw_t *w, const web_rf_trail_t *t, struct web_frrs *frrs,
                 const char *mac, long long now_s);

#endif
