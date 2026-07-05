#ifndef WIFI_MERGE_H
#define WIFI_MERGE_H

#include "sloth.h"

/* Multi-radio Wi-Fi observation merge (issue #21).
 *
 * Each monitor-mode adapter is a SENSOR_WIFI sensor with an id in
 * [0, MAX_SENSORS). Every 802.11 observation is tagged with the radio
 * that heard it and folded into one entity-keyed world model. The merge
 * is passive bookkeeping only: it never touches a radio, a channel, or
 * link state — it just reconciles what several passive feeds report. */

/* Reset the table to empty. */
void wifi_merge_reset(wifi_merge_t *m);

/* Fold one observation into the table.
 *   sensor_id  observing radio, [0, MAX_SENSORS); out of range => dropped
 *   key        entity address (AP BSSID or STA MAC), 6 bytes
 *   channel    observed channel (0 = unknown)
 *   freq_mhz   observed frequency in MHz (0 = unknown)
 *   rssi_dbm   observed signal (negative dBm; 0 = unknown, not merged as "best")
 *   seen_at    observation timestamp
 * Returns the merged entry, or NULL if the observation was dropped
 * (bad sensor id, NULL key, or table full). Idempotent per entity:
 * repeated hits from the same radio update recency without inflating
 * seen_by. */
wifi_merged_t *wifi_merge_observe(wifi_merge_t *m, int sensor_id,
                                  const uint8_t key[6], int channel,
                                  int freq_mhz, int rssi_dbm, time_t seen_at);

/* Look up a merged entity by key, or NULL if absent. */
wifi_merged_t *wifi_merge_find(wifi_merge_t *m, const uint8_t key[6]);

/* Rebuild the merged table from the current beacon-AP table, tagging every
 * AP with sensor_id. This is the single-active-radio bridge: until the
 * capture path runs one thread per adapter, the poll loop attributes the
 * live beacon table to the active Wi-Fi sensor. Additional radios call
 * wifi_merge_observe directly with their own id. */
void wifi_merge_from_beacons(sloth_state_t *s, int sensor_id);

#endif /* WIFI_MERGE_H */
