#ifndef SLOTH_PROBE_PNL_H
#define SLOTH_PROBE_PNL_H

#include <stdint.h>
#include "sloth.h"

/* Per-MAC Preferred Network List aggregation.
 *
 * Each directed probe request observed by the capture thread feeds
 * probe_pnl_observe(mac, ssid). The module dedupes SSIDs per MAC and
 * keeps a per-client probe counter + first/last seen timestamps.
 * Snapshot copies into sloth_state_t for the view.
 *
 * Wildcard probes (empty SSID) are dropped — they leak no PNL info. */

/* `os_fp` and `phy` may be NULL or empty; non-empty values get
 * sticky-stored on the matching client entry (first strong
 * fingerprint wins; PHY tier only upgrades, never downgrades). */
void probe_pnl_observe(const uint8_t mac[6], const char *ssid,
                        const char *os_fp, const char *phy);

/* Walk the IE blob from an 802.11 probe-request frame body and return
 * a short OS fingerprint string ("Apple", "Windows", "ESP32"…) when
 * a strong vendor IE is present. Returns NULL on a weak / unknown
 * pattern — callers fall back to leaving os_fp empty. */
const char *probe_pnl_fingerprint_ies(const uint8_t *ies, int ielen);

/* Classify maximum PHY tier from the same IE blob. Returns one of
 *   "Wi-Fi 7"  (tag 255 ext id 108 / 81 / EHT)
 *   "Wi-Fi 6"  (tag 255 ext id 35  / HE Capabilities)
 *   "Wi-Fi 5"  (tag 191 / VHT Capabilities)
 *   "Wi-Fi 4"  (tag 45  / HT Capabilities)
 *   "legacy"   none of the above
 * The string is a static literal — callers do not own it. */
const char *probe_pnl_phy_ies(const uint8_t *ies, int ielen);
void probe_pnl_snapshot(sloth_state_t *s);
void probe_pnl_clear(void);

/* Direct accessors for tests. */
int  probe_pnl_count(void);
int  probe_pnl_ssid_count(const uint8_t mac[6]);

#endif /* SLOTH_PROBE_PNL_H */
