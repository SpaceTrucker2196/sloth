#ifndef BLE_FLOOD_H
#define BLE_FLOOD_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"
#include "ble_hci.h"

/* BLE advertising-flood windows (#144 slice 4): the table
 * BLE_ADV_FLOOD reads.
 *
 * Every decoded advertisement from any BLE sensor is counted under one
 * key: (sensor kind, sensor iface, HCI Event_Type, payload family, id,
 * subtype). The family is Manufacturer Specific Data when the report
 * carries it (id = company ID, subtype = the first octet after it: the
 * Continuity message type for Apple, the beacon ID for Microsoft), else
 * Service Data - 16-bit UUID (id = the UUID, no subtype). A report with
 * neither is not counted: no spam family the sources document is
 * carried any other way.
 *
 * Per key, tumbling windows of ble.flood_window_s on the monotonic
 * clock, each holding the advertisement count, the distinct (address,
 * type) count up to BLE_FLOOD_ADDR_CAP, the FRESH count (addresses not
 * heard on the key in either of the two windows before, through a Bloom
 * set per window, uncapped), whether the window before held anything
 * (`baseline`), and the median of the first BLE_FLOOD_RSSI_CAP RSSI
 * samples. Tumbling, not sliding: a burst that
 * straddles a boundary is split across two windows, so each half is
 * judged alone. That can only under-count, never invent a flood.
 *
 * The three gates are evaluated in src/ble_detect.c, not here; this
 * module only counts. The table is a stab_t (STAB_OLDEST): keys are
 * whatever arrives over the air, so a spray of keys churns it and every
 * loss lands in evict_ble_flood. Its own mutex; ble_hci.c calls in with
 * its own held, always in that order. */

/* Count one advertisement. `addr` is display order. */
void ble_flood_note(const ble_obs_t *o, const uint8_t addr[6],
                    uint64_t now_ms);

/* Roll every window to `now_ms` and copy the rows into s->ble_flood. */
void ble_flood_snapshot(sloth_state_t *s, uint64_t now_ms);

/* Empty the table. The eviction tally is untouched. */
void ble_flood_clear(void);

/* 1 when (family, id, subtype) is on the documented BLE-spam list, and
 * *source (if non-NULL) names the primary source that documents it.
 * subtype -1 = the family has none. */
int ble_spam_family_known(int family, uint16_t id, int subtype,
                          const char **source);

/* Stable names for the JSONL contract: "none", "mfr", "svc_data". */
const char *ble_family_name(int family);

#endif /* BLE_FLOOD_H */
