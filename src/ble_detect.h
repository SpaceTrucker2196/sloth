#ifndef BLE_DETECT_H
#define BLE_DETECT_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* The three BLE detector lanes (#144 slice 4), as one pure function of
 * the snapshot: src/alerts/rules_ble.c fires one alert per finding, and
 * src/jsonl.c writes one `ble_alert` record per finding, from the same
 * list, so the two can never disagree about what was found.
 *
 * Every finding is WARN. The issue's CRIT ("stalk-grade" watchlist
 * category from a non-resident source) is deferred: "non-resident" has
 * no definition yet, and a CRIT on an undefined term would be a claim
 * the sensor cannot back. Nothing here transmits, connects, or reads
 * GATT: every input is an advertisement some other device broadcast.
 *
 * ── BLE_ADV_FLOOD ──
 *
 * One src/ble_flood.c window, current or immediately previous, passing
 * ALL THREE gates:
 *
 *   1. distinct (address, type) >= ble.flood_distinct_addrs
 *   2. advertisements / window length >= ble.flood_rate per second
 *   3. the (family, id, subtype) key is on the documented spam list
 *      (ble_spam_family_known(); not tunable)
 *
 * No threshold in gates 1 and 2 has a cited basis for where legitimate
 * traffic stops. The tool's source is the basis for the SHAPE - it
 * randomises its address and advertises every 20 to 500 ms
 * (research/bluetooth/ble-spam-flood.md) - but no source measures how
 * many Proximity Pair advertisers a crowded room holds. So no gate can
 * be switched off, and the defaults are a judgement, stated as one.
 *
 * ── BLE_HID_UNEXPECTED ──
 *
 * Two forms. (a) A PUBLIC address (type 0 or 2) whose OUI is in one of
 * the attacker-helper tables that exist (src/wifi_oui_attacker.h: Hak5,
 * Espressif) advertising a HID appearance (Bluetooth SIG Assigned
 * Numbers, category 0x00F: 0x03C0..0x03CA) or the HID service UUID
 * 0x1812. (b) At least ble.hid_rotate_addrs distinct RANDOM addresses
 * (type 1 or 3) on one sensor, each first heard inside the last
 * ble.hid_rotate_window_s and each advertising a HID appearance, after
 * BLE observation began more than that window ago (so the first window of a run, when every address is new,
 * cannot qualify). (b)'s threshold has no cited basis.
 *
 * Both are precursors at most. CVE-2023-45866 is an unauthenticated HID
 * peripheral being accepted by a host; sloth sees no pairing and no
 * connection, and the public proof of concept presents over BR/EDR, not
 * LE (research/cve/2023-45866.md). The finding corroborates; it never
 * confirms.
 *
 * ── BLE_WATCHLIST ──
 *
 * One finding per (sensor, category): the addresses whose row matched a
 * src/ble_watchlist.c category and was heard in the last
 * BLE_WATCH_RECENT_SECS. The count is of ADDRESSES, which
 * rotate, so it is not a count of devices; the finding names a
 * category, never a device or a person. With the shipped (empty) table
 * it never fires. */

/* Shipped defaults of the five --tune rows (src/tune.c). */
#define BLE_FLOOD_WINDOW_S        10
#define BLE_FLOOD_DISTINCT_ADDRS  20
#define BLE_FLOOD_RATE            10   /* advertisements per second */
#define BLE_HID_ROTATE_ADDRS      3
#define BLE_HID_ROTATE_WINDOW_S   900

/* A watchlist row heard this recently is "in range"; after that the
 * finding stops being asserted and the engine resolves it. */
#define BLE_WATCH_RECENT_SECS     120

#define BLE_FINDINGS_MAX          64

typedef enum {
    BLE_FIND_FLOOD = 1,
    BLE_FIND_HID_OUI,
    BLE_FIND_HID_ROTATE,
    BLE_FIND_WATCH
} ble_find_kind_t;

typedef struct {
    int      kind;              /* ble_find_kind_t */
    int      alert_type;        /* alert_type_t */
    char     key[96];           /* the alert key, also the JSONL identity */
    uint8_t  sensor_kind;
    char     sensor_iface[24];
    uint8_t  sampled;
    /* FLOOD */
    uint8_t  adv_type, family;
    uint16_t id;
    int16_t  subtype;
    uint8_t  window;            /* 0 the window in progress, 1 the previous one */
    uint32_t window_s;
    uint32_t total;
    uint16_t distinct;
    uint8_t  distinct_capped;
    uint32_t rate_x10;          /* advertisements per second, x10 */
    uint8_t  has_rssi;
    int8_t   rssi_median;
    const char *spam_source;
    /* HID_OUI */
    uint8_t  addr[6];
    uint8_t  addr_type;
    uint8_t  hid;               /* BLE_HID_APPEARANCE | BLE_HID_SERVICE */
    uint16_t appearance;
    const char *oui_table;      /* "Hak5", "Espressif" */
    /* HID_ROTATE and WATCH */
    int      addrs;
    char     category[16];
} ble_finding_t;

/* "ADV_IND", "ADV_NONCONN_IND", ... for an HCI Event_Type; "adv" for
 * any other value. */
const char *ble_adv_type_name(uint8_t event_type);

/* 1 for a Bluetooth SIG HID appearance, 0x03C0..0x03CA. */
int ble_appearance_is_hid(uint16_t appearance);

/* The findings in `s` at this snapshot, judged at wall clock `now`
 * (device rows carry the frame clock, which a live source and the
 * replay both anchor at the wall clock), at most `max`. Returns the
 * count; *dropped (if non-NULL) is how many more there were. */
int ble_findings_build(const sloth_state_t *s, time_t now,
                       ble_finding_t *out, int max, int *dropped);

#endif /* BLE_DETECT_H */
