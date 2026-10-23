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
 * the sensor cannot back. The hook it should read is
 * ble_identity_hint_t.root_first (#156): a definition built on a row's
 * first_seen alone calls a resident random-address device new at every
 * rotation, and with --ble-rotation-hints on, root_first is the first
 * report of the earliest address chained to the row. It must stand
 * without the hints too, since they are off by default. Nothing here transmits, connects, or reads
 * GATT: every input is an advertisement some other device broadcast.
 *
 * ── BLE_ADV_FLOOD ──
 *
 * One src/ble_flood.c window, current or immediately previous, passing
 * ALL THREE gates:
 *
 *   1. FRESH (address, type) >= ble.flood_distinct_addrs: addresses
 *      first heard on this key inside the window, heard in neither of
 *      the two windows before it, and only in a window whose
 *      predecessor held advertisements on the key (`baseline`)
 *   2. advertisements / window length >= ble.flood_rate per second
 *   3. the (family, id, subtype) key is on the documented spam list
 *      (ble_spam_family_known(); not tunable)
 *
 * Gate 1 counts fresh addresses, not addresses present, because a crowd
 * of genuine devices is the false positive the other two gates cannot
 * tell apart: 25 Fast Pair headsets re-advertising every 250 ms are 25
 * addresses at 100/s on a listed key. What separates them is the
 * tool's own behaviour: ble_spam.c start_extra_beacon() calls
 * randomize_mac() before every payload when the attack sets random_mac,
 * and holds each payload for one 20..500 ms delay
 * (research/bluetooth/ble-spam-flood.md), so its addresses do not
 * survive into the next window; a genuine advertiser's do. The cost:
 * a key's first window, and the first after a silent one, cannot fire,
 * so a flood is reported one window late; and the tool's three Apple
 * attacks set random_mac = false (one address per run), so only the
 * mixed "Kitchen Sink" mode puts Apple keys on many addresses - a
 * single-address Apple flood is not this rule's shape at all.
 *
 * No threshold in gates 1 and 2 has a cited basis for where legitimate
 * traffic stops: no source measures how many new Proximity Pair
 * addresses a busy concourse produces in 10 s. So no gate can be
 * switched off, and the defaults are a judgement, stated as one.
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
 * THAT SENSOR's first advertisement is more than that window old (so
 * the first window of a run, or of a sensor started later, when every
 * address is new to it, cannot qualify). (b)'s threshold has no cited
 * basis. Known limit: a row evicted from the ble_device table (256,
 * STAB_OLDEST) and heard again is re-created with a fresh first_seen,
 * so on a site busy enough to churn the table a resident random-address
 * keyboard can count as new; evict_ble_device in sensor_health says
 * when that is happening.
 *
 * With --ble-rotation-hints (#156, src/ble_rotation.h) form (b)
 * compares ble.hid_rotate_addrs against advertisers, not addresses:
 * rows a committed PAYLOAD hint chains together count once, so a HID
 * advertiser carrying a documented token across its rotations does not
 * read as N new HID addresses. Timing-only hints never reduce the
 * count. The research grades timing a corroborator, never a finding;
 * a lone fast rotator is never ambiguous on timing, so it would chain
 * completely and suppress the very rotation this form is for. The
 * trade, accepted: a HID advertiser rotating with no token (most
 * keyboards) is counted per address with the flag on, as without it.
 * The finding's `addrs` stays the address count. Off by default, and
 * then the gate is the address count, as before.
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
    uint32_t fresh;             /* gate 1's count */
    /* The last CLOSED window, whatever window passed: the ble_alert
     * change signature reads these, so a flood in progress is one state,
     * not a count climbing from zero every window. */
    uint32_t prev_total, prev_fresh;
    uint8_t  prev_has_rssi;
    int8_t   prev_rssi_median;
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
