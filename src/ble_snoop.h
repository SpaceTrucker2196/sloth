#ifndef BLE_SNOOP_H
#define BLE_SNOOP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* BLE HCI passive advertisement decoder — issue #144 slice 1.
 *
 * Pure, stateless parsing only: no sensor registration, no device table,
 * no alert rule, no view. Proving the decoder correct against the spec
 * before anything is built on top of it, same precedent as #101 slice 1
 * (src/reg_ie.c) and #104 slice 1 (src/mle.c).
 *
 * Covers the legacy LE Advertising Report (HCI_EV_LE_Meta subevent 0x02,
 * Bluetooth Core Spec v5.x Vol 4 Part E §7.7.65.2) and the AD-structure
 * TLVs inside its Data field (Vol 3 Part C §11, types registered in the
 * Bluetooth "Assigned Numbers" supplement). The Extended Advertising
 * Report (subevent 0x0D, BT 5+ coded/extended PHY) is NOT decoded here —
 * named as a follow-up slice, not built.
 */

#define BLE_LOCAL_NAME_MAX 32
#define BLE_MFR_DATA_MAX   27 /* max AD payload (31) minus the 2-byte company ID */

typedef struct {
    /* From the HCI event's per-report fixed fields. */
    uint8_t event_type;
    uint8_t addr_type;  /* 0=public 1=random 2=public-identity 3=random-identity */
    uint8_t addr[6];    /* as received over HCI (little-endian octet order) */
    bool    has_rssi;   /* false when the HCI RSSI field reads 127 ("not available") */
    int8_t  rssi;

    /* From the AD-structure walk of that report's Data field. Every
     * has_* field is false (0) until ble_ad_parse() finds that AD type;
     * fields are never invented from absence. */
    bool     has_flags;
    uint8_t  flags;

    bool     has_service_uuid16; /* first 16-bit Service UUID found (type 0x02/0x03) */
    uint16_t service_uuid16;

    bool     has_local_name;
    bool     local_name_complete; /* true = Complete (0x09), false = Shortened (0x08) */
    char     local_name[BLE_LOCAL_NAME_MAX + 1];

    bool    has_tx_power;
    int8_t  tx_power;

    bool     has_appearance;
    uint16_t appearance;

    bool     has_mfr_data;      /* AD type 0xFF */
    uint16_t mfr_id;            /* Company ID, Assigned Numbers §7 */
    uint8_t  mfr_data[BLE_MFR_DATA_MAX];
    uint8_t  mfr_data_len;

    bool truncated; /* an AD structure's declared length ran past the data blob */
} ble_adv_report_t;

/* Walks the AD structures (length, type, value) inside one advertising
 * report's Data field and fills in the AD-derived fields of `out`.
 * Does not touch the HCI-header fields (event_type/addr_type/addr/rssi) —
 * callers fill those separately. Never reads past `len`; a structure
 * whose declared length would overrun `len` sets `out->truncated` and
 * stops the walk, keeping whatever decoded before it. `out` must already
 * be zeroed (ble_hci_adv_walk() does this for its callers). */
void ble_ad_parse(const uint8_t *data, size_t len, ble_adv_report_t *out);

/* Per-report callback for ble_hci_adv_walk(). `report` is valid only for
 * the duration of the call. */
typedef void (*ble_report_cb_t)(const ble_adv_report_t *report, void *ctx);

/* Parses an HCI event buffer whose event code is HCI_EV_LE_Meta (0x3E)
 * and whose subevent code is LE Advertising Report (0x02). The event's
 * parameters are struct-of-arrays (every Event_Type octet, then every
 * Address_Type octet, then every 6-octet Address, then every Data_Length
 * octet, then each report's Data back to back, then every RSSI octet) —
 * the whole structure is bounds-checked before any report is decoded, so
 * a short or malformed buffer decodes nothing rather than a truncated
 * prefix. Calls `cb` once per report. Returns the number of reports
 * decoded, or 0 for a buffer that is too short, the wrong event/subevent
 * code, or Num_Reports == 0. */
int ble_hci_adv_walk(const uint8_t *evt, size_t len, ble_report_cb_t cb, void *ctx);

#endif /* BLE_SNOOP_H */
