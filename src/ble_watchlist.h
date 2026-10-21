#ifndef BLE_WATCHLIST_H
#define BLE_WATCHLIST_H

#include <stdint.h>
#include "ble_snoop.h"

/* BLE_WATCHLIST rows (#144 slice 4): which advertisement shapes name a
 * CATEGORY of device - a crowd-sourced finder tag, for example - that
 * an operator wants to know is in range.
 *
 * The shipped table is EMPTY, for the reason src/tool_fingerprint.c
 * (#68) gives: a row invented from memory passes every test written
 * against it while matching nothing real, and a row that is wrong is
 * worse than none, because an operator reads silence as "not here".
 * A row lands with the primary source that documents the payload shape,
 * one per commit (owner standard, #145: no row without a primary
 * source). research/bluetooth/ble-watchlist-categories.md lists the
 * candidate categories and what each still needs; the tests drive the
 * matcher through an in-test table.
 *
 * Category, never identity (the #94 posture). A finder tag's address is
 * random and rotates by design, so a match says "an advertiser of this
 * kind is in range", never "this tag" and never "this person". Nothing
 * here decrypts or resolves anything; the matcher reads only the
 * advertisement's own public fields.
 *
 * A row matches when every field it constrains matches:
 *
 *   match    BLE_WL_MFR      Manufacturer Specific Data, id = company ID
 *            BLE_WL_SVC_DATA Service Data - 16-bit UUID, id = the UUID
 *            BLE_WL_UUID16   a 16-bit Service UUID listed, id = the UUID
 *   subtype  the first payload octet after the id, or -1 for any
 *            (unused for BLE_WL_UUID16)
 *   min_len  payload octets after the id, inclusive bounds; -1 = no bound
 *   max_len  (unused for BLE_WL_UUID16)
 *   category the slug reported; at most 15 characters
 *   source   the primary source the row rests on. Required: a row with
 *            no source is refused by ble_watchlist_set_table(). */
typedef enum {
    BLE_WL_MFR = 1,
    BLE_WL_SVC_DATA,
    BLE_WL_UUID16
} ble_wl_match_t;

typedef struct {
    const char *category;
    uint8_t     match;      /* ble_wl_match_t */
    uint16_t    id;
    int16_t     subtype;    /* -1 = any */
    int16_t     min_len;    /* -1 = no bound */
    int16_t     max_len;    /* -1 = no bound */
    const char *source;
} ble_wl_row_t;

#define BLE_WL_CATEGORY_MAX 15

/* Category of the first row `r` matches, or NULL. */
const char *ble_watchlist_match(const ble_adv_report_t *r);

/* Rows in force. 0 for the shipped table. */
int ble_watchlist_count(void);

/* Replace the table (tests, and any future operator-supplied list).
 * Returns 0, or -1 and leaves the table unchanged when a row is
 * malformed: no category, a category longer than BLE_WL_CATEGORY_MAX,
 * an unknown match kind, or no source. The rows are not copied: the
 * array must outlive its use. */
int ble_watchlist_set_table(const ble_wl_row_t *rows, int n);

/* Back to the shipped (empty) table. */
void ble_watchlist_reset(void);

#endif /* BLE_WATCHLIST_H */
