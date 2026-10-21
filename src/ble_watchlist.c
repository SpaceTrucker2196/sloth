#include <stddef.h>
#include <string.h>
#include "ble_watchlist.h"

/* Contract in ble_watchlist.h. The shipped table has no rows: there is
 * nothing here to point at, so the "table" is a NULL pointer and a zero
 * count rather than an empty array, which C99 does not have. */
static const ble_wl_row_t *g_rows;
static int                 g_n;

static int len_ok(const ble_wl_row_t *w, size_t len) {
    if (w->min_len >= 0 && len < (size_t)w->min_len) return 0;
    if (w->max_len >= 0 && len > (size_t)w->max_len) return 0;
    return 1;
}

static int sub_ok(const ble_wl_row_t *w, const uint8_t *data, size_t len) {
    if (w->subtype < 0) return 1;
    return len >= 1 && data[0] == (uint8_t)w->subtype;
}

static int row_matches(const ble_wl_row_t *w, const ble_adv_report_t *r) {
    switch (w->match) {
    case BLE_WL_MFR:
        return r->has_mfr_data && r->mfr_id == w->id &&
               sub_ok(w, r->mfr_data, r->mfr_data_len) &&
               len_ok(w, r->mfr_data_len);
    case BLE_WL_SVC_DATA:
        return r->has_svc_data16 && r->svc_data_uuid16 == w->id &&
               sub_ok(w, r->svc_data, r->svc_data_len) &&
               len_ok(w, r->svc_data_len);
    case BLE_WL_UUID16:
        for (int i = 0; i < r->uuid16_count && i < BLE_UUID16_LIST_MAX; i++)
            if (r->uuid16_list[i] == w->id) return 1;
        return 0;
    default:
        return 0;
    }
}

const char *ble_watchlist_match(const ble_adv_report_t *r) {
    if (!r) return NULL;
    for (int i = 0; i < g_n; i++)
        if (row_matches(&g_rows[i], r)) return g_rows[i].category;
    return NULL;
}

int ble_watchlist_count(void) { return g_n; }

int ble_watchlist_set_table(const ble_wl_row_t *rows, int n) {
    if (n < 0 || (n > 0 && !rows)) return -1;
    for (int i = 0; i < n; i++) {
        const ble_wl_row_t *w = &rows[i];
        if (!w->category || !w->category[0] ||
            strlen(w->category) > BLE_WL_CATEGORY_MAX) return -1;
        if (w->match < BLE_WL_MFR || w->match > BLE_WL_UUID16) return -1;
        if (!w->source || !w->source[0]) return -1;
    }
    g_rows = n ? rows : NULL;
    g_n    = n;
    return 0;
}

void ble_watchlist_reset(void) {
    g_rows = NULL;
    g_n    = 0;
}
