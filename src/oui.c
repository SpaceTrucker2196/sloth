#include "oui.h"
#include <stddef.h>
#include <stdio.h>

/* Sorted by OUI value (ascending) for binary search: the rows are
 * intel/oui-builtin/oui_builtin.csv, which tools/intel_gen refuses
 * unsorted or repeated (#231). */
static const struct { uint32_t oui; const char *vendor; } g_oui[] = {
#include "oui_builtin.inc"
};

#define OUI_COUNT ((int)(sizeof g_oui / sizeof g_oui[0]))

const char *oui_lookup(const uint8_t *mac) {
    if (mac[0] & 0x02) return "Randomized";
    if (mac[0] & 0x01) return "Multicast";

    uint32_t key = ((uint32_t)mac[0] << 16) |
                   ((uint32_t)mac[1] <<  8) |
                    (uint32_t)mac[2];

    int lo = 0, hi = OUI_COUNT - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if      (g_oui[mid].oui < key) lo = mid + 1;
        else if (g_oui[mid].oui > key) hi = mid - 1;
        else                           return g_oui[mid].vendor;
    }
    return NULL;
}

int oui_builtin_count(void) { return OUI_COUNT; }

const char *oui_vendor_label(const uint8_t *mac, int *is_random) {
    if (is_random) *is_random = (mac[0] & 0x02) != 0;
    const char *v = oui_lookup(mac);
    return (v && v[0]) ? v : "?";
}

const char *oui_lookup_str(const char *bssid_str) {
    unsigned b0, b1, b2, b3, b4, b5;
    if (sscanf(bssid_str, "%x:%x:%x:%x:%x:%x",
               &b0, &b1, &b2, &b3, &b4, &b5) != 6)
        return NULL;
    uint8_t mac[6] = { (uint8_t)b0, (uint8_t)b1, (uint8_t)b2,
                       (uint8_t)b3, (uint8_t)b4, (uint8_t)b5 };
    return oui_lookup(mac);
}
