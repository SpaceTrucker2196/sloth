#include "web_vendorkb.h"

#include <string.h>

/* The table and its keys are build/web/web_vendorkb_table.c's. */

const web_vkb_t *web_vendorkb_find(const char *ieee_name) {
    return web_vendorkb_lookup(ieee_name, NULL);
}

const web_vkb_t *web_vendorkb_lookup(const char *ieee_name, int *affiliate) {
    if (affiliate) *affiliate = 0;
    if (!ieee_name || web_vkb_nkeys <= 0) return NULL;
    char key[WEB_VKB_KEY_MAX + 1];
    if (!web_vkb_norm(ieee_name, key, sizeof(key))) return NULL;
    int lo = 0, hi = web_vkb_nkeys;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        int c = strcmp(web_vkb_keys[mid].key, key);
        if (c < 0) lo = mid + 1;
        else if (c > 0) hi = mid;
        else {
            int e = web_vkb_keys[mid].entry;
            if (affiliate) *affiliate = web_vkb_keys[mid].affiliate != 0;
            return e >= 0 && e < web_vkb_n ? &web_vkb[e] : NULL;
        }
    }
    return NULL;
}
