/* Wired-attachment correlation seam (#89 slice 3).
 * Contract and the reasoning behind the UNKNOWN default: wired_attach.h. */

#include <stddef.h>
#include "wired_attach.h"

static wired_attach_fn g_fn;
static void           *g_ctx;

void wired_attach_register(wired_attach_fn fn, void *ctx) {
    g_fn  = fn;
    g_ctx = fn ? ctx : NULL;
}

void wired_attach_clear(void) {
    g_fn  = NULL;
    g_ctx = NULL;
}

int wired_attach_have_correlator(void) {
    return g_fn != NULL;
}

wired_attach_t wired_attach_lookup(const uint8_t bssid[6]) {
    if (!g_fn || !bssid) return WIRED_ATTACH_UNKNOWN;
    wired_attach_t v = g_fn(bssid, g_ctx);
    /* Anything sloth does not recognise is not knowledge. Falling back
     * to UNKNOWN rather than passing the value through means a bug in a
     * correlator can only ever cost sloth an answer, never invent one —
     * and "there is a rogue on your wired network" is the claim in this
     * file with the heaviest consequences if it is wrong. */
    if (v != WIRED_ATTACH_ATTACHED && v != WIRED_ATTACH_NOT_ATTACHED)
        return WIRED_ATTACH_UNKNOWN;
    return v;
}

const char *wired_attach_label(wired_attach_t v) {
    switch (v) {
    case WIRED_ATTACH_ATTACHED:     return "yes";
    case WIRED_ATTACH_NOT_ATTACHED: return "no";
    case WIRED_ATTACH_UNKNOWN:
    default:                        return "?";
    }
}
