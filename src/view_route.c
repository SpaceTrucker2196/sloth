/* Key-routing policy: does the active view claim a given key over the
 * global view-switch letters?
 *
 * Extracted from main.c into its own TU so unit tests can cover the
 * routing decision directly — without this, view_*_key handlers pass
 * their unit tests while the running UI silently swallows their
 * bindings (see issue #13). */

#include "sloth.h"

int view_claims_key(view_t v, int key) {
    switch (v) {
    case VIEW_IFACE:
        /* 't' toggles hidden, 'm' assigns the capture iface. Both
         * collide with global view-switch letters (TLS, Channel).
         * 'y' toggles data-stream selection (#17); 'y' is free at
         * the global level today but we claim it explicitly so a
         * future global letter doesn't silently shadow it. */
        return key == 't' || key == 'T'
            || key == 'm' || key == 'M'
            || key == 'y' || key == 'Y';
    case VIEW_CONNS:
        /* 's' cycles sort. Collides with global SSDP switch. */
        return key == 's' || key == 'S';
    case VIEW_PACKETS:
        /* 'p' pauses, 'x' clears filter, 'w' saves pcap. Collide with
         * global NTP, Twins, Assoc switches. */
        return key == 'p' || key == 'P'
            || key == 'x' || key == 'X'
            || key == 'w' || key == 'W';
    case VIEW_STATS:
        /* 'r' resets baseline. Collides with global DNS switch. */
        return key == 'r' || key == 'R';
    case VIEW_DASH:
        /* Tab cycles dashboard panels; the global tab handler would
         * otherwise cycle *views*. */
        return key == '\t';
    default:
        return 0;
    }
}
