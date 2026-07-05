#ifndef OUI_H
#define OUI_H
#include <stdint.h>

/* Returns a static vendor string, "Randomized", "Multicast", or NULL. */
const char *oui_lookup(const uint8_t *mac);

/* Parses "aa:bb:cc:dd:ee:ff" bssid format, then calls oui_lookup. */
const char *oui_lookup_str(const char *bssid_str);

/* Display vendor label for a client MAC — the single source of truth for
 * how probe/roaming panels render the vendor column. Never NULL: the OUI
 * vendor, "Randomized", "Multicast", or "?" when unknown. If is_random is
 * non-NULL it receives 1 for a locally-administered (randomised) MAC, so
 * callers can style it without re-deriving the flag. */
const char *oui_vendor_label(const uint8_t *mac, int *is_random);

#endif /* OUI_H */
