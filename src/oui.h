#ifndef OUI_H
#define OUI_H
#include <stdint.h>

/* Returns a static vendor string, "Randomized", "Multicast", or NULL. */
const char *oui_lookup(const uint8_t *mac);

/* Parses "aa:bb:cc:dd:ee:ff" bssid format, then calls oui_lookup. */
const char *oui_lookup_str(const char *bssid_str);

#endif /* OUI_H */
