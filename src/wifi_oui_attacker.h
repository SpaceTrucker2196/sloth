#ifndef WIFI_OUI_ATTACKER_H
#define WIFI_OUI_ATTACKER_H

#include <stdint.h>

/* Attacker OUI tables — known-bad vendor prefixes for the first three
 * bytes of a BSSID. Used by rule_evil_twin to raise severity when the
 * vendor side of a same-SSID/same-cipher twin pair belongs to a tool
 * commonly used for rogue APs.
 *
 * The lists are deliberately conservative — we want strong signal, not
 * coverage. Espressif chips ship in legitimate consumer kit too, so the
 * match is only meaningful when paired with twin-pair geometry. */

int oui_is_hak5     (const uint8_t oui[3]);  /* Pineapple / Bash Bunny / etc. */
int oui_is_espressif(const uint8_t oui[3]);  /* ESP32 / ESP8266 rogue APs    */

#endif /* WIFI_OUI_ATTACKER_H */
