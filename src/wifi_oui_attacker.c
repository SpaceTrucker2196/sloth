#include "wifi_oui_attacker.h"

/* The rows are intel/attacker-ouis/attacker_ouis.csv (#231), one array
 * per `family`, in the file's order; that pack's SOURCE.md carries the
 * citations that stood here.
 *
 * Hak5 — Pineapple radios, Bash Bunny, Packet Squirrel. The 00:13:37
 * prefix is a long-standing Hak5 vanity OUI; 00:c0:ca is the Alfa-Networks
 * USB radio they ship in newer kit. Both have appeared in evil-twin
 * captures at conferences and pentest engagements; matching them on the
 * vendor side of a twin pair is a strong signal. */
static const uint8_t kHak5Ouis[][3] = {
#include "attacker_hak5.inc"
};

/* Espressif — ESP32 / ESP8266 / ESP32-C3 OUI ranges. Listed because
 * cheap-rogue-AP builds (ESP32-Marauder, Wi-Fi-Nugget) ride these chips.
 * Espressif chips also ship in legitimate IoT, so this signal only
 * matters when twin-pair geometry already triggered the WARN branch.
 * AC:0B:FB (#74) is the Flipper Zero Wi-Fi devboard's ESP32-S2, which
 * the OUI cannot tell from any other ESP32 project — hence this table
 * and not a Flipper one. Unverified. */
static const uint8_t kEspressifOuis[][3] = {
#include "attacker_espressif.inc"
};

static int oui_in_table(const uint8_t oui[3],
                        const uint8_t (*table)[3], int n) {
    for (int i = 0; i < n; i++) {
        if (oui[0] == table[i][0] &&
            oui[1] == table[i][1] &&
            oui[2] == table[i][2]) return 1;
    }
    return 0;
}

int oui_is_hak5(const uint8_t oui[3]) {
    return oui_in_table(oui, kHak5Ouis,
                        (int)(sizeof(kHak5Ouis) / sizeof(kHak5Ouis[0])));
}

int oui_is_espressif(const uint8_t oui[3]) {
    return oui_in_table(oui, kEspressifOuis,
                        (int)(sizeof(kEspressifOuis) / sizeof(kEspressifOuis[0])));
}

int oui_hak5_count(void) {
    return (int)(sizeof(kHak5Ouis) / sizeof(kHak5Ouis[0]));
}

int oui_espressif_count(void) {
    return (int)(sizeof(kEspressifOuis) / sizeof(kEspressifOuis[0]));
}
