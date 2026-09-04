#include "wifi_oui_attacker.h"

/* Hak5 — Pineapple radios, Bash Bunny, Packet Squirrel. The 00:13:37
 * prefix is a long-standing Hak5 vanity OUI; 00:c0:ca is the Alfa-Networks
 * USB radio they ship in newer kit. Both have appeared in evil-twin
 * captures at conferences and pentest engagements; matching them on the
 * vendor side of a twin pair is a strong signal. */
static const uint8_t kHak5Ouis[][3] = {
    {0x00, 0x13, 0x37},   /* Hak5 LLC */
    {0x00, 0xc0, 0xca},   /* Alfa Networks (commonly bundled by Hak5) */
};

/* Espressif — ESP32 / ESP8266 / ESP32-C3 OUI ranges. Listed because
 * cheap-rogue-AP builds (ESP32-Marauder, Wi-Fi-Nugget) ride these chips.
 * Espressif chips also ship in legitimate IoT, so this signal only
 * matters when twin-pair geometry already triggered the WARN branch. */
static const uint8_t kEspressifOuis[][3] = {
    {0x24, 0x0a, 0xc4},   /* Espressif (ESP32 — most common) */
    {0x24, 0x6f, 0x28},   /* Espressif (ESP32 — secondary)   */
    {0x24, 0xb2, 0xde},   /* Espressif (ESP32 — tertiary)    */
    {0x30, 0xae, 0xa4},   /* Espressif (ESP8266)             */
    {0x84, 0xf3, 0xeb},   /* Espressif (ESP8266 — alt block) */
    {0xa0, 0x20, 0xa6},   /* Espressif (ESP-WROOM modules)   */
    {0xa4, 0xcf, 0x12},   /* Espressif (ESP32 — wide block)  */
    {0xb4, 0xe6, 0x2d},   /* Espressif (ESP32 — newer)       */
    {0xc4, 0x4f, 0x33},   /* Espressif (ESP32 — newer)       */
    {0xec, 0xfa, 0xbc},   /* Espressif (ESP32-C3)            */
    /* From #74. The Flipper Zero's Wi-Fi devboard is an ESP32-S2, so
     * this block reaches sloth as "Flipper" in the field — but the OUI
     * cannot say that. It cannot separate a Flipper devboard from an
     * ESP32 Marauder from any other ESP32 project, which is why it sits
     * in the Espressif table and not a Flipper one. Unverified: taken
     * from the issue's research, not measured here. */
    {0xac, 0x0b, 0xfb},   /* Espressif (ESP32-S2 — Flipper devboard) */
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
