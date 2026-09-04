#include "runner.h"
#include "wifi_oui_attacker.h"

/* The OUI tables are tiny and stable — we test boundary identity
 * (known good, known bad, edge octets) rather than full enumeration. */

static void test_hak5_known_oui_matches(void) {
    uint8_t pineapple[3] = {0x00, 0x13, 0x37};
    ASSERT_EQ(oui_is_hak5(pineapple), 1);
    uint8_t alfa[3] = {0x00, 0xc0, 0xca};
    ASSERT_EQ(oui_is_hak5(alfa), 1);
}

static void test_hak5_unknown_oui_no_match(void) {
    uint8_t apple[3] = {0x00, 0x17, 0xf2};   /* Apple — not in list */
    ASSERT_EQ(oui_is_hak5(apple), 0);
    uint8_t zero[3]  = {0x00, 0x00, 0x00};
    ASSERT_EQ(oui_is_hak5(zero), 0);
}

/* A one-byte miss must NOT match — protects against any future
 * accidental substring / prefix lookup. */
static void test_hak5_offbyone_no_match(void) {
    uint8_t near_pineapple[3] = {0x00, 0x13, 0x38};
    ASSERT_EQ(oui_is_hak5(near_pineapple), 0);
    uint8_t near_alfa[3] = {0x00, 0xc0, 0xcb};
    ASSERT_EQ(oui_is_hak5(near_alfa), 0);
}

static void test_espressif_known_oui_matches(void) {
    uint8_t esp32_main[3] = {0x24, 0x0a, 0xc4};
    ASSERT_EQ(oui_is_espressif(esp32_main), 1);
    uint8_t esp32c3[3] = {0xec, 0xfa, 0xbc};
    ASSERT_EQ(oui_is_espressif(esp32c3), 1);
    uint8_t esp8266[3] = {0x30, 0xae, 0xa4};
    ASSERT_EQ(oui_is_espressif(esp8266), 1);
}

static void test_flipper_devboard_oui_is_espressif(void) {
    /* AC:0B:FB arrived via #74 as "Flipper Zero devboard". It is an
     * Espressif block — the devboard is an ESP32-S2 — which is why it
     * lives here and not in a Flipper table: the OUI cannot separate a
     * Flipper from an ESP32 Marauder from any other ESP32 project, and
     * a function named oui_is_flipper() would claim it could. */
    const uint8_t flipper_devboard[3] = {0xac, 0x0b, 0xfb};
    ASSERT_EQ(oui_is_espressif(flipper_devboard), 1);
    ASSERT_EQ(oui_is_hak5(flipper_devboard), 0);
}

static void test_espressif_unknown_oui_no_match(void) {
    uint8_t cisco[3] = {0x00, 0x40, 0x96};
    ASSERT_EQ(oui_is_espressif(cisco), 0);
    uint8_t pineapple[3] = {0x00, 0x13, 0x37};
    ASSERT_EQ(oui_is_espressif(pineapple), 0);  /* not cross-listed */
}

static void test_hak5_and_espressif_disjoint(void) {
    /* A Hak5 OUI must never look Espressif and vice versa — sanity
     * check that the tables haven't accidentally drifted into overlap. */
    uint8_t hak5_a[3] = {0x00, 0x13, 0x37};
    ASSERT_EQ(oui_is_espressif(hak5_a), 0);
    uint8_t esp_a[3] = {0x24, 0x0a, 0xc4};
    ASSERT_EQ(oui_is_hak5(esp_a), 0);
}

void run_wifi_oui_attacker_tests(void) {
    TEST_SUITE("wifi OUI attacker tables");
    RUN_TEST(test_hak5_known_oui_matches);
    RUN_TEST(test_hak5_unknown_oui_no_match);
    RUN_TEST(test_hak5_offbyone_no_match);
    RUN_TEST(test_espressif_known_oui_matches);
    RUN_TEST(test_flipper_devboard_oui_is_espressif);
    RUN_TEST(test_espressif_unknown_oui_no_match);
    RUN_TEST(test_hak5_and_espressif_disjoint);
}
