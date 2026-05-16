#include <string.h>
#include "runner.h"
#include "oui.h"

static void test_oui_espressif(void) {
    uint8_t mac[6] = { 0x18, 0xFE, 0x34, 0x00, 0x00, 0x00 };
    const char *v = oui_lookup(mac);
    ASSERT(v != NULL);
    ASSERT_STR(v, "Espressif");
}

static void test_oui_raspberry_pi3(void) {
    uint8_t mac[6] = { 0xB8, 0x27, 0xEB, 0xAA, 0xBB, 0xCC };
    const char *v = oui_lookup(mac);
    ASSERT(v != NULL);
    ASSERT_STR(v, "Raspberry Pi");
}

static void test_oui_raspberry_pi4(void) {
    uint8_t mac[6] = { 0xDC, 0xA6, 0x32, 0x01, 0x02, 0x03 };
    const char *v = oui_lookup(mac);
    ASSERT(v != NULL);
    ASSERT_STR(v, "Raspberry Pi");
}

static void test_oui_apple(void) {
    uint8_t mac[6] = { 0x00, 0x17, 0xF2, 0x00, 0x00, 0x00 };
    const char *v = oui_lookup(mac);
    ASSERT(v != NULL);
    ASSERT_STR(v, "Apple");
}

static void test_oui_intel(void) {
    uint8_t mac[6] = { 0x00, 0x03, 0x47, 0x00, 0x00, 0x00 };
    const char *v = oui_lookup(mac);
    ASSERT(v != NULL);
    ASSERT_STR(v, "Intel");
}

static void test_oui_randomized_bit(void) {
    uint8_t mac[6] = { 0x02, 0xAB, 0xCD, 0xEF, 0x01, 0x23 };
    const char *v = oui_lookup(mac);
    ASSERT(v != NULL);
    ASSERT_STR(v, "Randomized");
}

static void test_oui_multicast_bit(void) {
    uint8_t mac[6] = { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x01 };
    const char *v = oui_lookup(mac);
    ASSERT(v != NULL);
    ASSERT_STR(v, "Multicast");
}

static void test_oui_unknown(void) {
    /* OUI 00:00:01 is not in the table */
    uint8_t mac[6] = { 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    const char *v = oui_lookup(mac);
    ASSERT(v == NULL);
}

static void test_oui_lookup_str_lowercase(void) {
    const char *v = oui_lookup_str("b8:27:eb:aa:bb:cc");
    ASSERT(v != NULL);
    ASSERT_STR(v, "Raspberry Pi");
}

static void test_oui_lookup_str_uppercase(void) {
    const char *v = oui_lookup_str("18:FE:34:AA:BB:CC");
    ASSERT(v != NULL);
    ASSERT_STR(v, "Espressif");
}

static void test_oui_lookup_str_invalid(void) {
    const char *v = oui_lookup_str("not-a-mac");
    ASSERT(v == NULL);
}

static void test_oui_espressif_5ccf7f(void) {
    uint8_t mac[6] = { 0x5C, 0xCF, 0x7F, 0x00, 0x00, 0x00 };
    const char *v = oui_lookup(mac);
    ASSERT(v != NULL);
    ASSERT_STR(v, "Espressif");
}

void run_oui_tests(void) {
    TEST_SUITE("OUI lookup");
    RUN_TEST(test_oui_espressif);
    RUN_TEST(test_oui_raspberry_pi3);
    RUN_TEST(test_oui_raspberry_pi4);
    RUN_TEST(test_oui_apple);
    RUN_TEST(test_oui_intel);
    RUN_TEST(test_oui_randomized_bit);
    RUN_TEST(test_oui_multicast_bit);
    RUN_TEST(test_oui_unknown);
    RUN_TEST(test_oui_lookup_str_lowercase);
    RUN_TEST(test_oui_lookup_str_uppercase);
    RUN_TEST(test_oui_lookup_str_invalid);
    RUN_TEST(test_oui_espressif_5ccf7f);
}
