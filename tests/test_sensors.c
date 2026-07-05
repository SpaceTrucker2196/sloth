#include "runner.h"
#include "sloth.h"
#include "sensors.h"
#include <stdio.h>
#include <string.h>

static void test_register_find_or_create(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    sensor_t *a = sensor_register(&s, SENSOR_WIFI, "Wi-Fi monitor", "wlan1mon", 100);
    ASSERT(a != NULL);
    ASSERT_EQ(s.sensor_count, 1);
    ASSERT_EQ(a->state, SENSOR_STATE_PRESENT);
    ASSERT_STR(a->iface, "wlan1mon");
    ASSERT_EQ((long long)a->first_seen, 100);

    sensor_t *b = sensor_register(&s, SENSOR_WIFI, "x", "wlan1mon", 200);
    ASSERT(a == b);                 /* same kind+iface → same sensor */
    ASSERT_EQ(s.sensor_count, 1);

    sensor_t *c = sensor_register(&s, SENSOR_WIFI, "y", "wlan2mon", 300);
    ASSERT(c != a);                 /* different iface → new sensor */
    ASSERT_EQ(s.sensor_count, 2);
}

static void test_observe_promotes_to_active(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    sensor_t *a = sensor_register(&s, SENSOR_WIFI, "w", "mon0", 100);
    ASSERT_EQ(a->state, SENSOR_STATE_PRESENT);
    sensor_observe(a, 0, 110);      /* nothing seen yet */
    ASSERT_EQ(a->state, SENSOR_STATE_PRESENT);
    sensor_observe(a, 42, 120);     /* frames seen → active */
    ASSERT_EQ(a->state, SENSOR_STATE_ACTIVE);
    ASSERT_EQ((long long)a->observed, 42);
    ASSERT_EQ((long long)a->last_seen, 120);
}

static void test_registry_full(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    for (int i = 0; i < MAX_SENSORS; i++) {
        char ifc[16]; snprintf(ifc, sizeof(ifc), "mon%d", i);
        ASSERT(sensor_register(&s, SENSOR_WIFI, "w", ifc, 0) != NULL);
    }
    ASSERT_EQ(s.sensor_count, MAX_SENSORS);
    ASSERT(sensor_register(&s, SENSOR_WIFI, "w", "overflow", 0) == NULL);
}

static void test_kind_state_names(void) {
    ASSERT_STR(sensor_kind_name(SENSOR_WIFI), "wifi");
    ASSERT_STR(sensor_kind_name(SENSOR_BLE),  "ble");
    ASSERT_STR(sensor_kind_name(SENSOR_CAN),  "can");
    ASSERT_STR(sensor_kind_name(999),         "?");
    ASSERT_STR(sensor_state_name(SENSOR_STATE_ACTIVE), "active");
    ASSERT_STR(sensor_state_name(SENSOR_STATE_ERROR),  "error");
}

void run_sensors_tests(void) {
    TEST_SUITE("passive sensor registry");
    RUN_TEST(test_register_find_or_create);
    RUN_TEST(test_observe_promotes_to_active);
    RUN_TEST(test_registry_full);
    RUN_TEST(test_kind_state_names);
}
