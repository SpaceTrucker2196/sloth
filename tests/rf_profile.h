#ifndef SLOTH_TEST_RF_PROFILE_H
#define SLOTH_TEST_RF_PROFILE_H

#include "alerts/rules.h"
#include "sensor_health.h"
#include "sys_status.h"

/* What sloth-rf is when its main() reaches the first tick (#213,
 * src/rf/main.c): its own rule table selected and nothing else
 * registered, because it does not link src/capture_side.c - so
 * sys_status has no capture side and the memory sample no resolver.
 *
 * The test binary is `sloth`'s (tests/main_test.c installs the capture
 * side before every test), so a test that wants to hold sloth-rf's
 * behaviour to something puts the services in that shape with this,
 * and the next test's setup puts them back. */
static inline void rf_profile_select(void) {
    alerts_set_table(&g_alert_table_rf);
    sys_status_set_capture_side(NULL);
    sh_set_resolver_calls_fn(NULL);
}

#endif /* SLOTH_TEST_RF_PROFILE_H */
