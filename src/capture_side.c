#include "capture_side.h"
#include "alerts/rules.h"
#include "beacon_snoop.h"
#include "db.h"
#include "dns.h"
#include "sensor_health.h"
#include "sys_status.h"

static long long resolver_calls(void) {
    dns_resolver_stats_t ds;
    dns_resolver_stats(&ds);
    return (long long)ds.getnameinfo_calls;
}

static const sys_capture_side_t g_sys_capture_side = {
    sys_status_capture_fill,
    beacon_recall_stat,
};

void capture_side_install(void) {
    alerts_set_table(&g_alert_table_wifi);
    sys_status_set_capture_side(&g_sys_capture_side);
    sh_set_resolver_calls_fn(resolver_calls);
    /* This daemon has no decoder (#216): no RF source row and none of
     * the receiver's or the decoders' tables. Nothing registers either
     * in sloth-wifi, so these two lines change nothing there; they are
     * here for the test binary, which links both sides and puts this
     * one back before every test. */
    sys_status_set_rf_side(NULL);
    db_set_rf_side(NULL);
}
