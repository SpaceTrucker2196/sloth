#include "capture_side.h"
#include "alerts/rules.h"
#include "beacon_snoop.h"
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
    alerts_set_table(&g_alert_table_sloth);
    sys_status_set_capture_side(&g_sys_capture_side);
    sh_set_resolver_calls_fn(resolver_calls);
}
