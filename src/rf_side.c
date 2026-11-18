#include "rf_side.h"
#include "adsb.h"
#include "alerts/rules.h"
#include "db.h"
#include "sys_status.h"

#ifdef WITH_SQLITE
static const db_rf_side_t g_db_rf_side = {
    adsb_row_sig,
    adsb_emergency_name,
};
#endif

void rf_side_install(void) {
    alerts_set_table(&g_alert_table_rf);
    sys_status_set_rf_side(sys_status_rf_fill);
#ifdef WITH_SQLITE
    db_set_rf_side(&g_db_rf_side);
#endif
}
