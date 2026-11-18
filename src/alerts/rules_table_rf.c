/* The rule table sloth-rf selects (#213, ADR 0010): the GNSS rules,
 * ADSB_EMERGENCY and SENSOR_SOURCE_DOWN, in the order the one table ran
 * them before the cutover (#216). The first five are this table's
 * alone now; sloth-wifi's (src/alerts/rules_table.c) has none of them.
 * Nothing else lives here.
 *
 * SENSOR_UNDERVOLT is absent on purpose. It reports the host's supply,
 * not a source, and a host running both daemons would report one
 * brown-out twice; the owner ruled on 2026-11-15 that the daemon with
 * the capture reports it and this one does not. tests/test_rf_rules.c
 * holds the absence, this table's rows and their order by name, and
 * that the only row the two tables share is rule_sensor_source_down.
 *
 * No exporter: both of them write captured frames, and this daemon
 * captures none. That is also what keeps src/alert_pcap.c and
 * src/evidence_export.c, and the handshake export behind them, out of
 * its link. */
#include "rules.h"
#include "engine_internal.h"

#define R(fn) { #fn, fn }

static const alert_rule_t rf_rules[] = {
    /* Jamming first, as in the full table: when a jam and a
     * reacquisition land in one tick, the interference reaches the
     * stream before the suspicion it feeds. */
    R(rule_gnss_jamming),
    R(rule_gnss_time_jump),
    R(rule_gnss_position_jump),
    R(rule_gnss_spoof_suspect),
    R(rule_adsb_emergency),
    /* Reads sys_status_get(), whose rows in this daemon are its own
     * sources only (src/sys_status.h). */
    R(rule_sensor_source_down),
};

#undef R

static void (*const rf_forget[])(void) = {
    rules_gnss_forget,
    rules_adsb_forget,
    rules_sensor_forget,
};

const alert_rule_table_t g_alert_table_rf = {
    rf_rules,
    (int)(sizeof(rf_rules) / sizeof(rf_rules[0])),
    rf_forget,
    (int)(sizeof(rf_forget) / sizeof(rf_forget[0])),
    NULL,
};
