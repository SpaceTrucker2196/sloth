#ifndef SLOTH_RF_SIDE_H
#define SLOTH_RF_SIDE_H

/* What the daemon with the decoders plugs into the services both
 * daemons share (#216, ADR 0010). The mirror of src/capture_side.h.
 *
 * Until the cutover sys_status and the database writer named the
 * decoders directly: the adsb / aprs / rtl433 / victron source rows,
 * and the gnss_*, adsb_*, aprs_* and victron_* tables. Linking either
 * linked the decoders, so sloth-wifi could not shed them. Each takes
 * that part as data now, and this is the one place that hands it over:
 *
 *   alerts_set_table()         the GNSS rules, ADSB_EMERGENCY and
 *                              SENSOR_SOURCE_DOWN  (alerts/rules.h)
 *   sys_status_set_rf_side()   the four decoder rows  (sys_status.h)
 *   db_set_rf_side()           the receiver's and the decoders' tables
 *                              (db.h)
 *
 * sloth-rf calls it first thing in main(). sloth-wifi does not link
 * this file, which is what "no decoder" means to the three services;
 * the Makefile's check_wifi_no_rf holds its link to that. Idempotent. */
void rf_side_install(void);

#endif /* SLOTH_RF_SIDE_H */
