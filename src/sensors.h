#ifndef SENSORS_H
#define SENSORS_H

#include "sloth.h"

/* Passive sensor registry (issue #28) — the normalization seam every
 * observation source registers through. Small and boring by design. */

/* Find-or-create a sensor keyed by (kind, iface). Returns NULL only if the
 * registry is full. New sensors start PRESENT with first/last-seen = now. */
sensor_t *sensor_register(sloth_state_t *s, sensor_kind_t kind,
                          const char *name, const char *iface, time_t now);

/* Record the cumulative observation count; bumps last_seen and promotes a
 * PRESENT sensor to ACTIVE once it has produced anything. */
void sensor_observe(sensor_t *sn, uint64_t total_observed, time_t now);

void sensor_set_state(sensor_t *sn, sensor_state_e state);

const char *sensor_kind_name(int kind);   /* "wifi", "ble", … */
const char *sensor_state_name(int state); /* "present", "active", … */

#endif /* SENSORS_H */
