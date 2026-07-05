#include "sensors.h"
#include <string.h>
#include <stdio.h>

static const char *KIND[SENSOR_KIND_COUNT] = {
    "wifi", "ble", "zigbee", "sdr", "gps", "adsb", "meshtastic", "can"
};

const char *sensor_kind_name(int kind) {
    return (kind >= 0 && kind < SENSOR_KIND_COUNT) ? KIND[kind] : "?";
}

const char *sensor_state_name(int state) {
    switch (state) {
    case SENSOR_STATE_PRESENT: return "present";
    case SENSOR_STATE_ACTIVE:  return "active";
    case SENSOR_STATE_HIDDEN:  return "hidden";
    case SENSOR_STATE_ERROR:   return "error";
    default:                   return "?";
    }
}

sensor_t *sensor_register(sloth_state_t *s, sensor_kind_t kind,
                          const char *name, const char *iface, time_t now) {
    if (!s) return NULL;
    const char *ifc = iface ? iface : "";
    for (int i = 0; i < s->sensor_count; i++) {
        sensor_t *sn = &s->sensors[i];
        if (sn->kind == (int)kind &&
            strncmp(sn->iface, ifc, sizeof(sn->iface)) == 0)
            return sn;
    }
    if (s->sensor_count >= MAX_SENSORS) return NULL;
    sensor_t *sn = &s->sensors[s->sensor_count++];
    memset(sn, 0, sizeof(*sn));
    sn->kind  = (int)kind;
    sn->state = SENSOR_STATE_PRESENT;
    snprintf(sn->name,  sizeof(sn->name),  "%s",
             (name && name[0]) ? name : sensor_kind_name(kind));
    snprintf(sn->iface, sizeof(sn->iface), "%s", ifc);
    sn->first_seen = sn->last_seen = now;
    return sn;
}

void sensor_observe(sensor_t *sn, uint64_t total_observed, time_t now) {
    if (!sn) return;
    sn->observed  = total_observed;
    sn->last_seen = now;
    if (total_observed > 0 && sn->state == SENSOR_STATE_PRESENT)
        sn->state = SENSOR_STATE_ACTIVE;
}

void sensor_set_state(sensor_t *sn, sensor_state_e state) {
    if (sn) sn->state = (int)state;
}
