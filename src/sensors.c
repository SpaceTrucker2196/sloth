#include "sensors.h"
#include <string.h>
#include <stdio.h>

static const char *KIND[SENSOR_KIND_COUNT] = {
    "wifi", "ble", "zigbee", "sdr", "gps", "adsb", "meshtastic", "can",
    "aprs", "rtl433"
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
    /* Look up what would be STORED, not what was passed. The row's
     * iface is a truncated copy, so comparing the caller's full string
     * against it never matched for a source id of 32 bytes or more: the
     * same source re-registered on every poll, filled the 16 slots and
     * then got NULL, which stops its observation count dead while the
     * first (permanently PRESENT) row is the one every reader finds.
     * Found on #208, whose source label on the reference host
     * ("file:/var/lib/rtl_433/events.jsonl") is 34 bytes; --aprs's is
     * 31 and so never reached it. Two sources agreeing in the first
     * 31 bytes now share a row, which is what storing a truncated id
     * already meant. */
    char want[sizeof(((sensor_t *)0)->iface)];
    snprintf(want, sizeof(want), "%s", ifc);
    for (int i = 0; i < s->sensor_count; i++) {
        sensor_t *sn = &s->sensors[i];
        if (sn->kind == (int)kind && strcmp(sn->iface, want) == 0)
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
