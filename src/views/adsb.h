#ifndef VIEW_ADSB_H
#define VIEW_ADSB_H

#include "sloth.h"

/* [^] ADS-B (2026-11-07): the aircraft a local decoder's aircraft.json
 * lists, one row per address — ICAO, callsign, squawk, altitude, ground
 * speed, track, RSSI and age, with distance and bearing from the sensor
 * when a sensor position is known. Reads s->adsb / s->adsb_rows only,
 * plus gps_location_current() for the sensor's own position
 * (docs/views/adsb.md, docs/wiki/adsb.md). */
void view_adsb_draw(const sloth_state_t *s);
void view_adsb_key (sloth_state_t *s, int key);

#endif /* VIEW_ADSB_H */
