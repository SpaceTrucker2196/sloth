/* /api/positions?mac=MAC[&format=json|geojson|gpx][&since=S][&until=U]
 * (sloth --gps, 2026-10-27).
 *
 * sloth.db's device_positions for one MAC — where the SENSOR was when
 * it heard the device; sloth has one antenna and no bearing, so this is
 * never the device's own position — and sensor_positions over the same
 * span (the sensor's track), newest first, at most WEB_POS_MAX of each,
 * last_seen in [since, until] (default: all of it up to now). Every
 * statement goes through the M4 reader and its allow-list
 * (web_slothdb.h); a file before schema v9 has neither table and
 * answers empty lists.
 *
 * Three renderings of the same rows. json: {"mac","positions":[...],
 * "track":[...],"more":bool}. geojson (RFC 7946): a FeatureCollection of
 * one Point per sample (properties ts, acc_m, rssi) and one LineString
 * of the track, coordinates [lon, lat] as §3.1.1 orders them. gpx (GPX
 * 1.1): a <wpt> per sample and one <trk>. Both are assembled from
 * numbers and fixed text only (the MAC is canonical hex and colons),
 * so no stream string reaches XML or GeoJSON. The capture scope does
 * not apply: a sample is the sensor's position, not a capture. */
#ifndef SLOTHWEB_POSITIONS_H
#define SLOTHWEB_POSITIONS_H

#include <stddef.h>

#include "web_devices.h"

enum { WEB_POS_JSON = 0, WEB_POS_GEOJSON, WEB_POS_GPX };

/* An answer is one buffer of WEB_SSE_MAX_UNSENT (64 KiB, web_server.h);
 * the widest rendering, GeoJSON, is about 190 bytes a sample plus 28 a
 * track point, so 200 of each leaves room. "more" says when there were
 * more: ask again with until= set to the oldest sample's ts. */
#define WEB_POS_MAX 200

/* Renders into body; *format says which content type the router must
 * declare (json for every error). 0 with *status set, -1 when body did
 * not fit. */
int web_positions_route(const web_m4_t *m, const char *query, long long now_s,
                        char *body, size_t cap, size_t *len, int *status,
                        int *format);

/* The Content-Type and the attachment's file extension for a format. */
const char *web_positions_ctype(int format);
const char *web_positions_ext(int format);

#endif
