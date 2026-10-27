/* Where the sensor was (sloth --location / --gps, 2026-10-27), as
 * slothweb reads and serves it.
 *
 * Two sources, one shape. A stream alert record carries sloth's "loc"
 * object, which web_jl_parse() keeps as "loc.lat", "loc.src", ... fields
 * (web_jsonl.h); a schema-v9 alerts row carries the same six columns
 * (lat, lon, alt_m, acc_m, loc_src, loc_ts). Either way the value is
 * range-checked before it is kept: a latitude outside -90..90, a
 * longitude outside -180..180 or a source other than "gps"/"fixed" is
 * no location at all, never a clamped one.
 * /api/positions is web_positions.h. */
#ifndef SLOTHWEB_LOC_H
#define SLOTHWEB_LOC_H

#include <stddef.h>

#include "web_json.h"
#include "web_jsonl.h"

typedef struct {
    int       has;
    double    lat, lon;
    int       has_alt, has_acc;
    double    alt_m, acc_m;
    char      src[8];              /* "gps" | "fixed" */
    long long ts;
} web_loc_t;

/* Range-check and keep. 1 kept, 0 refused (out->has 0). */
int  web_loc_set(web_loc_t *out, double lat, double lon, int has_alt,
                 double alt_m, int has_acc, double acc_m, const char *src,
                 long long ts);

/* The "loc.*" fields of a stream record. 1 kept, 0 none or refused. */
int  web_loc_from_jrec(const web_jrec_t *r, web_loc_t *out);

/* `null`, or {"lat":..,"lon":..,"alt_m":..|null,"acc_m":..|null,
 * "src":"gps"|"fixed","ts":N}, degrees to 7 places, metres to 1. */
void web_loc_json(web_jw_t *w, const web_loc_t *l);

#endif
