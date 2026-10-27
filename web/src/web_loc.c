#include "web_loc.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

int web_loc_set(web_loc_t *out, double lat, double lon, int has_alt,
                double alt_m, int has_acc, double acc_m, const char *src,
                long long ts) {
    memset(out, 0, sizeof(*out));
    if (!isfinite(lat) || !isfinite(lon) || lat < -90.0 || lat > 90.0 ||
        lon < -180.0 || lon > 180.0)
        return 0;
    if (!src || (strcmp(src, "gps") != 0 && strcmp(src, "fixed") != 0))
        return 0;
    if (ts < 0) return 0;
    out->lat = lat;
    out->lon = lon;
    if (has_alt && isfinite(alt_m) && alt_m >= -1000.0 && alt_m <= 100000.0) {
        out->has_alt = 1;
        out->alt_m = alt_m;
    }
    if (has_acc && isfinite(acc_m) && acc_m >= 0.0 && acc_m <= 1e7) {
        out->has_acc = 1;
        out->acc_m = acc_m;
    }
    snprintf(out->src, sizeof(out->src), "%s", src);
    out->ts = ts;
    out->has = 1;
    return 1;
}

int web_loc_from_jrec(const web_jrec_t *r, web_loc_t *out) {
    memset(out, 0, sizeof(*out));
    double lat, lon, alt = 0, acc = 0;
    if (!web_jl_num(r, "loc.lat", &lat) || !web_jl_num(r, "loc.lon", &lon))
        return 0;
    int ha = web_jl_num(r, "loc.alt_m", &alt);
    int hc = web_jl_num(r, "loc.acc_m", &acc);
    long long ts = web_jl_int(r, "loc.ts", -1);
    return web_loc_set(out, lat, lon, ha, alt, hc, acc,
                       web_jl_str(r, "loc.src"), ts);
}

/* slothweb never calls setlocale(), so %f's point is '.'. */
static void num(web_jw_t *w, double v, int places) {
    char b[48];
    snprintf(b, sizeof(b), "%.*f", places, v);
    web_jw_raw(w, b);
}

void web_loc_json(web_jw_t *w, const web_loc_t *l) {
    if (!l || !l->has) { web_jw_raw(w, "null"); return; }
    web_jw_raw(w, "{\"lat\":");  num(w, l->lat, 7);
    web_jw_raw(w, ",\"lon\":");  num(w, l->lon, 7);
    web_jw_raw(w, ",\"alt_m\":");
    if (l->has_alt) num(w, l->alt_m, 1); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"acc_m\":");
    if (l->has_acc) num(w, l->acc_m, 1); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"src\":");  web_jw_str(w, l->src);
    web_jw_raw(w, ",\"ts\":");   web_jw_int(w, l->ts);
    web_jw_raw(w, "}");
}
