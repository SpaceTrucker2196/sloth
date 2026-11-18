#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sloth.h"
#include "gps.h"

/* libFuzzer smoke target for the --gps gpsd:// path (2026-10-27).
 *
 * The bytes are what a gpsd -- or anything listening on the port sloth
 * was pointed at -- sends after ?WATCH: one JSON object per line
 * (https://gpsd.gitlab.io/gpsd/gpsd_json.html), TPV / SKY / VERSION and
 * every other class, nested arrays of satellites, strings holding
 * brackets, numbers with exponents. gpsd_json_parse() sees the input
 * whole, then the framer streams it in two input-chosen chunks into the
 * arbitration state. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65536) return 0;
    static gpsd_msg_t m;
    if (gpsd_json_parse((const char *)data, size, &m) == 1) {
        int64_t ms;
        (void)strnlen(m.time, sizeof(m.time));
        /* The receiver's stamp parser sees every "time" the object
         * parser accepted (2026-11-02). */
        (void)gpsd_time_parse(m.time, &ms);
    }
    /* And the whole input as a time string, NUL-terminated. */
    {
        char t[64];
        size_t k = size < sizeof(t) - 1 ? size : sizeof(t) - 1;
        int64_t ms;
        memcpy(t, data, k);
        t[k] = '\0';
        (void)gpsd_time_parse(t, &ms);
    }

    static gps_lines_t L;
    gps_location_reset();
    gps_location_set_gps("gpsd:127.0.0.1:2947");
    gps_lines_init(&L, GPS_FEED_GPSD);
    size_t cut = size ? data[size - 1] % (size + 1) : 0;
    gps_lines_feed(&L, data, cut, 1800000000);
    gps_lines_feed(&L, data + cut, size - cut, 1800000001);
    gps_lines_feed(&L, (const uint8_t *)"\n", 1, 1800000001);
    loc_stamp_t l;
    gps_location_current(&l, 1800000001);
    char j[256];
    gps_loc_json(&l, j, sizeof(j));
    /* The sky and fix the stream left, and their signatures. */
    static gnss_sky_t k;
    static gnss_fix_t f;
    gps_sky_snapshot(&k);
    gps_fix_snapshot(&f);
    (void)gps_gnss_fix_sig(&f, &k);
    (void)gps_gnss_sky_sig(&k);
    for (int i = 0; i < k.n && i < GNSS_MAX_SATS; i++)
        (void)gps_gnss_sat_sig(&k.sats[i]);
    return 0;
}
