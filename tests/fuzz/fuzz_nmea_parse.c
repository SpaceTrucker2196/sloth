#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sloth.h"
#include "gps.h"

/* libFuzzer smoke target for the --gps serial path (2026-10-27).
 *
 * Every byte is the receiver's, or whatever sits on the far end of the
 * serial line: NMEA 0183 sentences ("$TTSSS,f,...*hh\r\n", at most 82
 * bytes, https://gpsd.gitlab.io/gpsd/NMEA.html), or anything else. The
 * input is parsed once whole by nmea_parse(), which must refuse what is
 * over length or mis-summed without reading past n, and then streamed
 * through the line framer in two chunks split at an input-chosen point,
 * which merges every sentence into the receiver state and the
 * arbitration the alert engine reads. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65536) return 0;
    nmea_fix_t f;
    nmea_fix_init(&f);
    (void)nmea_checksum_ok((const char *)data, size);
    (void)nmea_parse((const char *)data, size, &f);
    (void)nmea_fix_usable(&f);

    static gps_lines_t L;
    gps_location_reset();
    gps_location_set_gps("nmea:/dev/fuzz");
    gps_lines_init(&L, GPS_FEED_NMEA);
    size_t cut = size ? data[0] % (size + 1) : 0;
    gps_lines_feed(&L, data, cut, 1800000000);
    gps_lines_feed(&L, data + cut, size - cut, 1800000001);
    gps_lines_feed(&L, (const uint8_t *)"\n", 1, 1800000001);
    loc_stamp_t l;
    gps_location_current(&l, 1800000001);
    char j[256], t[160];
    gps_loc_json(&l, j, sizeof(j));
    gps_loc_text(&l, 1800000001, t, sizeof(t));
    return 0;
}
