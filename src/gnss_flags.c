#include <stdio.h>
#include <stdlib.h>

#include "gnss_flags.h"
#include "gps.h"
#include "capture/gps_reader.h"

/* src/gnss_flags.h. Moved out of src/main.c, text unchanged. */

int gnss_flag_baud(const char *arg, int *out) {
    char *end = NULL;
    long b = strtol(arg, &end, 10);
    if (!end || *end || !gps_reader_baud_ok((int)b)) {
        fprintf(stderr, "sloth: --gps-baud %s: want 4800, 9600, "
                        "19200, 38400, 57600 or 115200\n", arg);
        return 2;
    }
    *out = (int)b;
    return 0;
}

int gnss_flags_check(const gnss_flags_t *f, int strict, int replay) {
    /* 2026-10-27: --location is validated here so a mistyped position
     * exits before anything opens; --gps is checked for shape and
     * scope here and opened just before the privilege drop. */
    if (f->location) {
        char lerr[160];
        if (gps_location_parse_fixed(f->location, lerr, sizeof(lerr)) != 0) {
            fprintf(stderr, "sloth: --location %s: %s\n", f->location, lerr);
            return 2;
        }
        fprintf(stderr, "sloth: --location fixed sensor position %s (WGS84): "
                        "stamped on new alert incidents in the JSONL log, "
                        "--db and the evidence manifests\n", f->location);
    }
    if (f->baud && !f->gps) {
        fprintf(stderr, "sloth: --gps-baud needs --gps /dev/...\n");
        return 2;
    }
    if (f->gps) {
        gps_spec_t gsp;
        char gerr[160];
        if (gps_spec_parse(f->gps, &gsp, gerr, sizeof(gerr)) != 0) {
            fprintf(stderr, "sloth: --gps %s: %s\n", f->gps, gerr);
            return 2;
        }
        if (replay) {
            fprintf(stderr, "sloth: --replay reads savefiles, not a live "
                            "receiver: --gps does not apply (--location "
                            "does)\n");
            return 2;
        }
        if (gps_spec_is_remote(&gsp) && strict) {
            fprintf(stderr, "sloth: --strict refuses a remote gpsd (%s): "
                            "use gpsd://127.0.0.1 or a serial device, or "
                            "drop --strict\n", gsp.host);
            return 2;
        }
        if (gps_spec_is_remote(&gsp) && !f->allow_remote) {
            fprintf(stderr, "sloth: --gps %s is not loopback; pass "
                            "--gps-allow-remote to read a remote gpsd\n",
                    f->gps);
            return 2;
        }
        if (f->baud && gsp.kind != GPS_SPEC_SERIAL) {
            fprintf(stderr, "sloth: --gps-baud applies to a serial "
                            "--gps /dev/... only\n");
            return 2;
        }
    } else if (f->allow_remote) {
        fprintf(stderr, "sloth: --gps-allow-remote ignored: no --gps\n");
    }
    return 0;
}

int gnss_flags_open(const gnss_flags_t *f) {
    /* 2026-10-27: --gps. A serial receiver is opened here, before the
     * drop, because the drop clears supplementary groups and the device
     * is usually group dialout; gpsd is only recorded here and dialled
     * by the worker after the drop. Read-only either way except for the
     * one ?WATCH line gpsd needs, which is announced. */
    if (!f->gps) return 0;
    char gerr[320];
    if (gps_reader_configure(f->gps, f->allow_remote, f->baud,
                             gerr, sizeof(gerr)) != 0) {
        fprintf(stderr, "sloth: --gps %s\n", gerr);
        return 2;
    }
    gps_spec_t gsp;
    char ann[400];
    if (gps_spec_parse(f->gps, &gsp, NULL, 0) == 0) {
        gps_spec_announce(&gsp, ann, sizeof(ann));
        fprintf(stderr, "sloth: --gps %s\n", ann);
    }
    return 0;
}
