#include <stdio.h>
#include <string.h>

#include "sys_status.h"
#include "adsb.h"
#include "aprs.h"
#include "rtl433.h"
#include "victron.h"

/* The RF side's source rows (#216): the ADS-B, APRS and rtl_433
 * decoders and sloth-va's Victron file. Out of src/sys_status.c,
 * unchanged, so that file no longer names a decoder and sloth-wifi
 * links none; src/sys_status.h says what registers this and what a
 * daemon without it reports. The mirror of src/sys_status_capture.c. */

void sys_status_rf_fill(const sloth_state_t *s, sys_source_t *src,
                        uint64_t mono_ms) {
    sys_source_t *o;

    o = &src[SYS_SRC_ADSB];
    o->name = "adsb"; o->flag = "--adsb"; o->unit = "messages";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "adsb");
    if (s->adsb.configured) {
        const adsb_health_t *a = &s->adsb;
        snprintf(o->endpoint, sizeof(o->endpoint), "%s", a->src);
        o->count = a->messages; o->errors = a->read_errors + a->parse_errors;
        o->age_s = a->age_s;
        snprintf(o->detail, sizeof(o->detail), "%s%s%.70s", adsb_state_name(a->state),
                 a->err[0] ? ": " : "", a->err);
        o->state = a->state == ADSB_LIVE ? SYS_ST_OK
                 : a->state == ADSB_ERROR ? SYS_ST_DOWN : SYS_ST_STALE;
    }

    o = &src[SYS_SRC_APRS];
    o->name = "aprs"; o->flag = "--aprs"; o->unit = "packets";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "aprs");
    if (s->aprs.configured) {
        const aprs_health_t *a = &s->aprs;
        snprintf(o->endpoint, sizeof(o->endpoint), "%s", a->src);
        o->count = a->packets; o->errors = a->read_errors + a->bad_lines;
        o->age_s = sys_status_track_age(SYS_SRC_APRS, a->packets, mono_ms);
        snprintf(o->detail, sizeof(o->detail), "%s%s%s%.60s", aprs_state_name(a->state),
                 a->missing ? " (file not there yet)" : "", a->err[0] ? ": " : "", a->err);
        /* A quiet channel is not a fault (aprs_health_t): live stays ok
         * however old the last packet; its age says how quiet. */
        o->state = a->state == APRS_LIVE ? SYS_ST_OK
                 : a->state == APRS_ERROR ? SYS_ST_DOWN : SYS_ST_STALE;
    }

    o = &src[SYS_SRC_RTL433];
    o->name = "rtl433"; o->flag = "--rtl433"; o->unit = "messages";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "sub-ghz");
    if (s->rtl433.configured) {
        const rtl433_health_t *r = &s->rtl433;
        snprintf(o->endpoint, sizeof(o->endpoint), "%s", r->src);
        o->count = r->msgs; o->errors = r->read_errors + r->bad_lines;
        o->age_s = sys_status_track_age(SYS_SRC_RTL433, r->msgs, mono_ms);
        snprintf(o->detail, sizeof(o->detail), "%s%s%s%.60s",
                 rtl433_state_name(r->state),
                 r->missing ? " (file not there yet)" : "",
                 r->err[0] ? ": " : "", r->err);
        /* A quiet band is not a fault (rtl433_health_t): live stays ok
         * however old the last decode; its age says how quiet. */
        o->state = r->state == RTL433_LIVE ? SYS_ST_OK
                 : r->state == RTL433_ERROR ? SYS_ST_DOWN : SYS_ST_STALE;
    }

    o = &src[SYS_SRC_VICTRON];
    o->name = "victron"; o->flag = "--victron"; o->unit = "records";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "victron");
    if (s->victron.configured) {
        const victron_health_t *v = &s->victron;
        snprintf(o->endpoint, sizeof(o->endpoint), "%s", v->src);
        o->count = v->records; o->errors = v->read_errors + v->bad_lines;
        o->age_s = sys_status_track_age(SYS_SRC_VICTRON, v->records, mono_ms);
        snprintf(o->detail, sizeof(o->detail), "%s%s%s%.60s",
                 victron_state_name(v->state),
                 v->missing ? " (file not there yet)" : "",
                 v->err[0] ? ": " : "", v->err);
        /* Quiet is not a fault (victron_health_t): sloth-va writes
         * nothing while the devices are out of range, so live stays ok
         * however old the last record; its age says how quiet. A file
         * that is not there yet (sloth-va not started, or no record
         * yet) is stale, so it is held and then reported. */
        o->state = v->state == VICTRON_LIVE ? SYS_ST_OK
                 : v->state == VICTRON_ERROR ? SYS_ST_DOWN : SYS_ST_STALE;
    }
}
