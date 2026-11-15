#include "poll.h"
#include "adsb.h"
#include "aprs.h"
#include "rtl433.h"
#include "victron.h"
#include "sensors.h"
#include "jsonl.h"

/* The RF decoders' poll stages and the RF table (#212): ADS-B, APRS and
 * rtl_433. sloth-rf passes g_poll_rf (#213, src/rf/main.c); `sloth`
 * runs the first two stages from its own table (g_poll_sloth,
 * src/poll.c). Nothing here, or reachable from the table below, is a
 * capture stage, and the Makefile's `nm` gate on sloth-rf is what holds
 * that. */

void poll_st_health_rf(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* --adsb (#26 slice 1): expire the aircraft the decoder stopped
     * reporting and copy the table, before anything this tick reads it. */
    adsb_health_poll(s, ctx->wall, ctx->mono_ms);
    /* --aprs: expire the stations unheard for an hour and copy the
     * table and the packet ring, before anything this tick reads them. */
    aprs_health_poll(s, ctx->wall, ctx->mono_ms);
    /* --rtl433 (#208): copy the sub-GHz device table and its health,
     * before anything this tick reads them. No expiry: a device heard
     * once is a real observation of the band, and only the table
     * filling removes a row. */
    rtl433_health_poll(s, ctx->wall);
    /* --victron: copy sloth-va's device table and the file's health. */
    victron_health_poll(s, ctx->wall);
}

void poll_st_sensors_rf(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* ADS-B (#26 slice 1): the --adsb decoder file, observing parsed
     * documents. A missing, unreadable or malformed file, or a decoder
     * whose clock stopped advancing, is the registry's ERROR; recovery
     * puts it back to ACTIVE (or PRESENT before any document). After the
     * GNSS receiver, for the same id-slot reason. */
    if (s->adsb.configured) {
        sensor_t *ad = sensor_register(s, SENSOR_ADSB, "ADS-B decoder",
                                       s->adsb.src, ctx->wall);
        sensor_observe(ad, s->adsb.reads, ctx->wall);
        if (s->adsb.state == ADSB_ERROR || s->adsb.state == ADSB_STALE)
            sensor_set_state(ad, SENSOR_STATE_ERROR);
        else
            sensor_set_state(ad, s->adsb.reads ? SENSOR_STATE_ACTIVE
                                               : SENSOR_STATE_PRESENT);
    }
    /* APRS: Dire Wolf's packet log, observing decoded packets. An
     * unreadable file is the registry's ERROR; a missing one (Dire Wolf
     * creates it with its first packet) and a quiet channel are not:
     * PRESENT until a packet, ACTIVE after. After the ADS-B decoder,
     * for the same id-slot reason. */
    if (s->aprs.configured) {
        sensor_t *ap = sensor_register(s, SENSOR_APRS, "APRS decoder",
                                       s->aprs.src, ctx->wall);
        sensor_observe(ap, s->aprs.packets, ctx->wall);
        if (s->aprs.state == APRS_ERROR)
            sensor_set_state(ap, SENSOR_STATE_ERROR);
        else
            sensor_set_state(ap, s->aprs.packets ? SENSOR_STATE_ACTIVE
                                                 : SENSOR_STATE_PRESENT);
    }
    /* rtl_433 (#208): the --rtl433 event log, observing decoded
     * messages. The same rule as APRS - an unreadable file is the
     * registry's ERROR, a missing one (rtl_433 creates it with its
     * first decode) and a quiet band are not. After the APRS decoder,
     * for the same id-slot reason. */
    if (s->rtl433.configured) {
        sensor_t *rt = sensor_register(s, SENSOR_RTL433, "rtl_433 decoder",
                                       s->rtl433.src, ctx->wall);
        sensor_observe(rt, s->rtl433.msgs, ctx->wall);
        if (s->rtl433.state == RTL433_ERROR)
            sensor_set_state(rt, SENSOR_STATE_ERROR);
        else
            sensor_set_state(rt, s->rtl433.msgs ? SENSOR_STATE_ACTIVE
                                                : SENSOR_STATE_PRESENT);
    }
    /* Victron: sloth-va's JSONL, observing records. The same rule as
     * rtl_433: an unreadable file is ERROR, a missing one (sloth-va
     * creates it with its first reading) and a quiet one are not. After
     * rtl_433, for the same id-slot reason. */
    if (s->victron.configured) {
        sensor_t *vi = sensor_register(s, SENSOR_VICTRON, "Victron (sloth-va)",
                                       s->victron.src, ctx->wall);
        sensor_observe(vi, s->victron.records, ctx->wall);
        if (s->victron.state == VICTRON_ERROR)
            sensor_set_state(vi, SENSOR_STATE_ERROR);
        else
            sensor_set_state(vi, s->victron.records ? SENSOR_STATE_ACTIVE
                                                    : SENSOR_STATE_PRESENT);
    }
}

void poll_st_jsonl_rf(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    /* sloth-rf's EMIT stage (#213): the records this daemon has, through
     * the emitters `sloth` uses for the same ones. Last before durable
     * state, for the reason poll_st_jsonl() gives. */
    jsonl_emit_state_rf(s);
}

/* The RF half, which sloth-rf runs: the receiver and the decoders, the
 * host's own state, the alert engine (over the table the daemon
 * selected, src/alerts/rules_table_rf.c), the sensor's own track and
 * the two sinks. health_gnss stays ahead of health_rf (the APRS region
 * check) and health_host behind both (it reads them). "positions" is
 * here since the 2026-11-15 ruling that both daemons write
 * sensor_positions (ADR 0010); "jsonl" is this daemon's own stage under
 * the union's name. */
static const poll_stage_t rf_stages[] = {
    { "health_gnss",  PH_PLATFORM, poll_st_health_gnss  },
    { "health_rf",    PH_PLATFORM, poll_st_health_rf    },
    { "health_host",  PH_PLATFORM, poll_st_health_host  },

    { "sensors_gnss", PH_DERIVE,   poll_st_sensors_gnss },
    { "sensors_rf",   PH_DERIVE,   poll_st_sensors_rf   },

    { "alerts",       PH_ALERTS,   poll_st_alerts       },

    { "positions",    PH_POST,     poll_st_positions    },

    { "jsonl",        PH_EMIT,     poll_st_jsonl_rf     },

    { "db",           PH_DURABLE,  poll_st_db           },
};
const poll_table_t g_poll_rf = {
    rf_stages, (int)(sizeof(rf_stages) / sizeof(rf_stages[0]))
};
