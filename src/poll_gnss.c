#include "poll.h"
#include "gps.h"
#include "sensors.h"

/* The GNSS receiver's poll stages (#212). Both daemons of #211 link the
 * one gpsd reader, so both tables carry these two; they are apart from
 * the Wi-Fi stages (src/poll.c) and the RF ones (src/poll_rf.c) so that
 * neither has to come along. */

void poll_st_health_gnss(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* --location / --gps (2026-10-27): the reader's state into s->gps,
     * before anything this tick stamps a position - and before the RF
     * health stage, whose APRS region check reads s->gps. */
    gps_health_poll(s, ctx->wall);
}

void poll_st_sensors_gnss(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* GNSS (2026-11-02): the --gps receiver is a sensor too, observing
     * parsed sentences / gpsd objects. After the radios: a sensor's id
     * is its registry slot and wifi_merged publishes it, so the radio
     * keeps id 0 whether or not a receiver is configured. s->gps is
     * this tick's (health_gnss ran in PLATFORM). A --location alone
     * registers nothing: it is a setting, not a receiver. */
    if (s->gps.has_gps) {
        sensor_t *gn = sensor_register(s, SENSOR_GPS, "GNSS receiver",
                                       s->gps.src, ctx->wall);
        sensor_observe(gn, s->gps.sentences, ctx->wall);
    }
}
