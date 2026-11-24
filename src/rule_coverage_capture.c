#include <string.h>
#include "rule_coverage_live.h"
#include "mon_radios.h"
#include "wifi_chanhop.h"
#include "ownership.h"
#include "db.h"
#include "alerts/rules.h"

/* The capture side of the coverage environment (#242 slice 2): the
 * 802.11 radios, the host tables and the operator's configuration.
 * Registered by capture_side_install() and named nowhere else, so that
 * sloth-rf links none of what this file reads.
 *
 * WHAT THE RADIO FIGURES ARE. `radios` counts the monitor radios that
 * are open; `channels` the channels over all their plans (a radio that
 * is not retuned counts one); `bands` the bands those channels lie in.
 * Under --hop the bands are the plan's, so a band the radios visit and
 * hear nothing in still counts as visited. Without --hop a radio's
 * channel is known only from the newest frame it received, so the band
 * is unknown (0, no band check) until a frame arrives - and for a
 * single radio that is never registered in the radio table it stays
 * unknown: every 802.11 rule reads `partly`, `fixed_channel` there
 * whatever the band, and no rule is called blind for a band on a
 * guess. */

/* main.c names every replayed stream's interface "replay" (#119). */
static int is_replay(const char *iface) { return strcmp(iface, "replay") == 0; }

int cov_capture_fill(const sloth_state_t *s, cov_env_t *e) {
    if (is_replay(s->pkt_iface) || is_replay(s->probe_iface) || is_replay(s->bt_iface))
        return 0;
    /* The socket table, the neighbour table and the interface list are
     * read each tick by the platform poll: this daemon has them for as
     * long as it runs. */
    e->input[COV_IN_HOST] = COV_AV_UP;

    if (ownership_any())             e->config |= COV_N_OWN_NET;
    if (ownership_known_count() > 0) e->config |= COV_N_ROSTER;
    if (db_is_open())                e->config |= COV_N_DB;

    /* What SENSOR_SUPPRESSED holds open (#242 item 4). Read before this
     * tick's rules run (the health stage is ahead of them), so a signal
     * that opens or closes this tick reaches the statuses on the next:
     * one second behind an incident that is minutes long. */
    rules_sensor_suppressed(&e->suppressed, &e->suppressed_frames);

    if (e->input[COV_IN_DOT11] == COV_AV_NONE) return 1;

    e->hopping = s->scan_chan_count > 0;
    if (mon_radios_active()) {
        int n = mon_radios_count();
        for (int k = 0; k < n; k++) {
            mon_radio_t r;
            if (!mon_radios_get(k, &r) || !mon_radio_alive(r.state)) continue;
            e->radios++;
            e->channels += r.hop_channels > 0 ? r.hop_channels : 1;
            if (r.hop_channels <= 0) e->bands |= cov_band_of_mhz(r.freq_mhz);
        }
        if (e->hopping) {
            int mhz[CHANHOP_MAX];
            int m = mon_hop_plan_mhz(mhz, CHANHOP_MAX);
            for (int i = 0; i < m; i++) e->bands |= cov_band_of_mhz(mhz[i]);
        }
    } else {
        e->radios = 1;
        e->channels = e->hopping ? s->scan_chan_count : 1;
        for (int i = 0; i < s->scan_chan_count; i++)
            e->bands |= cov_band_of_mhz(chanhop_freq(s->scan_chans[i]));
    }
    return 1;
}
