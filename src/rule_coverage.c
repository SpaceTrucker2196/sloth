#include <stdio.h>
#include "rule_coverage.h"
#include "sloth_compat.h"

/* Coverage assessment (#242): the per-kind declarations and the status
 * derived from them. Contract and limits: rule_coverage.h. */

static const cov_inputs_t cov_table[] = {
#define X(id, in, frames, bands, shape, needs) \
    [ALERT_TYPE_##id] = { COV_IN_##in, (frames), (bands), COV_SHAPE_##shape, (needs) },
#include "sloth_alert_inputs.def"
#undef X
};
SLOTH_STATIC_ASSERT(sizeof(cov_table) / sizeof(*cov_table) == ALERT_TYPE_COUNT,
                    cov_table_covers_every_type);

const cov_inputs_t *cov_inputs(alert_type_t t) {
    if ((int)t < 0 || t >= ALERT_TYPE_COUNT) return NULL;
    return &cov_table[t];
}

int cov_daemon_raises(cov_daemon_t d, alert_type_t t) {
    const cov_inputs_t *in = cov_inputs(t);
    if (!in) return 0;
    int rf_input = in->input == COV_IN_GNSS || in->input == COV_IN_ADSB;
    if (d == COV_DAEMON_RF) return rf_input || t == ALERT_TYPE_SENSOR_SOURCE_DOWN;
    return !rf_input;
}

cov_status_t cov_rule_status(alert_type_t t, const cov_env_t *env,
                             cov_reason_t *why) {
    cov_reason_t r = COV_R_NONE;
    cov_status_t st = COV_OBSERVABLE;
    const cov_inputs_t *d = cov_inputs(t);

    if (!d || !env) {
        if (why) *why = COV_R_NO_SOURCE;
        return COV_BLIND;
    }
    cov_avail_t av = env->input[d->input];
    unsigned missing = d->needs & ~env->config;

    if (av == COV_AV_NONE)               { st = COV_BLIND; r = COV_R_NO_SOURCE; }
    else if (av == COV_AV_DOWN)          { st = COV_BLIND; r = COV_R_SOURCE_DOWN; }
    else if (missing & COV_N_OWN_NET)    { st = COV_BLIND; r = COV_R_NO_OWN_NET; }
    else if (missing & COV_N_ROSTER)     { st = COV_BLIND; r = COV_R_NO_ROSTER; }
    else if (missing & COV_N_DB)         { st = COV_BLIND; r = COV_R_NO_DB; }
    else if (d->input == COV_IN_DOT11 && d->bands != COV_B_ANY &&
             env->bands && !(d->bands & env->bands)) {
        st = COV_BLIND; r = COV_R_BAND;
    } else if (av == COV_AV_STALE) {
        st = COV_PARTLY; r = COV_R_SOURCE_STALE;
    } else if (d->input == COV_IN_DOT11) {
        if (!env->hopping) {
            /* A radio that is never retuned hears its one channel
             * whole and nothing else: every 802.11 rule, whatever its
             * shape, is watching a fraction of the site. */
            st = COV_PARTLY; r = COV_R_FIXED_CHANNEL;
        } else if (d->shape != COV_SHAPE_STATE && env->channels > env->radios) {
            /* More channels than radios: each is left for a time, and a
             * window, a single frame or an exchange that falls in that
             * time is lost. One radio per channel leaves no such gap. */
            st = COV_PARTLY; r = COV_R_HOP;
        }
    }
    if (why) *why = r;
    return st;
}

const char *cov_input_name(cov_input_t in) {
    static const char *const n[COV_IN_COUNT] = {
        [COV_IN_DOT11] = "dot11", [COV_IN_IP] = "ip", [COV_IN_HOST] = "host",
        [COV_IN_BLE_ADV] = "ble_adv", [COV_IN_BLE_HCI] = "ble_hci",
        [COV_IN_GNSS] = "gnss", [COV_IN_ADSB] = "adsb", [COV_IN_SYS] = "sys",
    };
    return (int)in >= 0 && in < COV_IN_COUNT ? n[in] : "";
}

const char *cov_shape_name(cov_shape_t sh) {
    switch (sh) {
    case COV_SHAPE_STATE:    return "state";
    case COV_SHAPE_RATE:     return "rate";
    case COV_SHAPE_EVENT:    return "event";
    case COV_SHAPE_EXCHANGE: return "exchange";
    case COV_SHAPE_NA:       break;
    }
    return "";
}

const char *cov_status_name(cov_status_t st) {
    switch (st) {
    case COV_BLIND:      return "blind";
    case COV_PARTLY:     return "partly";
    case COV_OBSERVABLE: return "observable";
    }
    return "";
}

const char *cov_reason_name(cov_reason_t r) {
    static const char *const n[COV_R_COUNT] = {
        [COV_R_NONE] = "", [COV_R_NO_SOURCE] = "no_source",
        [COV_R_SOURCE_DOWN] = "source_down", [COV_R_NO_OWN_NET] = "no_own_net",
        [COV_R_NO_ROSTER] = "no_roster", [COV_R_NO_DB] = "no_db",
        [COV_R_BAND] = "band", [COV_R_SOURCE_STALE] = "source_stale",
        [COV_R_FIXED_CHANNEL] = "fixed_channel", [COV_R_HOP] = "hop",
    };
    return (int)r >= 0 && r < COV_R_COUNT ? n[r] : "";
}

typedef struct { unsigned bit; const char *name; } cov_bit_t;

static int mask_str(unsigned mask, const cov_bit_t *bits, int nbits,
                    char *out, size_t sz) {
    size_t len = 0;
    if (!out || !sz) return 0;
    out[0] = '\0';
    for (int i = 0; i < nbits; i++) {
        if (!(mask & bits[i].bit)) continue;
        int w = snprintf(out + len, sz - len, "%s%s", len ? "," : "", bits[i].name);
        if (w < 0) break;
        if ((size_t)w >= sz - len) { len = sz - 1; break; }
        len += (size_t)w;
    }
    return (int)len;
}

int cov_frames_str(unsigned frames, char *out, size_t sz) {
    static const cov_bit_t b[] = {
        { COV_F_BEACON, "beacon" }, { COV_F_PROBE, "probe" },
        { COV_F_AUTH, "auth" }, { COV_F_ASSOC, "assoc" },
        { COV_F_DEAUTH, "deauth" }, { COV_F_ACTION, "action" },
        { COV_F_CTRL, "ctrl" }, { COV_F_DATA, "data" },
        { COV_F_EAPOL, "eapol" },
    };
    return mask_str(frames, b, (int)(sizeof(b) / sizeof(*b)), out, sz);
}

int cov_bands_str(unsigned bands, char *out, size_t sz) {
    static const cov_bit_t b[] = {
        { COV_B_24, "2.4" }, { COV_B_5, "5" }, { COV_B_5DFS, "5dfs" },
        { COV_B_6, "6" },
    };
    return mask_str(bands, b, (int)(sizeof(b) / sizeof(*b)), out, sz);
}

int cov_needs_str(unsigned needs, char *out, size_t sz) {
    static const cov_bit_t b[] = {
        { COV_N_OWN_NET, "own_net" }, { COV_N_ROSTER, "roster" },
        { COV_N_DB, "db" },
    };
    return mask_str(needs, b, (int)(sizeof(b) / sizeof(*b)), out, sz);
}

unsigned cov_band_of_mhz(int mhz) {
    /* Written out here and not asked of src/wifi_freq.c and
     * src/reg_table.c, so that this file names no 802.11 module and
     * links into sloth-rf. The DFS span is the union of the two
     * jurisdictions that table carries: channels 52-64 and 100-144,
     * centre frequencies 5260-5320 and 5500-5720 MHz (47 CFR
     * 15.407(h)(2); EN 301 893 4.2.6). tests/test_rule_coverage.c holds the
     * edges to those channel numbers. */
    if (mhz >= 2400 && mhz <= 2500) return COV_B_24;
    if (mhz >= 5150 && mhz < 5250)  return COV_B_5;
    if (mhz >= 5250 && mhz < 5735)  return COV_B_5DFS;
    if (mhz >= 5735 && mhz <= 5895) return COV_B_5;
    if (mhz >= 5925 && mhz <= 7125) return COV_B_6;
    return 0;
}
