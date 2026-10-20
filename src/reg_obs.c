#include <math.h>
#include <stdio.h>
#include <string.h>

#include "reg_obs.h"

int reg_obs_any(const reg_ie_t *r, const reg_6g_t *g) {
    if (r && (r->country_present || r->power_constraint_present ||
              r->tpc_present || r->malformed_country ||
              r->malformed_power_constraint || r->malformed_tpc))
        return 1;
    if (g && (g->he6_present || g->tpe_count ||
              g->malformed_he6 || g->malformed_tpe))
        return 1;
    return 0;
}

static int any_malformed(const reg_ie_t *r, const reg_6g_t *g) {
    return (r && (r->malformed_country || r->malformed_power_constraint ||
                  r->malformed_tpc)) ||
           (g && (g->malformed_he6 || g->malformed_tpe));
}

static void country_token(const reg_ie_t *r, char *t, size_t sz) {
    if (!r || !r->country_present) { snprintf(t, sz, "--"); return; }
    /* Two octets the transmitter chose; only what could be an ISO code
     * reaches the screen as itself. */
    char cc[3];
    for (int i = 0; i < 2; i++) {
        char c = r->country[i];
        cc[i] = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9')) ? c : '?';
    }
    cc[2] = '\0';
    const char *env = "";
    switch (r->env) {
    case REG_ENV_INDOOR:        env = "/I"; break;
    case REG_ENV_OUTDOOR:       env = "/O"; break;
    case REG_ENV_NON_COUNTRY:   env = "/X"; break;
    case REG_ENV_OPCLASS_TABLE: env = "/T"; break;
    case REG_ENV_UNKNOWN:       env = "/?"; break;
    default:                    break;
    }
    snprintf(t, sz, "%s%s", cc, env);
}

#define REG_TOK_LEN 12

void reg_obs_column(const reg_ie_t *r, const reg_6g_t *g, int width,
                    char *out, size_t sz) {
    if (!out || sz == 0) return;
    out[0] = '\0';
    if (width < 1) return;
    if ((size_t)width >= sz) width = (int)sz - 1;
    if (!reg_obs_any(r, g)) { snprintf(out, sz, "-"); return; }

    char tok[REG_TOK_LEN];
    country_token(r, tok, sizeof(tok));
    snprintf(out, (size_t)width + 1, "%s", tok);
    size_t len = strlen(out);

    char toks[6][REG_TOK_LEN];
    int  n = 0;
    if (any_malformed(r, g)) snprintf(toks[n++], REG_TOK_LEN, "MAL");
    if (g && g->he6_present) {
        if (g->he6_reg_info == REG_6G_INDOOR_AP)
            snprintf(toks[n++], REG_TOK_LEN, "6G:IN");
        else if (g->he6_reg_info == REG_6G_STANDARD_AP)
            snprintf(toks[n++], REG_TOK_LEN, "6G:SP");
        else
            snprintf(toks[n++], REG_TOK_LEN, "6G:R%u",
                     (unsigned)(g->he6_reg_info & 0x07));
    }
    if (r && r->tpc_present)
        snprintf(toks[n++], REG_TOK_LEN, "TPC%d", (int)r->tpc_tx_power_dbm);
    if (r && r->power_constraint_present)
        snprintf(toks[n++], REG_TOK_LEN, "PC%u",
                 (unsigned)r->power_constraint_db);
    if (g && g->tpe_count)
        snprintf(toks[n++], REG_TOK_LEN, "TPE%u", (unsigned)g->tpe_count);

    for (int i = 0; i < n; i++) {
        size_t tl = strlen(toks[i]);
        if (len + 1 + tl > (size_t)width) break;
        out[len++] = ' ';
        memcpy(out + len, toks[i], tl + 1);
        len += tl;
    }
}

double reg_obs_fspl_1m_db(int freq_mhz) {
    if (freq_mhz <= 0) return 0.0;
    return 20.0 * log10((double)freq_mhz) - 27.55;
}

int reg_obs_freq_mhz(int channel, uint8_t channel_source) {
    if (channel <= 0) return 0;
    if (channel_source == CH_SRC_HE_6GHZ) {
        /* 802.11ax-2021 Annex E: 6 GHz channel n centres at 5950 + 5n
         * MHz; channel 2 is the 5935 MHz exception. */
        if (channel == 2) return 5935;
        return channel <= 233 ? 5950 + 5 * channel : 0;
    }
    if (channel == 14) return 2484;
    if (channel >= 1 && channel <= 13) return 2407 + 5 * channel;
    if (channel >= 32 && channel <= 177) return 5000 + 5 * channel;
    return 0;
}

int reg_obs_power(const beacon_ap_t *ap, reg_power_obs_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!ap) return 0;

    /* TPC Report first: §9.4.2.16 makes its Transmit Power the power the
     * frame carrying it was sent at, which is the number a received
     * level can be compared with. The TPE is only a ceiling — an AP
     * below it widens the apparent loss, so a positive excess against
     * it still means what it says. */
    if (ap->reg.tpc_present) {
        out->src         = REG_PWR_SRC_TPC;
        out->claimed_dbm = ap->reg.tpc_tx_power_dbm;
    } else {
        for (int i = 0; i < ap->reg6g.tpe_count && i < REG_6G_MAX_TPE; i++) {
            const reg_tpe_t *e = &ap->reg6g.tpe[i];
            if (e->interp == REG_TPE_LOCAL_EIRP &&
                e->category == REG_TPE_CAT_DEFAULT && e->n_values >= 1) {
                out->src         = REG_PWR_SRC_TPE;
                out->claimed_dbm = e->values_half_db[0] / 2.0;
                break;
            }
        }
    }
    int freq = reg_obs_freq_mhz(ap->channel, ap->channel_source);
    if (out->src == REG_PWR_SRC_NONE || ap->signal_dbm >= 0 || freq == 0) {
        memset(out, 0, sizeof(*out));
        return 0;
    }
    out->heard_dbm        = ap->signal_dbm;
    out->freq_mhz         = freq;
    out->fspl_1m_db       = reg_obs_fspl_1m_db(freq);
    out->apparent_loss_db = out->claimed_dbm - out->heard_dbm;
    out->excess_db        = out->fspl_1m_db - out->apparent_loss_db;
    return 1;
}
