#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "views/view_page.h"
#include "oui.h"
#include "views/beacon.h"
#include "wifi_assess.h"
#include "beacon_snoop.h"
/* ../ is required: src/views/alerts.h is the view header and would
 * shadow the rules header on a bare "alerts.h" from this directory.
 * Same form src/views/twins.c already uses. Needed for the
 * WPS_LOCKOUT_CYCLING threshold and window, so the detail screen
 * renders the rule's own numbers rather than a second opinion. */
#include "../alerts.h"
#include "wps_track.h"   /* WPS SESSIONS block (#82) */
#include "eap_parse.h"   /* WSC_OP_* and wsc_msg_name() */
#include "tune.h"        /* wps.pixie_silence_s */
#include "reg_obs.h"     /* REG column + power observation (#101 slice B) */

#define BEACON_PAGE 30

static char fmt_bssid[18];

static const char *bssid_str(const uint8_t *b) {
    snprintf(fmt_bssid, sizeof(fmt_bssid),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
    return fmt_bssid;
}

/* Same shape as src/views/eapol.c and src/views/seqnum.c — kept local
 * rather than shared, matching how every other view spells it. */
static void fmt_age(time_t ts, char *buf, int sz) {
    long age = (long)(sloth_wall() - ts);
    if (age < 0)     age = 0;
    if (age > 99999) age = 99999;
    if      (age <   60) snprintf(buf, sz, "%lds", age);
    else if (age < 3600) snprintf(buf, sz, "%ldm", age / 60);
    else                 snprintf(buf, sz, "%ldh", age / 3600);
}

/* ── WPS registration sessions on the AP detail screen (#82) ──────
 *
 * WPS_PIN_BRUTE, WPS_PBC_RACE and the two Pixie-Dust rules all read
 * the wps_track session table, and until this block nothing in the TUI
 * showed it: each alert named a count or a sequence with no frames
 * behind it on screen. The table is not on sloth_state_t, so this reads
 * a copy through wps_track_for_bssid() — the same copy-under-the-lock
 * the rules take — rather than the live table.
 *
 * Bounded on both axes so a hostile enrollee spraying sessions cannot
 * push the rest of the detail screen off the terminal: at most
 * WPS_DETAIL_SESSIONS sessions and WPS_DETAIL_EVENTS frames each, with
 * the remainder counted rather than dropped silently. */
#define WPS_DETAIL_SESSIONS 4
#define WPS_DETAIL_EVENTS   8

static const char *wps_op_name(int op) {
    switch (op) {
    case WSC_OP_START:    return "Start";
    case WSC_OP_ACK:      return "ACK";
    case WSC_OP_NACK:     return "NACK";
    case WSC_OP_MSG:      return "MSG";
    case WSC_OP_DONE:     return "Done";
    case WSC_OP_FRAG_ACK: return "FragACK";
    default:              return "?";
    }
}

static const char *wps_state_name(int st) {
    switch (st) {
    case WPS_S_IDLE:    return "idle";
    case WPS_S_M1_SEEN: return "M1";
    case WPS_S_M3_SEEN: return "M3";
    case WPS_S_NACKED:  return "NACKed";
    case WPS_S_DONE:    return "done";
    default:            return "?";
    }
}

static void draw_wps_sessions(const beacon_ap_t *ap) {
    wps_session_t sess[MAX_WPS_SESSIONS];
    int n = wps_track_for_bssid(ap->bssid, sess, MAX_WPS_SESSIONS);
    if (n == 0 && !ap->has_wps) return;

    const time_t now     = sloth_wall();
    const int    silence = (int)tune_val(TUNE_WPS_PIXIE_SILENCE_S);

    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 WPS SESSIONS (%d) \xe2\x94\x80\xe2\x94\x80\n", n);
    if (ap->wps_probe_resp_n > 0) {
        tui_dim();
        TPRINT("  WSC element also read from %d probe response%s\n",
               ap->wps_probe_resp_n, ap->wps_probe_resp_n == 1 ? "" : "s");
    }
    if (n == 0) {
        tui_dim();
        TPRINT("  (no EAP-WSC registration heard for this AP)\n");
        return;
    }

    int shown = n < WPS_DETAIL_SESSIONS ? n : WPS_DETAIL_SESSIONS;
    for (int i = 0; i < shown; i++) {
        const wps_session_t *w = &sess[i];
        char sta[18], age[8];
        snprintf(sta, sizeof(sta), "%02x:%02x:%02x:%02x:%02x:%02x",
                 w->sta[0], w->sta[1], w->sta[2],
                 w->sta[3], w->sta[4], w->sta[5]);
        fmt_age(w->last_seen, age, sizeof(age));
        tui_normal(); TPRINT("  %s", sta);
        tui_dim();    TPRINT("  state ");
        tui_normal(); TPRINT("%s", wps_state_name(w->state));
        tui_dim();    TPRINT("  msgs ");
        /* The lifetime M1..M8 strip, so a run that never got past M3
         * reads as a gap at M4 at a glance. */
        for (int m = 1; m <= 8; m++) {
            if (w->msg_bits & (1u << m)) { tui_normal(); TPRINT("%d", m); }
            else                         { tui_dim();    TPRINT("."); }
        }
        tui_dim();    TPRINT("  cycles ");
        tui_normal(); TPRINT("%d", w->cycle_count);
        tui_dim();    TPRINT("  last %s ago\n", age);

        time_t m3 = 0;
        int quiet = 0;
        if (wps_track_m3_abandon(w, now, &m3, &quiet)) {
            /* Heat only at the rule's own floor, as the lock block does:
             * the colour means "this is what WPS_PIXIE_PROBE reads". */
            if (quiet >= silence) tui_heat(1.0); else tui_normal();
            TPRINT("    stopped after M3, no M4: quiet %ds/%ds", quiet, silence);
            tui_dim();
            TPRINT("  (Pixie-Dust shape, WPS_PIXIE_PROBE)\n");
        }
        if (w->cred_ts) {
            char cage[8];
            fmt_age(w->cred_ts, cage, sizeof(cage));
            tui_heat(0.7);
            TPRINT("    reached the credentials (M7/M8/Done) %s ago\n", cage);
        }

        wps_evt_t ev[WPS_EVT_RING];
        int en = wps_track_events(w, ev, WPS_EVT_RING);
        int skip = en > WPS_DETAIL_EVENTS ? en - WPS_DETAIL_EVENTS : 0;
        int older = w->ev_n - en + skip;
        if (older > 0) {
            tui_dim();
            TPRINT("    (%d earlier frame%s not shown)\n",
                   older, older == 1 ? "" : "s");
        }
        for (int j = skip; j < en; j++) {
            char eage[8];
            fmt_age(ev[j].ts, eage, sizeof(eage));
            tui_dim();    TPRINT("    %5s ago  ", eage);
            tui_normal(); TPRINT("%s", wps_op_name(ev[j].op));
            /* Only a MSG frame's Message Type names an M-message; on a
             * NACK or Done op it just repeats the op. */
            if (ev[j].op == WSC_OP_MSG && ev[j].msg >= 0) {
                tui_dim(); TPRINT(" %s", wsc_msg_name(ev[j].msg));
            }
            TPRINT("\n");
        }
    }
    if (n > shown) {
        tui_dim();
        TPRINT("  ... and %d more session%s\n",
               n - shown, n - shown == 1 ? "" : "s");
    }
}

/* Stack-measurement block (#77): the IE-order hash and the TBTT jitter
 * that the JSONL `beacon` record has carried since 874f6b9 / a56903a,
 * surfaced here with the same zero-reading rules the schema documents.
 * Both raw zeros are ambiguous on their own, so neither is printed as a
 * bare 0:
 *
 *   - ie_order_hash 0 means "not decoded" (no elements, or the frame
 *     overran), never a hash value.
 *   - a 0 µs stddev is a real reading only with at least
 *     TBTT_JITTER_MIN_SAMPLES residuals behind it; with fewer it means
 *     "not enough beacons yet", which a bare 0 would misstate as a
 *     perfectly scheduled AP.
 *
 * `resets` counts every discarded baseline - a TSF that ran backwards,
 * a changed Beacon Interval, or a gap past BEACON_AGE_SECS - so it is
 * labelled by all three causes. A hopping capture radio or an AP at the
 * edge of range builds up gap rebases, and calling those "TSF resets"
 * would read as a timer restart the AP never made.
 *
 * Measurement only. No threshold or verdict is drawn: the jitter has no
 * sourced number to compare against and the order hash has no
 * known-stack table (both wait on rig captures; see
 * docs/wiki/attack-hardware-fingerprints.md). Kept in its own function
 * so the #82 timeline work on this screen does not interleave with it. */
/* blank, header, IE order, TBTT jitter, baseline resets. The resets get
 * their own row: appended to the jitter line, the not-measured hint plus
 * a reset count reached 134 columns and wrapped at the 100-column minimum,
 * pushing the back hint off a screen this block had measured as fitting. */
#define STACK_BLOCK_ROWS 5
#define DETAIL_FOOTER_ROWS 2 /* blank, back hint */

/* The detail screen does not scroll, so a row drawn past the bottom is
 * dropped. The block is drawn after CAPTURED HANDSHAKES and only when it
 * and the footer both still fit: being measurement-only, it is the part
 * that gives way, never the handshake counts or the back hint. The ANSI
 * fallback has no screen height and always draws it. */
static int stack_block_fits(void) {
#ifdef WITH_NCURSES
    return LINES - getcury(stdscr) >= STACK_BLOCK_ROWS + DETAIL_FOOTER_ROWS;
#else
    return 1;
#endif
}

static void draw_detail_stack_measures(const beacon_ap_t *ap) {
    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 STACK MEASUREMENTS (no threshold "
           "until a capture backs one) \xe2\x94\x80\xe2\x94\x80\n");

    tui_dim(); TPRINT("  IE order:    ");
    if (ap->fp.ie_order_hash) {
        tui_normal();
        TPRINT("0x%08x", (unsigned)ap->fp.ie_order_hash);
        tui_dim();
        TPRINT("  (%u element%s; JSONL ie_order_hash %u)",
               (unsigned)ap->fp.ie_order_count,
               ap->fp.ie_order_count == 1 ? "" : "s",
               (unsigned)ap->fp.ie_order_hash);
    } else {
        tui_dim();
        TPRINT("not decoded (no elements, or the frame overran)");
    }
    TPRINT("\n");

    uint32_t sd = 0;
    int have = beacon_tbtt_jitter(&ap->tbtt, &sd, NULL);
    tui_dim(); TPRINT("  TBTT jitter: ");
    if (have) {
        tui_normal();
        TPRINT("%u us", (unsigned)sd);
        tui_dim();
        TPRINT(" stddev over %u samples", (unsigned)ap->tbtt.samples);
    } else {
        /* Every beacon carries a Timestamp (802.11-2020 §9.4.1.10);
         * what keeps the count low is managed-mode capture (an IE blob
         * with no frame) or too few consecutive beacons. */
        tui_dim();
        TPRINT("not measured (%u/%d samples; monitor mode only, needs "
               "consecutive beacons)", (unsigned)ap->tbtt.samples,
               TBTT_JITTER_MIN_SAMPLES);
    }
    TPRINT("\n");
    if (ap->tbtt.resets) {
        tui_dim();
        TPRINT("  TBTT basis:  %u baseline reset%s (TSF back / BI change / gap)\n",
               (unsigned)ap->tbtt.resets,
               ap->tbtt.resets == 1 ? "" : "s");
    }
}

/* REG column (#101 slice B). Every other list column is fixed, so REG
 * takes what the terminal has left after them, between a floor that
 * still shows a country and its environment ("US/I") and a ceiling past
 * which the tokens run out. REG_COL_FIXED is the rest of the row: the
 * leading space, the eleven columns before REG with their separators,
 * REG's own separator, and "  Last". Below the floor the column is not
 * drawn at all (width 0, separator included): forcing it in would wrap
 * a row that fits without it, and the detail screen carries the same
 * claims in full. */
#define REG_COL_MIN    4
#define REG_COL_MAX   28
#define REG_COL_ANSI  14
#define REG_COL_FIXED (1 + 122 + 2 + 6)

static int reg_column_width(void) {
#ifdef WITH_NCURSES
    int w = COLS - 1 - REG_COL_FIXED;
#else
    int w = REG_COL_ANSI;
#endif
    if (w < REG_COL_MIN) return 0;
    if (w > REG_COL_MAX) w = REG_COL_MAX;
    return w;
}

/* The REGULATORY block (#101 slice B): what the AP claims about its
 * regulatory envelope, and how the received level compares with the
 * power it claims. Drawn only for an AP that ever sent a regulatory
 * element, and only when it and the footer fit — the detail screen does
 * not scroll. Like the stack block, it gives way before the handshake
 * counts or the back hint do. */
#define REG_BLOCK_ROWS 9

static int reg_block_fits(void) {
#ifdef WITH_NCURSES
    return LINES - getcury(stdscr) >= REG_BLOCK_ROWS + DETAIL_FOOTER_ROWS;
#else
    return 1;
#endif
}

static const char *env_label(uint8_t env) {
    switch (env) {
    case REG_ENV_ANY:           return "any environment";
    case REG_ENV_INDOOR:        return "indoor";
    case REG_ENV_OUTDOOR:       return "outdoor";
    case REG_ENV_NON_COUNTRY:   return "non-country entity";
    case REG_ENV_OPCLASS_TABLE: return "Annex E table";
    default:                    return "undefined octet";
    }
}

static void draw_detail_regulatory(const beacon_ap_t *ap) {
    const reg_ie_t *r = &ap->reg;
    const reg_6g_t *g = &ap->reg6g;

    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 REGULATORY (claimed by the AP; "
           "observation, not an alert) \xe2\x94\x80\xe2\x94\x80\n");

    tui_dim(); TPRINT("  Country:     ");
    if (r->country_present) {
        char col[REG_COL_MAX + 1];
        reg_obs_column(r, NULL, 2, col, sizeof(col));  /* the code alone */
        tui_bright(); TPRINT("%s", col);
        tui_dim();
        TPRINT("  %s (0x%02x), %u triplet%s%s", env_label(r->env),
               (unsigned)r->env_raw, (unsigned)r->triplet_count,
               r->triplet_count == 1 ? "" : "s",
               r->triplets_truncated ? " (more dropped)" : "");
    } else {
        TPRINT("no Country element heard");
    }
    TPRINT("\n");

    tui_dim(); TPRINT("  Power:       ");
    if (r->power_constraint_present) {
        tui_normal();
        TPRINT("constraint %u dB", (unsigned)r->power_constraint_db);
    } else {
        TPRINT("no Power Constraint");
    }
    tui_dim(); TPRINT("   ");
    if (r->tpc_present) {
        tui_normal(); TPRINT("TPC Report %d dBm", (int)r->tpc_tx_power_dbm);
    } else {
        TPRINT("no TPC Report");
    }
    TPRINT("\n");

    tui_dim(); TPRINT("  6 GHz info:  ");
    if (g->he6_present) {
        tui_normal();
        TPRINT("Regulatory Info %u", (unsigned)g->he6_reg_info);
        tui_dim();
        TPRINT(" (%s)",
               g->he6_reg_info == REG_6G_INDOOR_AP   ? "Indoor AP" :
               g->he6_reg_info == REG_6G_STANDARD_AP ? "Standard Power AP" :
               "reserved in 802.11ax-2021");
    } else {
        TPRINT("not advertised (no HE 6 GHz Operation Information)");
    }
    TPRINT("\n");

    tui_dim(); TPRINT("  TPE:         ");
    if (g->tpe_count == 0) {
        TPRINT("no Transmit Power Envelope");
    } else {
        /* One row, the first value of each entry: the 20 MHz figure for
         * EIRP, the first subchannel for PSD. Entries are added while
         * the whole row fits — the 15-cell "  TPE:         " prefix, the
         * entries, and whichever "; +N more" and "; more dropped" tails
         * that choice leaves — because a wrapped row pushes the back
         * hint off a screen that does not scroll. The full lists are in
         * the wifi_regulatory JSONL record. */
#ifdef WITH_NCURSES
        size_t room = COLS > 1 + 15 + 24 ? (size_t)(COLS - 1 - 15) : 24;
#else
        size_t room = 120;
#endif
        const size_t dropped_len = g->tpe_truncated ? strlen("; more dropped") : 0;
        char line[256] = "";
        size_t used = 0;
        int shown = 0;
        int count = g->tpe_count < REG_6G_MAX_TPE ? g->tpe_count : REG_6G_MAX_TPE;
        for (int i = 0; i < count; i++) {
            const reg_tpe_t *e = &g->tpe[i];
            char ent[64];
            if (e->n_values)
                snprintf(ent, sizeof(ent), "%s%s%s %.1f %s", i ? "; " : "",
                         reg_tpe_interp_name(e->interp),
                         e->category == REG_TPE_CAT_SUBORDINATE ? "/sub" : "",
                         e->values_half_db[0] / 2.0,
                         reg_tpe_is_psd(e->interp) ? "dBm/MHz" : "dBm");
            else
                snprintf(ent, sizeof(ent), "%s%s%s (reserved)", i ? "; " : "",
                         reg_tpe_interp_name(e->interp),
                         e->category == REG_TPE_CAT_SUBORDINATE ? "/sub" : "");
            size_t el = strlen(ent);
            int left = g->tpe_count - (i + 1);
            char more[24] = "";
            if (left > 0) snprintf(more, sizeof(more), "; +%d more", left);
            if (used + el + strlen(more) + dropped_len > room ||
                used + el >= sizeof(line)) break;
            memcpy(line + used, ent, el + 1);
            used += el;
            shown++;
        }
        tui_normal(); TPRINT("%s", line);
        int hidden = g->tpe_count - shown;
        if (hidden > 0) { tui_dim(); TPRINT("%s+%d more", shown ? "; " : "", hidden); }
        if (g->tpe_truncated) { tui_dim(); TPRINT("; more dropped"); }
    }
    TPRINT("\n");

    /* The observed-vs-claimed power delta. Not an alert (#145 ruling):
     * the received level depends on a distance and antenna gains the
     * sensor does not know, so the line states the one assumption it
     * makes — free-space loss at 1 m — and what a positive excess would
     * mean under it. Only an excess past REG_OBS_EXCESS_MARGIN_DB is
     * highlighted; below that the TPC tolerance and receive gain alone
     * can produce it. */
    reg_power_obs_t o;
    tui_dim(); TPRINT("  Power delta: ");
    if (!reg_obs_power(ap, &o)) {
        TPRINT("nothing to compare (needs a TPC Report or local EIRP TPE, "
               "and a signal)\n");
    } else {
        tui_normal();
        TPRINT("heard %d dBm vs %s %.1f dBm: apparent loss %.1f dB\n",
               o.heard_dbm,
               o.src == REG_PWR_SRC_TPC ? "TPC Report" : "TPE local EIRP",
               o.claimed_dbm, o.apparent_loss_db);
        tui_dim(); TPRINT("               ");
        if (o.beyond_margin) {
            tui_heat(0.7);
            TPRINT("%.1f dB stronger than the claim allows at 1 m",
                   o.excess_db);
        } else if (o.excess_db > 0) {
            /* Inside the stated margin: the number, not a highlight. */
            tui_normal();
            TPRINT("%.1f dB over the 1 m figure, within the %.0f dB margin",
                   o.excess_db, REG_OBS_EXCESS_MARGIN_DB);
        } else {
            tui_normal();
            TPRINT("consistent with the claim at 1 m or more");
        }
        tui_dim();
        TPRINT(" (FSPL 1 m @ %d MHz: %.1f dB)\n",
               o.freq_mhz, o.fspl_1m_db);
    }
    tui_dim();
    TPRINT("  Assumes free-space loss and 0 dBi antennas; distance unknown, "
           "so never an alert.\n");
}

/* Full-screen detail panel for the selected AP. Triggered by Enter
 * in the beacons list; Enter/Esc returns. Renders every field we've
 * already collected for this BSSID, plus cross-references against
 * the assoc tracker and EAPOL log. Each section is annotated with
 * attacker / defender notes so the operator gets the SIGINT context
 * inline instead of cross-referencing four other views. */
static void draw_beacon_detail(const sloth_state_t *s) {
    if (s->beacon_sel < 0 || s->beacon_sel >= s->beacon_count) {
        tui_dim();
        TPRINT(" (no AP selected — press Enter to return)\n");
        return;
    }
    const beacon_ap_t *ap = &s->beacon_aps[s->beacon_sel];

    tui_dim(); TPRINT(" \xe2\x94\x80\xe2\x94\x80 AP DETAIL \xe2\x94\x80\xe2\x94\x80\n");

    /* Header: SSID + BSSID */
    if (ap->ssid[0]) tui_bright();
    else             tui_dim();
    TPRINT("  %-12s", ap->ssid[0] ? ap->ssid : "(hidden)");
    if (ap->revealed) { tui_dim(); TPRINT(" * (revealed via probe response)"); }
    TPRINT("\n");

    tui_dim();    TPRINT("  BSSID:       ");
    tui_bright(); TPRINT("%s", bssid_str(ap->bssid));
    {
        const char *oui_v = oui_lookup(ap->bssid);
        if (oui_v && oui_v[0]) {
            tui_dim();    TPRINT("   (OUI: ");
            tui_normal(); TPRINT("%s", oui_v);
            tui_dim();    TPRINT(")");
        }
    }
    TPRINT("\n");

    /* Radio */
    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 RADIO \xe2\x94\x80\xe2\x94\x80\n");
    TPRINT("  Channel:     "); tui_bright();
    TPRINT("%d", ap->channel);
    tui_dim(); TPRINT("  (%s)\n", ap_band_label(ap->channel, ap->channel_source));
    TPRINT("  Signal:      "); {
        double frac = (ap->signal_dbm + 90.0) / 60.0;
        if (frac < 0) frac = 0;
        if (frac > 1) frac = 1;
        tui_heat(frac);
    }
    TPRINT("%d dBm\n", ap->signal_dbm);
    tui_dim(); TPRINT("  Beacon intv: "); tui_normal();
    TPRINT("%u ms\n", (unsigned)ap->beacon_ms);
    tui_dim(); TPRINT("  PHY tier:    ");
    if (ap->phy[0]) tui_bright(); else tui_dim();
    TPRINT("%s\n", ap->phy[0] ? ap->phy : "?");
    tui_dim(); TPRINT("  Vendor:      ");
    if (ap->vendor[0]) tui_bright(); else tui_dim();
    TPRINT("%s\n", ap->vendor[0] ? ap->vendor : "?");

    /* Security */
    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 SECURITY \xe2\x94\x80\xe2\x94\x80\n");
    TPRINT("  Encryption:  ");
    if (strcmp(ap->enc, "OPEN") == 0 || strcmp(ap->enc, "WEP") == 0)
        tui_heat(0.9);
    else if (strcmp(ap->enc, "WPA3") == 0)
        tui_bright();
    else
        tui_normal();
    TPRINT("%s\n", ap->enc);
    tui_dim(); TPRINT("  Pairwise:    "); tui_normal();
    TPRINT("%s", ap->pairwise[0] ? ap->pairwise : "-");
    if (strcmp(ap->pairwise, "TKIP") == 0) {
        tui_heat(0.7); TPRINT("   (TKIP on WPA2 — downgrade smell)");
    }
    TPRINT("\n");
    tui_dim(); TPRINT("  Group:       "); tui_normal();
    TPRINT("%s\n", ap->group[0]    ? ap->group    : "-");
    tui_dim(); TPRINT("  AKM:         "); tui_normal();
    TPRINT("%s\n", ap->akm[0]      ? ap->akm      : "-");
    tui_dim(); TPRINT("  MFP:         ");
    if (ap->mfp == 2)       { tui_bright(); TPRINT("REQUIRED"); }
    else if (ap->mfp == 1)  { tui_normal(); TPRINT("capable"); }
    else                    { tui_heat(0.7); TPRINT("off (deauth-attackable)"); }
    TPRINT("\n");
    tui_dim(); TPRINT("  WPS:         ");
    if (ap->has_wps) {
        /* AP Setup Locked overrides — locked means PIN attacks won't
         * work, so render the "interesting" coloring only when both
         * unlocked AND not configured. */
        int unlocked_unconfigured =
            (ap->wps_locked == 1 && ap->wps_state == 1);
        if (unlocked_unconfigured) tui_heat(1.0);
        else                       tui_heat(0.7);
        TPRINT("ON");
        tui_dim();
        if (ap->wps_state == 1)      TPRINT("  (NotConfigured)");
        else if (ap->wps_state == 2) TPRINT("  (Configured)");
        if (ap->wps_locked == 2)     TPRINT("  [LOCKED]");
        else if (ap->wps_locked == 1) {
            tui_heat(1.0);
            TPRINT("  [UNLOCKED — PixieDust / WPS-PIN candidate]");
        }
        /* Device Password ID 0x0004 = Push Button (#82). Live, not
         * sticky — only shown while the current beacon still carries
         * it, i.e. the pairing window is open right now. */
        if (ap->wps_device_pwd_id == 0x0004) {
            tui_heat(1.0);
            TPRINT("  [PBC ACTIVE — open pairing window]");
        }
    } else {
        tui_normal(); TPRINT("-");
    }
    TPRINT("\n");
    /* WPS vendor-string leakage (#77): only shown when the beacon's WPS
     * IE actually leaked one of these — most APs don't. Fingerprinting
     * value regardless of which tool, if any, is behind the AP. */
    if (ap->wps_manufacturer[0] || ap->wps_model_name[0] ||
        ap->wps_model_number[0] || ap->wps_serial[0]) {
        tui_dim(); TPRINT("  WPS ID:      "); tui_heat(0.7);
        TPRINT("%s", ap->wps_manufacturer[0] ? ap->wps_manufacturer : "?");
        if (ap->wps_model_name[0] || ap->wps_model_number[0]) {
            TPRINT(" / %s", ap->wps_model_name[0] ? ap->wps_model_name : "?");
            if (ap->wps_model_number[0])
                TPRINT(" (%s)", ap->wps_model_number);
        }
        if (ap->wps_serial[0]) TPRINT("  SN:%s", ap->wps_serial);
        TPRINT("\n");
    }

    /* AP Setup Locked history (#82). WPS_LOCKOUT_CYCLING names a cycle
     * count in its detail string, and until this block the operator had
     * nowhere to read the transitions behind it — the WARN was a number
     * with no inspectable evidence anywhere in the TUI.
     *
     * Rendered whenever there is history even if has_wps is now 0: an
     * AP that stops advertising the WPS IE mid-attack must not erase
     * what was already observed from the screen. */
    if (ap->has_wps || ap->wps_lock_n > 0) {
        wps_lock_evt_t hist[WPS_LOCK_RING];
        int hn      = wps_lock_history(ap, hist, WPS_LOCK_RING);
        int dropped = wps_lock_dropped(ap);
        int thresh  = alerts_wps_lockout_cycles();
        int win     = wps_lock_cycles_in_window(ap, sloth_wall(),
                                                WPS_LOCKOUT_WINDOW_S);
        tui_dim();
        TPRINT("\n \xe2\x94\x80\xe2\x94\x80 WPS ACTIVITY \xe2\x94\x80\xe2\x94\x80\n");
        tui_dim();    TPRINT("  Lock cycles: ");
        tui_normal(); TPRINT("%d lifetime", ap->wps_lock_cycles);
        tui_dim();    TPRINT("   last %dh: ", WPS_LOCKOUT_WINDOW_S / 3600);
        /* Heat only at or above the rule's own floor, so the colour
         * means "this is what fired", not "this AP uses WPS". */
        if (win >= thresh) tui_heat(1.0);
        else               tui_normal();
        TPRINT("%d/%d", win, thresh);
        tui_dim();    TPRINT("  (WPS_LOCKOUT_CYCLING threshold)\n");

        if (hn == 0) {
            tui_dim();
            TPRINT("  (no lock-state transitions observed — an AP that "
                   "never changes state is a posture)\n");
        } else {
            if (dropped > 0) {
                tui_dim();
                TPRINT("  (%d earlier transition%s aged out of the "
                       "%d-slot ring)\n",
                       dropped, dropped == 1 ? "" : "s", WPS_LOCK_RING);
            }
            /* Oldest first, so the sawtooth reads as a sequence. */
            for (int j = 0; j < hn; j++) {
                char age[8];
                fmt_age(hist[j].ts, age, sizeof(age));
                tui_dim();    TPRINT("    %5s ago  ", age);
                /* Unlocked is the hot end: it is the window in which
                 * the AP accepts registrar PINs again. */
                if (hist[j].to == 2) { tui_normal(); TPRINT("LOCKED"); }
                else                 { tui_heat(1.0); TPRINT("unlocked"); }
                TPRINT("\n");
            }
        }
    }

    draw_wps_sessions(ap);

    /* Associated clients we've observed. */
    int my_assocs[MAX_ASSOC_ENTRIES];
    int my_assoc_n = 0;
    for (int i = 0; i < s->assoc_count; i++) {
        if (memcmp(s->assocs[i].bssid, ap->bssid, 6) == 0)
            my_assocs[my_assoc_n++] = i;
    }
    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 ASSOCIATED CLIENTS (%d) \xe2\x94\x80\xe2\x94\x80\n",
           my_assoc_n);
    if (my_assoc_n == 0) {
        tui_dim();
        TPRINT("  (none observed)\n");
    } else {
        for (int j = 0; j < my_assoc_n && j < 10; j++) {
            const assoc_t *as = &s->assocs[my_assocs[j]];
            char m[20];
            snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
                     as->sta_mac[0], as->sta_mac[1], as->sta_mac[2],
                     as->sta_mac[3], as->sta_mac[4], as->sta_mac[5]);
            tui_normal(); TPRINT("  %s", m);
            tui_dim();
            if (as->sta_random)         TPRINT("  (random)");
            else {
                const char *v = oui_lookup(as->sta_mac);
                if (v && v[0]) TPRINT("  %.14s", v);
            }
            tui_dim();    TPRINT("  via ");
            if (as->source == ASSOC_SRC_EAPOL) tui_bright(); else tui_normal();
            TPRINT("%s",
                   as->source == ASSOC_SRC_EAPOL   ? "EAPOL" :
                   as->source == ASSOC_SRC_ASSOC   ? "AssocResp" :
                   as->source == ASSOC_SRC_REASSOC ? "ReassocResp" : "?");
            TPRINT("\n");
        }
        if (my_assoc_n > 10) {
            tui_dim();
            TPRINT("  ... and %d more (see [w] Assoc view)\n",
                   my_assoc_n - 10);
        }
    }

    /* 802.11k Neighbor Reports — APs this AP advertises as neighbors.
     * Useful for ESS topology mapping and for discovering BSSIDs we
     * haven't tuned to yet (off-channel). */
    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 NEIGHBORS (802.11k, %d) \xe2\x94\x80\xe2\x94\x80\n",
           ap->neighbor_count);
    if (ap->neighbor_count == 0) {
        tui_dim();
        TPRINT("  (none advertised — AP doesn't emit Neighbor Report IEs)\n");
    } else {
        for (int j = 0; j < ap->neighbor_count; j++) {
            const ap_neighbor_t *n = &ap->neighbors[j];
            char m[20];
            snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
                     n->bssid[0], n->bssid[1], n->bssid[2],
                     n->bssid[3], n->bssid[4], n->bssid[5]);
            /* Is this neighbor a BSSID we've also seen directly? */
            int direct = 0;
            for (int k = 0; k < s->beacon_count; k++) {
                if (memcmp(s->beacon_aps[k].bssid, n->bssid, 6) == 0) {
                    direct = 1;
                    break;
                }
            }
            tui_normal(); TPRINT("  %s", m);
            tui_dim();    TPRINT("  ch ");
            tui_bright(); TPRINT("%d", n->channel);
            tui_dim();    TPRINT("  %s\n",
                                  direct ? "(observed directly)"
                                         : "(NOT directly seen \xe2\x80\x94 hop here)");
        }
    }

    /* Captured handshakes against this BSSID. */
    int crit = 0, pmkid = 0;
    for (int i = 0; i < s->eapol_count; i++) {
        if (memcmp(s->eapol_events[i].bssid, ap->bssid, 6) != 0) continue;
        if (s->eapol_events[i].handshake_complete) crit++;
        if (s->eapol_events[i].has_pmkid)          pmkid++;
    }
    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 CAPTURED HANDSHAKES \xe2\x94\x80\xe2\x94\x80\n");
    if (crit > 0 || pmkid > 0) {
        if (pmkid > 0) { tui_heat(1.0); TPRINT("  %d PMKID capture(s)", pmkid); TPRINT("\n"); }
        if (crit > 0)  { tui_heat(1.0); TPRINT("  %d full 4-way handshake(s)", crit); TPRINT("\n"); }
        tui_dim();
        TPRINT("  See [e] EAPOL for details. --eapol-dir DIR writes "
               "hashcat 22000.\n");
    } else {
        tui_dim();
        TPRINT("  (none yet — wait for a client (re)association)\n");
    }

    if (reg_obs_any(&ap->reg, &ap->reg6g) && reg_block_fits())
        draw_detail_regulatory(ap);

    int stack_shown = stack_block_fits();
    if (stack_shown) draw_detail_stack_measures(ap);

    tui_dim(); TPRINT("\n [Enter / Esc] back to beacons list");
    if (!stack_shown) TPRINT("  (taller terminal shows stack measurements)");
    TPRINT("\n");
    tui_normal();
}

void view_beacon_draw(const sloth_state_t *s) {
    if (s->beacon_detail) { draw_beacon_detail(s); return; }

    tui_normal(); TPRINT(" Passive beacons: ");
    tui_bright();  TPRINT("%d", s->beacon_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear");
    if (s->twin_episode_count > 0) {
        tui_dim();    TPRINT("  twin episodes: ");
        tui_bright(); TPRINT("%d", s->twin_episode_count);
        tui_dim();    TPRINT(" [x]");
    }
    if (s->probe_iface[0]) {
        tui_dim(); TPRINT("  iface: %s", s->probe_iface);
    }
    TPRINT("\n");

    int reg_w = reg_column_width();
    char reg_rule[REG_COL_MAX + 1];
    memset(reg_rule, '-', (size_t)reg_w);
    reg_rule[reg_w] = '\0';

    tui_clip_rows(1);   /* the table only: lines above it wrap */
    tui_dim();
    TPRINT(" %-22s  %-17s  %4s  %-7s  %-5s  %-9s  %-8s  %-10s  %-3s  %-9s  %-8s",
           "SSID", "BSSID", "Sig", "Ch", "Enc",
           "Pairwise", "posture", "AKM", "WPS", "Vendor", "PHY");
    if (reg_w) TPRINT("  %-*s", reg_w, "REG");
    TPRINT("  %4s\n", "Last");
    TPRINT(" %-22s  %-17s  %4s  %-7s  %-5s  %-9s  %-8s  %-10s  %-3s  %-9s  %-8s",
           "----------------------", "-----------------",
           "----", "-------", "-----", "---------", "--------",
           "----------", "---", "---------", "--------");
    if (reg_w) TPRINT("  %-*s", reg_w, reg_rule);
    TPRINT("  %4s\n", "----");
    tui_normal();

    if (s->beacon_count == 0) {
        tui_dim();
        TPRINT("  (no beacons seen -- waiting for 802.11 beacon frames on monitor iface)\n");
        tui_normal();
        return;
    }

    /* 802.11k survey activity (#61). A footer rather than a column:
     * it is a property of the airspace over the last few minutes, not
     * of any one row, and most of the time there is nothing to say.
     * Counted before the table so the page leaves its row free. */
    int surveys = 0, reports = 0;
    for (int i = 0; i < s->rrm_pair_count; i++) {
        surveys += s->rrm_pairs[i].targeted_reqs;
        reports += s->rrm_pairs[i].reports_seen;
    }
    int rrm_rows = surveys > 0 ? 1 : 0;
    int page = view_page_budget(rrm_rows, BEACON_PAGE);
    int page_top = s->beacon_sel - page / 2;
    if (page_top + page > s->beacon_count) page_top = s->beacon_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->beacon_count) page_end = s->beacon_count;

    time_t now = sloth_wall();
    for (int row = page_top; row < page_end; row++) {
        const beacon_ap_t *ap = &s->beacon_aps[row];

        char ssid_display[40];
        /* Look up twin-cluster membership: '!' = chain-tainted twin
         * (attack-in-progress), '#' = vendor-IE hash mismatch detected,
         * '@' = OUI on the Hak5/Espressif attacker list, '~' = appears
         * in a twin pair as the legit "real" side, '?' = in an
         * unattributed pair (#89) where neither half is accused.
         * Glyphs are ASCII to match the Twins view legend.
         *
         * '~' is only reachable on an attributed episode. On an
         * unattributed one `real_bssid` is just the half that sorted
         * lower, so calling it the legit side would have printed a
         * clean bill of health derived from a memcmp. */
        char twin_glyph[4] = "";
        for (int t = 0; t < s->twin_episode_count; t++) {
            const twin_episode_t *e = &s->twin_episodes[t];
            int is_twin = memcmp(e->twin_bssid, ap->bssid, 6) == 0;
            int is_real = memcmp(e->real_bssid, ap->bssid, 6) == 0;
            if (!is_twin && !is_real) continue;
            if (!e->attributed) {
                if      (e->attack_in_progress) twin_glyph[0] = '!';
                else if (e->attacker_oui)       twin_glyph[0] = '@';
                else                            twin_glyph[0] = '?';
                break;
            }
            if (is_twin) {
                if      (e->attack_in_progress) twin_glyph[0] = '!';
                else if (e->attacker_oui)       twin_glyph[0] = '@';
                else if (e->hash_mismatch)      twin_glyph[0] = '#';
                else                            twin_glyph[0] = '*';
            } else {
                twin_glyph[0] = '~';
            }
            break;
        }
        const char *gsuffix = twin_glyph[0] ? twin_glyph : "";

        if (ap->ssid[0]) {
            if (ap->revealed)
                snprintf(ssid_display, sizeof(ssid_display), "%s *%s",
                         ap->ssid, gsuffix);
            else
                snprintf(ssid_display, sizeof(ssid_display), "%s%s",
                         ap->ssid, gsuffix);
        } else {
            snprintf(ssid_display, sizeof(ssid_display), "(hidden)%s",
                     gsuffix);
        }
        const char *ssid = ssid_display;

        char sig_buf[8];
        snprintf(sig_buf, sizeof(sig_buf), "%d", ap->signal_dbm);

        int age = (int)(now - ap->last_seen);
        char age_buf[16];
        if      (age < 60)   snprintf(age_buf, sizeof(age_buf), "%ds",  age);
        else if (age < 3600) snprintf(age_buf, sizeof(age_buf), "%dm",  age / 60);
        else                 snprintf(age_buf, sizeof(age_buf), "%dh",  age / 3600);

        /* Posture, not just MFP (#62). When the AP advertises a
         * downgrade lane the column names it — that is the finding, and
         * "cap" alone never conveyed it. With no downgrade the column
         * falls back to the MFP state it always showed. */
        /* Channel with its operating width (#66): "36/80" is a very
         * different amount of spectrum from "36", and sloth treated
         * every AP as 20 MHz until the operation IEs were decoded. */
        char ch_buf[10];
        if (ap->operating_width == CH_WIDTH_80P80)
            snprintf(ch_buf, sizeof(ch_buf), "%d/80+", ap->channel);
        else if (ap->operating_width)
            snprintf(ch_buf, sizeof(ch_buf), "%d/%u", ap->channel,
                     (unsigned)ap->operating_width);
        else
            snprintf(ch_buf, sizeof(ch_buf), "%d", ap->channel);

        const char *dg_s  = wifi_downgrade_column(ap->downgrade_flags);
        const char *mfp_s = dg_s ? dg_s
                          : (ap->mfp == 2) ? "REQ"
                          : (ap->mfp == 1) ? "cap" : "-";
        const char *pw    = ap->pairwise[0] ? ap->pairwise : "-";
        const char *akm   = ap->akm[0]      ? ap->akm      : "-";
        const char *wps_s = ap->has_wps ? "ON" : "-";
        const char *vend  = ap->vendor[0] ? ap->vendor : "-";
        const char *phy_s = ap->phy[0]    ? ap->phy    : "-";

        /* A pending channel switch replaces the PHY cell while it is in
         * flight (#63). It is transient and it is the more urgent fact:
         * the PHY tier will still be there after the AP has moved. */
        char phy_or_csa[12];
        if (ap->pending_csa_channel) {
            snprintf(phy_or_csa, sizeof(phy_or_csa), "CSA>%u",
                     ap->pending_csa_channel);
            phy_s = phy_or_csa;
        }

        char reg_buf[REG_COL_MAX + 1];
        reg_obs_column(&ap->reg, &ap->reg6g, reg_w, reg_buf, sizeof(reg_buf));

        if (row == s->beacon_sel) {
            tui_sel();
            TPRINT(" %-22.22s  %-17.17s  %4s  %-7s  %-5.5s  %-9.9s  %-8s  %-10.10s  %-3s  %-9.9s  %-8.8s",
                   ssid, bssid_str(ap->bssid), sig_buf, ch_buf,
                   ap->enc, pw, mfp_s, akm, wps_s, vend, phy_s);
            if (reg_w) TPRINT("  %-*s", reg_w, reg_buf);
            TPRINT("  %s\n", age_buf);
            tui_reset();
        } else {
            /* dim hidden SSIDs */
            if (!ap->ssid[0]) tui_dim(); else tui_normal();
            TPRINT(" %-22.22s", ssid);

            tui_dim();
            TPRINT("  %-17.17s", bssid_str(ap->bssid));

            /* signal heat */
            double frac = (ap->signal_dbm + 90.0) / 60.0;  /* -90=0.0, -30=1.0 */
            tui_heat(frac);
            TPRINT("  %4s", sig_buf);

            tui_normal();
            TPRINT("  %-7s", ch_buf);

            /* enc color: OPEN/WEP dim, WPA/WPA2/WPA3 normal/bright */
            if (strcmp(ap->enc, "OPEN") == 0 || strcmp(ap->enc, "WEP") == 0)
                tui_dim();
            else if (strcmp(ap->enc, "WPA3") == 0)
                tui_bright();
            else
                tui_normal();
            TPRINT("  %-5.5s", ap->enc);

            /* pairwise cipher — TKIP is a smell on a WPA2 net */
            if (strcmp(pw, "TKIP") == 0) tui_heat(0.7);
            else                          tui_normal();
            TPRINT("  %-9.9s", pw);

            /* Posture — a named downgrade lane is heat-coloured
             * because it is the finding; otherwise the old MFP shading
             * (REQ bright, cap normal, off dim). */
            if (dg_s)                    tui_heat(0.85);
            else if (ap->mfp == 2)       tui_bright();
            else if (ap->mfp == 1)       tui_normal();
            else                         tui_dim();
            TPRINT("  %-8s", mfp_s);

            tui_normal();
            TPRINT("  %-10.10s", akm);

            /* WPS — on = heat-coloured smell (PixieDust / PIN-attack
             * vector). off = dim. */
            if (ap->has_wps) tui_heat(0.7);
            else             tui_dim();
            TPRINT("  %-3s", wps_s);

            /* Vendor — bright for known, dim "-" for unknown. */
            if (ap->vendor[0]) tui_bright();
            else                tui_dim();
            TPRINT("  %-9.9s", vend);

            /* PHY — Wi-Fi 6/7 bright, Wi-Fi 5 normal, older dim. */
            if (ap->phy[0]) {
                if (strncmp(ap->phy, "Wi-Fi 6", 7) == 0 ||
                    strncmp(ap->phy, "Wi-Fi 7", 7) == 0) tui_bright();
                else if (strncmp(ap->phy, "Wi-Fi 5", 7) == 0) tui_normal();
                else                                          tui_dim();
            } else { tui_dim(); }
            /* A pending switch overrides the PHY shading — it is the
             * transient fact and the more urgent one. */
            if (ap->pending_csa_channel) tui_heat(0.8);
            TPRINT("  %-8.8s", phy_s);

            /* REG (#101 slice B): what the AP claims, never a verdict.
             * Dim when nothing was ever parsed; heat only for a
             * malformed element, the one token that is itself a
             * signal. */
            if (reg_w) {
                if (!reg_obs_any(&ap->reg, &ap->reg6g)) tui_dim();
                else if (strstr(reg_buf, "MAL"))         tui_heat(0.7);
                else                                     tui_normal();
                TPRINT("  %-*s", reg_w, reg_buf);
            }

            tui_dim();
            TPRINT("  %s\n", age_buf);
            tui_normal();
        }
    }

    if (surveys > 0) {
        tui_dim();
        TPRINT(" RRM surveys: ");
        tui_normal();
        TPRINT("%d targeted request%s", surveys, surveys == 1 ? "" : "s");
        tui_dim();
        TPRINT(" in the last %ds, %d reported back\n",
               RRM_SURVEY_WIN_SECS, reports);
        tui_normal();
    }
    tui_normal();
}

void view_beacon_key(sloth_state_t *s, int key) {
    /* Detail mode swallows nav keys; Enter or Esc returns. */
    if (s->beacon_detail) {
        if (key == '\r' || key == '\n' || key == 27)
            s->beacon_detail = 0;
        else if (key == 'c' || key == 'C') {
            beacon_clear();
            s->beacon_count   = 0;
            s->beacon_sel     = 0;
            s->beacon_detail  = 0;
        }
        return;
    }

    switch (key) {
    case SLOTH_KEY_UP:
        if (s->beacon_sel > 0) s->beacon_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->beacon_count > 0 && s->beacon_sel < s->beacon_count - 1)
            s->beacon_sel++;
        break;
    case '\r': case '\n':
        if (s->beacon_count > 0) s->beacon_detail = 1;
        break;
    case 'c': case 'C':
        beacon_clear();
        s->beacon_count = 0;
        s->beacon_sel   = 0;
        break;
    default:
        break;
    }
}
