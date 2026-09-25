#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "oui.h"
#include "seqnum_track.h"
#include "views/seqnum.h"

/* VIEW_SEQNUM — sequence-number correlation across MAC rotations.
 *
 * Top half: possible device correlations, sorted by descending
 * confidence, each shown with the score and the observation window it
 * rests on. The wording is deliberate (#94): a shared forward counter is
 * *consistent with* one radio rotating its address, and independent
 * radios in a dense room produce the same pattern at a rate this panel's
 * score is calibrated against. The panel offers a hypothesis about a
 * radio — never an identification of a person.
 *
 * Bottom half: raw per-MAC seqnum trail for forensic context. */

static void fmt_mac(const uint8_t *m, char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void fmt_age(time_t ts, char *buf, int sz) {
    long age = (long)(time(NULL) - ts);
    if (age < 0)     age = 0;
    if (age > 99999) age = 99999;
    if      (age <   60) snprintf(buf, sz, "%lds", age);
    else if (age < 3600) snprintf(buf, sz, "%ldm", age / 60);
    else                 snprintf(buf, sz, "%ldh", age / 3600);
}

void view_seqnum_draw(const sloth_state_t *s) {
    tui_normal(); TPRINT(" Seqnum tracker: ");
    tui_bright(); TPRINT("%d clients", s->seqnum_count);
    tui_dim();    TPRINT(", ");
    tui_bright(); TPRINT("%d correlations", s->seqnum_correlation_count);
    tui_dim();    TPRINT("  [up/dn] navigate correlations  [c] clear\n");

    /* ── Correlations ───────────────────────────────────── */
    tui_dim();
    if (!seqnum_corr_enabled()) {
        TPRINT(" Possible device correlation: OFF (--no-correlate)\n");
    } else {
        TPRINT(" Possible device correlation — same-radio hypothesis, "
               "not identification (retain %ds)\n", seqnum_corr_retain_secs());
    }
    TPRINT(" %-17s %-3s   %-17s %-3s   %4s  %6s  %-11s  %s\n",
           "MAC A", "rnd", "MAC B", "rnd", "fwd", "dt", "window", "support");
    TPRINT(" %-17s %-3s   %-17s %-3s   %4s  %6s  %-11s  %s\n",
           "-----------------", "---", "-----------------", "---",
           "----", "------", "-----------", "--------------------------");
    tui_normal();

    if (s->seqnum_correlation_count == 0) {
        tui_dim();
        if (!seqnum_corr_enabled()) {
            TPRINT("  (longitudinal correlation disabled — per-MAC trails below are unaffected)\n");
        } else {
            TPRINT("  (no correlations — needs 2 MACs whose counters continue forward across a rotation)\n");
            if (s->probe_iface[0]) {
                TPRINT("  Monitoring on ");
                tui_bright(); TPRINT("%s", s->probe_iface); tui_dim();
                TPRINT(" — wait for a randomised device to probe across a MAC rotation.\n");
            }
        }
        tui_normal();
    } else {
        for (int i = 0; i < s->seqnum_correlation_count; i++) {
            const seqnum_correlation_t *c = &s->seqnum_correlations[i];
            char a[20], b[20];
            fmt_mac(c->mac_a, a, sizeof(a));
            fmt_mac(c->mac_b, b, sizeof(b));

            /* Heat is reserved for the one shape that distinguishes a
             * rotation from a coincidence — see seqnum_corr_is_strong().
             * A high score alone no longer earns it: the dense fixture in
             * tests/test_seqnum_track.c measures coincidences that score
             * into the same band. */
            int strong = seqnum_corr_is_strong(c);

            if (i == s->seqnum_corr_sel) tui_sel();
            else if (strong)              tui_heat(1.0);
            else                          tui_normal();
            TPRINT(" %-17s", a);

            tui_dim();
            TPRINT(" %-3s", c->mac_a_random ? "Y" : "-");

            if (i == s->seqnum_corr_sel) tui_sel();
            else if (strong)              tui_heat(1.0);
            else                          tui_normal();
            TPRINT("   %-17s", b);

            tui_dim();
            TPRINT(" %-3s", c->mac_b_random ? "Y" : "-");

            if (i == s->seqnum_corr_sel) tui_sel();
            else if (strong)              tui_heat(1.0);
            else                          tui_normal();
            TPRINT("   %4d  %4lds  ", c->fwd_gap, c->dt_ms / 1000);

            /* The window the pair was decided on, so a score is never
             * read without the evidence behind it. */
            tui_dim();
            {
                long win = (long)(c->window_end - c->window_start);
                if (win < 0) win = 0;
                TPRINT("%2dv%-2d/%-4lds  ", c->a_hist_n, c->b_hist_n, win);
            }

            /* Wording: a score and a qualifier. Never a verdict, and
             * never "same device" — let alone "same person". */
            if (strong)                  { tui_heat(1.0); TPRINT("%d%% possible rotation", c->confidence); }
            else if (c->confidence >= 45) { tui_normal();  TPRINT("%d%% moderate", c->confidence); }
            else                          { tui_dim();     TPRINT("%d%% weak", c->confidence); }
            tui_reset();
            TPRINT("\n");
        }
        tui_dim();
        TPRINT("  A correlation is evidence about a radio. Not an identification of a "
               "person, and not\n  grounds on its own for personnel action, physical "
               "location, or automated containment.\n");
        tui_normal();
    }

    /* ── Per-MAC table ──────────────────────────────────── */
    TPRINT("\n");
    tui_dim();
    TPRINT(" Per-MAC seqnum history (newest left)\n");
    TPRINT(" %-17s  %-14s  %4s  %4s  %s\n",
           "MAC", "vendor", "rnd", "age", "recent seqnums");
    TPRINT(" %-17s  %-14s  %4s  %4s  %s\n",
           "-----------------", "--------------", "----", "----",
           "-----------------------------------");
    tui_normal();

    int max_rows = s->seqnum_count;
    if (max_rows > 20) max_rows = 20;
    for (int i = 0; i < max_rows; i++) {
        const seqnum_client_t *c = &s->seqnum_clients[i];
        char macbuf[20], agebuf[8];
        fmt_mac(c->mac, macbuf, sizeof(macbuf));
        fmt_age(c->last_seen, agebuf, sizeof(agebuf));

        tui_normal(); TPRINT(" %-17s", macbuf);
        if (c->mac_random) { tui_dim(); TPRINT("  %-14s", "(random)"); }
        else {
            const char *v = oui_lookup(c->mac);
            if (!v || !v[0]) { tui_dim(); v = "?"; } else { tui_bright(); }
            TPRINT("  %-14.14s", v);
        }
        tui_dim();
        TPRINT("  %-4s  %-4s  ", c->mac_random ? "Y" : "-", agebuf);
        tui_normal();
        for (int j = 0; j < c->hist_n && j < 6; j++) {
            if (j > 0) { tui_dim(); TPRINT(" "); tui_normal(); }
            TPRINT("%04u", (unsigned)c->hist[j]);
        }
        TPRINT("\n");
    }
    tui_normal();
}

void view_seqnum_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->seqnum_corr_sel > 0) s->seqnum_corr_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->seqnum_correlation_count > 0 &&
            s->seqnum_corr_sel < s->seqnum_correlation_count - 1)
            s->seqnum_corr_sel++;
        break;
    case 'c': case 'C':
        seqnum_clear();
        s->seqnum_count = 0;
        s->seqnum_correlation_count = 0;
        s->seqnum_corr_sel = 0;
        break;
    default:
        break;
    }
}
