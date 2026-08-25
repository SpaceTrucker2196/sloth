#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "oui.h"
#include "assoc_track.h"
#include "beacon_snoop.h"
#include "views/assoc.h"

/* ∆ U+2206 INCREMENT — the downgrade marker. Written as bytes for
 * the same reason the box-drawing macros are: the source stays
 * ASCII and the encoding is explicit rather than dependent on how
 * the file was saved. */
#define G_DELTA "\xe2\x88\x86"

/* VIEW_ASSOC — STA <-> AP association tracker.
 *
 * One row per (BSSID, STA) pair we've observed evidence for: completed
 * EAPOL handshake, assoc-response status=0, or reassoc-response
 * status=0. Disassoc / deauth removes the row. Answers "who is on
 * which WiFi network right now?" — useful for tracking who's roamed
 * onto a target AP or evaluating which clients are exposed to the
 * same network's auth crypto. */

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

/* The ask that pairs with this grant. Reads the state snapshot rather
 * than assoc_request_find() so the view stays a pure function of state
 * — the table is bounded at MAX_ASSOC_ENTRIES, so the scan is bounded
 * too. */
static const assoc_req_t *find_req(const sloth_state_t *s,
                                   const uint8_t bssid[6],
                                   const uint8_t sta[6]) {
    for (int i = 0; i < s->assoc_req_count; i++) {
        if (memcmp(s->assoc_reqs[i].bssid, bssid, 6) == 0 &&
            memcmp(s->assoc_reqs[i].sta,   sta,   6) == 0)
            return &s->assoc_reqs[i];
    }
    return NULL;
}

static const char *src_label(int s) {
    switch (s) {
    case ASSOC_SRC_EAPOL:   return "EAPOL";
    case ASSOC_SRC_ASSOC:   return "AssocResp";
    case ASSOC_SRC_REASSOC: return "ReassocResp";
    default:                return "?";
    }
}

void view_assoc_draw(const sloth_state_t *s) {
    tui_normal(); TPRINT(" Associated clients: ");
    tui_bright(); TPRINT("%d", s->assoc_count);
    tui_dim();    TPRINT("  [up/dn] navigate  [c] clear\n");

    tui_dim();
    TPRINT(" %-17s  %-16s  %-17s  %-14s  %3s  %3s  %4s  %-8s  %-11s  %4s\n",
           "BSSID", "SSID", "STA", "vendor", "ch", "rnd", "sig",
           "asked", "via", "age");
    TPRINT(" %-17s  %-16s  %-17s  %-14s  %3s  %3s  %4s  %-8s  %-11s  %4s\n",
           "-----------------", "----------------",
           "-----------------", "--------------",
           "---", "---", "----", "--------", "-----------", "----");
    tui_normal();

    if (s->assoc_count == 0) {
        tui_dim();
        if (s->probe_iface[0]) {
            TPRINT("  Monitoring on ");
            tui_bright(); TPRINT("%s", s->probe_iface); tui_dim();
            TPRINT(" — associations appear on EAPOL completion / assoc-response.\n");
        } else {
            TPRINT("  (no monitor-mode iface available)\n");
        }
        tui_normal();
        return;
    }

    for (int i = 0; i < s->assoc_count; i++) {
        const assoc_t *a = &s->assocs[i];
        char bssid_buf[20], sta_buf[20], age_buf[8];
        fmt_mac(a->bssid,   bssid_buf, sizeof(bssid_buf));
        fmt_mac(a->sta_mac, sta_buf,   sizeof(sta_buf));
        fmt_age(a->last_seen, age_buf, sizeof(age_buf));

        if (i == s->assoc_sel) tui_sel(); else tui_normal();
        TPRINT(" %-17s  ", bssid_buf);

#ifdef WITH_NCURSES
        if (a->ssid[0]) {
            char b[24];
            snprintf(b, sizeof(b), "%-16.16s", a->ssid);
            tui_ssid_addstr(b, 0);
        } else {
            tui_dim(); TPRINT("%-16s", "(?)");
        }
#else
        if (a->ssid[0]) TPRINT("%-16.16s", a->ssid);
        else            TPRINT("%-16s",    "(?)");
#endif

        if (i == s->assoc_sel) tui_sel(); else tui_normal();
        TPRINT("  %-17s  ", sta_buf);

        /* Vendor — dim for random/unknown, bright for known OUI. */
        if (a->sta_random) {
            tui_dim();    TPRINT("%-14s", "(random)");
        } else {
            const char *v = oui_lookup(a->sta_mac);
            if (!v || !v[0]) { tui_dim(); v = "?"; } else { tui_bright(); }
            TPRINT("%-14.14s", v);
        }

        tui_dim();
        TPRINT("  %3d  %-3s  %4d  ", a->channel,
               a->sta_random ? "Y" : "-", a->signal_dbm);

        /* What the client asked for (#60). The grant carries no RSNE
         * outside FT/OWE (§9.3.3.7), so there is no "granted AKM" to
         * show beside it — the request is the only place the client's
         * choice is on the air. */
        const assoc_req_t *req = find_req(s, a->bssid, a->sta_mac);
        char ask[12] = "-";
        if (req) rsn_akm_label(req->akm_bits, ask, sizeof(ask));
        if (req && (req->downgrade_flags & ASSOC_DG_AKM)) tui_heat(1.0);
        else if (req)                                     tui_normal();
        else                                              tui_dim();
        TPRINT("%-8.8s", ask);

        /* via — EAPOL is the strongest signal, brighten it. */
        if (a->source == ASSOC_SRC_EAPOL) tui_bright();
        else                              tui_normal();
        TPRINT("  %-11s", src_label(a->source));

        tui_dim();
        TPRINT("  %-4s", age_buf);

        /* The downgrade rides as a trailing marker rather than two more
         * columns. The row is already 110 characters wide, a downgrade
         * is the exception rather than the norm, and "what it asked for
         * before" is only meaningful when it changed — a permanent
         * prev_akm column would be "-" on almost every row. */
        if (req && req->downgrade_flags) {
            char prev[12];
            rsn_akm_label(req->prev_akm_bits, prev, sizeof(prev));
            tui_heat(1.0);
            TPRINT("  %s ", G_DELTA);
            if (req->downgrade_flags & ASSOC_DG_AKM)
                TPRINT("%s->%s ", prev, ask);
            if (req->downgrade_flags & ASSOC_DG_MFP)
                TPRINT("MFP%d->%d ", req->prev_mfp, req->requested_mfp);
            if (req->downgrade_flags & ASSOC_DG_PAIRWISE)
                TPRINT("cipher ");
        }
        TPRINT("\n");
        tui_reset();
    }
    tui_normal();
}

void view_assoc_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->assoc_sel > 0) s->assoc_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->assoc_count > 0 && s->assoc_sel < s->assoc_count - 1)
            s->assoc_sel++;
        break;
    case 'c': case 'C':
        assoc_clear();
        s->assoc_count = 0;
        s->assoc_sel   = 0;
        break;
    default:
        break;
    }
}
