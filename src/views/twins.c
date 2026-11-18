#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "views/view_page.h"
#include "views/twins.h"
/* ../ is required: src/views/alerts.h is the view header and would
 * shadow the rules header on a bare "alerts.h" from this directory.
 * Same form src/views/alerts.c already uses. */
#include "../alerts.h"
#include "../wired_attach.h"
#include "tui_glyph.h"

#define TWINS_PAGE 30
/* Rows the legend under the table takes: flags, class and wired, two
 * lines each. Left out of the page budget, a full table pushed the
 * legend - the lines saying `?` is not a verdict - off the screen. */
#define TWINS_LEGEND_ROWS 6

/* Twins' columns at the screen width (#150). In full they take 105
 * columns plus the age, and the list clip holds back the last one, so
 * at the 100-column minimum Flags started at column 97: a `!*#?` row
 * showed `!*`, losing the hash-mismatch mark and the `?` that says
 * neither half is accused, while the legend under the table still
 * explained it. (Five marks since #188 added `>`; the column is six.) Flags is what this view exists to show, so the room
 * comes out of SSID first (a twin's two halves share it, and the
 * BSSIDs tell them apart) and then Last, which is only shown whole.
 * The ANSI build has no width and keeps every column. */
#define TWINS_SSID_MAX  18
#define TWINS_SSID_MIN  12
#define TWINS_LAST_W     8      /* "1234567s": eleven days in seconds */
/* " " plus everything from BSSID A through Flags, each with its gap. */
#define TWINS_FIXED_W   (1 + 19 + 19 + 8 + 6 + 10 + 7 + 7 + 8)

typedef struct { int ssid; int last; } twins_plan_t;

static int twins_cols(void) {
#ifdef WITH_NCURSES
    return COLS > 0 ? COLS : 100;
#else
    return 1 << 12;
#endif
}

static twins_plan_t twins_plan(int cols) {
    int room = cols - 1;        /* the clip keeps the last column */
    twins_plan_t w;
    w.ssid = room - TWINS_FIXED_W;
    if (w.ssid > TWINS_SSID_MAX) w.ssid = TWINS_SSID_MAX;
    if (w.ssid < TWINS_SSID_MIN) w.ssid = TWINS_SSID_MIN;
    w.last = TWINS_FIXED_W + w.ssid + 2 + TWINS_LAST_W <= room;
    return w;
}

static void fmt_mac(const uint8_t mac[6], char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ── G8, the chain lanes for the selected pair (#195) ─────────
 * docs/web-visual-spec.md §5 G8's TUI form: one lane per stage in the
 * order the chain runs, on one time axis ending now. An EVIL_TWIN or
 * KARMA_AP incident naming either BSSID at its key's fixed fields
 * (alert_pair_key()'s two after "twin:" / "twin-fp:", karma_alert_key()'s
 * one after "karma:"; never a substring, as web_sdb_chain_stages() reads
 * them) is `━` from open to last observation, `●` at an end inside the
 * window, in the severity it reached. A deauth stream addressed to
 * either BSSID is `▌` across its span; an association to either is `●`
 * at its first frame; both in the one ink, with the DEAUTH_FLOOD
 * severity as the lane's word. The links sloth made are words under
 * the lanes. */
#define CHAIN_ROWS   7      /* title, four lanes, axis, links */
#define CHAIN_CELLS 24
#define CHAIN_MIN_S 600
#define CHAIN_MAX_S 86400

static int key_bssid_at(const char *key, size_t off, const char *mac) {
    return strlen(key) >= off + 17 && strncmp(key + off, mac, 17) == 0;
}

/* Which BSSID of the pair (1 or 2) the key names at its fixed fields,
 * or 0. */
static int stage_key_names(const alert_t *a, const char *m1, const char *m2) {
    const char *k = a->key;
    const char *m[2] = { m1, m2 };
    for (int i = 0; i < 2; i++) {
        if (a->type == ALERT_TYPE_EVIL_TWIN) {
            if (strncmp(k, "twin:", 5) == 0 &&
                (key_bssid_at(k, 5, m[i]) || key_bssid_at(k, 23, m[i])))
                return i + 1;
            if (strncmp(k, "twin-fp:", 8) == 0 &&
                (key_bssid_at(k, 8, m[i]) || key_bssid_at(k, 26, m[i])))
                return i + 1;
        } else if (a->type == ALERT_TYPE_KARMA_AP) {
            if (strncmp(k, "karma:", 6) == 0 && key_bssid_at(k, 6, m[i]))
                return i + 1;
        } else if (a->type == ALERT_TYPE_DEAUTH_FLOOD) {
            const char *at = strrchr(k, '@');
            if (strncmp(k, "deauth:", 7) == 0 && at && strcmp(at + 1, m[i]) == 0)
                return i + 1;
        }
    }
    return 0;
}

static void draw_lane(const char *name, int sev, const tg_lane_t *l) {
    char label[16];
    if (sev >= 0)
        snprintf(label, sizeof(label), "%s %s", name,
                 sev == ALERT_SEV_CRIT ? "CRIT" : sev == ALERT_SEV_WARN ? "WARN" : "LOW");
    else
        snprintf(label, sizeof(label), "%s", name);
    if (sev >= 0) tg_tone_apply(tg_sev_tone(sev)); else tui_dim();
    TPRINT("  %-12s ", label);
    for (int i = 0; i < l->n; i++) {
        tg_tone_apply(l->cell[i].tone);
        TPRINT("%s", l->cell[i].glyph);
    }
    TPRINT("\n");
}

static void draw_chain(const sloth_state_t *s, const twin_episode_t *e) {
    char m1[20], m2[20];
    fmt_mac(e->real_bssid, m1, sizeof(m1));
    fmt_mac(e->twin_bssid, m2, sizeof(m2));
    time_t now = sloth_wall(), first = now;

    /* The axis: from the earliest stage seen (at least ten minutes, at
     * most a day) to now. */
    for (int i = 0; i < s->alert_count && i < MAX_ALERTS; i++) {
        const alert_t *a = &s->alerts[i];
        if (stage_key_names(a, m1, m2) && a->first_detected > 0 &&
            a->first_detected < first)
            first = a->first_detected;
    }
    for (int i = 0; i < s->deauth_count && i < MAX_DEAUTH_ENTRIES; i++) {
        const deauth_event_t *d = &s->deauth_events[i];
        if ((!memcmp(d->bssid, e->real_bssid, 6) || !memcmp(d->bssid, e->twin_bssid, 6)) &&
            d->first_seen > 0 && d->first_seen < first)
            first = d->first_seen;
    }
    time_t span = now - first;
    if (span < CHAIN_MIN_S) span = CHAIN_MIN_S;
    if (span > CHAIN_MAX_S) span = CHAIN_MAX_S;
    time_t from = now - span;

    tg_lane_t deauth, twin, assoc, karma;
    tg_lane_init(&deauth, CHAIN_CELLS);
    tg_lane_init(&twin,   CHAIN_CELLS);
    tg_lane_init(&assoc,  CHAIN_CELLS);
    tg_lane_init(&karma,  CHAIN_CELLS);
    int sev_d = -1, sev_t = -1, sev_k = -1, nassoc = 0;

    for (int i = 0; i < s->deauth_count && i < MAX_DEAUTH_ENTRIES; i++) {
        const deauth_event_t *d = &s->deauth_events[i];
        if (memcmp(d->bssid, e->real_bssid, 6) && memcmp(d->bssid, e->twin_bssid, 6))
            continue;
        int a = tg_lane_col(&deauth, d->first_seen < from ? from : d->first_seen, from, now);
        int b = tg_lane_col(&deauth, d->last_seen, from, now);
        for (int c = a; a >= 0 && b >= 0 && c <= b; c++) {
            deauth.cell[c].glyph = "\xe2\x96\x8c";   /* ▌ */
            deauth.cell[c].tone  = TG_NORMAL;
        }
    }
    for (int i = 0; i < s->assoc_count && i < MAX_ASSOC_ENTRIES; i++) {
        const assoc_t *as = &s->assocs[i];
        if (memcmp(as->bssid, e->real_bssid, 6) && memcmp(as->bssid, e->twin_bssid, 6))
            continue;
        if (as->first_seen >= from) nassoc++;
        tg_lane_mark(&assoc, as->first_seen, from, now, "\xe2\x97\x8f", TG_NORMAL);
    }
    for (int i = 0; i < s->alert_count && i < MAX_ALERTS; i++) {
        const alert_t *a = &s->alerts[i];
        if (!stage_key_names(a, m1, m2)) continue;
        int sv = (int)a->sev;
        if (a->type == ALERT_TYPE_DEAUTH_FLOOD) {
            if (sv > sev_d) sev_d = sv;
        } else {
            tg_lane_t *l = a->type == ALERT_TYPE_EVIL_TWIN ? &twin : &karma;
            int *ms = a->type == ALERT_TYPE_EVIL_TWIN ? &sev_t : &sev_k;
            if (sv > *ms) *ms = sv;
            tg_lane_bar(l, a->first_detected, a->last_seen, from, now,
                        tg_sev_tone(sv));
        }
    }

    tui_dim();
    /* The pair is the highlighted row above; its BSSIDs are not
     * repeated, so a search for one finds the table row alone. */
    TPRINT(" \xe2\x94\x80\xe2\x94\x80 chain of the selected pair, by stage"
           " \xe2\x94\x80\xe2\x94\x80\n");
    draw_lane("deauth", sev_d, &deauth);
    draw_lane("twin",   sev_t, &twin);
    draw_lane("assoc",  -1,    &assoc);
    draw_lane("karma",  sev_k, &karma);
    char t0[8], tm_buf[8];
    struct tm tm;
    if (localtime_r(&from, &tm)) strftime(t0, sizeof(t0), "%H:%M", &tm);
    else snprintf(t0, sizeof(t0), "?");
    if (localtime_r(&now, &tm)) strftime(tm_buf, sizeof(tm_buf), "%H:%M", &tm);
    else snprintf(tm_buf, sizeof(tm_buf), "?");
    tui_dim();
    TPRINT("  %-12s %-*s%s  %ld min, %d assoc\n", "", CHAIN_CELLS - 5, t0,
           tm_buf, (long)(span / 60), nassoc);
    /* The links sloth made, in words (P9, P11). */
    TPRINT("  links: %s; %s\n",
           e->attack_in_progress ? "deauth taint, attack in progress"
                                 : "no deauth taint",
           e->attributed ? "impostor attributed" : "unattributed");
    tui_normal();
}

void view_twins_draw(const sloth_state_t *s) {
    /* Status bar */
    tui_normal(); TPRINT(" Evil-twin episodes: ");
    tui_bright(); TPRINT("%d", s->twin_episode_count);
    tui_dim();    TPRINT(" / max %d", MAX_TWIN_EPISODES);
    int in_progress = 0;
    for (int i = 0; i < s->twin_episode_count; i++) {
        if (s->twin_episodes[i].attack_in_progress) in_progress++;
    }
    if (in_progress > 0) {
        tui_dim();    TPRINT("  attack-in-progress: ");
        tui_bright(); TPRINT("%d", in_progress);
    }
    /* Whether anything is even looking at the wire (#89 slice 3). A
     * Wired column full of `?` reads very differently depending on the
     * answer: "nobody asked" is not "nothing found", and an operator
     * who cannot tell those apart will eventually read the first as the
     * second. */
    tui_dim();    TPRINT("  wired correlation: ");
    tui_bright(); TPRINT("%s", wired_attach_have_correlator()
                               ? "active" : "none");
    TPRINT("\n");

    /* Column headers: SSID | A 17 | B 17 | enc 6 | conf 4 | class 8 |
     * wired 5 | swing 5 | flags 6 | last. Laid out by twins_plan(), so
     * a 100-column screen narrows SSID and drops Last rather than
     * clipping Flags.
     *
     * "BSSID A / B" rather than "Real / Twin" (#89). On a `?`-flagged
     * row nothing has established which half is the impostor and the
     * two columns are only the pair in canonical order — heading them
     * "Real" and "Twin" made the table state a verdict sloth does not
     * have. An attributed row says so by *not* carrying the `?`.
     *
     * Class and Wired are two columns rather than one (#89 slice 3)
     * because they answer questions with different evidence
     * requirements. Class is decidable from RF plus the approved
     * inventory. Wired attachment is not decidable from RF at all, so
     * it can never be filled in by anything in this view's data path —
     * separating them is what keeps "impostor" from being read as
     * "rogue on our LAN". */
    twins_plan_t w = twins_plan(twins_cols());
    tui_clip_rows(1);   /* the table only: the status line above wraps */
    tui_dim();
    TPRINT(" %-*s  %-17s  %-17s  %-6s  %-4s  %-8s  %-5s  %-5s  %-6s",
           w.ssid, "SSID", "BSSID A", "BSSID B", "Cipher", "Conf", "Class",
           "Wired", "Swing", "Flags");
    if (w.last) TPRINT("  %s", "Last");
    TPRINT("\n");
    TPRINT(" %-*.*s  %-17s  %-17s  %-6s  %-4s  %-8s  %-5s  %-5s  %-6s",
           w.ssid, w.ssid, "------------------",
           "-----------------",
           "-----------------",
           "------", "----", "--------", "-----", "-----", "------");
    if (w.last) TPRINT("  %s", "----");
    TPRINT("\n");
    tui_normal();

    if (s->twin_episode_count == 0) {
        tui_dim();
        TPRINT("  (no twin pairs observed — sloth needs at least two same-SSID,\n"
               "   same-cipher beacons plus some positive impersonation\n"
               "   evidence to record one.)\n");
        tui_normal();
        return;
    }

    int page = view_page_budget(TWINS_LEGEND_ROWS + CHAIN_ROWS, TWINS_PAGE);
    int top = s->twin_episode_sel - page / 2;
    if (top + page > s->twin_episode_count) top = s->twin_episode_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > s->twin_episode_count) end = s->twin_episode_count;

    for (int row = top; row < end; row++) {
        const twin_episode_t *e = &s->twin_episodes[row];
        char real_mac[20], twin_mac[20], swing[8], flags[8], conf[8];
        fmt_mac(e->real_bssid, real_mac, sizeof(real_mac));
        fmt_mac(e->twin_bssid, twin_mac, sizeof(twin_mac));
        if (e->rssi_swing_dbm) snprintf(swing, sizeof(swing), "%udB", e->rssi_swing_dbm);
        else                   snprintf(swing, sizeof(swing), "-");
        /* Confidence, not severity (#89) — how likely the pair is an
         * impersonation, which the alert row's colour does not tell you. */
        if (e->confidence) snprintf(conf, sizeof(conf), "%u%%", e->confidence);
        else               snprintf(conf, sizeof(conf), "-");
        /* The two pair axes (#89 slice 3). Both render their unknown as
         * a literal `?` rather than a blank: an empty cell invites the
         * reader to supply their own answer, and on the Wired column
         * the answer they supply is usually the alarming one. */
        const char *cls_s   = twin_class_label((twin_class_t)e->ap_class);
        const char *wired_s =
            wired_attach_label((wired_attach_t)e->wired_attach);
        /* Flag glyphs (ASCII for portability):
         *   ! = attack-in-progress (deauth-fed chain CRIT)
         *   * = attacker-tool OUI (Hak5 / Espressif)
         *   # = vendor-IE hash mismatch
         *   > = late arrival: first heard well after the other half
         *   ? = unattributed — candidate pair, neither half accused */
        int  fi = 0;
        if (e->attack_in_progress) flags[fi++] = '!';
        if (e->attacker_oui)       flags[fi++] = '*';
        if (e->hash_mismatch)      flags[fi++] = '#';
        if (e->late_arrival)       flags[fi++] = '>';
        if (!e->attributed)        flags[fi++] = '?';
        flags[fi] = '\0';
        if (!flags[0]) snprintf(flags, sizeof(flags), "-");

        char age[12];
        time_t now = sloth_wall();
        if (e->last_seen == 0) snprintf(age, sizeof(age), "?");
        else snprintf(age, sizeof(age), "%lds", (long)(now - e->last_seen));

#ifdef WITH_NCURSES
        if (row == s->twin_episode_sel) {
            tui_sel();
            tui_printf(" %-*.*s  %-17s  %-17s  %-6.6s  %-4s  %-8.8s  %-5.5s"
                   "  %-5s  %-6s",
                   w.ssid, w.ssid, e->ssid, real_mac, twin_mac, e->enc, conf,
                   cls_s, wired_s, swing, flags);
            if (w.last) tui_printf("  %s", age);
            tui_printf("\n");
            tui_reset();
        } else {
            tui_bright(); tui_printf(" %-*.*s", w.ssid, w.ssid, e->ssid);
            tui_dim();    tui_printf("  %-17s", real_mac);
            /* Bright on the B column only when the pair is attributed —
             * there it really is the suspected rogue. On an
             * unattributed pair the two halves are peers and colouring
             * one of them would accuse whichever BSSID sorted higher. */
            if (e->attributed) tui_bright(); else tui_dim();
            tui_printf("  %-17s", twin_mac);
            tui_dim();    tui_printf("  %-6.6s", e->enc);
            tui_normal(); tui_printf("  %-4s", conf);
            /* Bright only on a class that names an impersonator. A
             * `neighbor` or `declared` row is the detector saying "not
             * your problem" and should not compete for attention. */
            if (e->ap_class == (uint8_t)TWIN_CLASS_IMPERSONATOR) tui_bright();
            else                                                 tui_dim();
            tui_printf("  %-8.8s", cls_s);
            /* Never bright on `?`, which is every row until a
             * correlator exists: highlighting a column sloth has no
             * answer for would advertise the absence as a finding. */
            if (e->wired_attach == (uint8_t)WIRED_ATTACH_ATTACHED) tui_bright();
            else                                                   tui_dim();
            tui_printf("  %-5.5s", wired_s);
            tui_normal(); tui_printf("  %-5s", swing);
            if (e->attack_in_progress) tui_bright(); else tui_dim();
            tui_printf("  %-6s", flags);
            tui_dim();
            if (w.last) tui_printf("  %s", age);
            tui_printf("\n");
            tui_normal();
        }
#else
        if (row == s->twin_episode_sel) {
            tui_sel();
            tui_printf(" %-*.*s  %-17s  %-17s  %-6.6s  %-4s  %-8.8s  %-5.5s"
                   "  %-5s  %-6s",
                   w.ssid, w.ssid, e->ssid, real_mac, twin_mac, e->enc, conf,
                   cls_s, wired_s, swing, flags);
            if (w.last) tui_printf("  %s", age);
            tui_reset(); tui_printf("\n");
        } else {
            tui_bright(); tui_printf(" %-*.*s", w.ssid, w.ssid, e->ssid);
            tui_dim();    tui_printf("  %-17s", real_mac);
            if (e->attributed) tui_bright(); else tui_dim();
            tui_printf("  %-17s", twin_mac);
            tui_dim();    tui_printf("  %-6.6s", e->enc);
            tui_normal(); tui_printf("  %-4s", conf);
            if (e->ap_class == (uint8_t)TWIN_CLASS_IMPERSONATOR) tui_bright();
            else                                                 tui_dim();
            tui_printf("  %-8.8s", cls_s);
            if (e->wired_attach == (uint8_t)WIRED_ATTACH_ATTACHED) tui_bright();
            else                                                   tui_dim();
            tui_printf("  %-5.5s", wired_s);
            tui_normal(); tui_printf("  %-5s", swing);
            if (e->attack_in_progress) tui_bright(); else tui_dim();
            tui_printf("  %-6s", flags);
            tui_dim();
            if (w.last) tui_printf("  %s", age);
            tui_printf("\n");
            tui_normal();
        }
#endif
    }
    tui_normal();

    if (s->twin_episode_sel >= 0 && s->twin_episode_sel < s->twin_episode_count)
        draw_chain(s, &s->twin_episodes[s->twin_episode_sel]);

    /* Legend */
    tui_dim();
    TPRINT(" flags: ! attack-in-progress  * attacker OUI  # vendor-IE hash mismatch"
           "  > late arrival\n");
    TPRINT("        ? sides unattributed - candidate pair, neither half accused\n");
    /* The three categories #89 asked the UI to separate, and the one it
     * asked the UI not to assert. */
    TPRINT(" class: impostor over-the-air impersonation  neighbor outside the declared\n");
    TPRINT("        estate  declared both halves in the approved inventory  ? no inventory\n");
    TPRINT(" wired: ? not established - RF cannot show what a radio is plugged into;\n");
    TPRINT("        needs controller/switch/DHCP correlation%s\n",
           wired_attach_have_correlator() ? "" : " (none registered)");
    tui_normal();
}

void view_twins_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->twin_episode_sel > 0) s->twin_episode_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->twin_episode_count > 0 &&
            s->twin_episode_sel < s->twin_episode_count - 1)
            s->twin_episode_sel++;
        break;
    default:
        break;
    }
}
