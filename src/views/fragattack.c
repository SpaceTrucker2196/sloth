#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/fragattack.h"

/* FragAttacks tracker — issue #75 slice 5.
 *
 * Seven detectors (src/fragattack.c, src/alerts.c) have been shipping
 * since slice 1 with nowhere an operator could see the running count
 * without grepping alert history. This is that surface: one row per
 * BSSID with a live per-CVE breakdown for the selection, the same
 * "table + detail pane" shape VIEW_RESEARCH already uses.
 *
 * No new SQLite table and no per-event evidence blob, per this issue's
 * own earlier reshape call — src/alert_pcap.c already writes a
 * per-alert pcap with the triggering frames, which is a better fixture
 * seed than truncated bytes in a DB row and needs no schema change.
 * This view is a counter table, not an event log. */

#define FRAG_PAGE 20

static void fmt_mac(const uint8_t *mac, char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void fmt_age(time_t last_hit, char *buf, int sz) {
    if (last_hit == 0) { snprintf(buf, sz, "-"); return; }
    long age = (long)(time(NULL) - last_hit);
    if (age < 0)     age = 0;
    if (age > 99999) age = 99999;
    if      (age <   60) snprintf(buf, sz, "%lds", age);
    else if (age < 3600) snprintf(buf, sz, "%ldm", age / 60);
    else                 snprintf(buf, sz, "%ldh", age / 3600);
}

static uint32_t findings_total(const frag_bss_row_t *r) {
    /* protected_frames is gate evidence (a station installed a key),
     * not a finding — summing it in would make an ordinary encrypted
     * BSS with zero attacks look like it had hundreds. */
    return r->plaintext_unicast + r->plaintext_bcast_frag
         + r->cache_poison + r->mixed_protect + r->amsdu_flip
         + r->amsdu_eapol_spoof + r->mixed_key
         + r->pn_gap + r->eapol_relay;
}

/* One row of the detail breakdown: display title, CVE(s), the counter
 * to read. Matches src/alerts.c's fire() titles and docs/views/alerts.md
 * exactly, so a row here and a row in [v] Alerts or [f] Research name
 * the same thing. */
static void draw_detail_row(const char *title, const char *cve,
                            uint32_t count) {
    if (count > 0) tui_bright(); else tui_dim();
    TPRINT("  %-18s %-24s %6u\n", title, cve, count);
    tui_normal();
}

void view_fragattack_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 16;
    if (page < 3) page = 3;
#else
    int page = FRAG_PAGE;
#endif

    uint32_t total = 0;
    for (int i = 0; i < s->frag_row_count; i++)
        total += findings_total(&s->frag_rows[i]);

    tui_normal(); TPRINT(" FragAttacks (#75): ");
    tui_bright(); TPRINT("%d", s->frag_row_count);
    tui_dim();    TPRINT(" BSSID%s tracked, ", s->frag_row_count == 1 ? "" : "s");
    if (total > 0) tui_heat(1.0); else tui_bright();
    TPRINT("%u", total);
    tui_dim(); TPRINT(" findings across 7 CVEs\n");
    tui_normal();

    if (s->frag_row_count == 0) {
        tui_dim();
        TPRINT("  (no FragAttacks activity observed yet — see [v] Alerts and\n"
               "   docs/wiki/fragattacks.md for what each of the seven rules\n"
               "   watches for.)\n");
        tui_normal();
        return;
    }

    tui_dim();
    TPRINT(" %-18s  %8s  %-38s  %s\n",
           "BSSID", "FINDINGS", "LAST SA -> DA", "AGE");
    TPRINT(" %-18s  %8s  %-38s  %s\n",
           "------------------", "--------",
           "--------------------------------------", "----");
    tui_normal();

    int top = s->frag_sel - page / 2;
    if (top + page > s->frag_row_count) top = s->frag_row_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > s->frag_row_count) end = s->frag_row_count;

    for (int i = top; i < end; i++) {
        const frag_bss_row_t *r = &s->frag_rows[i];
        int selected = (i == s->frag_sel);
        char bss[18], sa[18], da[18], sadada[40], age[8], marker_bss[20];

        fmt_mac(r->bssid, bss, sizeof(bss));
        fmt_age(r->last_hit, age, sizeof(age));
        uint32_t rf = findings_total(r);
        snprintf(marker_bss, sizeof(marker_bss), "%c%-17s",
                 selected ? '>' : ' ', bss);

        if (selected) tui_bright(); else tui_normal();
        TPRINT(" %-18s  ", marker_bss);

        if (rf > 0) tui_heat(1.0); else tui_dim();
        TPRINT("%8u", rf);
        tui_normal();

        if (rf > 0) {
            fmt_mac(r->last_sa, sa, sizeof(sa));
            fmt_mac(r->last_da, da, sizeof(da));
            snprintf(sadada, sizeof(sadada), "%s -> %s", sa, da);
        } else {
            snprintf(sadada, sizeof(sadada), "-");
        }
        TPRINT("  %-38s  %s\n", sadada, age);
    }

    /* Detail for the selection. */
    const frag_bss_row_t *r = &s->frag_rows[s->frag_sel];
    char bss[18];
    fmt_mac(r->bssid, bss, sizeof(bss));

    TPRINT("\n");
    tui_dim(); TPRINT(" ── FragAttacks findings for "); tui_normal();
    tui_bright(); TPRINT("%s", bss);
    tui_dim(); TPRINT(" ──\n"); tui_normal();

    draw_detail_row("FRAG_PLAINTEXT",   "CVE-2020-26140/-26143", r->plaintext_unicast);
    draw_detail_row("FRAG_BCAST",       "CVE-2020-26145",        r->plaintext_bcast_frag);
    draw_detail_row("FRAG_CACHE",       "CVE-2020-24586",        r->cache_poison);
    draw_detail_row("FRAG_MIXED",       "CVE-2020-26147",        r->mixed_protect);
    draw_detail_row("FRAG_AMSDU",       "CVE-2020-24588",        r->amsdu_flip);
    draw_detail_row("FRAG_AMSDU_EAPOL", "CVE-2020-26144",        r->amsdu_eapol_spoof);
    draw_detail_row("FRAG_MIXKEY",      "CVE-2020-24587",        r->mixed_key);
    draw_detail_row("FRAG_PN_GAP",      "CVE-2020-26146",        r->pn_gap);
    draw_detail_row("FRAG_EAPOL_RELAY", "CVE-2020-26139",        r->eapol_relay);

    tui_dim();
    TPRINT("  %u protected frame%s witnessed on this BSSID (key-install gate)\n",
           r->protected_frames, r->protected_frames == 1 ? "" : "s");
    tui_normal();
}

void view_fragattack_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->frag_sel > 0) s->frag_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->frag_row_count > 0 && s->frag_sel < s->frag_row_count - 1)
            s->frag_sel++;
        break;
    default:
        break;
    }
}
