#include <stdio.h>
#include <string.h>
#include "sloth.h"
#include "tui.h"
#include "views/research.h"

/* Research corpus — issue #73 slice 3.
 *
 * A companion to VIEW_ALERTS, answering the question that view raises:
 * *why should I believe this?* One row per alert kind that fired, with
 * the sources behind it.
 *
 * The uncited rows are the point. An operator deciding whether to act
 * on a CRIT needs to know whether the threshold has a cited basis or is
 * a behavioural guess, and a view that showed only the covered kinds
 * would answer the easy half of that question. */

#define RESEARCH_PAGE 20

static const char *sev_label(int sev) {
    switch (sev) {
    case ALERT_SEV_CRIT: return "CRIT";
    case ALERT_SEV_WARN: return "WARN";
    default:             return "INFO";
    }
}

/* The same heat tiers VIEW_ALERTS uses, so a CRIT is the same red in
 * both places. Two views disagreeing about what red means is worse than
 * either being wrong. */
static void sev_colour(int sev) {
    switch (sev) {
    case ALERT_SEV_CRIT: tui_heat(1.0); break;
    case ALERT_SEV_WARN: tui_heat(0.5); break;
    case ALERT_SEV_LOW:  tui_heat(0.3); break;
    default:             tui_dim();     break;
    }
}

void view_research_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 12;
    if (page < 3) page = 3;
#else
    int page = RESEARCH_PAGE;
#endif

    int cited = 0;
    for (int i = 0; i < s->research_cov_count; i++)
        if (s->research_cov[i].doc_count > 0) cited++;

    tui_normal(); TPRINT(" Research corpus: ");
    if (s->research_open) {
        tui_bright(); TPRINT("loaded");
        tui_dim();    TPRINT("  cited ");
        tui_bright(); TPRINT("%d", cited);
        tui_dim();    TPRINT("/%d fired alert kinds", s->research_cov_count);
    } else {
        tui_heat(0.5); TPRINT("not loaded");
        tui_dim();
        TPRINT("  %s", s->research_status[0] ? s->research_status
                                             : "start with --with-research PATH");
    }
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-4s  %-20s  %-4s  %-4s  %s\n",
           "SEV", "ALERT", "HITS", "DOCS", "KIND");
    TPRINT(" %-4s  %-20s  %-4s  %-4s  %s\n",
           "----", "--------------------", "----", "----",
           "--------------------");
    tui_normal();

    if (s->research_cov_count == 0) {
        tui_dim();
        TPRINT("  (no alerts have fired yet — this view lists the sources\n"
               "   behind each alert once there is one to explain.)\n");
        tui_normal();
        return;
    }

    int top = s->research_sel - page / 2;
    if (top + page > s->research_cov_count) top = s->research_cov_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > s->research_cov_count) end = s->research_cov_count;

    for (int i = top; i < end; i++) {
        const research_cov_t *c = &s->research_cov[i];
        int selected = (i == s->research_sel);

        if (selected) { tui_bright(); TPRINT(">"); }
        else          { tui_normal(); TPRINT(" "); }

        sev_colour(c->severity);
        TPRINT("%-4s", sev_label(c->severity));
        tui_normal();
        TPRINT("  %-20.20s  %4d  ", c->label, c->fired);

        /* Zero is coloured, not blank. A blank cell reads as "not
         * applicable"; this is "nothing backs this rule", which is a
         * finding about sloth rather than about the network. */
        if (c->doc_count > 0) { tui_bright(); TPRINT("%4d", c->doc_count); }
        else                  { tui_heat(0.5); TPRINT("%4s", "-"); }
        tui_normal();
        tui_dim(); TPRINT("  %s\n", c->kind);
        tui_normal();
    }

    /* Detail for the selection. */
    const research_cov_t *c = &s->research_cov[s->research_sel];
    TPRINT("\n");
    tui_dim(); TPRINT(" ── sources for "); tui_normal();
    tui_bright(); TPRINT("%s", c->kind);
    tui_dim(); TPRINT(" ──\n"); tui_normal();

    if (c->doc_count == 0) {
        tui_heat(0.5);
        TPRINT("  No document in the corpus cites this rule.\n");
        tui_dim();
        TPRINT("  A behavioural threshold with no cited basis is\n"
               "  indistinguishable from a guess. See docs/wiki/research-corpus.md\n"
               "  for how to add one.\n");
        tui_normal();
        return;
    }

    for (int d = 0; d < c->doc_count; d++) {
        const research_doc_t *doc = &c->docs[d];
        tui_normal(); TPRINT("  %s\n", doc->title);
        tui_dim();    TPRINT("    %s", doc->source_url);
        if (doc->retrieved[0]) TPRINT("  (retrieved %s)", doc->retrieved);
        TPRINT("\n");
        tui_normal();
    }
    if (c->docs_truncated) {
        tui_dim();
        TPRINT("  ... more in the corpus than fit here (showing %d)\n",
               MAX_RESEARCH_DOCS);
        tui_normal();
    }
}

void view_research_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->research_sel > 0) s->research_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->research_cov_count > 0 &&
            s->research_sel < s->research_cov_count - 1)
            s->research_sel++;
        break;
    default:
        break;
    }
}
