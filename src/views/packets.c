#include <stdio.h>
#include <string.h>
#include "ntop.h"
#include "tui.h"
#include "views/packets.h"

#define PKTS_PAGE 30

/* Return total displayable count and ring-buffer start index. */
static void ring_range(const ntop_state_t *s, int *count, int *start) {
    *count = (s->pkt_count < MAX_PACKETS) ? s->pkt_count : MAX_PACKETS;
    *start = (s->pkt_count < MAX_PACKETS) ? 0            : s->pkt_head;
}

/* ── Draw ───────────────────────────────────────────────── */

void view_packets_draw(const ntop_state_t *s) {
#ifndef WITH_PCAP
    (void)s;
    TPRINT("  Packet capture disabled (build with WITH_PCAP=1)\n");
    return;
#else
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = PKTS_PAGE;
#endif

    int count, start;
    ring_range(s, &count, &start);

    /* status bar */
    TPRINT(" Packets: %d", count);
    if (s->pkt_count > MAX_PACKETS) TPRINT(" (ring)");
    if (s->pkt_paused)              TPRINT("  [PAUSED]");
#ifndef WITH_NCURSES
    TPRINT("  [p]ause  [up/dn] navigate");
#endif
    TPRINT("\n");

    /* column headers */
    TPRINT(" %-11s  %-21s  %-21s  %5s  %5s  %s\n",
           "Time", "Source", "Destination", "Proto", "Len", "Info");
    TPRINT(" %-11s  %-21s  %-21s  %5s  %5s  %s\n",
           "-----------", "---------------------",
           "---------------------", "-----", "-----", "----");

    if (count == 0) {
        TPRINT("  (no packets captured — requires root or CAP_NET_RAW)\n");
        return;
    }

    /* when live (not paused) always follow newest */
    int sel = s->pkt_paused ? s->pkt_sel : count - 1;

    /* viewport centred on sel */
    int top = sel - page / 2;
    if (top + page > count) top = count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > count) end = count;

    for (int row = top; row < end; row++) {
        int                  idx = (start + row) % MAX_PACKETS;
        const packet_info_t *p   = &s->packets[idx];

        char src[48], dst[48];
        if (p->src_port) snprintf(src, sizeof(src), "%s:%u", p->src, p->src_port);
        else             snprintf(src, sizeof(src), "%s",    p->src);
        if (p->dst_port) snprintf(dst, sizeof(dst), "%s:%u", p->dst, p->dst_port);
        else             snprintf(dst, sizeof(dst), "%s",    p->dst);

#ifdef WITH_NCURSES
        if (row == sel) attron(A_REVERSE);
        TPRINT(" %04u.%06u  %-21.21s  %-21.21s  %5d  %5u  %.40s\n",
               (unsigned)(p->ts_sec % 10000), (unsigned)p->ts_usec,
               src, dst, p->proto, (unsigned)p->len, p->info);
        if (row == sel) attroff(A_REVERSE);
#else
        TPRINT("%c%04u.%06u  %-21.21s  %-21.21s  %5d  %5u  %.40s\n",
               (row == sel && s->pkt_paused) ? '>' : ' ',
               (unsigned)(p->ts_sec % 10000), (unsigned)p->ts_usec,
               src, dst, p->proto, (unsigned)p->len, p->info);
#endif
    }
#endif /* WITH_PCAP */
}

/* ── Key handler ────────────────────────────────────────── */

void view_packets_key(ntop_state_t *s, int key) {
    int count, start;
    ring_range(s, &count, &start);
    (void)start;

    switch (key) {
    case 'p': case 'P': case ' ':
        s->pkt_paused = !s->pkt_paused;
        /* jump selection to newest on either transition */
        s->pkt_sel = count > 0 ? count - 1 : 0;
        break;
    case NTOP_KEY_UP:
        if (s->pkt_paused && s->pkt_sel > 0) s->pkt_sel--;
        break;
    case NTOP_KEY_DOWN:
        if (s->pkt_paused && count > 0 && s->pkt_sel < count - 1) s->pkt_sel++;
        break;
    default:
        break;
    }
}
