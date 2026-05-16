#include <stdio.h>
#include <string.h>
#include "ntop.h"
#include "tui.h"
#include "capture/capture.h"
#include "views/packets.h"

#define PKTS_PAGE 30

static void ring_range(const ntop_state_t *s, int *count, int *start) {
    *count = (s->pkt_count < MAX_PACKETS) ? s->pkt_count : MAX_PACKETS;
    *start = (s->pkt_count < MAX_PACKETS) ? 0            : s->pkt_head;
}

#ifdef WITH_PCAP
/* Phosphor intensity by IP protocol number. */
static void phos_proto(int proto) {
    switch (proto) {
    case 1:  /* ICMP   */
    case 58: /* ICMPv6 */
        tui_bright(); break;
    case 6:  /* TCP */
    case 17: /* UDP */
        tui_normal(); break;
    case 0:  /* ARP / unknown ethertype */
    default:
        tui_dim(); break;
    }
}
#endif /* WITH_PCAP */

/* ── Draw ───────────────────────────────────────────────── */

void view_packets_draw(const ntop_state_t *s) {
#ifndef WITH_PCAP
    (void)s;
    tui_dim(); TPRINT("  Packet capture disabled (build with WITH_PCAP=1)\n");
    tui_normal(); return;
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
    tui_normal(); TPRINT(" Packets: ");
    tui_bright();  TPRINT("%d", count);
    if (s->pkt_count > MAX_PACKETS) { tui_dim(); TPRINT(" (ring)"); }
    if (s->pkt_paused) { tui_bright(); TPRINT("  [PAUSED]"); }
    if (s->pkt_filter[0]) {
        tui_dim(); TPRINT("  filter: ");
        tui_bright(); TPRINT("%s", s->pkt_filter);
    }
    if (s->pkt_filter_err[0]) {
        tui_dim(); TPRINT("  [ERR: %s]", s->pkt_filter_err);
    }
#ifndef WITH_NCURSES
    tui_dim(); TPRINT("  [p]ause  [/] filter  [x] clear  [up/dn] navigate");
#endif
    TPRINT("\n");

    /* filter input prompt */
    if (s->pkt_filter_mode) {
        char buf[257];
        memcpy(buf, s->pkt_filter_buf, (size_t)s->pkt_filter_len);
        buf[s->pkt_filter_len] = '\0';
        tui_bright(); TPRINT(" Filter> %s_\n", buf); tui_normal();
    }

    /* column headers */
    tui_dim();
    TPRINT(" %-11s  %-21s  %-21s  %5s  %5s  %s\n",
           "Time", "Source", "Destination", "Proto", "Len", "Info");
    TPRINT(" %-11s  %-21s  %-21s  %5s  %5s  %s\n",
           "-----------", "---------------------",
           "---------------------", "-----", "-----", "----");
    tui_normal();

    if (count == 0) {
        tui_dim(); TPRINT("  (no packets captured — requires root or CAP_NET_RAW)\n");
        tui_normal(); return;
    }

    int sel = s->pkt_paused ? s->pkt_sel : count - 1;

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
        if (row == sel) {
            tui_sel();
            printw(" %04u.%06u  %-21.21s  %-21.21s  %5d  %5u  %.40s\n",
                   (unsigned)(p->ts_sec % 10000), (unsigned)p->ts_usec,
                   src, dst, p->proto, (unsigned)p->len, p->info);
            tui_reset();
        } else {
            tui_dim();
            printw(" %04u.%06u  ", (unsigned)(p->ts_sec % 10000), (unsigned)p->ts_usec);
            phos_proto(p->proto);
            printw("%-21.21s  %-21.21s  %5d  %5u  %.40s\n",
                   src, dst, p->proto, (unsigned)p->len, p->info);
            tui_normal();
        }
#else
        if (row == sel) {
            tui_sel();
            printf(" %04u.%06u  %-21.21s  %-21.21s  %5d  %5u  %.40s",
                   (unsigned)(p->ts_sec % 10000), (unsigned)p->ts_usec,
                   src, dst, p->proto, (unsigned)p->len, p->info);
            tui_reset(); printf("\n");
        } else {
            tui_dim();
            printf(" %04u.%06u  ", (unsigned)(p->ts_sec % 10000), (unsigned)p->ts_usec);
            phos_proto(p->proto);
            printf("%-21.21s  %-21.21s  %5d  %5u  %.40s\n",
                   src, dst, p->proto, (unsigned)p->len, p->info);
            tui_normal();
        }
#endif
    }
    tui_normal();
#endif /* WITH_PCAP */
}

/* ── Key handler ────────────────────────────────────────── */

void view_packets_key(ntop_state_t *s, int key) {
    if (s->pkt_filter_mode) {
        if (key == '\r' || key == '\n') {
            s->pkt_filter_buf[s->pkt_filter_len] = '\0';
            char err[128] = "";
            if (capture_set_filter(s->pkt_filter_buf, err, sizeof(err)) == 0) {
                memcpy(s->pkt_filter, s->pkt_filter_buf, sizeof(s->pkt_filter));
                s->pkt_filter_err[0] = '\0';
            } else {
                snprintf(s->pkt_filter_err, sizeof(s->pkt_filter_err), "%s", err);
            }
            s->pkt_filter_mode = 0;
        } else if (key == '\033') {
            s->pkt_filter_mode = 0;
            s->pkt_filter_err[0] = '\0';
        } else if (key == NTOP_KEY_BACKSPACE) {
            if (s->pkt_filter_len > 0) s->pkt_filter_len--;
        } else if (key >= 32 && key < 127) {
            if (s->pkt_filter_len < (int)sizeof(s->pkt_filter_buf) - 1)
                s->pkt_filter_buf[s->pkt_filter_len++] = (char)key;
        }
        return;
    }

    int count, start;
    ring_range(s, &count, &start);
    (void)start;

    switch (key) {
    case '/': case 'f': case 'F':
        s->pkt_filter_mode = 1;
        s->pkt_filter_len  = (int)strlen(s->pkt_filter);
        memcpy(s->pkt_filter_buf, s->pkt_filter, (size_t)s->pkt_filter_len + 1);
        break;
    case 'x': case 'X': {
        char err[128] = "";
        capture_set_filter("", err, sizeof(err));
        s->pkt_filter[0]     = '\0';
        s->pkt_filter_err[0] = '\0';
        break;
    }
    case 'p': case 'P': case ' ':
        s->pkt_paused = !s->pkt_paused;
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
