#include <stdio.h>
#include <string.h>
#include "sloth.h"
#include "tui.h"
#include "capture/capture.h"
#include "dns.h"
#include "services.h"
#include "views/packets.h"
#include "pcap_write.h"

#define PKTS_PAGE 30

static void ring_range(const sloth_state_t *s, int *count, int *start) {
    *count = (s->pkt_count < MAX_PACKETS) ? s->pkt_count : MAX_PACKETS;
    *start = (s->pkt_count < MAX_PACKETS) ? 0            : s->pkt_head;
}

#ifdef WITH_PCAP
/* ── Detail panel ───────────────────────────────────────── */

static void draw_detail(const sloth_state_t *s) {
    int count, start;
    ring_range(s, &count, &start);
    int sel = (count > 0) ? s->pkt_sel : 0;
    int idx = (start + sel) % MAX_PACKETS;
    const packet_info_t *p = &s->packets[idx];

    char src[64], dst[64];
    if (p->src_port) {
        if (s->dns_enabled) dns_fmt_addr(p->src, p->src_port, src, sizeof(src));
        else svc_fmt_addr(src, sizeof(src), p->src, p->src_port);
    } else {
        snprintf(src, sizeof(src), "%s", s->dns_enabled ? dns_lookup(p->src) : p->src);
    }
    if (p->dst_port) {
        if (s->dns_enabled) dns_fmt_addr(p->dst, p->dst_port, dst, sizeof(dst));
        else svc_fmt_addr(dst, sizeof(dst), p->dst, p->dst_port);
    } else {
        snprintf(dst, sizeof(dst), "%s", s->dns_enabled ? dns_lookup(p->dst) : p->dst);
    }

    tui_dim(); TPRINT(" \xe2\x94\x80\xe2\x94\x80 PACKET DETAIL \xe2\x94\x80\xe2\x94\x80\n");

    tui_dim();   TPRINT("  Time:     "); tui_bright(); TPRINT("%04u.%06u\n",
                 (unsigned)(p->ts_sec % 10000), (unsigned)p->ts_usec);
    tui_dim();   TPRINT("  Source:   "); tui_bright(); TPRINT("%s\n", src);
    tui_dim();   TPRINT("  Dest:     "); tui_bright(); TPRINT("%s\n", dst);
    tui_dim();   TPRINT("  Protocol: "); tui_bright(); TPRINT("%d\n", p->proto);
    tui_dim();   TPRINT("  Length:   "); tui_bright(); TPRINT("%u\n", (unsigned)p->len);
    tui_dim();   TPRINT("  Info:     "); tui_bright(); TPRINT("%s\n", p->info);

    tui_dim(); TPRINT(" \xe2\x94\x80\xe2\x94\x80 HEX DUMP (%u bytes) \xe2\x94\x80\xe2\x94\x80\n",
                      (unsigned)p->raw_len);

    if (p->raw_len == 0) {
        tui_dim(); TPRINT("  (no raw bytes \xe2\x80\x94 build with WITH_PCAP=1)\n");
    } else {
        int total = (int)p->raw_len;
        for (int off = 0; off < total; off += 16) {
            tui_dim(); TPRINT("  %04x  ", (unsigned)off);
            int line = total - off;
            if (line > 16) line = 16;
            /* hex bytes — two groups of 8 */
            for (int b = 0; b < 16; b++) {
                if (b == 8) TPRINT(" ");
                if (b < line) { tui_normal(); TPRINT("%02x ", (unsigned)p->raw[off + b]); }
                else          { tui_dim();    TPRINT("   "); }
            }
            TPRINT(" ");
            /* ASCII */
            for (int b = 0; b < line; b++) {
                unsigned char c = p->raw[off + b];
                if (c >= 32 && c < 127) { tui_bright(); TPRINT("%c", (int)c); }
                else                    { tui_dim();    TPRINT("."); }
            }
            TPRINT("\n");
        }
    }

    tui_dim(); TPRINT(" [Enter/Esc] back to packet list\n");
    tui_normal();
}

#endif /* WITH_PCAP */

/* ── Draw ───────────────────────────────────────────────── */

void view_packets_draw(const sloth_state_t *s) {
#ifndef WITH_PCAP
    (void)s;
    tui_dim(); TPRINT("  Packet capture disabled (build with WITH_PCAP=1)\n");
    tui_normal(); return;
#else
    if (s->pkt_detail) { draw_detail(s); return; }

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
    if (s->pkt_iface[0]) {
        tui_dim();    TPRINT("  iface: ");
        tui_bright(); TPRINT("%s", s->pkt_iface);
    }
    /* show associated WiFi network if known */
#ifdef WITH_WIFI
    for (int i = 0; i < s->ap_count; i++) {
        if (s->aps[i].status == WIFI_STATUS_ASSOC && s->aps[i].ssid[0]) {
            tui_dim();    TPRINT("  WiFi: ");
            tui_bright(); TPRINT("%.24s", s->aps[i].ssid);
            break;
        }
    }
#endif
    if (s->pkt_paused) { tui_bright(); TPRINT("  [PAUSED]"); }
    if (s->pkt_filter[0]) {
        tui_dim(); TPRINT("  filter: ");
        tui_bright(); TPRINT("%s", s->pkt_filter);
    }
    if (s->pkt_filter_err[0]) {
        tui_dim(); TPRINT("  [ERR: %s]", s->pkt_filter_err);
    }
    if (s->pkt_export_msg[0]) {
        tui_dim(); TPRINT("  %s", s->pkt_export_msg);
    }
    tui_dim(); TPRINT("  [n] ");
    tui_bright(); TPRINT("%s", s->dns_enabled ? "names" : "numeric");
#ifndef WITH_NCURSES
    tui_dim(); TPRINT("  [p]ause  [/] filter  [x] clear  [w] save  [up/dn] navigate");
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

        char src[64], dst[64];
        if (p->src_port) {
            if (s->dns_enabled) dns_fmt_addr(p->src, p->src_port, src, sizeof(src));
            else svc_fmt_addr(src, sizeof(src), p->src, p->src_port);
        } else {
            snprintf(src, sizeof(src), "%s", s->dns_enabled ? dns_lookup(p->src) : p->src);
        }
        if (p->dst_port) {
            if (s->dns_enabled) dns_fmt_addr(p->dst, p->dst_port, dst, sizeof(dst));
            else svc_fmt_addr(dst, sizeof(dst), p->dst, p->dst_port);
        } else {
            snprintf(dst, sizeof(dst), "%s", s->dns_enabled ? dns_lookup(p->dst) : p->dst);
        }

#ifdef WITH_NCURSES
        if (row == sel) {
            tui_sel();
        } else {
            tui_pkt_bg(p->proto);
        }
        printw(" %04u.%06u  %-21.21s  %-21.21s  %5d  %5u  %.40s\n",
               (unsigned)(p->ts_sec % 10000), (unsigned)p->ts_usec,
               src, dst, p->proto, (unsigned)p->len, p->info);
        if (row == sel) tui_reset();
        else            tui_normal();
#else
        if (row == sel) tui_sel();
        else            tui_normal();
        printf(" %04u.%06u  %-21.21s  %-21.21s  %5d  %5u  %.40s\n",
               (unsigned)(p->ts_sec % 10000), (unsigned)p->ts_usec,
               src, dst, p->proto, (unsigned)p->len, p->info);
        if (row == sel) tui_reset();
#endif
    }
    tui_normal();
#endif /* WITH_PCAP */
}

/* ── Key handler ────────────────────────────────────────── */

void view_packets_key(sloth_state_t *s, int key) {
    if (s->pkt_detail) {
        if (key == '\r' || key == '\n' || key == '\033')
            s->pkt_detail = 0;
        /* all other keys consumed — do nothing */
        return;
    }

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
        } else if (key == SLOTH_KEY_BACKSPACE) {
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
    case '\r': case '\n':
        if (s->pkt_paused && count > 0) s->pkt_detail = 1;
        break;
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
    case SLOTH_KEY_UP:
        if (s->pkt_paused && s->pkt_sel > 0) s->pkt_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->pkt_paused && count > 0 && s->pkt_sel < count - 1) s->pkt_sel++;
        break;
    case 'w': case 'W': {
        char path[128] = "";
        int n = pcap_export(s, path, sizeof(path));
        if (n < 0)
            snprintf(s->pkt_export_msg, sizeof(s->pkt_export_msg),
                     "export failed");
        else
            snprintf(s->pkt_export_msg, sizeof(s->pkt_export_msg),
                     "saved %d pkts -> %.50s", n, path);
        break;
    }
    default:
        break;
    }
}
