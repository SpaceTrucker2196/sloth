#include <stdio.h>
#include "ntop.h"
#include "tui.h"
#include "views/packets.h"

void view_packets_draw(const ntop_state_t *s) {
#ifndef WITH_PCAP
    (void)s;
    TPRINT("  Packet capture disabled (build with WITH_PCAP=1)\n");
    return;
#else
    if (s->pkt_count == 0) {
        TPRINT("  (no packets captured — requires root or CAP_NET_RAW)\n");
        return;
    }

    TPRINT("  %-11s  %-22s  %-22s  %-5s  %-5s  %s\n",
           "Time", "Source", "Dest", "Proto", "Len", "Info");
    TPRINT("  %-11s  %-22s  %-22s  %-5s  %-5s  %s\n",
           "-----------", "----------------------",
           "----------------------", "-----", "-----", "----");

    /* ring buffer: oldest entry is at pkt_head when buffer is full */
    int count = (s->pkt_count < MAX_PACKETS) ? s->pkt_count : MAX_PACKETS;
    int start = (s->pkt_count < MAX_PACKETS) ? 0 : s->pkt_head;

    for (int i = 0; i < count; i++) {
        int idx = (start + i) % MAX_PACKETS;
        const packet_info_t *p = &s->packets[idx];
        char src[48], dst[48];
        snprintf(src, sizeof(src), "%s:%u", p->src, p->src_port);
        snprintf(dst, sizeof(dst), "%s:%u", p->dst, p->dst_port);
        TPRINT("  %04u.%06u  %-22s  %-22s  %-5d  %-5u  %s\n",
               (unsigned)(p->ts_sec % 10000), (unsigned)p->ts_usec,
               src, dst, p->proto, (unsigned)p->len, p->info);
    }
#endif /* WITH_PCAP */
}
