#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "pcap_write.h"

/* pcap global header */
#define PCAP_MAGIC   0xa1b2c3d4u
#define PCAP_MAJOR   2
#define PCAP_MINOR   4
#define PCAP_SNAPLEN 65535

static void write_u32le(FILE *f, uint32_t v) {
    uint8_t b[4] = { v & 0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff };
    fwrite(b, 1, 4, f);
}

static void write_u16le(FILE *f, uint16_t v) {
    uint8_t b[2] = { v & 0xff, (v>>8)&0xff };
    fwrite(b, 1, 2, f);
}

int pcap_export(const sloth_state_t *s, char *path_out, int path_sz) {
    char path[128];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(path, sizeof(path),
             "ntop_%04d%02d%02d_%02d%02d%02d.pcap",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour,        t->tm_min,      t->tm_sec);

    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    /* global header */
    int dlt = s->pkt_linktype ? s->pkt_linktype : 1; /* default DLT_EN10MB */
    write_u32le(f, PCAP_MAGIC);
    write_u16le(f, PCAP_MAJOR);
    write_u16le(f, PCAP_MINOR);
    write_u32le(f, 0);           /* thiszone: UTC */
    write_u32le(f, 0);           /* sigfigs */
    write_u32le(f, PCAP_SNAPLEN);
    write_u32le(f, (uint32_t)dlt);

    /* walk ring buffer oldest-first */
    int start = (s->pkt_count < MAX_PACKETS) ? 0
                                              : s->pkt_head;
    int written = 0;
    for (int i = 0; i < s->pkt_count; i++) {
        int slot = (start + i) % MAX_PACKETS;
        const packet_info_t *p = &s->packets[slot];
        if (p->raw_len == 0) continue;

        uint16_t caplen = p->raw_len;
        write_u32le(f, p->ts_sec);
        write_u32le(f, p->ts_usec);
        write_u32le(f, caplen);
        write_u32le(f, p->len ? p->len : caplen);
        fwrite(p->raw, 1, caplen, f);
        written++;
    }

    fclose(f);

    if (path_out && path_sz > 0)
        snprintf(path_out, path_sz, "%s", path);

    return written;
}
