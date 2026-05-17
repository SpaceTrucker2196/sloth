#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "alert_pcap.h"

/* pcap-on-alert: when a rule fires with a concrete match_ip (and optional
 * match_port), dump every packet currently in the s->packets[] ring whose
 * src or dst matches, into a fresh per-alert pcap file. */

#define PCAP_MAGIC   0xa1b2c3d4u
#define PCAP_MAJOR   2
#define PCAP_MINOR   4
#define PCAP_SNAPLEN 65535

static char g_dir[256];

void alert_pcap_set_dir(const char *dir) {
    if (!dir || !dir[0]) { g_dir[0] = '\0'; return; }
    snprintf(g_dir, sizeof(g_dir), "%s", dir);
}

int alert_pcap_enabled(void) {
    return g_dir[0] != '\0';
}

static void write_u32le(FILE *f, uint32_t v) {
    uint8_t b[4] = { v & 0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff };
    fwrite(b, 1, 4, f);
}

static void write_u16le(FILE *f, uint16_t v) {
    uint8_t b[2] = { v & 0xff, (v>>8)&0xff };
    fwrite(b, 1, 2, f);
}

/* sanitize a title chunk for use in a filename: keep [A-Za-z0-9_], else '_'. */
static void slugify(const char *src, char *out, int sz) {
    int i = 0;
    for (; src[i] && i + 1 < sz; i++) {
        unsigned char c = (unsigned char)src[i];
        out[i] = (isalnum(c) || c == '_') ? (char)c : '_';
    }
    out[i] = '\0';
}

/* Match a packet against an alert's match criteria.
 *   - match_ip == src OR dst
 *   - match_port (if non-zero) == src_port OR dst_port */
static int packet_matches(const packet_info_t *p, const alert_t *a) {
    if (!a->match_ip[0]) return 0;
    int ip_ok = (strcmp(p->src, a->match_ip) == 0) ||
                (strcmp(p->dst, a->match_ip) == 0);
    if (!ip_ok) return 0;
    if (a->match_port != 0) {
        if (p->src_port != a->match_port && p->dst_port != a->match_port)
            return 0;
    }
    return 1;
}

int alert_pcap_dump(const sloth_state_t *s, const alert_t *a,
                    char *out_path, int out_sz) {
    if (!alert_pcap_enabled()) return 0;
    if (!s || !a) return -1;
    if (!a->match_ip[0]) return 0;

    char slug[24]; slugify(a->title, slug, sizeof(slug));

    char path[512];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(path, sizeof(path),
             "%s/alert_%04d%02d%02d_%02d%02d%02d_%s.pcap",
             g_dir,
             t ? t->tm_year + 1900 : 1970,
             t ? t->tm_mon + 1     : 1,
             t ? t->tm_mday        : 1,
             t ? t->tm_hour        : 0,
             t ? t->tm_min         : 0,
             t ? t->tm_sec         : 0,
             slug);

    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    int dlt = s->pkt_linktype ? s->pkt_linktype : 1; /* DLT_EN10MB default */
    write_u32le(f, PCAP_MAGIC);
    write_u16le(f, PCAP_MAJOR);
    write_u16le(f, PCAP_MINOR);
    write_u32le(f, 0);
    write_u32le(f, 0);
    write_u32le(f, PCAP_SNAPLEN);
    write_u32le(f, (uint32_t)dlt);

    int start = (s->pkt_count < MAX_PACKETS) ? 0 : s->pkt_head;
    int written = 0;
    for (int i = 0; i < s->pkt_count; i++) {
        int slot = (start + i) % MAX_PACKETS;
        const packet_info_t *p = &s->packets[slot];
        if (p->raw_len == 0) continue;
        if (!packet_matches(p, a))     continue;

        write_u32le(f, p->ts_sec);
        write_u32le(f, p->ts_usec);
        write_u32le(f, p->raw_len);
        write_u32le(f, p->len ? p->len : p->raw_len);
        fwrite(p->raw, 1, p->raw_len, f);
        written++;
    }
    fclose(f);

    if (written == 0) {
        /* Empty pcap is noise — remove it. */
        remove(path);
        return 0;
    }

    if (out_path && out_sz > 0)
        snprintf(out_path, (size_t)out_sz, "%s", path);
    return written;
}
