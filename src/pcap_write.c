#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include "pcap_write.h"
#include "sloth_clock.h"
#include "secure_file.h"
#include "pcap_format.h"

void pcap_export_stem(const struct tm *t, char *out, size_t sz) {
    if (!t) {
        /* Failing the clock must not cost the operator the capture: the
         * ring is the only copy of those packets. The epoch stem is
         * obviously wrong to a human reading the directory, and
         * sfile_fopen_unique() suffixes a repeat, so nothing collides. */
        snprintf(out, sz, "ntop_19700101_000000");
        return;
    }
    snprintf(out, sz,
             "ntop_%04d%02d%02d_%02d%02d%02d",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour,        t->tm_min,     t->tm_sec);
}

int pcap_export(const sloth_state_t *s, char *path_out, int path_sz) {
    char stem[64], path[96], err[SFILE_ERR_MAX];
    time_t now = sloth_wall();
    /* localtime_r: the shared static struct tm behind localtime() is the
     * aliasing hazard that mis-stamped the alert panel (#95), and its
     * result was dereferenced here unchecked. Both go away together. */
    struct tm tmv;
    pcap_export_stem(localtime_r(&now, &tmv), stem, sizeof(stem));

    /* Raw packets: exclusive-create 0600 in the working directory
     * (#87). Never follows or reuses whatever is already at the name;
     * a second export in the same second gets a suffix. */
    FILE *f = sfile_fopen_unique(AT_FDCWD, stem, ".pcap", path, sizeof(path),
                                 err, sizeof(err));
    if (!f) return -1;

    /* The same ring as the per-alert pcap, so the same 64-byte truth
     * (PCAP_SNAPLEN_WIRED_RING, #145). */
    pcap_fmt_put_file_hdr(f, pcap_fmt_dlt_or_default(s->pkt_linktype),
                          PCAP_SNAPLEN_WIRED_RING);

    /* walk ring buffer oldest-first */
    int start = (s->pkt_count < MAX_PACKETS) ? 0
                                              : s->pkt_head;
    int written = 0;
    for (int i = 0; i < s->pkt_count; i++) {
        int slot = (start + i) % MAX_PACKETS;
        const packet_info_t *p = &s->packets[slot];
        if (p->raw_len == 0) continue;

        pcap_fmt_put_rec(f, p->ts_sec, p->ts_usec,
                         p->raw, p->raw_len,
                         p->len ? (uint32_t)p->len : (uint32_t)p->raw_len);
        written++;
    }

    if (sfile_fclose(f, path, err, sizeof(err)) != 0) {
        unlink(path);          /* no truncated capture left behind */
        return -1;             /* the packets view shows "export failed" */
    }

    if (path_out && path_sz > 0)
        snprintf(path_out, path_sz, "%s", path);

    return written;
}
