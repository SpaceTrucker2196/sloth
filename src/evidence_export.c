#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "evidence_export.h"
#include "evidence_ring.h"
#include "eapol_log.h"
#include "pcap_format.h"

/* The savefile layout lives in src/pcap_format.h, shared with the three
 * other sinks that write one. This file used to carry its own copy and
 * write it in NATIVE byte order, which is valid pcap — libpcap reads
 * the magic to decide endianness — but meant sloth emitted two
 * different encodings depending on which sink wrote the file. The
 * shared writer is little-endian everywhere, so an evidence export now
 * hashes the same on any host that recorded it. */

/* write(2) until done or it genuinely fails. A short write on a regular
 * file is legal and is not an error; treating one as failure would
 * discard a good export under memory pressure. */
static int write_all(int fd, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) return -1;
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

int evidence_export_pcap(const char *name,
                         const uint64_t *ids, int n,
                         int *skipped,
                         char *err, size_t errsz) {
    if (skipped) *skipped = 0;
    if (!name || !*name || !ids || n <= 0) {
        if (err && errsz) snprintf(err, errsz, "bad arguments");
        return -1;
    }

    /* The gate is checked here only to produce a useful message. The
     * authoritative check is inside eapol_export_create(), under that
     * module's lock and at the last moment before a file exists, so a
     * gate that closes between these two points still refuses. Checking
     * twice is not redundancy — it is the difference between a clear
     * error and a confusing one. */
    if (!eapol_collect_enabled()) {
        if (err && errsz)
            snprintf(err, errsz,
                     "refused: raw 802.11 frames carry EAPOL/PMKID "
                     "material, so export needs --collect-handshakes");
        return -1;
    }

    int fd = eapol_export_create(name, err, errsz);
    if (fd < 0) return -1;

    uint8_t gh[PCAP_FILE_HDR_LEN];
    pcap_fmt_file_hdr(gh, PCAP_DLT_RADIOTAP, PCAP_SNAPLEN_LARGE);
    if (write_all(fd, gh, sizeof(gh)) != 0) {
        if (err && errsz) snprintf(err, errsz, "write failed (header)");
        close(fd);
        return -1;
    }

    /* One heap buffer reused across records rather than a stack array
     * sized to the ring's maximum: the cap is a tuning constant that has
     * grown before, and a stack frame that tracks it is a trap waiting
     * for the next increase. */
    size_t cap = evidence_ring_capacity();
    if (cap == 0) cap = 4096;
    uint8_t *frame = malloc(cap);
    if (!frame) {
        if (err && errsz) snprintf(err, errsz, "out of memory");
        close(fd);
        return -1;
    }

    int written = 0, missed = 0;
    for (int i = 0; i < n; i++) {
        evidence_rec_t rec;
        int got = evidence_ring_get(ids[i], &rec, frame, cap);
        if (got < 0) { missed++; continue; }   /* evicted or never issued */

        /* got is what the ring copied. It can be short of rec.cap_len if
         * the buffer could not hold the frame; write what is really in
         * hand and let caplen say so, because a record claiming more
         * bytes than follow it corrupts every record after it. */
        uint8_t rh[PCAP_REC_HDR_LEN];
        pcap_fmt_rec_hdr(rh, (uint32_t)rec.ts_sec, (uint32_t)rec.ts_usec,
                         (uint32_t)got, rec.orig_len);
        if (write_all(fd, rh, sizeof(rh)) != 0 ||
            write_all(fd, frame, (size_t)got) != 0) {
            if (err && errsz) snprintf(err, errsz, "write failed (record)");
            free(frame);
            close(fd);
            return -1;
        }
        written++;
    }

    free(frame);
    if (close(fd) != 0) {
        /* A close failure can be the first report of a write that never
         * reached the filesystem, so it is an error rather than a
         * nicety — the same reason sfile_fclose() reports it. */
        if (err && errsz) snprintf(err, errsz, "close failed");
        return -1;
    }
    if (skipped) *skipped = missed;
    return written;
}
