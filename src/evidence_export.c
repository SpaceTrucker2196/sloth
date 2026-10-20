#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "evidence_export.h"
#include "evidence_ring.h"
#include "eapol_log.h"
#include "pcap_format.h"
#include "secure_file.h"

/* The savefile layout lives in src/pcap_format.h, shared with the three
 * other sinks that write one. This file used to carry its own copy and
 * write it in NATIVE byte order, which is valid pcap — libpcap reads
 * the magic to decide endianness — but meant sloth emitted two
 * different encodings depending on which sink wrote the file. The
 * shared writer is little-endian everywhere, so an evidence export now
 * hashes the same on any host that recorded it. */

/* Test seam (header). One armed fault at a time; the alert engine and
 * this file run on the poll thread, so it needs no lock. */
static evx_fault_t g_fault;
static int         g_fault_nth;
static int         g_write_calls;

void evidence_export_test_fault(evx_fault_t where, int nth) {
    g_fault       = where;
    g_fault_nth   = nth < 1 ? 1 : nth;
    g_write_calls = 0;
}

/* True once, at the armed point. */
static int fault_hit(evx_fault_t where) {
    if (g_fault != where) return 0;
    if (where == EVX_FAULT_WRITE && ++g_write_calls < g_fault_nth) return 0;
    g_fault = EVX_FAULT_NONE;
    return 1;
}

/* write(2) until done or it genuinely fails. A short write on a regular
 * file is legal and is not an error; treating one as failure would
 * discard a good export under memory pressure. */
static int write_all(int fd, const uint8_t *buf, size_t n) {
    if (fault_hit(EVX_FAULT_WRITE)) return -1;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) return -1;
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

int evidence_export_enabled(void) { return eapol_export_ready(); }

int evidence_export_path(const char *name, char *out, size_t outsz) {
    return eapol_export_path(name, out, outsz);
}

int evidence_export_alert_name(const char *incident_id, uint64_t event_id,
                               const char *rule, char *out, size_t outsz) {
    if (!out || !outsz) return -1;
    out[0] = '\0';
    if (!incident_id || !incident_id[0] || event_id == 0 || !rule || !rule[0])
        return -1;
    for (const char *c = incident_id; *c; c++)
        if (!isxdigit((unsigned char)*c) || isupper((unsigned char)*c))
            return -1;
    /* The kind name is generated from sloth_alerts.def and is already
     * [A-Z0-9_]; reduced anyway, because this string becomes a file
     * name and that is not a property the .def promises. */
    char slug[48];
    size_t k = 0;
    for (; rule[k] && k + 1 < sizeof(slug); k++) {
        unsigned char c = (unsigned char)rule[k];
        slug[k] = (isalnum(c) || c == '_') ? (char)c : '_';
    }
    slug[k] = '\0';
    int n = snprintf(out, outsz, "%s-%llu-%s.pcap", incident_id,
                     (unsigned long long)event_id, slug);
    if (n <= 0 || (size_t)n >= outsz) { out[0] = '\0'; return -1; }
    return 0;
}

/* Every failure after the temp exists ends here: report, close if still
 * open, unlink the temp. `why` NULL keeps a reason already in err. */
static int fail_tmp(int fd, const char *tmp, const char *why,
                    char *err, size_t errsz) {
    if (err && errsz && why) snprintf(err, errsz, "%s", why);
    if (fd >= 0) close(fd);
    eapol_export_discard(tmp);
    eapol_export_note_failure("evidence",
                              why ? why : (err && errsz ? err : "failed"));
    return -1;
}

/* The kth candidate for `name`: k == 1 is the name itself, then
 * "<stem>-<k><ext>" with the extension split at the last '.'. A '-'
 * rather than alert_pcap's '_' because the alert-name rule slug is
 * already [A-Za-z0-9_], so "_2" would read as part of the kind
 * (DEAUTH_FLOOD_2) while "-2" cannot. */
static int candidate_name(const char *name, int k, char *out, size_t outsz) {
    int n;
    if (k == 1) {
        n = snprintf(out, outsz, "%s", name);
    } else {
        const char *dot = strrchr(name, '.');
        if (!dot || dot == name) dot = name + strlen(name);
        n = snprintf(out, outsz, "%.*s-%d%s",
                     (int)(dot - name), name, k, dot);
    }
    return (n > 0 && (size_t)n < outsz) ? 0 : -1;
}

static int export_impl(const char *name,
                       const uint64_t *ids, int n,
                       int *skipped, int unique,
                       char *name_out, size_t name_outsz,
                       char *err, size_t errsz) {
    if (name_out && name_outsz) name_out[0] = '\0';
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

    /* The temp is ".<name>.tmp" — the shape eapol_sweep() already
     * expires, so a crash mid-write cannot leave crackable bytes past
     * the retention window. A temp already at that name is our own,
     * left by such a crash (only sloth writes this 0700 directory), and
     * is cleared first so O_EXCL does not refuse every later attempt.
     * A '/' is refused here as well as by sfile_open(), because the
     * stale-temp discard runs before sfile_open() ever sees the name. */
    if (strchr(name, '/') != NULL) {
        if (err && errsz) snprintf(err, errsz, "not a bare file name");
        return -1;
    }
    char tmp[160];
    int tn = snprintf(tmp, sizeof(tmp), ".%s.tmp", name);
    if (tn <= 0 || (size_t)tn >= sizeof(tmp)) {
        if (err && errsz) snprintf(err, errsz, "name too long");
        return -1;
    }
    eapol_export_discard(tmp);
    char cerr[SFILE_ERR_MAX] = "";
    int fd = eapol_export_create(tmp, cerr, sizeof(cerr));
    if (fd < 0) {
        if (err && errsz) snprintf(err, errsz, "%s", cerr);
        /* A closed gate is the caller's question, not a failed write;
         * only a refused create past the gate is counted. */
        if (eapol_export_ready()) eapol_export_note_failure("evidence", cerr);
        return -1;
    }

    uint8_t gh[PCAP_FILE_HDR_LEN];
    pcap_fmt_file_hdr(gh, PCAP_DLT_RADIOTAP, PCAP_SNAPLEN_LARGE);
    if (write_all(fd, gh, sizeof(gh)) != 0)
        return fail_tmp(fd, tmp, "write failed (header)", err, errsz);

    /* One heap buffer reused across records rather than a stack array
     * sized to the ring's maximum: the cap is a tuning constant that has
     * grown before, and a stack frame that tracks it is a trap waiting
     * for the next increase. */
    size_t cap = evidence_ring_capacity();
    if (cap == 0) cap = 4096;
    uint8_t *frame = fault_hit(EVX_FAULT_ALLOC) ? NULL : malloc(cap);
    if (!frame)
        return fail_tmp(fd, tmp, "out of memory", err, errsz);

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
            free(frame);
            return fail_tmp(fd, tmp, "write failed (record)", err, errsz);
        }
        written++;
    }
    free(frame);
    if (skipped) *skipped = missed;

    if (written == 0) {
        /* Every cited frame had aged out. Not a failure — there is
         * nothing to retry for — and not a file either. */
        close(fd);
        eapol_export_discard(tmp);
        return 0;
    }

    /* Durable before it is visible: a rename that reaches the disk
     * ahead of the data is exactly the truncated-under-the-final-name
     * file this ordering exists to rule out. */
    if (fault_hit(EVX_FAULT_FSYNC) || fsync(fd) != 0)
        return fail_tmp(fd, tmp, "fsync failed", err, errsz);
    if (close(fd) != 0) {
        /* A close failure can be the first report of a write that never
         * reached the filesystem, so it is an error rather than a
         * nicety — the same reason sfile_fclose() reports it. */
        return fail_tmp(-1, tmp, "close failed", err, errsz);
    }

    if (fault_hit(EVX_FAULT_COMMIT))
        return fail_tmp(-1, tmp, "commit failed (injected)", err, errsz);

    /* A taken name is not transient: nothing frees it, so the unique
     * variant moves on to "<stem>-2<ext>" and the plain one refuses.
     * Each candidate is checked and renamed under the EAPOL lock, so
     * the loop needs no lock of its own. */
    const int tries = unique ? EVX_UNIQUE_MAX : 1;
    char cand[sizeof(tmp)];
    for (int k = 1; k <= tries; k++) {
        if (candidate_name(name, k, cand, sizeof(cand)) != 0)
            return fail_tmp(-1, tmp, "name too long", err, errsz);
        int rc = eapol_export_commit(tmp, cand, err, errsz);
        if (rc == 0) {
            if (name_out && name_outsz)
                snprintf(name_out, name_outsz, "%s", cand);
            return written;
        }
        if (rc != EAPOL_COMMIT_EXISTS)
            return fail_tmp(-1, tmp, NULL, err, errsz);
    }
    if (!unique) return fail_tmp(-1, tmp, NULL, err, errsz);
    char why[SFILE_ERR_MAX];
    snprintf(why, sizeof(why), "%s: %d same-named files already exist",
             name, EVX_UNIQUE_MAX);
    fail_tmp(-1, tmp, why, err, errsz);
    return EVX_REFUSED;
}

int evidence_export_pcap(const char *name,
                         const uint64_t *ids, int n,
                         int *skipped,
                         char *err, size_t errsz) {
    return export_impl(name, ids, n, skipped, 0, NULL, 0, err, errsz);
}

int evidence_export_pcap_unique(const char *name,
                                const uint64_t *ids, int n,
                                int *skipped,
                                char *name_out, size_t name_outsz,
                                char *err, size_t errsz) {
    return export_impl(name, ids, n, skipped, 1, name_out, name_outsz,
                       err, errsz);
}
