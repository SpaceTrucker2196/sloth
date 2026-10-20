#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include "alert_pcap.h"
#include "sloth_clock.h"
#include "fs_capacity.h"
#include "pcap_format.h"
#include "tune.h"
#include "secure_file.h"
#include "evidence_manifest.h"

/* pcap-on-alert: when a rule fires with a concrete match_ip (and optional
 * match_port), dump every packet currently in the s->packets[] ring whose
 * src or dst matches, into a fresh per-alert pcap file. */

/* The header's snaplen is a claim about every record in the file; it
 * is only true while the ring entry it is read from is exactly that
 * size. Fails to compile the day packet_info_t.raw changes, rather than
 * shipping a file that lies again. */
typedef char alert_pcap_raw_is_snaplen[
    sizeof(((packet_info_t *)0)->raw) == PCAP_SNAPLEN_WIRED_RING ? 1 : -1];

/* g_dirfd pins the directory validated at set time (#87); files are
 * created relative to it. g_dir is kept to build the reported path. */
static char         g_dir[256];
static int          g_dirfd = -1;
static sfile_fail_t g_fail;

int alert_pcap_set_dir(const char *dir) {
    if (g_dirfd >= 0) { close(g_dirfd); g_dirfd = -1; }
    g_dir[0] = '\0';
    sfile_fail_reset(&g_fail);
    if (!dir || !dir[0]) return 0;
    int fd = sfile_private_dir(dir, g_fail.last, sizeof(g_fail.last));
    if (fd < 0) return -1;
    g_dirfd = fd;
    snprintf(g_dir, sizeof(g_dir), "%s", dir);
    return 0;
}

int alert_pcap_failures(void) { return g_fail.failures; }
const char *alert_pcap_error(void) { return g_fail.last; }

int alert_pcap_enabled(void) {
    return g_dir[0] != '\0';
}

int alert_pcap_capacity(fs_capacity_t *out) {
    if (!out) return -1;
    if (!alert_pcap_enabled()) { memset(out, 0, sizeof(*out)); return -1; }
    return fs_capacity_probe(g_dirfd, out);
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

    char stem[64], name[80], err[SFILE_ERR_MAX];
    time_t now = sloth_wall();
    /* localtime_r, as pcap_write.c already does: the capture thread and
     * the UI both stamp times, and localtime()'s shared static struct
     * tm is the aliasing hazard behind #95 (CWE-663). */
    struct tm tmv;
    struct tm *t = localtime_r(&now, &tmv);
    snprintf(stem, sizeof(stem),
             "alert_%04d%02d%02d_%02d%02d%02d_%s",
             t ? t->tm_year + 1900 : 1970,
             t ? t->tm_mon + 1     : 1,
             t ? t->tm_mday        : 1,
             t ? t->tm_hour        : 0,
             t ? t->tm_min         : 0,
             t ? t->tm_sec         : 0,
             slug);

    /* Refuse before creating, when the operator has set a floor (#96).
     *
     * This sink is the one with no cap and no sweep, so it is the one
     * that fills a filesystem — and it fills it with INODES first. The
     * floors default to 0 (off), so this is a no-op unless asked for;
     * when it does refuse, it goes through the same sfile_fail counter
     * every other write failure here uses, which means the operator
     * sees it in `storage_failures` and on the `!persist` badge without
     * any new reporting path.
     *
     * Checked per dump rather than cached: the point is the margin at
     * the moment of writing, and a cached figure is exactly what makes
     * a full disk look like a healthy one. fstatvfs on a held
     * descriptor is cheap and this path already does file IO. */
    const uint64_t min_bytes = (uint64_t)tune_val(TUNE_STORAGE_MIN_FREE_MB)
                               * 1024u * 1024u;
    const uint64_t min_files = (uint64_t)tune_val(TUNE_STORAGE_MIN_FREE_INODES);
    const int      min_pct   = (int)tune_val(TUNE_STORAGE_MIN_FREE_PCT);
    if (min_bytes || min_files || min_pct) {
        fs_capacity_t cap;
        char why[SFILE_ERR_MAX];
        if (fs_capacity_probe(g_dirfd, &cap) == 0 &&
            fs_capacity_blocked(&cap, min_bytes, min_files, min_pct,
                                why, sizeof(why))) {
            sfile_fail(&g_fail, "alert pcap", why);
            return -1;
        }
        /* A failed probe is deliberately NOT a refusal. fstatvfs can
         * fail on an exotic or unmounting filesystem, and turning
         * "cannot measure" into "do not record" would lose evidence
         * over a diagnostic. The write below then fails on its own
         * terms if there is really no room, and that failure is
         * already counted. */
    }

    /* Exclusive create: each dump is a new artifact. Two dumps for one
     * alert in the same second used to share a name and overwrite; a
     * suffix keeps both, and nothing already at the name is followed
     * or reused. */
    FILE *f = sfile_fopen_unique(g_dirfd, stem, ".pcap", name, sizeof(name),
                                 err, sizeof(err));
    if (!f) { sfile_fail(&g_fail, "alert pcap", err); return -1; }

    /* snaplen 64, not 65535: the ring holds at most 64 bytes of each
     * packet, and a reader takes the header at its word (#145). */
    pcap_fmt_put_file_hdr(f, pcap_fmt_dlt_or_default(s->pkt_linktype),
                          PCAP_SNAPLEN_WIRED_RING);

    int start = (s->pkt_count < MAX_PACKETS) ? 0 : s->pkt_head;
    int written = 0;
    for (int i = 0; i < s->pkt_count; i++) {
        int slot = (start + i) % MAX_PACKETS;
        const packet_info_t *p = &s->packets[slot];
        if (p->raw_len == 0) continue;
        if (!packet_matches(p, a))     continue;

        /* incl_len is what the ring stored, orig_len what was on the
         * wire; the clamp is the snaplen above, so no record can claim
         * more bytes than follow it or more than the header allows. */
        uint32_t incl = p->raw_len;
        if (incl > PCAP_SNAPLEN_WIRED_RING) incl = PCAP_SNAPLEN_WIRED_RING;
        pcap_fmt_put_rec(f, p->ts_sec, p->ts_usec, p->raw, incl,
                         p->len ? (uint32_t)p->len : incl);
        written++;
    }
    if (sfile_fclose(f, name, err, sizeof(err)) != 0) {
        unlinkat(g_dirfd, name, 0);     /* no truncated pcap left behind */
        sfile_fail(&g_fail, "alert pcap", err);
        return -1;
    }

    if (written == 0) {
        /* Empty pcap is noise — remove it. */
        unlinkat(g_dirfd, name, 0);
        return 0;
    }

    /* One manifest line per committed file (#92 slice 3). After the
     * empty-file unlink above, so a file that does not exist is never
     * listed, and after the close, so the hash is of the final bytes.
     * A failure is counted here like any other write failure of this
     * sink, and does not undo the pcap: the evidence is on disk either
     * way, and the manifest is the record of it, not a condition. */
    {
        char rule[48];
        const char *tn = alert_type_name(a->type);
        static const char pfx[] = "ALERT_TYPE_";
        if (tn && strncmp(tn, pfx, sizeof(pfx) - 1) == 0) tn += sizeof(pfx) - 1;
        snprintf(rule, sizeof(rule), "%s", tn ? tn : "");
        evm_meta_t m = { EVM_SINK_ALERT_PCAP, a->incident_id, rule };
        if (evidence_manifest_record(g_dirfd, name, &m, err, sizeof(err)) != 0)
            sfile_fail(&g_fail, "alert pcap manifest", err);
    }

    if (out_path && out_sz > 0) {
        /* A path that does not fit is reported as the bare name, which
         * is still true relative to --pcap-dir; a truncated path would
         * name a file that does not exist (alert_t.pcap_path). */
        int pn = snprintf(out_path, (size_t)out_sz, "%s/%s", g_dir, name);
        if (pn < 0 || pn >= out_sz)
            snprintf(out_path, (size_t)out_sz, "%s", name);
    }
    return written;
}
