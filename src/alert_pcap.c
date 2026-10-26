#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include "alert_pcap.h"
#include "sloth_clock.h"
#include "fs_capacity.h"
#include "pcap_format.h"
#include "tune.h"
#include "secure_file.h"
#include "evidence_manifest.h"
#include "eapol_log.h"

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

/* The age sweep (#166). g_sweep_d is open only while a pass has entries
 * left, which is what lets a pass span many poll ticks; g_sweep_start
 * == 0 means "never started", which makes the first maintain call the
 * startup pass. Kept apart from g_fail: that counter is write failures,
 * read by `storage_pcap_failures` and the !persist badge, and a sweep
 * that cannot delete has not lost any evidence. All of it is touched on
 * the main thread only — the alert engine's dump and the poll loop's
 * maintain both run there. */
static DIR               *g_sweep_d      = NULL;
static time_t             g_sweep_start  = 0;
static time_t             g_sweep_cutoff = 0;
static unsigned long long g_swept        = 0;
static sfile_fail_t       g_sweep_fail;
/* Both clocks as alert_pcap_set_dir() found them, for the stale-clock
 * guard in alert_pcap_sweep_step(). */
static time_t             g_set_wall     = 0;
static uint64_t           g_set_mono_ms  = 0;
static int                g_sweep_spare  = 0;

static void sweep_stop(void) {
    if (g_sweep_d) { closedir(g_sweep_d); g_sweep_d = NULL; }
}

int alert_pcap_set_dir(const char *dir) {
    sweep_stop();
    g_sweep_start = 0;                /* a new directory gets a startup pass */
    g_swept = 0;
    sfile_fail_reset(&g_sweep_fail);
    g_set_wall    = sloth_wall();
    g_set_mono_ms = sloth_mono_ms();
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
     * This sink is the one that fills a filesystem — and it fills it
     * with INODES first. The #166 age sweep bounds it over weeks; a
     * floor is what holds within one burst. The
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
         * more bytes than follow it or more than the header allows.
         * capture.c never stores more than 64, so the clamp only acts on
         * a corrupt raw_len; test_alert_pcap_clamps_a_corrupt_raw_len
         * seeds one to show it does. */
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
        /* "" for a kind outside the .def: the manifest then omits
         * `rule` rather than carry a placeholder (engine.c's evidence
         * sink follows the same rule). */
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

/* ── Age sweep (#166) ──────────────────────────────────────────────── */

#define ALERT_PCAP_SECS_PER_DAY 86400

static int all_digits(const char *p, int n) {
    for (int i = 0; i < n; i++)
        if (!isdigit((unsigned char)p[i])) return 0;
    return 1;
}

/* The exact shape alert_pcap_dump() produces: the stem snprintf above,
 * slugify()'s alphabet (which also covers sfile_fopen_unique()'s "_N"
 * suffix), and the 80-byte name buffer. Strict on purpose — the sweep
 * deletes sloth's artifacts, not the directory's contents, and a looser
 * "ends in .pcap" would take a capture the operator dropped in beside
 * them. The manifest is swept on the same window: its mtime is its
 * newest line, so it goes only once everything it lists could have. */
int alert_pcap_is_name(const char *name) {
    if (!name) return 0;
    if (evidence_manifest_is_name(name)) return 1;
    static const char pfx[] = "alert_", ext[] = ".pcap";
    const size_t pn = sizeof(pfx) - 1, en = sizeof(ext) - 1;
    size_t n = strlen(name);
    /* prefix + 8 date digits + '_' + 6 time digits + '_' + ext */
    if (n < pn + 8 + 1 + 6 + 1 + en || n >= 80) return 0;
    if (strncmp(name, pfx, pn) != 0) return 0;
    const char *p = name + pn;
    if (!all_digits(p, 8) || p[8] != '_' ||
        !all_digits(p + 9, 6) || p[15] != '_')
        return 0;
    if (strcmp(name + n - en, ext) != 0) return 0;
    for (const char *c = p + 16; c < name + n - en; c++)
        if (!isalnum((unsigned char)*c) && *c != '_') return 0;
    return 1;
}

int alert_pcap_retain_days(void) {
    return (int)tune_val(TUNE_PCAP_RETAIN_DAYS);
}

/* Not sfile_fail(): its line says "export failed", which README and
 * retention.md use to mean lost evidence, and a sweep error loses
 * none. Same once-then-count shape, its own words. */
static void sweep_err(const char *msg) {
    g_sweep_fail.failures++;
    snprintf(g_sweep_fail.last, sizeof(g_sweep_fail.last), "%s",
             msg ? msg : "?");
    if (!g_sweep_fail.reported) {
        fprintf(stderr, "sloth: --pcap-dir retention sweep: %s (further "
                        "sweep errors counted in "
                        "sensor_health.pcap_sweep_errors)\n",
                g_sweep_fail.last);
        g_sweep_fail.reported = 1;
    }
}

/* Open a new pass if one is due. 1 when a pass is now open. */
static int sweep_begin(time_t now, int days) {
    /* A clock stepped back past the last start would otherwise wait out
     * the whole interval; treat it as due, as eapol_maintain() does. */
    int due = g_sweep_start == 0 || now < g_sweep_start ||
              now - g_sweep_start >= ALERT_PCAP_SWEEP_INTERVAL_S;
    if (!due) return 0;
    /* Stamped before anything can fail: a directory that cannot be read
     * is retried next interval, not on every poll. */
    g_sweep_start = now;
    time_t window = (time_t)days * ALERT_PCAP_SECS_PER_DAY;
    if (now <= window) return 0;      /* nothing can predate epoch+window */
    /* One cutoff for the whole pass, so a pass spanning many ticks
     * applies one window rather than a sliding one. */
    g_sweep_cutoff = now - window;
    /* Stale-clock guard. Age is mtime against the wall clock, so a
     * sensor that started on a stale clock (no RTC, before NTP) stamps
     * its files in the past, and once NTP steps the clock forward they
     * look older than the window. Until this process has been up a
     * whole window by the monotonic clock, nothing it could have
     * written — any mtime at or after the wall time it started at — is
     * old enough to delete: on a clock that was right all along those
     * files are younger than the uptime, so this costs nothing. */
    g_sweep_spare = (sloth_mono_ms() - g_set_mono_ms) / 1000 <
                    (uint64_t)window;

    char err[SFILE_ERR_MAX];
    /* A duplicate, because closedir() closes the descriptor it is given
     * and g_dirfd must outlive the pass. */
    int dfd = fcntl(g_dirfd, F_DUPFD_CLOEXEC, 0);
    DIR *d  = dfd >= 0 ? fdopendir(dfd) : NULL;
    if (!d) {
        int e = errno;
        if (dfd >= 0) close(dfd);
        snprintf(err, sizeof(err), "%.200s: cannot read the directory: %s",
                 g_dir, strerror(e));
        sweep_err(err);
        return -1;
    }
    /* The duplicate shares its offset with g_dirfd; start at the top. */
    rewinddir(d);
    g_sweep_d = d;
    return 1;
}

int alert_pcap_sweep_step(int budget) {
    const int days = alert_pcap_retain_days();
    if (g_dirfd < 0 || days <= 0 || budget <= 0) {
        /* 0 can only come from startup --tune, but a pass left open by
         * a window that then closed must not go on deleting. */
        if (days <= 0) sweep_stop();
        return 0;
    }
    if (!g_sweep_d) {
        int b = sweep_begin(sloth_wall(), days);
        if (b <= 0) return b;
    }

    char err[SFILE_ERR_MAX];
    int removed = 0;
    for (int seen = 0; seen < budget; seen++) {
        errno = 0;
        struct dirent *e = readdir(g_sweep_d);
        if (!e) {
            if (errno) {
                snprintf(err, sizeof(err), "%.200s: readdir failed: %s",
                         g_dir, strerror(errno));
                sweep_err(err);
            }
            sweep_stop();             /* pass complete (or abandoned) */
            break;
        }
        if (!alert_pcap_is_name(e->d_name)) continue;
        struct stat st;
        if (fstatat(g_dirfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) continue;      /* raced away; fine */
            snprintf(err, sizeof(err), "%.100s: cannot stat: %s",
                     e->d_name, strerror(errno));
            sweep_err(err);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            /* A symlink, directory or FIFO at an artifact name is not
             * something sloth wrote. Left exactly as it is, whatever its
             * age — an mtime read off a planted link proves nothing — and
             * counted, because in a 0700 directory only sloth writes it
             * is operator error or someone steering the sweep. */
            snprintf(err, sizeof(err),
                     "%.100s: not a regular file - left in place, nothing "
                     "was followed", e->d_name);
            sweep_err(err);
            continue;
        }
        if (st.st_mtime >= g_sweep_cutoff) continue;
        if (g_sweep_spare && st.st_mtime >= g_set_wall) continue;
        /* unlinkat() removes the name, never what it points to, so an
         * entry swapped for a symlink between the stat and here costs
         * the link, not its target. */
        if (unlinkat(g_dirfd, e->d_name, 0) != 0) {
            if (errno == ENOENT) continue;
            snprintf(err, sizeof(err),
                     "%.100s: could not delete past the %d-day window: %s",
                     e->d_name, days, strerror(errno));
            sweep_err(err);
            continue;
        }
        removed++;
    }
    g_swept += (unsigned long long)removed;
    return removed;
}

int alert_pcap_maintain(void) {
    return alert_pcap_sweep_step(ALERT_PCAP_SWEEP_BUDGET);
}

int alert_pcap_shares_eapol_dir(void) {
    struct stat a, b;
    if (g_dirfd < 0 || fstat(g_dirfd, &a) != 0) return 0;
    if (eapol_export_dir_stat(&b) != 0) return 0;
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

int alert_pcap_sweep_in_progress(void) { return g_sweep_d != NULL; }
unsigned long long alert_pcap_swept(void) { return g_swept; }
int alert_pcap_sweep_errors(void) { return g_sweep_fail.failures; }
const char *alert_pcap_sweep_error(void) { return g_sweep_fail.last; }
