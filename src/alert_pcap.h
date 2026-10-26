#ifndef ALERT_PCAP_H
#define ALERT_PCAP_H

#include "sloth.h"
#include "fs_capacity.h"

/* Configure the directory where per-alert pcap snapshots are written.
 *   - NULL or empty: disable export (alert_pcap_dump becomes a no-op).
 *   - Otherwise: created 0700 if absent; an existing directory must be
 *     owned by the effective uid with no group/other bits and not be a
 *     symlink, else it is refused (never chmod'ed) and export stays
 *     disabled (#87).
 * Returns 0 on success, -1 on refusal with the reason in
 * alert_pcap_error(). */
int  alert_pcap_set_dir(const char *dir);

/* Dump failures since the last alert_pcap_set_dir(); the first is also
 * printed to stderr. */
int         alert_pcap_failures(void);
const char *alert_pcap_error(void);

/* Headroom of the filesystem holding the configured --pcap-dir.
 *
 * Reported unconditionally, because the operator failure mode here is
 * reassurance rather than surprise: before #166 this sink had no sweep,
 * and on the owner's own monitor host it had consumed ~93% of the
 * filesystem's inodes while `df -h` still read 39% used. Whoever is
 * watching needs the number that is actually running out, with no flag
 * to remember first.
 *
 * Returns 0 and fills *out when a directory is configured and the probe
 * succeeds; -1 otherwise (no --pcap-dir, or fstatvfs failed), with *out
 * zeroed either way. The module's dirfd never escapes. */
int         alert_pcap_capacity(fs_capacity_t *out);

/* Returns 1 if a dir was configured. */
int  alert_pcap_enabled(void);

/* ── Age sweep (#166) ──────────────────────────────────────────────
 *
 * Owner ruling 2026-10-26: alert pcaps are kept two weeks. The window is
 * the pcap.retain_days row of the --tune registry; 0 keeps them forever
 * (the pre-#166 behaviour). It runs beside the storage floors, which are
 * unchanged: the floors refuse a write, the sweep ages old files out.
 *
 * What is swept: only names this module writes into the directory
 * pinned by alert_pcap_set_dir() — alert_pcap_is_name() — that are
 * regular files whose mtime is older than the window. Every entry is
 * fstatat(AT_SYMLINK_NOFOLLOW)-ed and removed with unlinkat() relative
 * to the pinned descriptor, so a symlink or a renamed path can never
 * redirect a deletion. An artifact name that is not a regular file is
 * left as it is and counted as a sweep error.
 *
 * A pass starts at the first maintain call (startup) and then at most
 * once per ALERT_PCAP_SWEEP_INTERVAL_S, and each call examines at most
 * a fixed number of directory entries, resuming where the last call
 * stopped. The measured failure this exists for is a directory of
 * ~16M files; a pass that walked it in one call would stall the poll
 * loop for minutes. */
#define ALERT_PCAP_DEFAULT_RETAIN_DAYS 14
#define ALERT_PCAP_MAX_RETAIN_DAYS     3650
#define ALERT_PCAP_SWEEP_INTERVAL_S    3600
#define ALERT_PCAP_SWEEP_BUDGET        1024

/* 1 if `name` has a shape this module writes in --pcap-dir: an alert
 * pcap (alert_YYYYMMDD_HHMMSS_<slug>[_N].pcap) or a #92 slice 3 hashed
 * manifest. Anything else in the directory is the operator's. */
int  alert_pcap_is_name(const char *name);

/* pcap.retain_days, 0 = keep forever. */
int  alert_pcap_retain_days(void);

/* One bounded step of the sweep, reading sloth_wall(). Starts a pass
 * when one is due, examines at most `budget` directory entries, and
 * returns the files removed in this call (0 when idle, disabled or not
 * due; -1 when the directory could not be opened for a new pass, which
 * is also counted). alert_pcap_maintain() is this with
 * ALERT_PCAP_SWEEP_BUDGET; the budget is a parameter so a test can see
 * a pass resume without creating a thousand files. */
int  alert_pcap_sweep_step(int budget);
int  alert_pcap_maintain(void);

/* 1 while a pass has entries left to examine. */
int  alert_pcap_sweep_in_progress(void);

/* Lifetime counts since the last alert_pcap_set_dir(): files the sweep
 * removed, and entries it could not honour the window for (unreadable
 * directory, failed stat, a non-regular file at an artifact name, a
 * failed unlink). The first error is also printed to stderr; the latest
 * reason is alert_pcap_sweep_error(). */
unsigned long long alert_pcap_swept(void);
int         alert_pcap_sweep_errors(void);
const char *alert_pcap_sweep_error(void);

/* Walk s->packets[] and write any packets matching alert->match_ip
 * (and match_port, if non-zero) to a fresh pcap file under the
 * configured dir. Returns the number of packets written, or -1 on error.
 * If out_path is non-NULL, the file path is written there. */
int  alert_pcap_dump(const sloth_state_t *s, const alert_t *a,
                     char *out_path, int out_sz);

#endif /* ALERT_PCAP_H */
