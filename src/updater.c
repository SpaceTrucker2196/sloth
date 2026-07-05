/* Version check-in — notify-only manifest reader.
 *
 * sloth never fetches from the network. An external process (systemd
 * timer, cron, `examples/updater/check-latest.sh`) is responsible for
 * populating the manifest file; sloth only reads and compares.
 *
 * The manifest is JSON (small — no library needed):
 *   {
 *     "latest": "1.5.0",
 *     "url":    "https://…/releases/tag/v1.5.0",
 *     "checked_at": "2026-07-02T15:00:00Z"
 *   }
 *
 * Extra fields are ignored, matching semver 2.0's forward-compat rule.
 * A missing file or malformed JSON sets err=1 and never crashes. */

#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <pthread.h>
#include "updater.h"
#include "version.h"

/* Only re-stat / re-read every UPDATER_CHECK_INTERVAL_S. Bounds the
 * cost of the per-poll tick to one time(2) comparison in the common
 * case. 60s is arbitrary but well below any realistic release cadence. */
#define UPDATER_CHECK_INTERVAL_S 60

static char            g_path[512];
static int             g_enabled;
static time_t          g_next_check;
static time_t          g_last_mtime;

/* State written by tick, read by snapshot. Guarded so callers on
 * different threads see consistent snapshots even if we grow to a
 * background reader later. */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int             g_has_update;
static int             g_err;
static char            g_latest[16];
static char            g_url[128];
static char            g_err_msg[64];
static time_t          g_last_checked;

/* Skip whitespace (JSON's ws set). */
static const char *skip_ws(const char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    return s;
}

/* Naive extractor: find `"key"` in body, expect `:`, then read either
 * a quoted string (into out/outsz) or a bare literal (unused here).
 * Returns 1 on success, 0 if the key is missing or malformed.
 *
 * Not a general JSON parser — the file is trusted local input and the
 * schema is tiny. We reject anything we don't understand rather than
 * try to be forgiving. */
static int scan_str_field(const char *body, const char *key,
                          char *out, int outsz)
{
    if (outsz < 1) return 0;
    out[0] = '\0';

    /* Build a `"key"` needle so we don't match the key as part of some
     * other identifier. */
    char needle[64];
    int  n = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (n < 0 || n >= (int)sizeof(needle)) return 0;

    const char *p = strstr(body, needle);
    if (!p) return 0;
    p += n;
    p = skip_ws(p);
    if (*p != ':') return 0;
    p = skip_ws(p + 1);
    if (*p != '"') return 0;
    p++;

    int i = 0;
    while (*p && *p != '"' && i + 1 < outsz) {
        /* Very small escape handling — enough for URLs with encoded
         * characters not requiring backslash. Anything with an actual
         * backslash escape is treated as invalid. */
        if (*p == '\\') return 0;
        out[i++] = *p++;
    }
    if (*p != '"') return 0;
    out[i] = '\0';
    return 1;
}

/* Read the file at g_path into a fixed-size buffer. Returns bytes read
 * or -1 on error. Rejects anything larger than the buffer so a
 * malicious manifest can't grow unbounded — realistic manifests are
 * a few hundred bytes. */
static int read_all(char *buf, int bufsz) {
    FILE *fp = fopen(g_path, "r");
    if (!fp) return -1;
    int total = 0;
    while (total < bufsz - 1) {
        int r = (int)fread(buf + total, 1, (size_t)(bufsz - 1 - total), fp);
        if (r <= 0) break;
        total += r;
    }
    fclose(fp);
    buf[total] = '\0';
    return total;
}

static void reset_status(void) {
    g_has_update   = 0;
    g_err          = 0;
    g_latest[0]    = '\0';
    g_url[0]       = '\0';
    g_err_msg[0]   = '\0';
}

static void set_err(const char *msg) {
    g_err = 1;
    snprintf(g_err_msg, sizeof(g_err_msg), "%s", msg);
    /* Keep g_latest / g_url as-is: a transient read failure shouldn't
     * clobber the last-good status. */
}

/* Perform the actual read + compare. Caller holds g_mu. */
static void do_check(time_t now) {
    struct stat st;
    if (stat(g_path, &st) != 0) {
        set_err("manifest missing");
        return;
    }
    if (st.st_mtime == g_last_mtime && g_last_checked != 0) {
        /* Unchanged since last successful read — nothing to do. */
        return;
    }

    char buf[2048];
    int  n = read_all(buf, sizeof(buf));
    if (n <= 0) { set_err("manifest read failed"); return; }

    char latest[16];
    if (!scan_str_field(buf, "latest", latest, sizeof(latest))) {
        set_err("no \"latest\" field");
        return;
    }
    char url[128];
    scan_str_field(buf, "url", url, sizeof(url));   /* optional */

    semver_t curr, next;
    if (!semver_parse(SLOTH_VERSION, &curr)) {
        set_err("SLOTH_VERSION unparseable");
        return;
    }
    if (!semver_parse(latest, &next)) {
        set_err("latest not semver");
        return;
    }

    reset_status();
    snprintf(g_latest, sizeof(g_latest), "%s", latest);
    snprintf(g_url,    sizeof(g_url),    "%s", url);
    g_has_update   = semver_cmp(&next, &curr) > 0;
    g_last_mtime   = st.st_mtime;
    g_last_checked = now;
}

/* ── Public API ─────────────────────────────────────── */

void updater_init(const char *manifest_path) {
    pthread_mutex_lock(&g_mu);
    if (manifest_path && manifest_path[0]) {
        snprintf(g_path, sizeof(g_path), "%s", manifest_path);
        g_enabled = 1;
    } else {
        g_enabled = 0;
    }
    g_next_check   = 0;
    g_last_mtime   = 0;
    g_last_checked = 0;
    reset_status();
    pthread_mutex_unlock(&g_mu);
}

void updater_tick(time_t now) {
    if (!g_enabled) return;
    pthread_mutex_lock(&g_mu);
    if (now >= g_next_check) {
        do_check(now);
        g_next_check = now + UPDATER_CHECK_INTERVAL_S;
    }
    pthread_mutex_unlock(&g_mu);
}

void updater_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    s->updater.enabled      = g_enabled;
    s->updater.has_update   = g_has_update;
    s->updater.err          = g_err;
    snprintf(s->updater.current, sizeof(s->updater.current),
             "%s", SLOTH_VERSION);
    snprintf(s->updater.latest,  sizeof(s->updater.latest),  "%s", g_latest);
    snprintf(s->updater.url,     sizeof(s->updater.url),     "%s", g_url);
    snprintf(s->updater.err_msg, sizeof(s->updater.err_msg), "%s", g_err_msg);
    s->updater.last_checked = g_last_checked;
    pthread_mutex_unlock(&g_mu);
}
