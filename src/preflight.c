#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "preflight.h"
#include "fs_capacity.h"
#include "rule_coverage_live.h"
#include "sloth.h"

/* src/preflight.h. The checks: pure over what the command line asked
 * for and what preflight_gather() found, so tests/test_preflight.c
 * drives every line with no radio, no disk and no gpsd. */

/* PF_INTEL_MAX_AGE_DAYS (90): the issue's proposal (#247 item 4). The
 * packs are vendor and watch lists that change on the scale of months;
 * a quarter is old enough that a refresh is due and young enough that
 * the warning does not fire on every sensor all the time.
 *
 * PF_GPSD_TIMEOUT_MS (1500): gpsd is a local service and answers its
 * connect with its VERSION line at once; the receiver's reader allows
 * GPS_CONNECT_MS for the connect alone. A second and a half bounds the
 * whole probe on a host where gpsd is wedged. */

/* The NL80211_IFTYPE_MONITOR value (<linux/nl80211.h>, 6), kept here so
 * this file needs no Linux header. */
#define PF_IFTYPE_MONITOR 6
#define PF_ARPHRD_RADIOTAP 803

/* main.c copies up to MAX_IFACES --iface names into pf_config_t. */
#if PF_MAX_IFACE < MAX_IFACES
#error "PF_MAX_IFACE must hold every --iface main.c accepts (MAX_IFACES)"
#endif

/* A path the account running the preflight cannot see into is not
 * "missing": the run may be another account (root, or the one it
 * drops to), and a stat that EACCES says nothing about the file. */
#define DENIED "not visible to the account running --preflight (a directory on the way is closed to it)"

const char *pf_level_name(pf_level_t l) {
    switch (l) {
    case PF_OK:          return "ok";
    case PF_WARN:        return "warn";
    case PF_FAIL:        return "fail";
    case PF_NA:          return "n/a";
    case PF_NOT_CHECKED: return "not checked";
    }
    return "?";
}

static const char *level_key(pf_level_t l) {
    switch (l) {
    case PF_NA:          return "na";
    case PF_NOT_CHECKED: return "not_checked";
    default:             return pf_level_name(l);
    }
}

static void add(pf_result_t *r, const char *check, const char *item,
                pf_level_t level, const char *fmt, ...) {
    if (r->n >= PF_MAX_LINES) return;
    pf_line_t *l = &r->line[r->n++];
    l->check = check;
    snprintf(l->item, sizeof(l->item), "%s", item ? item : "");
    l->level = level;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(l->reason, sizeof(l->reason), fmt, ap);
    va_end(ap);
}

static const pf_netdev_t *find_netdev(const pf_facts_t *f, const char *name, int *idx) {
    for (int i = 0; i < f->n_netdev; i++)
        if (!strcmp(f->netdev[i].name, name)) {
            if (idx) *idx = i;
            return &f->netdev[i];
        }
    return NULL;
}

/* 1 supports monitor mode, 0 does not, -1 not known. */
static int phy_monitor(const pf_facts_t *f, int idx) {
    if (idx < 0 || idx >= f->n_netdev || !f->phy_iftypes_known[idx]) return -1;
    return (f->phy_iftypes[idx] >> PF_IFTYPE_MONITOR) & 1u;
}

static int is_monitor(const pf_netdev_t *d) { return d && d->type == PF_ARPHRD_RADIOTAP; }

/* The radio discovery would take with no --monitor-iface: the first
 * type-803 netdev, as src/capture/probe.c's find_monitor_iface() does. */
static const pf_netdev_t *discovered(const pf_facts_t *f) {
    for (int i = 0; i < f->n_netdev; i++)
        if (is_monitor(&f->netdev[i])) return &f->netdev[i];
    return NULL;
}

/* The radio the run opens as radio 0: the first --monitor-iface when it
 * is in monitor mode, else (none named) the one discovery takes; NULL
 * when there is none, and then no further radio is opened either
 * (main.c: no radio 0, no --monitor-iface 2-4 and no --df-iface). */
static const pf_netdev_t *radio0(const pf_config_t *c, const pf_facts_t *f) {
    if (!c->have_pcap || c->n_replay > 0) return NULL;
    if (c->n_mon > 0) {
        const pf_netdev_t *d = find_netdev(f, c->mon[0], NULL);
        return is_monitor(d) ? d : NULL;
    }
    return discovered(f);
}

/* ── 1. Radios ─────────────────────────────────────────────────── */

static void one_iface(const pf_facts_t *f, pf_result_t *r, const char *name,
                      pf_role_t role) {
    static const char *const flag[] = { "--iface", "--monitor-iface", "--df-iface" };
    int idx = -1;
    const pf_netdev_t *d = find_netdev(f, name, &idx);
    if (!d) {
        if (role == PF_ROLE_IP)
            add(r, "radios", name, PF_FAIL, "named by --iface and not on this "
                "host: the capture scope cannot be enforced, so sloth exits 1");
        else if (role == PF_ROLE_MONITOR)
            add(r, "radios", name, PF_FAIL, "named by --monitor-iface and not on "
                "this host: no 802.11 capture from it, and no fallback to another radio");
        else
            add(r, "radios", name, PF_WARN, "named by --df-iface and not on this "
                "host: left out of direction finding");
        return;
    }
    if (role == PF_ROLE_IP) {
        add(r, "radios", name, PF_OK, "present (type %d)%s", d->type,
            is_monitor(d) ? ", in monitor mode" : "");
        return;
    }
    if (is_monitor(d)) {
        add(r, "radios", name, PF_OK, "in monitor mode%s%s (%s)",
            d->phy[0] ? " on " : "", d->phy, flag[role]);
        return;
    }
    /* Named for 802.11 and not in monitor mode: sloth sets no mode, so
     * the radio would not be opened. Whether it could be put there is a
     * read-only GET_WIPHY, never a try. */
    pf_level_t lv = role == PF_ROLE_DF ? PF_WARN : PF_FAIL;
    const char *loses = role == PF_ROLE_DF ? "left out of direction finding"
                                           : "no 802.11 capture from it";
    if (!d->phy[0]) {
        add(r, "radios", name, lv, "not a wireless interface (type %d): %s",
            d->type, loses);
        return;
    }
    int m = phy_monitor(f, idx);
    if (m == 1)
        add(r, "radios", name, lv, "not in monitor mode (type %d); %s supports it, "
            "and sloth sets no mode: put it in monitor mode before the run (%s)",
            d->type, d->phy, loses);
    else if (m == 0)
        add(r, "radios", name, lv, "not in monitor mode (type %d), and %s does not "
            "support monitor mode (%s)", d->type, d->phy, loses);
    else
        add(r, "radios", name, lv, "not in monitor mode (type %d); whether %s "
            "supports it was not checked (no nl80211 reply) (%s)",
            d->type, d->phy, loses);
}

void pf_check_radios(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r) {
    if (c->n_replay > 0) {
        add(r, "radios", "", PF_NA, "a --replay run reads files, not interfaces");
        return;
    }
    if (!f->netdev_listed) {
        add(r, "radios", "", PF_NOT_CHECKED, "/sys/class/net could not be read");
        return;
    }
    for (int i = 0; i < c->n_iface; i++) one_iface(f, r, c->iface[i], PF_ROLE_IP);
    if (!c->have_pcap) {
        add(r, "radios", "monitor", PF_NA, "built without libpcap: no 802.11 capture");
    } else if (c->n_mon > 0) {
        for (int i = 0; i < c->n_mon; i++) one_iface(f, r, c->mon[i], PF_ROLE_MONITOR);
    } else {
        const pf_netdev_t *d = discovered(f);
        if (d) {
            add(r, "radios", d->name, PF_OK, "no --monitor-iface: discovery would "
                "take %s, the first interface in monitor mode (pin it with "
                "--monitor-iface)", d->name);
        } else {
            char cand[96] = "";
            for (int i = 0; i < f->n_netdev; i++) {
                if (phy_monitor(f, i) != 1) continue;
                size_t o = strlen(cand);
                snprintf(cand + o, sizeof(cand) - o, "%s%s", o ? ", " : "",
                         f->netdev[i].name);
            }
            add(r, "radios", "monitor", PF_WARN, "no interface in monitor mode: "
                "every 802.11 rule is blind (NO_MONITOR_MODE at run time)%s%s",
                cand[0] ? "; monitor mode is available on " : "", cand);
        }
    }
    for (int i = 0; i < c->n_df; i++) one_iface(f, r, c->df[i], PF_ROLE_DF);
    /* capture_scope_verdict(): --monitor-only with no monitor radio
     * open is CAPTURE_SCOPE_REFUSE_NO_MONITOR, and main.c exits 1. */
    if (c->monitor_only && !radio0(c, f))
        add(r, "radios", "monitor-only", PF_FAIL, "--monitor-only and no radio in "
            "monitor mode would be opened: the run refuses to start (exit 1)");
    if (f->netdev_truncated)
        add(r, "radios", "netdevs", PF_NOT_CHECKED, "more than %d interfaces under "
            "/sys/class/net: discovery and the shared-phy check saw the first %d "
            "(each named interface was looked up by its own path)",
            PF_MAX_NETDEV, PF_MAX_NETDEV);

    /* The regulatory domain. "00" is the world domain the kernel falls
     * back to when none is set. */
    if (f->reg_rc == 1 && strcmp(f->alpha2, "00") != 0)
        add(r, "radios", "regdom", PF_OK, "regulatory domain %s", f->alpha2);
    else if (f->reg_rc == 1)
        add(r, "radios", "regdom", PF_WARN, "regulatory domain not set (world "
            "domain 00, the most restrictive): set the country (iw reg set XX)");
    else if (f->reg_rc == 0)
        add(r, "radios", "regdom", PF_WARN, "nl80211 reported no regulatory domain");
    else
        add(r, "radios", "regdom", PF_NOT_CHECKED, "regulatory domain not readable "
            "(no nl80211%s)", c->have_wifi ? " reply" : " in this build");
}

/* ── 2. Clock ──────────────────────────────────────────────────── */

long pf_date_days(const char *s) {
    if (!s || strlen(s) != 10 || s[4] != '-' || s[7] != '-') return -1;
    for (int i = 0; i < 10; i++)
        if (i != 4 && i != 7 && (s[i] < '0' || s[i] > '9')) return -1;
    long y = (s[0]-'0')*1000 + (s[1]-'0')*100 + (s[2]-'0')*10 + (s[3]-'0');
    long m = (s[5]-'0')*10 + (s[6]-'0');
    long d = (s[8]-'0')*10 + (s[9]-'0');
    if (m < 1 || m > 12 || d < 1 || d > 31) return -1;
    /* days_from_civil (H. Hinnant), as src/gps.c's gpsd_time_parse. */
    y -= m <= 2;
    long era = (y >= 0 ? y : y - 399) / 400;
    long yoe = y - era * 400;
    long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static long now_days(const pf_facts_t *f) {
    return f->now >= 0 ? (long)(f->now / 86400) : -1;
}

static void ymd(time_t t, char *out, size_t n) {
    struct tm tm;
    if (gmtime_r(&t, &tm)) strftime(out, n, "%Y-%m-%d %H:%M UTC", &tm);
    else snprintf(out, n, "?");
}

void pf_check_clock(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r) {
    char when[32];
    ymd(f->now, when, sizeof(when));
    long pack = pf_date_days(f->intel_date);
    if (pack >= 0 && now_days(f) < pack)
        add(r, "clock", "time", PF_FAIL, "system clock reads %s, before the intel "
            "pack's date %s, the newest date this binary carries (no build date "
            "is compiled in)", when, f->intel_date);
    else if (f->sync_known && !f->synced)
        add(r, "clock", "time", PF_WARN, "%s; the kernel reports the clock "
            "unsynchronised (adjtimex)", when);
    else
        add(r, "clock", "time", PF_OK, "%s, not before the intel pack's date %s%s",
            when, f->intel_date ? f->intel_date : "?",
            f->sync_known ? "; kernel reports it synchronised"
                          : "; synchronisation not known");

    if (!c->gps) {
        if (c->location)
            add(r, "clock", "gps", PF_NA, "not configured: --location gives a fixed position");
        else
            add(r, "clock", "gps", PF_NA, "not configured");
        return;
    }
    if (!strncmp(c->gps, "/", 1)) {
        if (f->gps_serial_rc == 0)
            add(r, "clock", "gps", PF_OK, "%s is a character device; not opened "
                "(opening a tty raises DTR)", c->gps);
        else if (f->gps_serial_rc == -3)
            add(r, "clock", "gps", PF_NOT_CHECKED, "%s: %s", c->gps, DENIED);
        else if (f->gps_serial_rc == -1)
            add(r, "clock", "gps", PF_FAIL, "%s does not exist: sloth exits 2", c->gps);
        else
            add(r, "clock", "gps", PF_FAIL, "%s is not a character device", c->gps);
        return;
    }
    if (f->gps_rc == 1)
        add(r, "clock", "gps", PF_OK, "%s", f->gps_detail);
    else if (f->gps_rc == 0)
        add(r, "clock", "gps", PF_WARN, "%s; the reader keeps retrying and the "
            "position reads searching", f->gps_detail);
    else
        add(r, "clock", "gps", PF_NOT_CHECKED, "%s", f->gps_detail);
}

/* ── 3. Storage ────────────────────────────────────────────────── */

#define MIB (1024ull * 1024ull)

/* #251 part 2, point 4: evidence captures kept past PF_PLAIN_RETAIN_DAYS
 * on a disk with no dm-crypt under it are what a finder of a lost
 * sensor reads (docs/wiki/sensor-compromise.md). A warning, not a
 * failure: it is the operator's call, and 0 ("no dm-crypt") does not
 * exclude fscrypt or a self-encrypting drive, which the line says. */
static void check_at_rest(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r) {
    for (int i = 0; i < f->n_path; i++) {
        const pf_path_t *p = &f->path[i];
        int days;
        const char *knob, *item;
        if (!strcmp(p->what, "pcap-dir")) {
            days = c->pcap_retain_days; knob = "pcap.retain_days"; item = "pcap-dir-at-rest";
        } else if (!strcmp(p->what, "eapol-dir")) {
            days = c->eapol_retain_days; knob = "handshake.retention_days";
            item = "eapol-dir-at-rest";
        } else {
            continue;
        }
        if (p->denied || !p->dir_ok) continue;   /* the storage line says why */
        char kept[48];
        if (days <= 0) snprintf(kept, sizeof(kept), "kept until removed (%s=0)", knob);
        else snprintf(kept, sizeof(kept), "kept %d days (%s)", days, knob);
        const int long_kept = days <= 0 || days > PF_PLAIN_RETAIN_DAYS;
        if (p->crypt > 0)
            add(r, "storage", item, PF_OK, "%s: %s; on %s", p->path, kept, p->crypt_dev);
        else if (p->crypt < 0)
            add(r, "storage", item, PF_NOT_CHECKED, "%s: %s; whether %s is encrypted "
                "is not known: device %s is not a block device /sys traces (tmpfs, "
                "btrfs, ZFS, overlayfs, NFS) or a layer could not be read",
                p->path, kept, p->dir, p->crypt_dev);
        else if (long_kept)
            add(r, "storage", item, PF_WARN, "%s: %s on device %s, with no dm-crypt "
                "under it: whoever holds a lost sensor reads every capture. Keep %d "
                "days or fewer, or move it to an encrypted volume "
                "(docs/wiki/sensor-compromise.md). fscrypt and a self-encrypting "
                "drive are not seen here", p->path, kept, p->crypt_dev,
                PF_PLAIN_RETAIN_DAYS);
        else
            add(r, "storage", item, PF_OK, "%s: %s, within %d, on device %s with no "
                "dm-crypt under it", p->path, kept, PF_PLAIN_RETAIN_DAYS, p->crypt_dev);
    }
}

void pf_check_storage(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r) {
    if (f->n_path == 0)
        add(r, "storage", "", PF_NA, "no output path on the command line");
    for (int i = 0; i < f->n_path; i++) {
        const pf_path_t *p = &f->path[i];
        if (p->denied) {
            add(r, "storage", p->what, PF_NOT_CHECKED, "%s: %s", p->path, DENIED);
            continue;
        }
        if (!p->dir_ok) {
            add(r, "storage", p->what, PF_FAIL, "%s: directory %s does not exist",
                p->path, p->dir);
            continue;
        }
        if (p->refused) {
            add(r, "storage", p->what, PF_FAIL, "%s: the run refuses it "
                "(src/secure_file.h): %s", p->path, p->why);
            continue;
        }
        if (p->foreign) {
            add(r, "storage", p->what, PF_WARN, "%s: owned by uid %ld, not by the "
                "account running --preflight; the run refuses it unless it writes "
                "as uid %ld", p->path, p->owner_uid, p->owner_uid);
            continue;
        }
        if (!p->writable) {
            add(r, "storage", p->what, PF_WARN, "%s: %s is not writable by the "
                "account running --preflight (the run writes as the account it "
                "drops to)", p->path, p->dir);
            continue;
        }
        if (!p->has_fs) {
            add(r, "storage", p->what, PF_NOT_CHECKED, "%s: free space under %s "
                "not readable", p->path, p->dir);
            continue;
        }
        int band = fs_capacity_band(p->free_bytes, p->total_bytes);
        unsigned long long fm = (unsigned long long)(p->free_bytes / MIB);
        unsigned long long tm = (unsigned long long)(p->total_bytes / MIB);
        pf_level_t lv = band >= 4 ? PF_FAIL : band >= 2 ? PF_WARN : PF_OK;
        add(r, "storage", p->what, lv, "%s%s: %llu MiB free of %llu under %s%s",
            p->path, p->creates ? " (created at start)" : "", fm, tm, p->dir,
            band >= 4 ? ", under 1%" : band >= 2 ? ", under 10%" : "");
    }
    if (f->pcap_eapol_same)
        add(r, "storage", "pcap-eapol", PF_FAIL, "--pcap-dir %s and --eapol-dir %s "
            "are the same directory: the handshake sweep would expire alert pcaps, "
            "so sloth exits 2", c->pcap_dir, c->eapol_dir);
    check_at_rest(c, f, r);
    if (!c->db) return;
    if (!c->have_sqlite) {
        add(r, "storage", "db-schema", PF_FAIL, "built without SQLite: --db cannot open");
        return;
    }
    const char *wal = f->db_wal_bytes > 0
        ? "; a -wal beside it holds frames, so this is the main file's version" : "";
    if (f->db_exists < 0)
        add(r, "storage", "db-schema", PF_NOT_CHECKED, "%s: %s", c->db, DENIED);
    else if (f->db_rc == -2)
        add(r, "storage", "db-schema", PF_NOT_CHECKED, "%s: not readable by the "
            "account running --preflight", c->db);
    else if (!f->db_exists || f->db_bytes == 0)
        add(r, "storage", "db-schema", PF_OK, "new file: created at schema v%d at start",
            f->db_current);
    else if (f->db_rc != 0)
        add(r, "storage", "db-schema", PF_FAIL, "not a database this build reads: %s",
            f->db_err);
    else if (f->db_version < 0)
        add(r, "storage", "db-schema", PF_OK, "no version row: stamped v%d at start%s",
            f->db_current, wal);
    else if (f->db_version == 0)
        add(r, "storage", "db-schema", PF_FAIL, "the schema_version row holds no "
            "version: refused at start (use a separate file)%s", wal);
    else if (f->db_version == f->db_current)
        add(r, "storage", "db-schema", PF_OK, "schema v%d, current (opened read-only, "
            "immutable)%s", f->db_version, wal);
    else if (f->db_version > f->db_current)
        add(r, "storage", "db-schema", PF_FAIL, "schema v%d, written by a newer sloth "
            "(this build writes v%d): refused at start%s", f->db_version,
            f->db_current, wal);
    else if (f->db_version >= f->db_migrates_from)
        add(r, "storage", "db-schema", PF_OK, "schema v%d: migrated to v%d at start "
            "(not by the preflight)%s", f->db_version, f->db_current, wal);
    else
        add(r, "storage", "db-schema", PF_FAIL, "schema v%d: older than this build "
            "migrates (v%d onward)%s", f->db_version, f->db_migrates_from, wal);

    /* The ceiling against the room: the file may grow to db.max_mb. */
    const pf_path_t *dp = NULL;
    for (int i = 0; i < f->n_path; i++)
        if (!strcmp(f->path[i].what, "db")) dp = &f->path[i];
    if (c->db_max_mb <= 0) {
        add(r, "storage", "db.max_mb", PF_NA, "no ceiling (db.max_mb 0)");
    } else if (dp && dp->has_fs) {
        long long have = f->db_exists == 1 && f->db_bytes > 0 ? f->db_bytes : 0;
        long long grow = (long long)c->db_max_mb * (long long)MIB - have;
        if (grow > 0 && (unsigned long long)grow > dp->free_bytes)
            add(r, "storage", "db.max_mb", PF_WARN, "db.max_mb %d MiB, the file is "
                "%lld MiB and %llu MiB are free: the filesystem fills before the "
                "ceiling", c->db_max_mb, have / (long long)MIB,
                (unsigned long long)(dp->free_bytes / MIB));
        else
            add(r, "storage", "db.max_mb", PF_OK, "db.max_mb %d MiB fits in the %llu "
                "MiB free", c->db_max_mb, (unsigned long long)(dp->free_bytes / MIB));
    }
}

/* ── 4. Intel pack ─────────────────────────────────────────────── */

void pf_check_intel(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r) {
    (void)c;
    const char *h = f->intel_hash ? f->intel_hash : "";
    long pack = pf_date_days(f->intel_date);
    long today = now_days(f);
    if (pack < 0)
        add(r, "intel", "pack", PF_WARN, "version %s, hash %.12s, date unreadable",
            f->intel_version ? f->intel_version : "?", h);
    else if (today < pack)
        add(r, "intel", "pack", PF_WARN, "version %s, hash %.12s, dated %s: age "
            "unknown, the clock is before it", f->intel_version, h, f->intel_date);
    else if (today - pack > PF_INTEL_MAX_AGE_DAYS)
        add(r, "intel", "pack", PF_WARN, "version %s, hash %.12s, dated %s: %ld "
            "days old, past %d (make update-intel)", f->intel_version, h,
            f->intel_date, today - pack, PF_INTEL_MAX_AGE_DAYS);
    else
        add(r, "intel", "pack", PF_OK, "version %s, hash %.12s, dated %s: %ld "
            "day%s old", f->intel_version, h, f->intel_date, today - pack,
            today - pack == 1 ? "" : "s");
}

/* ── 5. Sources ────────────────────────────────────────────────── */

void pf_check_sources(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r) {
    int any = 0;
    if (c->bt_monitor) {
        any = 1;
        if (f->bt_controllers > 0)
            add(r, "sources", "btmon", PF_OK, "%d Bluetooth controller%s under "
                "/sys/class/bluetooth; the HCI monitor channel is opened at start "
                "(needs CAP_NET_RAW), not here", f->bt_controllers,
                f->bt_controllers == 1 ? "" : "s");
        else if (f->bt_controllers == 0)
            add(r, "sources", "btmon", PF_WARN, "no Bluetooth controller: the btmon "
                "source reads down");
        else
            add(r, "sources", "btmon", PF_NOT_CHECKED, "/sys/class/bluetooth not readable");
    }
    if (c->bt_capture) {
        any = 1;
        if (f->bt_capture_rc == 0)
            add(r, "sources", "btcap", PF_OK, "%s is a FIFO; not opened (the open "
                "waits for its writer)", c->bt_capture);
        else if (f->bt_capture_rc == 1)
            add(r, "sources", "btcap", PF_OK, "%s is a regular file", c->bt_capture);
        else if (f->bt_capture_rc == -3)
            add(r, "sources", "btcap", PF_NOT_CHECKED, "%s: %s", c->bt_capture, DENIED);
        else if (f->bt_capture_rc == -1)
            add(r, "sources", "btcap", PF_FAIL, "%s does not exist: sloth exits 2",
                c->bt_capture);
        else
            add(r, "sources", "btcap", PF_FAIL, "%s is not a FIFO or a regular file: "
                "sloth exits 2", c->bt_capture);
    }
    for (int i = 0; i < c->n_replay && i < PF_MAX_REPLAY; i++) {
        any = 1;
        if (f->replay_rc[i] == 0)
            add(r, "sources", "replay", PF_OK, "%s is a regular file", c->replay[i]);
        else if (f->replay_rc[i] == -3)
            add(r, "sources", "replay", PF_NOT_CHECKED, "%s: %s", c->replay[i], DENIED);
        else
            add(r, "sources", "replay", PF_FAIL, "%s %s: sloth exits 1", c->replay[i],
                f->replay_rc[i] == -1 ? "does not exist" : "is not a regular file");
    }
    if (c->baseline_in) {
        any = 1;
        if (f->baseline_rc == 0)
            add(r, "sources", "baseline", PF_OK, "%s is a regular file", c->baseline_in);
        else if (f->baseline_rc == -3)
            add(r, "sources", "baseline", PF_NOT_CHECKED, "%s: %s", c->baseline_in, DENIED);
        else
            add(r, "sources", "baseline", PF_WARN, "%s %s", c->baseline_in,
                f->baseline_rc == -1 ? "does not exist" : "is not a regular file");
    }
    if (!any)
        add(r, "sources", "", PF_NA, "no file or socket source configured (sloth-rf's "
            "decoders are sloth-rf's to check)");
}

/* ── 6. Host and the passive contract ──────────────────────────── */

void pf_check_host(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r) {
    if (!f->has_undervolt)
        add(r, "host", "undervolt", PF_NA, "no under-voltage alarm on this host");
    else if (f->undervolt)
        add(r, "host", "undervolt", PF_WARN, "the firmware's under-voltage alarm is "
            "set now (SENSOR_UNDERVOLT at run time)");
    else
        add(r, "host", "undervolt", PF_OK, "under-voltage alarm clear");

    /* sys_status's TEMP_EDGES: 80 C is its "critical" band. */
    if (!f->has_temp)
        add(r, "host", "temperature", PF_NA, "no temperature reading on this host");
    else if (f->hottest_c >= 80.0)
        add(r, "host", "temperature", PF_WARN, "hottest %.1f C (%s), critical",
            f->hottest_c, f->hottest_label);
    else
        add(r, "host", "temperature", PF_OK, "hottest %.1f C (%s)", f->hottest_c,
            f->hottest_label);

    /* The passive contract, as far as configuration can show it. Only
     * an interface already in monitor mode is opened for 802.11 (sloth
     * sets no mode; one that is not is left out, and check 1 says what
     * that costs), so what is checked is the phy of each radio the run
     * would open: no other interface on it that is up and not in
     * monitor mode, because that one can transmit through the radio (as
     * a client or an access point). sloth injects no frame (MISSION
     * section 2); what a command line can add is listed. */
    const pf_netdev_t *opened[1 + 2 * PF_MAX_NAMED];
    int n = 0;
    const pf_netdev_t *r0 = radio0(c, f);
    if (r0) {
        opened[n++] = r0;
        for (int i = 1; i < c->n_mon; i++) {
            const pf_netdev_t *d = find_netdev(f, c->mon[i], NULL);
            if (is_monitor(d) && d != r0) opened[n++] = d;
        }
        for (int i = 0; i < c->n_df; i++) {
            const pf_netdev_t *d = find_netdev(f, c->df[i], NULL);
            int dup = 0;
            for (int k = 0; k < n; k++) dup |= opened[k] == d;
            if (is_monitor(d) && !dup) opened[n++] = d;
        }
    }
    char shared[160] = "", down[96] = "";
    for (int i = 0; i < n; i++) {
        const pf_netdev_t *d = opened[i];
        if (!d->phy[0]) continue;
        for (int k = 0; k < f->n_netdev; k++) {
            const pf_netdev_t *o2 = &f->netdev[k];
            if (o2 == d || strcmp(o2->phy, d->phy) != 0 || is_monitor(o2)) continue;
            if (o2->up == 0) {
                if (!strstr(down, o2->name)) {
                    size_t o = strlen(down);
                    snprintf(down + o, sizeof(down) - o, "%s%s", o ? ", " : "", o2->name);
                }
                continue;
            }
            size_t o = strlen(shared);
            snprintf(shared + o, sizeof(shared) - o, "%s%s (%s, beside %s%s)",
                     o ? "; " : "", o2->name, o2->phy, d->name,
                     o2->up < 0 ? ", up or down not readable" : ", up");
        }
    }
    char optin[120] = "";
    if (c->allow_active)
        snprintf(optin, sizeof(optin), "--allow-active (PTR queries, scan triggers)");
    if (c->data_socket_remote) {
        size_t o = strlen(optin);
        snprintf(optin + o, sizeof(optin) - o, "%sa routable --data-socket (serves "
                 "whoever connects)", o ? ", " : "");
    }
    char downs[160] = "";
    if (down[0])
        snprintf(downs, sizeof(downs), "; down on a radio's phy, so not transmitting: %s",
                 down);
    if (n == 0)
        add(r, "host", "passive", PF_OK, "no 802.11 interface would be opened%s%s",
            optin[0] ? "; sending opt-ins given: " : "", optin);
    else if (shared[0])
        add(r, "host", "passive", PF_WARN, "a non-monitor interface shares the "
            "radio's phy and can transmit through it: %s", shared);
    else if (f->netdev_truncated)
        add(r, "host", "passive", PF_NOT_CHECKED, "the radios sloth would open are "
            "in monitor mode; interfaces past the first %d under /sys/class/net "
            "were not checked for sharing their phy", PF_MAX_NETDEV);
    else
        add(r, "host", "passive", PF_OK, "every 802.11 interface sloth would open is "
            "in monitor mode and no interface that is up shares its phy%s; sloth sets "
            "no mode and injects nothing. Not checked: a monitor interface made with "
            "the active flag ACKs frames sent to its own address, and no read-only "
            "path reports that flag%s%s", downs, optin[0] ? "; sending opt-ins given: " : "",
            optin);
}

/* ── 7. Output and notification ────────────────────────────────── */

void pf_check_output(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r) {
    if (!c->data_socket)
        add(r, "output", "socket", PF_NA, "no --data-socket");
    else if (f->sock_dir_rc == 1)
        add(r, "output", "socket", PF_NOT_CHECKED, "%s: a TCP listener is tested only "
            "by binding it, and the preflight binds nothing", c->data_socket);
    else if (f->sock_dir_rc == 0)
        add(r, "output", "socket", PF_OK, "%s: its directory is there (the socket "
            "is created at start)", c->data_socket);
    else if (f->sock_dir_rc == -1)
        add(r, "output", "socket", PF_FAIL, "%s: its directory does not exist",
            c->data_socket);
    else
        add(r, "output", "socket", PF_WARN, "%s: its directory is not writable by "
            "the account running --preflight", c->data_socket);
    /* Read in the source, not assumed: no file under src/ sends a
     * message (mail, webhook, push) to anyone. sloth's one notification
     * path is --notify-priority (#244), lines on its own stderr; a lane
     * that leaves the host is sloth-mesh's (sloth-mesh#18), and its test
     * message is that repository's to send. */
    if (!c->notify_priority)
        add(r, "output", "notify", PF_NA, "no --notify-priority: no notification "
            "path in sloth");
    else
        add(r, "output", "notify", PF_OK, "--notify-priority %d: a site question of "
            "priority %d%s that turns to a finding is a line on stderr (the journal "
            "under systemd); local only, no test message is sent", c->notify_priority,
            c->notify_priority, c->notify_priority > 1 ? " or more urgent" : "");
}

/* ── 8. Rule status ────────────────────────────────────────────── */

static void offer(cov_env_t *e, cov_input_t in, cov_avail_t av) {
    if (av > e->input[in]) e->input[in] = av;
}

void pf_rule_env(const pf_config_t *c, const pf_facts_t *f, cov_env_t *e) {
    memset(e, 0, sizeof(*e));
    e->input[COV_IN_SYS]  = COV_AV_UP;
    e->input[COV_IN_HOST] = COV_AV_UP;
    if (c->have_pcap) {
        int radios = 0, named = c->n_mon > 0;
        /* No radio 0, no further radios (main.c). */
        if (radio0(c, f)) {
            radios = 1;
            for (int i = 1; i < c->n_mon; i++)
                if (is_monitor(find_netdev(f, c->mon[i], NULL))) radios++;
        }
        if (radios) offer(e, COV_IN_DOT11, COV_AV_UP);
        else if (named) offer(e, COV_IN_DOT11, COV_AV_DOWN);
        e->radios = radios;
        if (radios) {
            e->hopping  = c->hop && c->n_hop > 0;
            e->channels = e->hopping ? c->n_hop : radios;
            /* Without --hop a radio's channel is known only from its
             * frames, so the band is unknown (rule_coverage_capture.c). */
            if (e->hopping)
                for (int i = 0; i < c->n_hop; i++) e->bands |= cov_band_of_mhz(c->hop_mhz[i]);
        }
        if (!c->monitor_only) {
            int missing = 0;
            for (int i = 0; i < c->n_iface; i++)
                if (!find_netdev(f, c->iface[i], NULL)) missing = 1;
            offer(e, COV_IN_IP, missing ? COV_AV_DOWN : COV_AV_UP);
        }
        if (c->bt_monitor) {
            cov_avail_t av = f->bt_controllers > 0 ? COV_AV_UP : COV_AV_DOWN;
            offer(e, COV_IN_BLE_HCI, av);
            offer(e, COV_IN_BLE_ADV, av);
        }
        if (c->bt_capture)   /* -3, not visible here, is not taken for down */
            offer(e, COV_IN_BLE_ADV, f->bt_capture_rc >= 0 || f->bt_capture_rc == -3
                                     ? COV_AV_UP : COV_AV_DOWN);
    }
    if (c->gps) {
        int up = c->gps[0] == '/' ? (f->gps_serial_rc == 0 || f->gps_serial_rc == -3)
                                  : f->gps_rc != 0;
        offer(e, COV_IN_GNSS, up ? COV_AV_UP : COV_AV_DOWN);
    }
    e->config = c->config & (COV_N_OWN_NET | COV_N_ROSTER);
    if (c->db && c->have_sqlite && (f->db_rc == 0 || f->db_rc == -2 || f->db_exists <= 0 ||
                                    f->db_bytes == 0))
        e->config |= COV_N_DB;
}

void pf_check_rules(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r) {
    r->observable = r->partly = r->blind = 0;
    if (c->n_replay > 0) {
        r->assessed = 0;
        add(r, "rules", "", PF_NA, "a --replay run is not assessed: the statuses are "
            "about the sensor's own radios and sources");
        return;
    }
    pf_rule_env(c, f, &r->env);
    r->assessed = 1;
    int down = 0;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        r->st[t] = (uint8_t)COV_OBSERVABLE;
        r->why[t] = (uint8_t)COV_R_NONE;
        if (!cov_daemon_raises(COV_DAEMON_WIFI, (alert_type_t)t)) continue;
        cov_reason_t why = COV_R_NONE;
        cov_status_t st = cov_rule_status((alert_type_t)t, &r->env, &why);
        r->st[t] = (uint8_t)st;
        r->why[t] = (uint8_t)why;
        if (st == COV_OBSERVABLE) r->observable++;
        else if (st == COV_PARTLY) r->partly++;
        else r->blind++;
        if (why == COV_R_SOURCE_DOWN) down++;
    }
    /* A rule blind for want of a source the operator did not configure
     * is a choice; one blind because a configured source would not
     * deliver is what the preflight is for. */
    if (down)
        add(r, "rules", "", PF_WARN, "expected, not measured: %d observable, %d partly, "
            "%d blind; %d blind because a configured source would not deliver",
            r->observable, r->partly, r->blind, down);
    else
        add(r, "rules", "", PF_OK, "expected for this configuration, not measured: %d "
            "observable, %d partly, %d blind", r->observable, r->partly, r->blind);
}

void pf_run_checks(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r) {
    memset(r, 0, sizeof(*r));
    pf_check_radios(c, f, r);
    pf_check_clock(c, f, r);
    pf_check_storage(c, f, r);
    pf_check_intel(c, f, r);
    pf_check_sources(c, f, r);
    pf_check_host(c, f, r);
    pf_check_output(c, f, r);
    pf_check_rules(c, f, r);
}

int pf_exit_code(const pf_result_t *r) {
    int code = 0;
    for (int i = 0; i < r->n; i++) {
        if (r->line[i].level == PF_FAIL) return 2;
        if (r->line[i].level == PF_WARN) code = 1;
    }
    return code;
}

static const char *verdict(int code) {
    return code == 0 ? "ready" : code == 1 ? "ready with warnings" : "not ready";
}

/* ── Printing ──────────────────────────────────────────────────── */

/* The kinds that are not observable, grouped as src/rule_coverage_live.h
 * groups them: blind first, then partly, each in the reason order of
 * cov_rule_status(). */
static void print_groups(const pf_result_t *r, FILE *out) {
    for (int st = COV_BLIND; st <= COV_PARTLY; st++)
        for (int why = 0; why < COV_R_COUNT; why++) {
            int n = 0;
            for (int t = 0; t < ALERT_TYPE_COUNT; t++)
                if (cov_daemon_raises(COV_DAEMON_WIFI, (alert_type_t)t) &&
                    r->st[t] == st && r->why[t] == why) n++;
            if (!n) continue;
            fprintf(out, "%25s%s %s (%d):", "", cov_status_name((cov_status_t)st),
                    cov_reason_name((cov_reason_t)why), n);
            for (int t = 0; t < ALERT_TYPE_COUNT; t++)
                if (cov_daemon_raises(COV_DAEMON_WIFI, (alert_type_t)t) &&
                    r->st[t] == st && r->why[t] == why)
                    fprintf(out, " %s", cov_kind_name((alert_type_t)t));
            fputc('\n', out);
        }
}

void pf_print_text(const pf_result_t *r, FILE *out) {
    fprintf(out, "sloth --preflight: sloth-wifi %s, this command line; nothing "
            "started\n", SLOTH_VERSION);
    for (int i = 0; i < r->n; i++) {
        const pf_line_t *l = &r->line[i];
        char what[64];
        snprintf(what, sizeof(what), "%s%s%s", l->check, l->item[0] ? " " : "", l->item);
        fprintf(out, "  %-11s  %-24s %s\n", pf_level_name(l->level), what, l->reason);
        if (!strcmp(l->check, "rules") && r->assessed) print_groups(r, out);
    }
    int code = pf_exit_code(r);
    fprintf(out, "%s (exit %d)\n", verdict(code), code);
}

/* The length of the well-formed UTF-8 sequence at p (RFC 3629 section
 * 4: no overlong form, no surrogate, nothing past U+10FFFF), 0 when the
 * bytes there are not one. */
static int utf8_len(const unsigned char *p) {
    unsigned c = p[0];
    int n;
    unsigned min;
    if (c >= 0xc2 && c <= 0xdf)      { n = 2; min = 0x80; c &= 0x1f; }
    else if (c >= 0xe0 && c <= 0xef) { n = 3; min = 0x800; c &= 0x0f; }
    else if (c >= 0xf0 && c <= 0xf4) { n = 4; min = 0x10000; c &= 0x07; }
    else return 0;
    for (int i = 1; i < n; i++) {
        if ((p[i] & 0xc0) != 0x80) return 0;
        c = (c << 6) | (p[i] & 0x3fu);
    }
    if (c < min || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) return 0;
    return n;
}

/* A JSON string (RFC 8259 section 7). A path from the command line is
 * bytes, not text: a byte that does not start a well-formed UTF-8
 * sequence is written as U+FFFD, so the object stays valid JSON. */
static void jstr(FILE *out, const char *s) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        if (*p == '"' || *p == '\\') fprintf(out, "\\%c", *p);
        else if (*p < 0x20 || *p == 0x7f) fprintf(out, "\\u%04x", *p);
        else if (*p < 0x80) fputc(*p, out);
        else {
            int n = utf8_len(p);
            if (n == 0) { fputs("\\ufffd", out); continue; }
            fwrite(p, 1, (size_t)n, out);
            p += n - 1;
        }
    }
    fputc('"', out);
}

void pf_json_str(FILE *out, const char *s) { jstr(out, s); }

void pf_print_json(const pf_result_t *r, FILE *out) {
    int code = pf_exit_code(r);
    fprintf(out, "{\"preflight\":{\"daemon\":\"sloth-wifi\",\"version\":");
    jstr(out, SLOTH_VERSION);
    fprintf(out, "},\"exit\":%d,\"verdict\":", code);
    jstr(out, code == 0 ? "ready" : code == 1 ? "ready_with_warnings" : "not_ready");
    fprintf(out, ",\"checks\":[");
    for (int i = 0; i < r->n; i++) {
        const pf_line_t *l = &r->line[i];
        fprintf(out, "%s{\"check\":", i ? "," : "");
        jstr(out, l->check);
        fprintf(out, ",\"item\":");
        jstr(out, l->item);
        fprintf(out, ",\"level\":");
        jstr(out, level_key(l->level));
        fprintf(out, ",\"reason\":");
        jstr(out, l->reason);
        fputc('}', out);
    }
    fprintf(out, "],\"rules\":{\"assessed\":%s", r->assessed ? "true" : "false");
    if (r->assessed) {
        fprintf(out, ",\"expectation\":true,\"observable\":%d,\"partly\":%d,"
                "\"blind\":%d,\"kinds\":[", r->observable, r->partly, r->blind);
        int first = 1;
        for (int st = COV_BLIND; st <= COV_PARTLY; st++)
            for (int why = 0; why < COV_R_COUNT; why++)
                for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
                    if (!cov_daemon_raises(COV_DAEMON_WIFI, (alert_type_t)t) ||
                        r->st[t] != st || r->why[t] != why) continue;
                    fprintf(out, "%s{\"kind\":", first ? "" : ",");
                    jstr(out, cov_kind_name((alert_type_t)t));
                    fprintf(out, ",\"status\":");
                    jstr(out, cov_status_name((cov_status_t)st));
                    fprintf(out, ",\"reason\":");
                    jstr(out, cov_reason_name((cov_reason_t)why));
                    fputc('}', out);
                    first = 0;
                }
        fputc(']', out);
    }
    fprintf(out, "}}\n");
}
