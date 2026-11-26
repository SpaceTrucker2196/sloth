#ifndef SLOTH_PREFLIGHT_H
#define SLOTH_PREFLIGHT_H

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "rule_coverage.h"
#include "sloth_alert.h"

/* ── sloth --preflight (#247) ────────────────────────────────────────
 *
 * Problems with a sensor's set-up show up at run time today, as
 * NO_MONITOR_MODE, SENSOR_SOURCE_DOWN, SENSOR_UNDERVOLT or a stderr
 * line, after the session has started. `sloth --preflight [the normal
 * options]` asks the same questions before one starts (FM 2-0 4-9 to
 * 4-11: verify the equipment, the databases and the reporting channels
 * before the mission) and prints one page: one line per item, ok, warn
 * or fail with the reason, then the exit code
 *
 *   0  ready
 *   1  ready with warnings
 *   2  not ready (and the exit code of a command line the argv checks
 *      refuse, which never reaches the preflight)
 *
 * `--preflight --json` prints the same as one JSON object.
 *
 * THREE HALVES, so every check is a test with no radio:
 *
 *   pf_config_t  what the command line asked for (main.c fills it after
 *                its whole-command-line checks)
 *   pf_facts_t   what the host has, gathered by preflight_gather():
 *                sysfs through sys_status's guarded readers (so the
 *                fake platform serves it in tests), statvfs, a stat of
 *                each named path, the database opened immutable and
 *                read-only, two read-only nl80211 GETs and, for a
 *                loopback gpsd, one connect and one read
 *   pf_result_t  the lines, from the pure checks pf_check_*() over the
 *                two
 *
 * WHAT IT NEVER DOES. It opens no capture handle, retunes no radio,
 * sets no interface mode, writes no file (the database is opened
 * `immutable=1`, which creates no -wal or -shm; a missing one is not
 * created), binds no socket, starts no thread and sends nothing: the
 * gpsd probe reads the banner gpsd sends on connect and writes no byte
 * (the ?WATCH line is the reader's, after start), a serial receiver is
 * stat()ed and not opened (opening a tty raises DTR), and a gpsd that
 * is not on loopback is not dialled. tests/test_preflight.c runs it
 * with every output path in a temporary directory and asserts the
 * directory is unchanged. */

typedef enum {
    PF_OK = 0,
    PF_WARN,
    PF_FAIL,
    PF_NA,            /* does not apply to this configuration */
    PF_NOT_CHECKED    /* applies, and could not be learnt without acting */
} pf_level_t;

const char *pf_level_name(pf_level_t l);   /* "ok", "warn", "fail", "n/a", "not checked" */

#define PF_MAX_IFACE   32     /* --iface names: main.c's MAX_IFACES, held by an #error */
#define PF_MAX_NAMED   16     /* --monitor-iface, --df-iface names (the CLI takes fewer) */
#define PF_MAX_NETDEV  128    /* netdevs listed under /sys/class/net; more is reported */
/* The netdev table: the listing, plus each named interface the listing
 * left out, looked up by its own path. */
#define PF_NETDEV_CAP  (PF_MAX_NETDEV + PF_MAX_IFACE + 2 * PF_MAX_NAMED)
#define PF_MAX_PATHS   8
#define PF_MAX_REPLAY  8
#define PF_MAX_HOP     32

/* The roles an interface is named in. */
typedef enum { PF_ROLE_IP = 0, PF_ROLE_MONITOR, PF_ROLE_DF } pf_role_t;

typedef struct {
    /* Interfaces, in the roles the command line gave them. */
    const char *iface[PF_MAX_IFACE];     /* --iface */
    int         n_iface;
    const char *mon[PF_MAX_NAMED];       /* --monitor-iface, in order */
    int         n_mon;
    const char *df[PF_MAX_NAMED];        /* --df-iface */
    int         n_df;
    int         monitor_only, hop, allow_active, strict;
    int         hop_mhz[PF_MAX_HOP];     /* the --hop plan's frequencies */
    int         n_hop;
    /* Sources. */
    int         bt_monitor;
    const char *bt_capture;
    const char *gps;                     /* --gps SPEC */
    int         gps_allow_remote;
    const char *location;
    const char *replay[PF_MAX_REPLAY];
    int         n_replay;
    const char *baseline_in;
    /* Outputs. */
    const char *db;
    const char *jsonl;
    const char *pcap_dir;
    const char *eapol_dir;
    const char *report_md, *report_json, *snapshot_out;
    const char *data_socket;
    int         data_socket_remote;      /* routable, allowed */
    int         db_max_mb;               /* db.max_mb, 0 none */
    /* #251: how long the evidence captures are kept, days, 0 forever
     * (pcap.retain_days, handshake.retention_days). */
    int         pcap_retain_days, eapol_retain_days;
    /* The operator's configuration the rules need (COV_N_*). */
    unsigned    config;
    /* --notify-priority (#244), 0 off. */
    int         notify_priority;
    /* The build. */
    int         have_pcap, have_wifi, have_sqlite;
} pf_config_t;

typedef struct {
    char name[16];
    int  type;          /* ARPHRD_*; -1 not readable */
    char phy[16];       /* "phy3", "" not wireless */
    int  phy_index;     /* -1 not known */
    int  up;            /* IFF_UP in .../flags: 1, 0, -1 not readable */
} pf_netdev_t;

/* One output path. `dir` is what is checked: the directory itself for
 * --pcap-dir / --eapol-dir (or its parent when it is to be created),
 * the parent for a file. */
typedef struct {
    const char *what;        /* "db", "jsonl", "pcap-dir", ... */
    const char *path;
    char        dir[256];
    int         dir_ok;      /* exists, is a directory */
    int         denied;      /* a directory on the way is closed to this account */
    int         writable;    /* access(W_OK|X_OK) as this account */
    int         creates;     /* the path itself does not exist yet */
    int         has_fs;
    uint64_t    free_bytes, total_bytes;
    /* An existing path, held to secure_file.c's rule the run applies
     * (sfile_validate_stat()): `refused` when its type, mode, link
     * count or a final symlink makes the run refuse it whatever account
     * it runs as, with the reason; `foreign` (owner `owner_uid`) when it
     * is owned by an account other than the one running the preflight
     * (the run refuses it unless it writes as that account). */
    int         refused;
    char        why[200];
    int         foreign;
    long        owner_uid;
    /* #251, for --pcap-dir and --eapol-dir: whether `dir`'s filesystem
     * sits on dm-crypt (pf_block_crypt()): 1 yes, 0 a block device with
     * no dm-crypt under it, -1 cannot tell (not checked: other paths). */
    int         crypt;
    char        crypt_dev[48];       /* "254:1 (dm-crypt sdcrypt)", "179:2" */
} pf_path_t;

typedef struct {
    /* /sys/class/net, through sys_status's readers. */
    int          netdev_listed;   /* the list could be read */
    int          netdev_truncated;/* more than PF_MAX_NETDEV entries: the rest unlisted */
    int          n_netdev;
    pf_netdev_t  netdev[PF_NETDEV_CAP];
    /* nl80211, read-only. phy_iftypes[i] is the NL80211_IFTYPE_* mask
     * of netdev[i]'s phy; phy_iftypes_known[i] is 1 when it was read,
     * 0 when it was not (no nl80211, no WITH_WIFI, not wireless). */
    unsigned     phy_iftypes[PF_NETDEV_CAP];
    int          phy_iftypes_known[PF_NETDEV_CAP];
    int          reg_rc;          /* 1 read, 0 none set, <0 not readable */
    char         alpha2[3];
    /* Clock. */
    time_t       now;
    int          sync_known, synced;   /* adjtimex(2), modes 0 */
    int          gps_rc;          /* 1 answered, 0 did not, -1 not checked */
    char         gps_detail[240];
    /* Intel pack (compiled in). */
    const char  *intel_version, *intel_hash, *intel_date;
    /* Storage. */
    int          n_path;
    pf_path_t    path[PF_MAX_PATHS];
    int          db_exists;       /* 1, 0, -1 not visible to this account */
    long long    db_bytes;
    int          db_rc;           /* 0 read, -1 not a database this reads,
                                   * -2 not readable by this account */
    int          db_version;      /* meta schema_version, -1 no row, 0 a row
                                   * that holds no version (refused at start) */
    long long    db_wal_bytes;    /* -wal beside it, -1 none */
    char         db_err[160];
    int          db_current;      /* DB_SCHEMA_VERSION */
    int          db_migrates_from;
    int          pcap_eapol_same; /* --pcap-dir and --eapol-dir one directory */
    /* Sources. */
    int          bt_controllers;  /* entries under /sys/class/bluetooth, -1 unreadable */
    /* Stat results: -3 is "not visible to the account running the
     * preflight" (EACCES on a directory on the way), never "missing". */
    int          bt_capture_rc;   /* 0 FIFO, 1 regular file, -1 missing, -2 other type, -3 */
    int          gps_serial_rc;   /* 0 char device, -1 missing, -2 not a char device, -3 */
    int          replay_rc[PF_MAX_REPLAY];   /* 0 regular file, -1 missing, -2 not regular, -3 */
    int          baseline_rc;
    int          sock_dir_rc;     /* unix: parent 0 ok, -1 missing, -2 not writable; 1 tcp */
    /* Host, through sys_status's readers. */
    int          has_undervolt, undervolt;
    int          has_temp;
    double       hottest_c;
    char         hottest_label[48];
} pf_facts_t;

typedef struct {
    const char *check;        /* "radios", "clock", "storage", ... */
    char        item[40];     /* "wlan1", "regdom", "db" */
    pf_level_t  level;
    char        reason[400];
} pf_line_t;

#define PF_MAX_LINES 64
typedef struct {
    int       n;
    pf_line_t line[PF_MAX_LINES];
    /* Check 8: the rule statuses this configuration would have. */
    int       assessed;       /* 0: a --replay run, not assessed */
    cov_env_t env;
    int       observable, partly, blind;
    uint8_t   st[ALERT_TYPE_COUNT];
    uint8_t   why[ALERT_TYPE_COUNT];
} pf_result_t;

/* The read-only probes that are not file reads, as hooks so a test can
 * stand in for nl80211 and gpsd. preflight_default_ops() gives the
 * real ones. Each returns as documented on pf_facts_t. */
typedef struct {
    int (*reg)(char alpha2[3]);
    int (*phy_iftypes)(int phy_index, unsigned *mask);
    int (*gpsd)(const char *host, int port, int timeout_ms,
                char *detail, size_t detail_sz);
    int (*clock_sync)(int *synced);
} pf_ops_t;
const pf_ops_t *preflight_default_ops(void);

/* Disk encryption under a filesystem (#251 part 2), read through
 * sys_status's guarded readers, so no root and the fake platform in
 * tests: /sys/dev/block/MAJ:MIN is the block device st_dev names; a
 * device-mapper node there has dm/uuid, "CRYPT-..." for dm-crypt (LUKS
 * and plain), and its slaves/ are walked (LVM on LUKS is an LVM node
 * over a CRYPT one). 1 dm-crypt found, `what` its name; 0 a block
 * device and nothing under it is dm-crypt; -1 cannot tell: no
 * /sys/dev/block entry (tmpfs, btrfs, ZFS, overlayfs and NFS report a
 * device number that is not a block device) or a layer unreadable.
 * What 0 does not exclude: fscrypt (per-directory, ext4/f2fs) and a
 * self-encrypting drive, neither of which this reads. */
int pf_block_crypt(unsigned maj, unsigned min, char *what, size_t whatsz);

/* Gather. Reads only; see the header comment. */
void preflight_gather(const pf_config_t *cfg, const pf_ops_t *ops,
                      pf_facts_t *facts);

/* The checks: pure over (cfg, facts), each appends its lines. */
void pf_check_radios(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r);
void pf_check_clock(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r);
void pf_check_storage(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r);
void pf_check_intel(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r);
void pf_check_sources(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r);
void pf_check_host(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r);
void pf_check_output(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r);
void pf_check_rules(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r);
/* All eight, in that order. */
void pf_run_checks(const pf_config_t *c, const pf_facts_t *f, pf_result_t *r);

/* The environment check 8 derives its statuses from. */
void pf_rule_env(const pf_config_t *c, const pf_facts_t *f, cov_env_t *env);

/* 2 when any line fails, 1 when any warns, else 0. */
int pf_exit_code(const pf_result_t *r);

/* The page, and the same as one JSON object (one line, newline-ended). */
void pf_print_text(const pf_result_t *r, FILE *out);
void pf_print_json(const pf_result_t *r, FILE *out);

/* One JSON string (RFC 8259 section 7) as the JSON page writes it: a
 * byte that does not start well-formed UTF-8 is U+FFFD. Shared with the
 * handoff packet's config.json (src/handoff.c). */
void pf_json_str(FILE *out, const char *s);

/* Gather with the default ops, check, print; returns the exit code. */
int preflight_main(const pf_config_t *cfg, int json, FILE *out);

/* Days from 1970-01-01 to "YYYY-MM-DD" at 00:00 UTC; -1 malformed. */
long pf_date_days(const char *ymd);

/* The intervals the checks use, each with its reason at its definition
 * in src/preflight.c. */
#define PF_INTEL_MAX_AGE_DAYS 90
#define PF_GPSD_TIMEOUT_MS    1500
/* Days an evidence capture may be kept on a disk with no dm-crypt under
 * it before --preflight warns (#251): handshake.retention_days'
 * default, the shortest window sloth ships for anything it keeps. */
#define PF_PLAIN_RETAIN_DAYS  7

#endif /* SLOTH_PREFLIGHT_H */
