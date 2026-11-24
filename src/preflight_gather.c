#include <errno.h>
#include <fcntl.h>
#include <sys/poll.h>  /* not <poll.h>: -Isrc puts src/poll.h first */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#ifdef __linux__
#include <sys/timex.h>
#endif

#include "preflight.h"
#include "db.h"
#include "fs_capacity.h"
#include "gps.h"
#include "intel_pack.h"
#include "sloth_clock.h"
#include "sys_status.h"
#ifdef PLATFORM_LINUX
#include "platform/linux_wifi.h"
#endif

/* src/preflight.h: what the host has, read and never changed. Every
 * read is named here with why it changes nothing:
 *
 *   /sys/class/net, /sys/class/bluetooth, thermal and hwmon
 *       sys_status's guarded readers: regular files under /sys only,
 *       through g_platform (the fake platform in tests)
 *   each output path    stat(2), access(2), and statvfs on its directory
 *                       opened O_RDONLY | O_DIRECTORY
 *   the database        db_probe_version(): immutable=1, read-only
 *   nl80211             GET_REG and GET_WIPHY, one reply each
 *   the clock           adjtimex(2) with modes 0, which reads
 *   gpsd                loopback only: connect, read the VERSION line
 *                       gpsd sends unasked, close; no byte written
 *   a serial receiver, the BLE FIFO, replay files    stat(2) only */

/* ── The default probes ────────────────────────────────────────── */

static int op_reg(char alpha2[3]) {
#ifdef PLATFORM_LINUX
    return linux_wifi_get_reg(alpha2);
#else
    alpha2[0] = '\0';
    return -EOPNOTSUPP;
#endif
}

static int op_phy_iftypes(int phy, unsigned *mask) {
#ifdef PLATFORM_LINUX
    return linux_wifi_phy_iftypes(phy, mask);
#else
    (void)phy;
    *mask = 0;
    return -EOPNOTSUPP;
#endif
}

static int op_clock_sync(int *synced) {
#ifdef __linux__
    struct timex tx;
    memset(&tx, 0, sizeof(tx));   /* modes 0: read, set nothing */
    int st = adjtimex(&tx);
    if (st < 0) return -1;
    *synced = st != TIME_ERROR && !(tx.status & STA_UNSYNC);
    return 0;
#else
    (void)synced;
    return -1;
#endif
}

static long long ms_left(uint64_t deadline) {
    uint64_t now = sloth_mono_ms();
    return now >= deadline ? 0 : (long long)(deadline - now);
}

static int op_gpsd(const char *host, int port, int timeout_ms, char *detail, size_t dsz) {
    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in  *a4 = (struct sockaddr_in *)&ss;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
    if (inet_pton(AF_INET, host, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port = htons((uint16_t)port);
        sl = sizeof(*a4);
    } else if (inet_pton(AF_INET6, host, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons((uint16_t)port);
        sl = sizeof(*a6);
    } else {
        snprintf(detail, dsz, "gpsd host %s is not a numeric address", host);
        return 0;
    }
    uint64_t deadline = sloth_mono_ms() + (uint64_t)timeout_ms;
    int fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        snprintf(detail, dsz, "gpsd at %s:%d: socket: %s", host, port, strerror(errno));
        return 0;
    }
    int ok = 0;
    if (connect(fd, (struct sockaddr *)&ss, sl) != 0 && errno != EINPROGRESS) {
        snprintf(detail, dsz, "gpsd at %s:%d: %s", host, port, strerror(errno));
        goto out;
    }
    struct pollfd p = { fd, POLLOUT, 0 };
    if (poll(&p, 1, (int)ms_left(deadline)) <= 0) {
        snprintf(detail, dsz, "gpsd at %s:%d: no connection within %d ms", host,
                 port, timeout_ms);
        goto out;
    }
    int soerr = 0;
    socklen_t el = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &el) != 0 || soerr) {
        snprintf(detail, dsz, "gpsd at %s:%d: %s", host, port,
                 strerror(soerr ? soerr : errno));
        goto out;
    }
    /* gpsd greets every client with its VERSION object; that read is the
     * whole exchange. Nothing is written: ?WATCH is the reader's. */
    char buf[512];
    size_t got = 0;
    while (got < sizeof(buf) - 1 && !memchr(buf, '\n', got)) {
        p.events = POLLIN;
        if (poll(&p, 1, (int)ms_left(deadline)) <= 0) break;
        ssize_t n = recv(fd, buf + got, sizeof(buf) - 1 - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
    buf[got] = '\0';
    if (strstr(buf, "\"class\":\"VERSION\"")) {
        char rel[24] = "";
        const char *v = strstr(buf, "\"release\":\"");
        if (v) {
            v += 11;
            size_t k = 0;
            while (v[k] && v[k] != '"' && k < sizeof(rel) - 1) {
                rel[k] = (v[k] >= 0x20 && v[k] < 0x7f) ? v[k] : '?';
                k++;
            }
            rel[k] = '\0';
        }
        snprintf(detail, dsz, "gpsd at %s:%d answered%s%s (connect and one read; "
                 "nothing sent)", host, port, rel[0] ? ", release " : "", rel);
        ok = 1;
    } else {
        snprintf(detail, dsz, "gpsd at %s:%d accepted the connection and sent no "
                 "VERSION line within %d ms", host, port, timeout_ms);
    }
out:
    close(fd);
    return ok;
}

static const pf_ops_t g_default_ops = { op_reg, op_phy_iftypes, op_gpsd, op_clock_sync };
const pf_ops_t *preflight_default_ops(void) { return &g_default_ops; }

/* ── Gathering ─────────────────────────────────────────────────── */

static int read_int(const char *path, long long lo, long long hi, long long *v) {
    char b[64];
    int n = sys_status_read(path, b, (int)sizeof(b));
    return n < 0 ? -1 : sys_parse_int(b, n, lo, hi, v);
}

static void gather_netdevs(const pf_ops_t *ops, pf_facts_t *f) {
    static char names[PF_MAX_NETDEV][SYS_NAME_MAX];
    int n = sys_status_list("/sys/class/net", names, PF_MAX_NETDEV);
    f->netdev_listed = n >= 0;
    f->n_netdev = 0;
    for (int i = 0; i < n && f->n_netdev < PF_MAX_NETDEV; i++) {
        if (strlen(names[i]) >= 16) continue;   /* not a kernel name */
        pf_netdev_t *d = &f->netdev[f->n_netdev];
        memset(d, 0, sizeof(*d));
        snprintf(d->name, sizeof(d->name), "%.15s", names[i]);
        char path[96], b[64];
        long long v;
        snprintf(path, sizeof(path), "/sys/class/net/%s/type", d->name);
        d->type = read_int(path, 0, 65535, &v) == 0 ? (int)v : -1;
        snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211/name", d->name);
        int k = sys_status_read(path, b, (int)sizeof(b));
        if (k > 0) sys_clean_str(b, k, d->phy, (int)sizeof(d->phy));
        snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211/index", d->name);
        d->phy_index = d->phy[0] && read_int(path, 0, 1000000, &v) == 0 ? (int)v : -1;
        f->n_netdev++;
    }
    /* One GET_WIPHY per phy, shared by the netdevs on it. */
    for (int i = 0; i < f->n_netdev; i++) {
        const pf_netdev_t *d = &f->netdev[i];
        if (d->phy_index < 0 || !ops->phy_iftypes) continue;
        int j;
        for (j = 0; j < i; j++)
            if (f->phy_iftypes_known[j] && f->netdev[j].phy_index == d->phy_index) break;
        if (j < i) {
            f->phy_iftypes[i] = f->phy_iftypes[j];
            f->phy_iftypes_known[i] = 1;
            continue;
        }
        unsigned mask = 0;
        if (ops->phy_iftypes(d->phy_index, &mask) == 1) {
            f->phy_iftypes[i] = mask;
            f->phy_iftypes_known[i] = 1;
        }
    }
}

static void dir_of(const char *path, char *out, size_t n) {
    const char *slash = strrchr(path, '/');
    if (!slash) snprintf(out, n, ".");
    else if (slash == path) snprintf(out, n, "/");
    else snprintf(out, n, "%.*s", (int)(slash - path), path);
}

static void add_path(pf_facts_t *f, const char *what, const char *path, int is_dir) {
    if (!path || !path[0] || f->n_path >= PF_MAX_PATHS) return;
    pf_path_t *p = &f->path[f->n_path++];
    memset(p, 0, sizeof(*p));
    p->what = what;
    p->path = path;
    struct stat sb;
    int exists = stat(path, &sb) == 0;
    p->creates = !exists;
    if (is_dir && exists && S_ISDIR(sb.st_mode)) snprintf(p->dir, sizeof(p->dir), "%s", path);
    else dir_of(path, p->dir, sizeof(p->dir));
    if (stat(p->dir, &sb) != 0) {
        p->denied = errno == EACCES;
        return;
    }
    p->dir_ok = S_ISDIR(sb.st_mode);
    if (!p->dir_ok) return;
    p->writable = access(p->dir, W_OK | X_OK) == 0;
    int fd = open(p->dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return;
    fs_capacity_t c;
    if (fs_capacity_probe(fd, &c) == 0 && c.total_bytes > 0) {
        p->has_fs = 1;
        p->free_bytes = c.free_bytes;
        p->total_bytes = c.total_bytes;
    }
    close(fd);
}

/* 0 FIFO, 1 regular, -1 missing, -2 another type, -3 not visible to
 * this account (a directory on the way is closed to it). */
static int stat_kind(const char *path) {
    struct stat sb;
    if (stat(path, &sb) != 0) return errno == EACCES ? -3 : -1;
    if (S_ISFIFO(sb.st_mode)) return 0;
    if (S_ISREG(sb.st_mode)) return 1;
    return -2;
}

static void gather_db(const pf_config_t *c, pf_facts_t *f) {
    f->db_current = db_schema_version();
    f->db_migrates_from = db_migrates_from();
    f->db_version = -1;
    f->db_wal_bytes = -1;
    if (!c->db) return;
    struct stat sb;
    if (stat(c->db, &sb) == 0) f->db_exists = 1;
    else f->db_exists = errno == EACCES ? -1 : 0;
    f->db_bytes = f->db_exists == 1 ? (long long)sb.st_size : 0;
    char wal[4096];
    snprintf(wal, sizeof(wal), "%s-wal", c->db);
    if (stat(wal, &sb) == 0) f->db_wal_bytes = (long long)sb.st_size;
    if (f->db_exists == 1 && f->db_bytes > 0 && c->have_sqlite) {
        if (access(c->db, R_OK) != 0)
            f->db_rc = -2;
        else
            f->db_rc = db_probe_version(c->db, &f->db_version, f->db_err,
                                        sizeof(f->db_err));
    }
}

static void gather_gps(const pf_config_t *c, const pf_ops_t *ops, pf_facts_t *f) {
    f->gps_rc = -1;
    f->gps_serial_rc = -1;
    if (!c->gps) return;
    gps_spec_t sp;
    char err[160];
    if (gps_spec_parse(c->gps, &sp, err, sizeof(err)) != 0) {
        snprintf(f->gps_detail, sizeof(f->gps_detail), "--gps %.60s: %.120s", c->gps, err);
        f->gps_rc = 0;
        return;
    }
    if (sp.kind == GPS_SPEC_SERIAL) {
        struct stat sb;
        if (stat(sp.path, &sb) != 0) f->gps_serial_rc = errno == EACCES ? -3 : -1;
        else f->gps_serial_rc = S_ISCHR(sb.st_mode) ? 0 : -2;
        return;
    }
    if (gps_spec_is_remote(&sp)) {
        snprintf(f->gps_detail, sizeof(f->gps_detail), "gpsd at %s:%d is not on "
                 "loopback, and the preflight dials loopback only", sp.host, sp.port);
        return;
    }
    if (ops->gpsd)
        f->gps_rc = ops->gpsd(sp.host, sp.port, PF_GPSD_TIMEOUT_MS, f->gps_detail,
                              sizeof(f->gps_detail));
}

static void gather_host(pf_facts_t *f) {
    static sys_snapshot_t sn;
    memset(&sn, 0, sizeof(sn));
    sys_status_sample_host(&sn);
    f->has_undervolt = sn.has_undervolt;
    f->undervolt = sn.undervolt;
    if (sn.hottest >= 0) {
        f->has_temp = 1;
        f->hottest_c = sn.temp[sn.hottest].val;
        snprintf(f->hottest_label, sizeof(f->hottest_label), "%s",
                 sn.temp[sn.hottest].label[0] ? sn.temp[sn.hottest].label
                                              : sn.temp[sn.hottest].id);
    }
}

static void gather_socket(const pf_config_t *c, pf_facts_t *f) {
    f->sock_dir_rc = 1;
    if (!c->data_socket || strncmp(c->data_socket, "unix:", 5) != 0) return;
    char dir[256];
    dir_of(c->data_socket + 5, dir, sizeof(dir));
    struct stat sb;
    if (stat(dir, &sb) != 0 || !S_ISDIR(sb.st_mode)) f->sock_dir_rc = -1;
    else f->sock_dir_rc = access(dir, W_OK | X_OK) == 0 ? 0 : -2;
}

void preflight_gather(const pf_config_t *c, const pf_ops_t *ops, pf_facts_t *f) {
    memset(f, 0, sizeof(*f));
    if (!ops) ops = preflight_default_ops();
    f->now = sloth_wall();
    if (ops->clock_sync && ops->clock_sync(&f->synced) == 0) f->sync_known = 1;

    gather_netdevs(ops, f);
    f->reg_rc = ops->reg ? ops->reg(f->alpha2) : -EOPNOTSUPP;

    f->intel_version = intel_pack_version();
    f->intel_hash = intel_pack_hash();
    f->intel_date = intel_pack_date();

    add_path(f, "db", c->db, 0);
    add_path(f, "jsonl", c->jsonl, 0);
    add_path(f, "pcap-dir", c->pcap_dir, 1);
    add_path(f, "eapol-dir", c->eapol_dir, 1);
    add_path(f, "report", c->report_md, 0);
    add_path(f, "report-json", c->report_json, 0);
    add_path(f, "snapshot", c->snapshot_out, 0);
    gather_db(c, f);

    gather_gps(c, ops, f);
    {
        static char names[16][SYS_NAME_MAX];
        int n = sys_status_list("/sys/class/bluetooth", names, 16);
        f->bt_controllers = 0;
        if (n < 0) f->bt_controllers = -1;
        for (int i = 0; i < n; i++)
            if (!strncmp(names[i], "hci", 3)) f->bt_controllers++;
    }
    f->bt_capture_rc = c->bt_capture ? stat_kind(c->bt_capture) : -1;
    for (int i = 0; i < c->n_replay && i < PF_MAX_REPLAY; i++) {
        int k = stat_kind(c->replay[i]);
        f->replay_rc[i] = k == 1 ? 0 : k < 0 ? k : -2;
    }
    if (c->baseline_in) {
        int k = stat_kind(c->baseline_in);
        f->baseline_rc = k == 1 ? 0 : k < 0 ? k : -2;
    }
    gather_socket(c, f);
    gather_host(f);
}

int preflight_main(const pf_config_t *cfg, int json, FILE *out) {
    static pf_facts_t f;
    static pf_result_t r;
    preflight_gather(cfg, preflight_default_ops(), &f);
    pf_run_checks(cfg, &f, &r);
    if (json) pf_print_json(&r, out);
    else pf_print_text(&r, out);
    fflush(out);
    return pf_exit_code(&r);
}
