#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sys_status.h"
#include "adsb.h"
#include "aprs.h"
#include "ble_hci.h"
#include "bt_stream.h"
#include "capture/capture.h"
#include "fs_capacity.h"
#include "gps.h"
#include "jsonl.h"
#include "sensor_health.h"
#include "sloth_clock.h"

/* Contract, rationale and what is deliberately absent: sys_status.h. */

/* ── The known-receiver table ────────────────────────────────────────
 *
 * Source for every ID and name: the USB ID repository, linux-usb.org
 * usb.ids, version 2024.03.18 (the names are that file's, shortened).
 * An ID that file does not carry is not here, however well known.
 *
 * Kinds:
 *   sdr                a software-defined radio. What it is tuned to is
 *                      the decoder's business (readsb, Dire Wolf), not
 *                      something a USB ID says.
 *   gnss               a GNSS receiver with its own USB ID.
 *   serial             a USB-serial bridge. GNSS pucks and TNCs commonly
 *                      sit behind one, and the ID names the bridge, not
 *                      what is behind it - so it is listed as what it
 *                      is and never called a GPS.
 *   wifi               an adapter whose chipset has a monitor-mode
 *                      driver in common use.
 *   bluetooth          a host controller.
 *   bluetooth-sniffer  an Ubertooth. */
const sys_usb_id_t sys_usb_table[] = {
    { 0x0bda, 0x2832, "sdr", "Realtek RTL2832U DVB-T (RTL-SDR)" },
    { 0x0bda, 0x2838, "sdr", "Realtek RTL2838 DVB-T (RTL-SDR)" },
    { 0x1d50, 0x60a1, "sdr", "Airspy" },
    { 0x03eb, 0x800c, "sdr", "Airspy HF+" },
    { 0x1d50, 0x6089, "sdr", "Great Scott Gadgets HackRF One" },
    { 0x1d50, 0x604b, "sdr", "HackRF Jawbreaker" },
    { 0x1d50, 0xcc15, "sdr", "rad1o badge (HackRF-compatible)" },
    { 0x1df7, 0x2500, "sdr", "SDRplay RSP1" },
    { 0x1df7, 0x3000, "sdr", "SDRplay RSP1a" },
    { 0x1d50, 0x6108, "sdr", "Myriad-RF LimeSDR" },
    { 0x2cf0, 0x5246, "sdr", "Nuand bladeRF" },
    { 0x2cf0, 0x5250, "sdr", "Nuand bladeRF 2.0 micro" },
    { 0x2500, 0x0020, "sdr", "Ettus USRP B210" },
    { 0x0456, 0xb673, "sdr", "Analog Devices ADALM-PLUTO" },
    { 0x1d50, 0x6002, "bluetooth-sniffer", "Ubertooth One" },
    { 0x1546, 0x01a5, "gnss", "u-blox 5" },
    { 0x1546, 0x01a6, "gnss", "u-blox 6" },
    { 0x1546, 0x01a7, "gnss", "u-blox 7" },
    { 0x1546, 0x01a8, "gnss", "u-blox 8" },
    { 0x091e, 0x0003, "gnss", "Garmin GPS (various models)" },
    { 0x0e8d, 0x3329, "gnss", "Qstarz BT-Q1000XT (MediaTek)" },
    { 0x067b, 0x2303, "serial", "Prolific PL2303 serial bridge" },
    { 0x10c4, 0xea60, "serial", "Silicon Labs CP210x UART bridge" },
    { 0x0403, 0x6001, "serial", "FTDI FT232 serial bridge" },
    { 0x1a86, 0x7523, "serial", "QinHeng CH340 serial bridge" },
    { 0x0cf3, 0x9271, "wifi", "Qualcomm Atheros AR9271 802.11n" },
    { 0x0bda, 0x8812, "wifi", "Realtek RTL8812AU 802.11ac" },
    { 0x0bda, 0x0811, "wifi", "Realtek 8812AU/8821AU 802.11ac" },
    { 0x0bda, 0x8813, "wifi", "Realtek RTL8814AU 802.11ac" },
    { 0x0bda, 0xb812, "wifi", "Realtek RTL88x2bu 802.11ac" },
    { 0x0e8d, 0x7612, "wifi", "MediaTek MT7612U 802.11ac" },
    { 0x148f, 0x5370, "wifi", "Ralink RT5370" },
    { 0x148f, 0x3070, "wifi", "Ralink RT2870/RT3070" },
    { 0x148f, 0x5572, "wifi", "Ralink RT5572" },
    { 0x8087, 0x0029, "bluetooth", "Intel AX200 Bluetooth" },
    { 0x8087, 0x0026, "bluetooth", "Intel AX201 Bluetooth" },
    { 0x8087, 0x0032, "bluetooth", "Intel AX210 Bluetooth" },
    { 0x8087, 0x0aaa, "bluetooth", "Intel 9460/9560 Bluetooth" },
    { 0x8087, 0x0a2b, "bluetooth", "Intel Bluetooth wireless interface" },
    { 0x8087, 0x07dc, "bluetooth", "Intel Bluetooth wireless interface" },
    { 0x0a12, 0x0001, "bluetooth", "Cambridge Silicon Radio Bluetooth dongle" },
    { 0x0a5c, 0x21e8, "bluetooth", "Broadcom BCM20702A0 Bluetooth 4.0" },
};
const int sys_usb_table_count =
    (int)(sizeof(sys_usb_table) / sizeof(sys_usb_table[0]));

const sys_usb_id_t *sys_usb_lookup(unsigned vid, unsigned pid) {
    for (int i = 0; i < sys_usb_table_count; i++)
        if (sys_usb_table[i].vid == vid && sys_usb_table[i].pid == pid)
            return &sys_usb_table[i];
    return NULL;
}

/* ── Parsers ─────────────────────────────────────────────────────── */

static const char *skip_sp(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    return p;
}

/* One run of decimal digits. -1 when there is none or it overflows. */
static int scan_u64(const char **pp, const char *end, uint64_t *out) {
    const char *p = skip_sp(*pp, end);
    if (p >= end || *p < '0' || *p > '9') return -1;
    uint64_t v = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        if (v > (UINT64_MAX - 9) / 10) return -1;
        v = v * 10 + (uint64_t)(*p - '0');
        p++;
    }
    *pp = p;
    *out = v;
    return 0;
}

/* "12.34": digits, optionally a point and more digits. The kernel
 * prints these with no sign and no exponent; anything else is refused.
 * The integer part is capped well under what a double holds exactly. */
static int scan_dec(const char **pp, const char *end, double *out) {
    const char *p = *pp;
    uint64_t ip;
    if (scan_u64(&p, end, &ip) != 0 || ip > 1000000000000ULL) return -1;
    double v = (double)ip;
    if (p < end && *p == '.') {
        p++;
        if (p >= end || *p < '0' || *p > '9') return -1;
        double scale = 0.1;
        int digits = 0;
        while (p < end && *p >= '0' && *p <= '9') {
            if (digits < 9) { v += (double)(*p - '0') * scale; scale /= 10.0; }
            digits++;
            p++;
        }
    }
    *pp = p;
    *out = v;
    return 0;
}

int sys_parse_cpu(const char *text, int len, sys_cpu_t *out) {
    if (!text || len < 5 || !out) return -1;
    const char *p = text, *end = text + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *eol = nl ? nl : end;
        /* "cpu " exactly: "cpu0" is one core, not the aggregate. */
        if (eol - p > 4 && memcmp(p, "cpu ", 4) == 0) {
            const char *q = p + 4;
            uint64_t f[8] = { 0 };
            int n = 0;
            while (n < 8 && scan_u64(&q, eol, &f[n]) == 0) n++;
            /* user nice system idle are the four every kernel has. */
            if (n < 4) return -1;
            uint64_t total = 0;
            for (int i = 0; i < n; i++) {
                if (f[i] > UINT64_MAX - total) return -1;
                total += f[i];
            }
            out->total  = total;
            out->idle   = f[3];
            out->iowait = n > 4 ? f[4] : 0;
            return 0;
        }
        p = nl ? nl + 1 : end;
    }
    return -1;
}

int sys_cpu_delta(const sys_cpu_t *a, const sys_cpu_t *b,
                  double *busy_pct, double *iowait_pct) {
    if (!a || !b || b->total <= a->total || b->idle < a->idle ||
        b->iowait < a->iowait)
        return -1;
    uint64_t dt = b->total - a->total;
    uint64_t di = b->idle - a->idle, dw = b->iowait - a->iowait;
    if (di > dt || dw > dt - di) return -1;
    *busy_pct   = 100.0 * (double)(dt - di - dw) / (double)dt;
    *iowait_pct = 100.0 * (double)dw / (double)dt;
    return 0;
}

int sys_parse_loadavg(const char *text, int len, double *l1, double *l5, double *l15) {
    if (!text || len <= 0) return -1;
    const char *p = text, *end = text + len;
    double v[3];
    for (int i = 0; i < 3; i++) {
        p = skip_sp(p, end);
        if (scan_dec(&p, end, &v[i]) != 0) return -1;
        /* A field must end at a space: "0.10abc" is not a load. */
        if (p >= end || *p != ' ') return -1;
    }
    *l1 = v[0]; *l5 = v[1]; *l15 = v[2];
    return 0;
}

/* The kB figure of a "Key:   1234 kB" line, -1 when absent. */
static long long meminfo_value(const char *text, int len, const char *key) {
    size_t kl = strlen(key);
    const char *p = text, *end = text + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *eol = nl ? nl : end;
        if ((size_t)(eol - p) > kl && memcmp(p, key, kl) == 0) {
            const char *q = p + kl;
            uint64_t v;
            if (scan_u64(&q, eol, &v) != 0 || v > (uint64_t)1 << 53) return -1;
            return (long long)v;
        }
        p = nl ? nl + 1 : end;
    }
    return -1;
}

int sys_parse_meminfo(const char *text, int len, long long *total_kb, long long *avail_kb) {
    if (!text || len <= 0) return -1;
    long long t = meminfo_value(text, len, "MemTotal:");
    long long a = meminfo_value(text, len, "MemAvailable:");
    /* More available than there is, is not a measurement. */
    if (t <= 0 || a < 0 || a > t) return -1;
    *total_kb = t;
    *avail_kb = a;
    return 0;
}

int sys_parse_uptime(const char *text, int len, long long *secs) {
    if (!text || len <= 0) return -1;
    const char *p = text, *end = text + len;
    double v;
    if (scan_dec(&p, end, &v) != 0) return -1;
    *secs = (long long)v;
    return 0;
}

int sys_parse_int(const char *text, int len, long long lo, long long hi, long long *out) {
    if (!text || len <= 0) return -1;
    const char *p = text, *end = text + len;
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
    int neg = 0;
    if (p < end && *p == '-') { neg = 1; p++; }
    uint64_t v;
    const char *q = p;
    /* scan_u64 skips blanks; a sign must be followed by a digit. */
    if (p >= end || *p < '0' || *p > '9' || scan_u64(&q, end, &v) != 0) return -1;
    while (q < end && (*q == ' ' || *q == '\t' || *q == '\n')) q++;
    if (q != end) return -1;
    if (v > (uint64_t)INT64_MAX) return -1;
    long long sv = neg ? -(long long)v : (long long)v;
    if (sv < lo || sv > hi) return -1;
    *out = sv;
    return 0;
}

void sys_clean_str(const char *text, int len, char *out, int cap) {
    if (!out || cap <= 0) return;
    out[0] = '\0';
    if (!text || len <= 0) return;
    const char *p = text, *end = text + len;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    int n = 0;
    while (p < end && *p != '\n' && *p != '\0' && n < cap - 1) {
        unsigned char c = (unsigned char)*p++;
        out[n++] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
    }
    while (n > 0 && out[n - 1] == ' ') n--;
    out[n] = '\0';
}

int sys_parse_uevent(const char *text, int len, const char *key, char *out, int cap) {
    if (!text || len <= 0 || !key || !out || cap <= 0) return -1;
    size_t kl = strlen(key);
    const char *p = text, *end = text + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *eol = nl ? nl : end;
        if ((size_t)(eol - p) > kl && memcmp(p, key, kl) == 0 && p[kl] == '=') {
            sys_clean_str(p + kl + 1, (int)(eol - p - (long)kl - 1), out, cap);
            return out[0] ? 0 : -1;
        }
        p = nl ? nl + 1 : end;
    }
    return -1;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int sys_parse_hex4(const char *text, int len, char out[5]) {
    if (!text || len < 4) return -1;
    for (int i = 0; i < 4; i++) {
        int h = hexval(text[i]);
        if (h < 0) return -1;
        out[i] = "0123456789abcdef"[h];
    }
    for (int i = 4; i < len; i++)
        if (text[i] != '\n' && text[i] != ' ') return -1;
    out[4] = '\0';
    return 0;
}

int sys_held_band(int prev, double v, const double *edges, int n, double margin) {
    int raw = 0;
    while (raw < n && v >= edges[raw]) raw++;
    if (prev < 0 || prev > n || raw >= prev) return raw;
    /* Leaving band `prev` downwards: only once clear of its lower edge. */
    int b = prev;
    while (b > raw && v < edges[b - 1] - margin) b--;
    return b;
}

int sys_age_band(long long age_s) {
    if (age_s < 0) return -1;
    if (age_s <= SYS_SRC_STALE_S) return 0;
    return age_s <= SYS_SRC_OLD_S ? 1 : 2;
}

const char *sys_age_band_name(int band) {
    switch (band) {
    case 0:  return "fresh";
    case 1:  return "stale";
    case 2:  return "old";
    default: return "never";
    }
}

const char *sys_src_state_name(int state) {
    switch (state) {
    case SYS_ST_OK:    return "ok";
    case SYS_ST_STALE: return "stale";
    case SYS_ST_DOWN:  return "down";
    default:           return "not_configured";
    }
}

/* ── The seam ────────────────────────────────────────────────────── */

int sys_path_ok(const char *path) {
    if (!path) return 0;
    if (strncmp(path, "/proc/", 6) != 0 && strncmp(path, "/sys/", 5) != 0) return 0;
    for (const char *p = path; *p; p++)
        if (p[0] == '/' && p[1] == '.' && p[2] == '.' && (p[3] == '/' || p[3] == '\0'))
            return 0;
    return 1;
}

static int sys_rd(const char *path, char *buf, int cap) {
    if (!g_platform.sys_read || cap < 2 || !sys_path_ok(path)) return -1;
    int n = g_platform.sys_read(path, buf, cap - 1);
    if (n < 0) return -1;
    if (n > cap - 1) n = cap - 1;
    buf[n] = '\0';
    return n;
}

/* An entry name fit to put back into a path: no separator, no dot
 * file, nothing outside printable ASCII. */
static int name_ok(const char *n) {
    if (!n || !n[0] || n[0] == '.') return 0;
    for (const char *p = n; *p; p++)
        if (*p == '/' || (unsigned char)*p <= 0x20 || (unsigned char)*p > 0x7e) return 0;
    return strlen(n) < SYS_NAME_MAX;
}

static int sys_ls(const char *dir, char names[][SYS_NAME_MAX], int max) {
    if (!g_platform.sys_list || !sys_path_ok(dir)) return -1;
    int n = g_platform.sys_list(dir, &names[0][0], SYS_NAME_MAX, max);
    if (n < 0) return -1;
    if (n > max) n = max;
    int k = 0;
    for (int i = 0; i < n; i++) {
        names[i][SYS_NAME_MAX - 1] = '\0';
        if (!name_ok(names[i])) continue;
        if (k != i) memcpy(names[k], names[i], SYS_NAME_MAX);
        k++;
    }
    return k;
}

int sys_io_read_file(const char *path, char *buf, int cap) {
    struct stat st;
    if (!path || !buf || cap <= 0) return -1;
    /* Before the open, not only after it: opening some device nodes is
     * itself an act (a tty raises DTR). */
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return -1; }
    int len = 0;
    while (len < cap) {
        ssize_t r = read(fd, buf + len, (size_t)(cap - len));
        if (r < 0) { close(fd); return -1; }   /* a faulted sensor reads EIO */
        if (r == 0) break;
        len += (int)r;
    }
    close(fd);
    return len;
}

int sys_io_list_dir(const char *dir, char *names, int name_sz, int max) {
    if (!dir || !names || name_sz < 2 || max <= 0) return -1;
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while (n < max && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (strlen(e->d_name) >= (size_t)name_sz) continue;
        snprintf(names + (size_t)n * (size_t)name_sz, (size_t)name_sz, "%s", e->d_name);
        n++;
    }
    closedir(d);
    return n;
}

/* ── Module state ────────────────────────────────────────────────── */

static struct {
    sys_snapshot_t snap;
    uint64_t  sample_ms, batch_ms, hw_ms;
    int       inited, sampled, batched, hw_scanned, batch_due;
    int       have_prev_cpu;
    sys_cpu_t prev_cpu;
    int       undervolt_emitted;        /* -1 absent */
    int       recall_emitted[2];        /* overflowed, quiet; -1 none yet */
    int       bands_emitted[4];
    int       cap_wireless;
    char      cap_wireless_for[32];
    char      disk_dir[256];
    char      disk_what[8];
    /* Per source: when its count last advanced (gnss and aprs keep no
     * arrival clock of their own), and what was last written. */
    struct {
        int      tracked;
        uint64_t track_count, advance_ms;
        int      advanced;
        uint64_t sig, sig_emitted;
        int      emitted;
        uint64_t emit_ms, emit_count;
    } st[SYS_SRC_COUNT];
} g;

/* The "absent" values a zeroed struct does not have. Separate from the
 * reset so the first poll of a process does not clear the disk path
 * main() set before it. */
static void init_sentinels(void) {
    g.inited = 1;
    g.snap.hottest = -1;
    g.snap.rss_kb = -1;
    g.snap.temp_band = g.snap.cpu_band = g.snap.mem_band = g.snap.disk_band = -1;
}

void sys_status_reset(void) {
    memset(&g, 0, sizeof(g));
    init_sentinels();
}

const sys_snapshot_t *sys_status_get(void) { return &g.snap; }

void sys_status_set_disk_path(const char *path, const char *what) {
    g.disk_dir[0] = '\0';
    g.disk_what[0] = '\0';
    if (!path || !path[0]) return;
    const char *slash = strrchr(path, '/');
    if (!slash) snprintf(g.disk_dir, sizeof(g.disk_dir), ".");
    else if (slash == path) snprintf(g.disk_dir, sizeof(g.disk_dir), "/");
    else if ((size_t)(slash - path) < sizeof(g.disk_dir))
        snprintf(g.disk_dir, sizeof(g.disk_dir), "%.*s", (int)(slash - path), path);
    else return;
    snprintf(g.disk_what, sizeof(g.disk_what), "%s", what ? what : "");
}

/* ── System sample ───────────────────────────────────────────────── */

static const double TEMP_EDGES[] = { 60.0, 70.0, 80.0 };
static const double CPU_EDGES[]  = { 50.0, 80.0, 95.0 };
/* Memory and disk as the share in use, so higher is worse like the
 * other two. */
static const double MEM_EDGES[]  = { 80.0, 90.0 };
static const double DISK_EDGES[] = { 85.0, 95.0 };
static const char *const TEMP_BAND[] = { "ok", "warm", "hot", "critical" };
static const char *const CPU_BAND[]  = { "low", "busy", "high", "saturated" };
static const char *const USE_BAND[]  = { "ok", "low", "critical" };

static int rd_int(const char *path, long long lo, long long hi, long long *out) {
    char b[64];
    int n = sys_rd(path, b, (int)sizeof(b));
    return n < 0 ? -1 : sys_parse_int(b, n, lo, hi, out);
}

static void rd_str(const char *path, char *out, int cap) {
    char b[128];
    int n = sys_rd(path, b, (int)sizeof(b));
    out[0] = '\0';
    if (n > 0) sys_clean_str(b, n, out, cap);
}

static void sample_thermal_zones(sys_snapshot_t *sn) {
    char path[96];
    /* Zones are numbered without gaps; the first one missing ends it. */
    for (int z = 0; z < SYS_MAX_TEMPS && sn->ntemp < SYS_MAX_TEMPS; z++) {
        long long mc;
        snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", z);
        int have = rd_int(path, -100000, 250000, &mc) == 0;
        snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/type", z);
        char type[48];
        rd_str(path, type, (int)sizeof(type));
        if (!have && !type[0]) break;
        if (!have) continue;        /* a zone that is there and not reading */
        sys_reading_t *r = &sn->temp[sn->ntemp++];
        memset(r, 0, sizeof(*r));
        snprintf(r->id, sizeof(r->id), "thermal_zone%d", z);
        snprintf(r->label, sizeof(r->label), "%s", type);
        r->has_val = 1;
        r->val = (double)mc / 1000.0;
    }
}

static void sample_hwmon(sys_snapshot_t *sn) {
    char path[96], name[24], lab[24];
    for (int h = 0; h < SYS_HWMON_MAX; h++) {
        snprintf(path, sizeof(path), "/sys/class/hwmon/hwmon%d/name", h);
        rd_str(path, name, (int)sizeof(name));
        if (!name[0]) continue;     /* hwmon numbers can have gaps */
        for (int c = 1; c <= SYS_HWMON_CHANNELS && sn->ntemp < SYS_MAX_TEMPS; c++) {
            long long mc;
            snprintf(path, sizeof(path), "/sys/class/hwmon/hwmon%d/temp%d_input", h, c);
            if (rd_int(path, -100000, 250000, &mc) != 0) continue;
            snprintf(path, sizeof(path), "/sys/class/hwmon/hwmon%d/temp%d_label", h, c);
            rd_str(path, lab, (int)sizeof(lab));
            sys_reading_t *r = &sn->temp[sn->ntemp++];
            memset(r, 0, sizeof(*r));
            snprintf(r->id, sizeof(r->id), "hwmon%d/temp%d", h, c);
            snprintf(r->label, sizeof(r->label), "%s%s%s", name, lab[0] ? " " : "", lab);
            r->has_val = 1;
            r->val = (double)mc / 1000.0;
        }
        for (int c = 0; c <= SYS_HWMON_CHANNELS && sn->nvolt < SYS_MAX_VOLTS; c++) {
            long long mv, al;
            snprintf(path, sizeof(path), "/sys/class/hwmon/hwmon%d/in%d_input", h, c);
            int have_v = rd_int(path, -100000, 100000, &mv) == 0;
            /* The Raspberry Pi firmware's under-voltage flag is an alarm
             * with no reading beside it (rpi_volt, in0_lcrit_alarm). */
            snprintf(path, sizeof(path), "/sys/class/hwmon/hwmon%d/in%d_lcrit_alarm", h, c);
            int have_a = rd_int(path, 0, 1, &al) == 0;
            if (!have_v && !have_a) continue;
            snprintf(path, sizeof(path), "/sys/class/hwmon/hwmon%d/in%d_label", h, c);
            rd_str(path, lab, (int)sizeof(lab));
            sys_reading_t *r = &sn->volt[sn->nvolt++];
            memset(r, 0, sizeof(*r));
            snprintf(r->id, sizeof(r->id), "hwmon%d/in%d", h, c);
            snprintf(r->label, sizeof(r->label), "%s%s%s", name, lab[0] ? " " : "", lab);
            if (have_v) { r->has_val = 1; r->val = (double)mv / 1000.0; }
            if (have_a) {
                r->has_alarm = 1;
                r->alarm = (int)al;
                sn->has_undervolt = 1;
                if (al) sn->undervolt = 1;
            }
        }
    }
}

static void sample_power(sys_snapshot_t *sn) {
    char names[SYS_MAX_POWER * 2][SYS_NAME_MAX], path[128];
    int n = sys_ls("/sys/class/power_supply", names, SYS_MAX_POWER * 2);
    for (int i = 0; i < n && sn->npower < SYS_MAX_POWER; i++) {
        sys_reading_t r;
        long long uv, cap;
        memset(&r, 0, sizeof(r));
        snprintf(r.id, sizeof(r.id), "%.*s", (int)sizeof(r.id) - 1, names[i]);
        snprintf(path, sizeof(path), "/sys/class/power_supply/%.31s/type", names[i]);
        rd_str(path, r.label, (int)sizeof(r.label));
        snprintf(path, sizeof(path), "/sys/class/power_supply/%.31s/voltage_now", names[i]);
        if (rd_int(path, 0, 100000000, &uv) == 0) { r.has_val = 1; r.val = (double)uv / 1e6; }
        snprintf(path, sizeof(path), "/sys/class/power_supply/%.31s/capacity", names[i]);
        if (rd_int(path, 0, 100, &cap) == 0) { r.has_capacity = 1; r.capacity = (int)cap; }
        snprintf(path, sizeof(path), "/sys/class/power_supply/%.31s/status", names[i]);
        rd_str(path, r.status, (int)sizeof(r.status));
        /* A supply that says nothing about itself is not a row. */
        if (!r.has_val && !r.has_capacity && !r.status[0]) continue;
        sn->power[sn->npower++] = r;
    }
}

static void sample_system(void) {
    sys_snapshot_t *sn = &g.snap;
    char b[4096];
    int n;

    sn->has_cpu = 0;
    if ((n = sys_rd("/proc/stat", b, (int)sizeof(b))) > 0) {
        sys_cpu_t now;
        if (sys_parse_cpu(b, n, &now) == 0) {
            if (g.have_prev_cpu &&
                sys_cpu_delta(&g.prev_cpu, &now, &sn->cpu_pct, &sn->iowait_pct) == 0)
                sn->has_cpu = 1;
            g.prev_cpu = now;
            g.have_prev_cpu = 1;
        } else g.have_prev_cpu = 0;
    } else g.have_prev_cpu = 0;

    sn->has_load = (n = sys_rd("/proc/loadavg", b, (int)sizeof(b))) > 0 &&
                   sys_parse_loadavg(b, n, &sn->load1, &sn->load5, &sn->load15) == 0;
    sn->has_mem = (n = sys_rd("/proc/meminfo", b, (int)sizeof(b))) > 0 &&
                  sys_parse_meminfo(b, n, &sn->mem_total_kb, &sn->mem_avail_kb) == 0;
    sn->has_uptime = (n = sys_rd("/proc/uptime", b, (int)sizeof(b))) > 0 &&
                     sys_parse_uptime(b, n, &sn->uptime_s) == 0;
    sn->rss_kb = -1;
    if ((n = sys_rd("/proc/self/status", b, (int)sizeof(b))) > 0) {
        long long hwm;
        sh_mem_parse_status(b, n, &sn->rss_kb, &hwm);
    }

    sn->ntemp = sn->nvolt = sn->npower = 0;
    sn->has_undervolt = sn->undervolt = 0;
    sample_thermal_zones(sn);
    sample_hwmon(sn);
    sample_power(sn);
    sn->hottest = -1;
    for (int i = 0; i < sn->ntemp; i++)
        if (sn->hottest < 0 || sn->temp[i].val > sn->temp[sn->hottest].val)
            sn->hottest = i;

    beacon_recall_stat(&sn->recall, sloth_mono_ms());
    sn->has_recall = 1;

    sn->temp_band = sn->hottest < 0 ? -1
        : sys_held_band(sn->temp_band, sn->temp[sn->hottest].val, TEMP_EDGES, 3, 2.0);
    /* CPU keeps its band across a sample with no figure (the first, or
     * a counter that ran backwards): absence is not a change. */
    if (sn->has_cpu)
        sn->cpu_band = sys_held_band(sn->cpu_band, sn->cpu_pct, CPU_EDGES, 3, 5.0);
    sn->mem_band = !sn->has_mem ? -1
        : sys_held_band(sn->mem_band,
                        100.0 - 100.0 * (double)sn->mem_avail_kb / (double)sn->mem_total_kb,
                        MEM_EDGES, 2, 3.0);
}

static void probe_disk(void) {
    sys_snapshot_t *sn = &g.snap;
    sn->has_disk = 0;
    if (!g.disk_dir[0]) { sn->disk_band = -1; return; }
    int fd = open(g.disk_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) { sn->disk_band = -1; return; }
    fs_capacity_t c;
    if (fs_capacity_probe(fd, &c) == 0 && c.total_bytes > 0) {
        sn->has_disk = 1;
        sn->disk_free_mb  = (long long)(c.free_bytes / (1024u * 1024u));
        sn->disk_total_mb = (long long)(c.total_bytes / (1024u * 1024u));
        snprintf(sn->disk_for, sizeof(sn->disk_for), "%s", g.disk_what);
        sn->disk_band = sys_held_band(sn->disk_band,
            100.0 - 100.0 * (double)c.free_bytes / (double)c.total_bytes,
            DISK_EDGES, 2, 2.0);
    } else sn->disk_band = -1;
    close(fd);
}

/* ── Receiver inventory ──────────────────────────────────────────── */

static int csv_has(const char *csv, const char *name) {
    size_t nl = strlen(name);
    if (!nl) return 0;
    for (const char *p = csv; *p; ) {
        const char *c = strchr(p, ',');
        size_t tl = c ? (size_t)(c - p) : strlen(p);
        if (tl == nl && memcmp(p, name, nl) == 0) return 1;
        p = c ? c + 1 : p + tl;
    }
    return 0;
}

static void csv_add(char *csv, size_t cap, const char *name) {
    size_t have = strlen(csv), nl = strlen(name);
    if (!nl || csv_has(csv, name) || have + nl + 2 > cap) return;
    snprintf(csv + have, cap - have, "%s%s", have ? "," : "", name);
}

/* "1-1.2": a device, not a root hub ("usb1") and not an interface
 * ("1-1.2:1.0"). */
static int usb_dev_name(const char *n) {
    int dash = 0;
    for (const char *p = n; *p; p++) {
        if (*p == '-') dash = 1;
        else if (*p != '.' && (*p < '0' || *p > '9')) return 0;
    }
    return dash;
}

/* bus and id from a device uevent: PCI_ID=8086:2723, SDIO_ID=02D0:A9A6,
 * PRODUCT=bda/8812/0 (USB, hex without leading zeros). */
static void uevent_bus_id(const char *ue, int n, sys_hw_t *h) {
    char v[40];
    unsigned a, b;
    if (sys_parse_uevent(ue, n, "PCI_ID", v, (int)sizeof(v)) == 0 &&
        sscanf(v, "%4x:%4x", &a, &b) == 2) {
        snprintf(h->bus, sizeof(h->bus), "pci");
        snprintf(h->id, sizeof(h->id), "%04x:%04x", a & 0xffffu, b & 0xffffu);
        (void)sys_parse_uevent(ue, n, "PCI_SLOT_NAME", h->slot, (int)sizeof(h->slot));
    } else if (sys_parse_uevent(ue, n, "SDIO_ID", v, (int)sizeof(v)) == 0 &&
               sscanf(v, "%4x:%4x", &a, &b) == 2) {
        snprintf(h->bus, sizeof(h->bus), "sdio");
        snprintf(h->id, sizeof(h->id), "%04x:%04x", a & 0xffffu, b & 0xffffu);
    } else if (sys_parse_uevent(ue, n, "PRODUCT", v, (int)sizeof(v)) == 0 &&
               sscanf(v, "%4x/%4x/", &a, &b) == 2) {
        snprintf(h->bus, sizeof(h->bus), "usb");
        snprintf(h->id, sizeof(h->id), "%04x:%04x", a & 0xffffu, b & 0xffffu);
        const sys_usb_id_t *e = sys_usb_lookup(a, b);
        if (e) { h->known = 1; snprintf(h->desc, sizeof(h->desc), "%s", e->name); }
    }
}

static int hw_claims(const sys_snapshot_t *sn, const char *iface) {
    for (int i = 0; i < sn->nhw; i++)
        if (csv_has(sn->hw[i].ifaces, iface)) return i;
    return -1;
}

static void scan_usb(sys_snapshot_t *sn) {
    static char names[SYS_LIST_MAX][SYS_NAME_MAX];
    char sub[8][SYS_NAME_MAX], path[160], b[256], vid[5], pid[5];
    int n = sys_ls("/sys/bus/usb/devices", names, SYS_LIST_MAX);
    for (int i = 0; i < n && sn->nhw < SYS_MAX_HW; i++) {
        if (!usb_dev_name(names[i])) continue;
        int r;
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%.31s/idVendor", names[i]);
        if ((r = sys_rd(path, b, (int)sizeof(b))) < 0 || sys_parse_hex4(b, r, vid) != 0) continue;
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%.31s/idProduct", names[i]);
        if ((r = sys_rd(path, b, (int)sizeof(b))) < 0 || sys_parse_hex4(b, r, pid) != 0) continue;
        unsigned v, p;
        if (sscanf(vid, "%4x", &v) != 1 || sscanf(pid, "%4x", &p) != 1) continue;
        const sys_usb_id_t *e = sys_usb_lookup(v, p);
        /* A receiver inventory, not a USB dump: a keyboard is not news. */
        if (!e) continue;
        sys_hw_t *h = &sn->hw[sn->nhw++];
        memset(h, 0, sizeof(*h));
        snprintf(h->key, sizeof(h->key), "usb:%.31s", names[i]);
        snprintf(h->kind, sizeof(h->kind), "%.19s", e->kind);
        snprintf(h->bus, sizeof(h->bus), "usb");
        snprintf(h->id, sizeof(h->id), "%.31s:%.31s", vid, pid);
        snprintf(h->desc, sizeof(h->desc), "%s", e->name);
        h->known = 1;
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%.31s/manufacturer", names[i]);
        rd_str(path, h->vendor, (int)sizeof(h->vendor));
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%.31s/product", names[i]);
        rd_str(path, h->product, (int)sizeof(h->product));
        /* Its interfaces, "<device>:<config>.<n>": the driver bound to
         * one, and the netdev, hci or tty the kernel hung under it. */
        size_t dl = strlen(names[i]);
        for (int j = 0; j < n; j++) {
            if (strncmp(names[j], names[i], dl) != 0 || names[j][dl] != ':') continue;
            if (!h->driver[0]) {
                snprintf(path, sizeof(path), "/sys/bus/usb/devices/%.31s/uevent", names[j]);
                if ((r = sys_rd(path, b, (int)sizeof(b))) > 0)
                    (void)sys_parse_uevent(b, r, "DRIVER", h->driver, (int)sizeof(h->driver));
            }
            static const char *const kids[] = { "net", "bluetooth", "tty" };
            for (int k = 0; k < 3; k++) {
                snprintf(path, sizeof(path), "/sys/bus/usb/devices/%.31s/%.31s", names[j], kids[k]);
                int m = sys_ls(path, sub, 8);
                for (int q = 0; q < m; q++)
                    if (!strchr(sub[q], ':')) csv_add(h->ifaces, sizeof(h->ifaces), sub[q]);
            }
            /* usb-serial hangs ttyUSBn directly under the interface. */
            snprintf(path, sizeof(path), "/sys/bus/usb/devices/%.31s", names[j]);
            int m = sys_ls(path, sub, 8);
            for (int q = 0; q < m; q++)
                if (!strncmp(sub[q], "ttyUSB", 6)) csv_add(h->ifaces, sizeof(h->ifaces), sub[q]);
        }
    }
}

/* Wireless interfaces and Bluetooth controllers the USB pass did not
 * already account for: an on-board or PCI radio, or a USB one whose ID
 * is not in the table. */
static void scan_class(sys_snapshot_t *sn, const char *dir, const char *prefix,
                       const char *kind, int wireless_only) {
    char names[32][SYS_NAME_MAX], sub[1][SYS_NAME_MAX], path[160], b[512];
    int n = sys_ls(dir, names, 32);
    for (int i = 0; i < n && sn->nhw < SYS_MAX_HW; i++) {
        if (strchr(names[i], ':')) continue;         /* hci0:11 is a link */
        if (hw_claims(sn, names[i]) >= 0) continue;
        if (wireless_only) {
            snprintf(path, sizeof(path), "%.31s/%.31s/wireless", dir, names[i]);
            int w = sys_ls(path, sub, 1) >= 0;
            if (!w) {
                snprintf(path, sizeof(path), "%.31s/%.31s/phy80211", dir, names[i]);
                w = sys_ls(path, sub, 1) >= 0;
            }
            if (!w) continue;
        }
        sys_hw_t h;
        memset(&h, 0, sizeof(h));
        snprintf(h.key, sizeof(h.key), "%.3s:%.31s", prefix, names[i]);
        snprintf(h.kind, sizeof(h.kind), "%.19s", kind);
        snprintf(h.ifaces, sizeof(h.ifaces), "%.31s", names[i]);
        snprintf(path, sizeof(path), "%.31s/%.31s/device/uevent", dir, names[i]);
        int r = sys_rd(path, b, (int)sizeof(b));
        if (r > 0) {
            (void)sys_parse_uevent(b, r, "DRIVER", h.driver, (int)sizeof(h.driver));
            uevent_bus_id(b, r, &h);
        }
        /* A second interface of one chip (wlan0 and wlan0mon) joins its
         * row instead of adding one, where the uevent identifies the
         * chip: same bus, ID, slot and driver. */
        int merged = 0;
        for (int k = 0; k < sn->nhw && h.id[0]; k++) {
            sys_hw_t *o = &sn->hw[k];
            if (strncmp(o->key, prefix, strlen(prefix)) == 0 && !strcmp(o->bus, h.bus) &&
                !strcmp(o->id, h.id) && !strcmp(o->slot, h.slot) &&
                !strcmp(o->driver, h.driver)) {
                csv_add(o->ifaces, sizeof(o->ifaces), names[i]);
                merged = 1;
                break;
            }
        }
        if (!merged) sn->hw[sn->nhw++] = h;
    }
}

static void scan_hw(const sloth_state_t *s) {
    sys_snapshot_t *sn = &g.snap;
    sn->nhw = 0;
    scan_usb(sn);
    scan_class(sn, "/sys/class/net", "net", "wifi", 1);
    scan_class(sn, "/sys/class/bluetooth", "bt", "bluetooth", 0);
    /* Is the IP capture's interface a wireless one? Asked here, on the
     * receivers' cadence, not on every tick. */
    g.cap_wireless = 0;
    snprintf(g.cap_wireless_for, sizeof(g.cap_wireless_for), "%s", s->pkt_iface);
    if (name_ok(s->pkt_iface)) {
        char path[96], sub[1][SYS_NAME_MAX];
        snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", s->pkt_iface);
        g.cap_wireless = sys_ls(path, sub, 1) >= 0;
        if (!g.cap_wireless) {
            snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211", s->pkt_iface);
            g.cap_wireless = sys_ls(path, sub, 1) >= 0;
        }
    }
}

/* ── Sources ─────────────────────────────────────────────────────── */

static uint64_t fnv_str(uint64_t h, const char *s) {
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 1099511628211ULL; }
    h ^= 0xff; h *= 1099511628211ULL;
    return h;
}

/* Age from the count advancing, for a reader with no arrival clock. */
static long long track_age(int i, uint64_t count, uint64_t mono_ms) {
    if (!g.st[i].tracked) {
        g.st[i].tracked = 1;
        g.st[i].track_count = count;
        /* Whatever it already delivered arrived before we looked. */
        if (count > 0) { g.st[i].advanced = 1; g.st[i].advance_ms = mono_ms; }
    } else if (count != g.st[i].track_count) {
        g.st[i].track_count = count;
        g.st[i].advanced = 1;
        g.st[i].advance_ms = mono_ms;
    }
    if (!g.st[i].advanced) return -1;
    return (long long)((mono_ms - g.st[i].advance_ms) / 1000u);
}

static void pcap_source(sys_source_t *o, const capture_health_t *h, const char *err) {
    o->count  = h->ps_recv;
    o->errors = h->ps_drop + h->ps_ifdrop;
    o->age_s  = h->stale_secs;
    if (!h->open) {
        o->state = SYS_ST_DOWN;
        snprintf(o->detail, sizeof(o->detail), "%s", err && err[0] ? err : "not open");
    } else if (!h->running) {
        o->state = SYS_ST_DOWN;
        snprintf(o->detail, sizeof(o->detail), "exit: %s%s%.60s",
                 capture_exit_name((capture_exit_t)h->exit_reason),
                 h->exit_detail[0] ? ": " : "", h->exit_detail);
    } else if (h->stale_secs < 0) {
        o->state = SYS_ST_STALE;
        snprintf(o->detail, sizeof(o->detail), "no frame yet");
    } else {
        o->state = h->stale_secs > SYS_SRC_STALE_S ? SYS_ST_STALE : SYS_ST_OK;
    }
}

static void tie(sys_source_t *o, const char *iface) {
    int k = hw_claims(&g.snap, iface);
    if (k < 0) return;
    const sys_hw_t *h = &g.snap.hw[k];
    snprintf(o->hw, sizeof(o->hw), "%s", h->key);
    snprintf(o->desc, sizeof(o->desc), "%s", h->desc[0] ? h->desc : h->product);
    snprintf(o->driver, sizeof(o->driver), "%s", h->driver);
}

static void fill_sources(const sloth_state_t *s, uint64_t mono_ms) {
    sys_source_t *o;
    memset(g.snap.src, 0, sizeof(g.snap.src));

    o = &g.snap.src[SYS_SRC_CAPTURE];
    o->name = "capture"; o->flag = "--iface"; o->unit = "frames";
    o->age_s = -1;
    snprintf(o->endpoint, sizeof(o->endpoint), "%s", s->pkt_iface);
    snprintf(o->kind, sizeof(o->kind), "%s",
             s->pkt_linktype == 127 ? "wifi-monitor"
             : (g.cap_wireless && !strcmp(g.cap_wireless_for, s->pkt_iface))
               ? "wifi-managed" : "ip-capture");
    if (!s->pkt_iface[0]) {
#ifdef WITH_PCAP
        snprintf(o->detail, sizeof(o->detail), "no capture interface");
#else
        snprintf(o->detail, sizeof(o->detail), "built without libpcap");
#endif
    } else {
        pcap_source(o, &s->cap_health, "");
        tie(o, s->pkt_iface);
    }

    o = &g.snap.src[SYS_SRC_MONITOR];
    o->name = "monitor"; o->flag = "a monitor-mode interface"; o->unit = "frames";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "wifi-monitor");
    snprintf(o->endpoint, sizeof(o->endpoint), "%s", s->probe_iface);
    if (!s->probe_iface[0]) {
#ifdef WITH_PCAP
        snprintf(o->detail, sizeof(o->detail), "%s",
                 s->probe_err[0] ? s->probe_err : "no monitor-mode interface found");
#else
        snprintf(o->detail, sizeof(o->detail), "built without libpcap");
#endif
    } else {
        pcap_source(o, &s->mon_health, s->probe_err);
        tie(o, s->probe_iface);
    }

    o = &g.snap.src[SYS_SRC_BTMON];
    o->name = "btmon"; o->flag = "--bt-monitor"; o->unit = "records";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "bluetooth");
    snprintf(o->endpoint, sizeof(o->endpoint), "%s", s->bt_iface);
    if (!s->bt_iface[0]) {
        snprintf(o->detail, sizeof(o->detail), "%s", s->bt_err);
    } else {
        /* The monitor channel carries every controller: no one hci to
         * tie it to. */
        pcap_source(o, &s->bt_health, s->bt_err);
        o->count  = s->ble_host.records;
        o->errors = s->ble_host.malformed;
    }

    o = &g.snap.src[SYS_SRC_BTCAP];
    o->name = "btcap"; o->flag = "--bt-capture"; o->unit = "records";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "bluetooth-sniffer");
    if (s->btcap.configured) {
        const bt_capture_health_t *c = &s->btcap;
        snprintf(o->endpoint, sizeof(o->endpoint), "%s", BT_CAPTURE_IFACE);
        o->count = c->recv; o->errors = c->drop; o->age_s = c->stale_secs;
        snprintf(o->detail, sizeof(o->detail), "%s%s%.70s", bt_cap_state_name(c->state),
                 c->err[0] ? ": " : "", c->err);
        if (c->state == BT_CAP_STREAMING)
            o->state = (c->stale_secs < 0 || c->stale_secs > SYS_SRC_STALE_S)
                       ? SYS_ST_STALE : SYS_ST_OK;
        else
            o->state = c->state == BT_CAP_WAITING ? SYS_ST_STALE : SYS_ST_DOWN;
    }

    o = &g.snap.src[SYS_SRC_GNSS];
    o->name = "gnss"; o->flag = "--gps"; o->unit = "sentences";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "gnss");
    if (s->gps.has_gps) {
        const gps_health_t *p = &s->gps;
        snprintf(o->endpoint, sizeof(o->endpoint), "%s", p->src);
        o->count = p->sentences;
        o->errors = p->bad_checksum + p->parse_errors;
        o->has_reconnects = 1; o->reconnects = p->reconnects;
        o->age_s = track_age(SYS_SRC_GNSS, p->sentences, mono_ms);
        /* Liveness is the receiver talking, not having a fix: a
         * receiver searching under a roof is a working source. The fix
         * state is the detail. */
        if (p->err[0]) {
            o->state = SYS_ST_DOWN;
            snprintf(o->detail, sizeof(o->detail), "%s: %.70s", gps_state_name(p->state), p->err);
        } else {
            o->state = (o->age_s < 0 || o->age_s > SYS_SRC_STALE_S) ? SYS_ST_STALE : SYS_ST_OK;
            snprintf(o->detail, sizeof(o->detail), "%s", gps_state_name(p->state));
        }
        /* Only a serial device names its hardware; gpsd is an endpoint. */
        if (!strncmp(p->src, "nmea:/dev/", 10)) {
            const char *base = strrchr(p->src, '/');
            if (base) tie(o, base + 1);
        }
    } else if (s->gps.has_fixed) {
        snprintf(o->detail, sizeof(o->detail), "--location only: a fixed position, no receiver");
    }

    o = &g.snap.src[SYS_SRC_ADSB];
    o->name = "adsb"; o->flag = "--adsb"; o->unit = "messages";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "adsb");
    if (s->adsb.configured) {
        const adsb_health_t *a = &s->adsb;
        snprintf(o->endpoint, sizeof(o->endpoint), "%s", a->src);
        o->count = a->messages; o->errors = a->read_errors + a->parse_errors;
        o->age_s = a->age_s;
        snprintf(o->detail, sizeof(o->detail), "%s%s%.70s", adsb_state_name(a->state),
                 a->err[0] ? ": " : "", a->err);
        o->state = a->state == ADSB_LIVE ? SYS_ST_OK
                 : a->state == ADSB_ERROR ? SYS_ST_DOWN : SYS_ST_STALE;
    }

    o = &g.snap.src[SYS_SRC_APRS];
    o->name = "aprs"; o->flag = "--aprs"; o->unit = "packets";
    o->age_s = -1;
    snprintf(o->kind, sizeof(o->kind), "aprs");
    if (s->aprs.configured) {
        const aprs_health_t *a = &s->aprs;
        snprintf(o->endpoint, sizeof(o->endpoint), "%s", a->src);
        o->count = a->packets; o->errors = a->read_errors + a->bad_lines;
        o->age_s = track_age(SYS_SRC_APRS, a->packets, mono_ms);
        snprintf(o->detail, sizeof(o->detail), "%s%s%s%.60s", aprs_state_name(a->state),
                 a->missing ? " (file not there yet)" : "", a->err[0] ? ": " : "", a->err);
        /* A quiet channel is not a fault (aprs_health_t): live stays ok
         * however old the last packet; its age says how quiet. */
        o->state = a->state == APRS_LIVE ? SYS_ST_OK
                 : a->state == APRS_ERROR ? SYS_ST_DOWN : SYS_ST_STALE;
    }

    for (int i = 0; i < SYS_SRC_COUNT; i++) {
        o = &g.snap.src[i];
        /* The state and the freshness BUCKET, never the age or a count:
         * each moves every second a source is working. */
        uint64_t h = 1469598103934665603ULL;
        h ^= (uint64_t)o->state;                 h *= 1099511628211ULL;
        h ^= (uint64_t)(sys_age_band(o->age_s) + 2); h *= 1099511628211ULL;
        h = fnv_str(h, o->kind);
        h = fnv_str(h, o->endpoint);
        h = fnv_str(h, o->detail);
        h = fnv_str(h, o->hw);
        g.st[i].sig = h;
    }
}

/* ── Poll ────────────────────────────────────────────────────────── */

void sys_status_poll(const sloth_state_t *s, time_t wall, uint64_t mono_ms) {
    (void)wall;
    if (!s) return;
    if (!g.inited) init_sentinels();
    if (!g.hw_scanned || mono_ms - g.hw_ms >= (uint64_t)SYS_EMIT_SECS * 1000u) {
        scan_hw(s);
        probe_disk();
        g.hw_scanned = 1;
        g.hw_ms = mono_ms;
    }
    if (!g.sampled || mono_ms - g.sample_ms >= (uint64_t)SYS_SAMPLE_SECS * 1000u) {
        sample_system();
        g.sampled = 1;
        g.sample_ms = mono_ms;
        g.snap.valid = 1;
        const sys_snapshot_t *sn = &g.snap;
        int uv = sn->has_undervolt ? sn->undervolt : -1;
        /* A band getting WORSE, between two bands that both exist. Not a
         * reading appearing or going away: the first CPU figure exists
         * only from the second sample, and that is not news worth a
         * batch of its own. And not a recovery, which waits for the
         * next minute's batch: a figure hovering at an edge (two CPU
         * readings ten seconds apart on the build host were 43 % and
         * 55 %, either side of the 50 % edge; an alarm toggling on a
         * marginal supply) would otherwise write a batch on every
         * swing. Each band can so add one batch after
         * a cadence batch that caught it low, and no more until the
         * next. */
        const int cur[7] = { sn->temp_band, sn->cpu_band, sn->mem_band, sn->disk_band, uv,
                             sn->recall.overflowed, sn->recall.quiet };
        const int was[7] = { g.bands_emitted[0], g.bands_emitted[1], g.bands_emitted[2],
                             g.bands_emitted[3], g.undervolt_emitted,
                             g.recall_emitted[0], g.recall_emitted[1] };
        for (int i = 0; i < 7 && g.batched; i++)
            if (cur[i] >= 0 && was[i] >= 0 && cur[i] > was[i]) g.batch_due = 1;
    }
    if (!g.batched || mono_ms - g.batch_ms >= (uint64_t)SYS_EMIT_SECS * 1000u)
        g.batch_due = 1;
    fill_sources(s, mono_ms);
}

/* ── Emit ────────────────────────────────────────────────────────── */

#define FL_MAX 48
typedef struct { jsonl_field_t f[FL_MAX]; int n; } fl_t;

static void f_str(fl_t *l, const char *k, const char *v) {
    if (l->n < FL_MAX) l->f[l->n++] = (jsonl_field_t){ k, JSONL_F_STR, v, 0, 0.0, 0 };
}
static void f_int(fl_t *l, const char *k, long long v) {
    if (l->n < FL_MAX) l->f[l->n++] = (jsonl_field_t){ k, JSONL_F_INT, NULL, v, 0.0, 0 };
}
static void f_fix(fl_t *l, const char *k, double v, int dp) {
    if (l->n < FL_MAX) l->f[l->n++] = (jsonl_field_t){ k, JSONL_F_FIXED, NULL, 0, v, dp };
}

static void emit_source(int i, time_t wall, uint64_t now_ms) {
    const sys_source_t *o = &g.snap.src[i];
    fl_t l = { .n = 0 };
    f_int(&l, "seq", g.snap.seq);
    f_str(&l, "name", o->name);
    f_str(&l, "kind", o->kind);
    f_str(&l, "flag", o->flag);
    f_str(&l, "state", sys_src_state_name(o->state));
    f_str(&l, "detail", o->detail);
    f_str(&l, "endpoint", o->endpoint);
    /* What the kernel says the receiver is, only where sysfs ties this
     * source to one. */
    if (o->hw[0]) {
        f_str(&l, "hw", o->hw);
        f_str(&l, "desc", o->desc);
        f_str(&l, "driver", o->driver);
    }
    if (o->state != SYS_ST_NOT_CONFIGURED) {
        f_int(&l, "age_s", o->age_s);
        f_str(&l, "age_band", sys_age_band_name(sys_age_band(o->age_s)));
        f_str(&l, "unit", o->unit);
        f_int(&l, "count", (long long)o->count);
        /* Per second since this row was last written. Absent on the
         * first row and when the count ran backwards (a decoder
         * restarted): a rate nobody measured is not zero. */
        if (g.st[i].emitted && now_ms - g.st[i].emit_ms >= 1000u &&
            o->count >= g.st[i].emit_count)
            f_fix(&l, "rate", (double)(o->count - g.st[i].emit_count) * 1000.0 /
                              (double)(now_ms - g.st[i].emit_ms), 2);
        f_int(&l, "errors", (long long)o->errors);
        if (o->has_reconnects) f_int(&l, "reconnects", (long long)o->reconnects);
    }
    jsonl_emit_fields("source_status", wall, l.f, l.n);
    g.st[i].emitted = 1;
    g.st[i].emit_ms = now_ms;
    g.st[i].emit_count = o->count;
    g.st[i].sig_emitted = g.st[i].sig;
}

static void emit_reading(const char *cls, const sys_reading_t *r, time_t wall) {
    fl_t l = { .n = 0 };
    f_int(&l, "seq", g.snap.seq);
    f_str(&l, "class", cls);
    f_str(&l, "id", r->id);
    f_str(&l, "label", r->label);
    if (r->has_val) f_fix(&l, cls[0] == 't' ? "c" : "v", r->val, cls[0] == 't' ? 1 : 3);
    if (r->has_alarm) f_int(&l, "alarm", r->alarm);
    if (r->has_capacity) f_int(&l, "capacity", r->capacity);
    if (r->status[0]) f_str(&l, "status", r->status);
    jsonl_emit_fields("sys_sensor", wall, l.f, l.n);
}

static void emit_batch(time_t wall, uint64_t now_ms) {
    sys_snapshot_t *sn = &g.snap;
    sn->seq++;
    int ok = 0, down = 0, conf = 0;
    for (int i = 0; i < SYS_SRC_COUNT; i++) {
        if (sn->src[i].state != SYS_ST_NOT_CONFIGURED) conf++;
        if (sn->src[i].state == SYS_ST_OK) ok++;
        if (sn->src[i].state == SYS_ST_DOWN) down++;
    }
    fl_t l = { .n = 0 };
    f_int(&l, "seq", sn->seq);
    f_int(&l, "interval_s", SYS_EMIT_SECS);
    if (sn->has_cpu) {
        f_fix(&l, "cpu_pct", sn->cpu_pct, 1);
        f_fix(&l, "cpu_iowait_pct", sn->iowait_pct, 1);
    }
    if (sn->cpu_band >= 0) f_str(&l, "cpu_band", CPU_BAND[sn->cpu_band]);
    if (sn->has_load) {
        f_fix(&l, "load1", sn->load1, 2);
        f_fix(&l, "load5", sn->load5, 2);
        f_fix(&l, "load15", sn->load15, 2);
    }
    if (sn->has_mem) {
        f_int(&l, "mem_total_kb", sn->mem_total_kb);
        f_int(&l, "mem_avail_kb", sn->mem_avail_kb);
        f_str(&l, "mem_band", USE_BAND[sn->mem_band]);
    }
    if (sn->has_uptime) f_int(&l, "uptime_s", sn->uptime_s);
    if (sn->rss_kb >= 0) f_int(&l, "rss_kb", sn->rss_kb);
    if (sn->has_disk) {
        f_str(&l, "disk_for", sn->disk_for);
        f_int(&l, "disk_free_mb", sn->disk_free_mb);
        f_int(&l, "disk_total_mb", sn->disk_total_mb);
        f_str(&l, "disk_band", USE_BAND[sn->disk_band]);
    }
    f_int(&l, "temps", sn->ntemp);
    if (sn->hottest >= 0) {
        f_fix(&l, "temp_max_c", sn->temp[sn->hottest].val, 1);
        f_str(&l, "temp_max_id", sn->temp[sn->hottest].id);
        f_str(&l, "temp_band", TEMP_BAND[sn->temp_band]);
    }
    f_int(&l, "volts", sn->nvolt);
    if (sn->has_undervolt) f_int(&l, "undervolt", sn->undervolt);
    f_int(&l, "power", sn->npower);
    f_int(&l, "sources", SYS_SRC_COUNT);
    f_int(&l, "sources_configured", conf);
    f_int(&l, "sources_ok", ok);
    f_int(&l, "sources_down", down);
    f_int(&l, "receivers", sn->nhw);
    /* JSONL 1.2.0: appended, so every earlier field keeps its place. */
    if (sn->has_recall) {
        f_int(&l, "beacon_recall_slots", sn->recall.slots);
        f_int(&l, "beacon_recall_max", sn->recall.max);
        f_int(&l, "beacon_recall_overflowed", sn->recall.overflowed);
        if (sn->recall.overflowed) f_int(&l, "beacon_recall_reach_s", sn->recall.reach_s);
        f_int(&l, "beacon_recall_quiet", sn->recall.quiet);
        if (sn->recall.quiet) f_int(&l, "beacon_recall_quiet_s", sn->recall.quiet_s);
    }
    jsonl_emit_fields("sys_status", wall, l.f, l.n);

    for (int i = 0; i < sn->ntemp; i++)  emit_reading("temp", &sn->temp[i], wall);
    for (int i = 0; i < sn->nvolt; i++)  emit_reading("volt", &sn->volt[i], wall);
    for (int i = 0; i < sn->npower; i++) emit_reading("power", &sn->power[i], wall);
    for (int i = 0; i < SYS_SRC_COUNT; i++) emit_source(i, wall, now_ms);
    for (int i = 0; i < sn->nhw; i++) {
        const sys_hw_t *h = &sn->hw[i];
        fl_t r = { .n = 0 };
        f_int(&r, "seq", sn->seq);
        f_str(&r, "key", h->key);
        f_str(&r, "kind", h->kind);
        f_str(&r, "bus", h->bus);
        f_str(&r, "id", h->id);
        f_int(&r, "known", h->known);
        f_str(&r, "desc", h->desc);
        f_str(&r, "vendor", h->vendor);
        f_str(&r, "product", h->product);
        f_str(&r, "driver", h->driver);
        f_str(&r, "ifaces", h->ifaces);
        jsonl_emit_fields("receiver_hw", wall, r.f, r.n);
    }

    g.batched = 1;
    g.batch_due = 0;
    g.batch_ms = now_ms;
    g.bands_emitted[0] = sn->temp_band;
    g.bands_emitted[1] = sn->cpu_band;
    g.bands_emitted[2] = sn->mem_band;
    g.bands_emitted[3] = sn->disk_band;
    g.undervolt_emitted = sn->has_undervolt ? sn->undervolt : -1;
    g.recall_emitted[0] = sn->has_recall ? sn->recall.overflowed : -1;
    g.recall_emitted[1] = sn->has_recall ? sn->recall.quiet : -1;
}

void sys_status_emit(const sloth_state_t *s) {
    (void)s;
    if (!g.snap.valid) return;
    time_t wall = sloth_wall();
    uint64_t now_ms = sloth_mono_ms();
    if (g.batch_due) { emit_batch(wall, now_ms); return; }
    for (int i = 0; i < SYS_SRC_COUNT; i++)
        if (g.st[i].sig != g.st[i].sig_emitted) emit_source(i, wall, now_ms);
}
