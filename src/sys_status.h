#ifndef SLOTH_SYS_STATUS_H
#define SLOTH_SYS_STATUS_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"
#include "beacon_snoop.h"

/* ── Host status and the receiver inventory ──────────────────────────
 *
 * Three things sensor_health did not say:
 *
 *   sources    every source sloth can read, configured or not: the IP
 *              capture, the monitor radio, the HCI monitor channel, an
 *              Ubertooth stream, the GNSS receiver, the ADS-B and APRS
 *              decoders. A source the command line did not enable is
 *              listed as not_configured, so a consumer shows the whole
 *              set rather than only what works.
 *   receivers  the receiver hardware attached to the host, from sysfs:
 *              USB devices matched against sys_usb_table[], wireless
 *              interfaces and Bluetooth controllers by class. An SDR is
 *              usually owned by an external decoder (readsb, Dire Wolf,
 *              gpsd), so sloth sees its endpoint, not the dongle; this
 *              is where the dongle is named. A source is tied to a
 *              receiver only where sysfs says so (an interface or tty
 *              name under the device); a TCP endpoint to a decoder is
 *              never guessed at.
 *   system     CPU, load, memory, uptime, sloth's own RSS, the free
 *              space under the output path, every temperature and
 *              voltage the kernel exposes, the firmware's under-voltage
 *              alarm, and a battery or UPS.
 *
 * PASSIVE, AND NARROWER THAN THAT. Every figure is the text of a
 * regular file under /proc or /sys, read through g_platform.sys_read /
 * sys_list: no ioctl, no netlink, no device node opened (a tty open
 * raises DTR; that is a transmission), no helper executed. sys_rd() and
 * sys_ls() refuse any other path before the platform sees it, and the
 * Linux reader refuses anything that is not a regular file.
 *
 * WHAT IS LEFT OUT ON PURPOSE. A USB serial number: it identifies one
 * physical device for its whole life, the forensic log travels (to a
 * SIEM, into a bundle, to a colleague), and nothing here needs it -
 * the port path already tells two identical dongles apart on this host
 * without naming either to anyone else.
 *
 * Every string read from sysfs is device-supplied: a USB descriptor is
 * whatever the plugged-in thing says it is. Each is bounded, reduced to
 * printable ASCII (sys_clean_str) and leaves through the JSONL
 * emitter's escaping like any other string.
 *
 * A reading the host does not have is ABSENT, never zero: a VM has no
 * hwmon, a desktop has no under-voltage alarm, and "0.0 C" would be a
 * measurement nobody made.
 *
 * Cadence. The system is sampled every SYS_SAMPLE_SECS and written as
 * one batch (sys_status, its sys_sensor rows, every source_status and
 * receiver_hw) every SYS_EMIT_SECS: a fixed cadence, because the point
 * is a trend and sensor_health's 300 s heartbeat is too sparse for
 * one. A batch also goes out at once when a BAND gets worse (the
 * hottest temperature, CPU, memory, disk, the under-voltage alarm),
 * never when a figure moves and never for a recovery, which rides the
 * next minute's batch; the bands are held as well (sys_held_band). So
 * a value swinging across an edge adds at most one batch per band per
 * minute, where reporting every crossing wrote one per sample. A
 * source's row goes out on its own the moment its state or freshness
 * bucket changes. */

#define SYS_SAMPLE_SECS    10
#define SYS_EMIT_SECS      60
/* A source that last delivered longer ago than this is stale; the same
 * figure sensor_health's stale_state() uses for the pcap streams. */
#define SYS_SRC_STALE_S    60
#define SYS_SRC_OLD_S      3600

#define SYS_MAX_TEMPS      16
#define SYS_MAX_VOLTS      16
#define SYS_MAX_POWER      4
#define SYS_MAX_HW         16
#define SYS_HWMON_MAX      16     /* hwmon0 .. hwmon15 */
#define SYS_HWMON_CHANNELS 8      /* temp1..temp8, in0..in8 */
#define SYS_LIST_MAX       96
#define SYS_NAME_MAX       32

/* One sensor reading. `id` is where it came from ("thermal_zone0",
 * "hwmon1/temp2", "hwmon0/in0", "BAT0"), `label` what the kernel or
 * the device calls it. */
typedef struct {
    char   id[24];
    char   label[48];
    int    has_val;
    double val;             /* degrees C, or volts */
    int    has_alarm, alarm;   /* volts: inN_lcrit_alarm */
    int    has_capacity, capacity;   /* power: percent */
    char   status[24];      /* power: "Charging", "Discharging", ... */
} sys_reading_t;

/* One attached receiver. `key` is "usb:<port>", "net:<iface>" or
 * "bt:<hci>". */
typedef struct {
    char key[SYS_NAME_MAX + 4];
    char kind[20];          /* "sdr", "gnss", "wifi", "bluetooth", ... */
    char bus[8];            /* "usb", "pci", "sdio", "" unknown */
    char id[12];            /* "0bda:2838", "" unknown */
    char desc[56];          /* sys_usb_table[]'s name, "" when not in it */
    char vendor[32];        /* the device's own manufacturer string */
    char product[48];       /* the device's own product string */
    char driver[24];
    char slot[24];          /* PCI_SLOT_NAME, to merge two vifs of one chip */
    char ifaces[64];        /* "wlan1,wlan1mon", "ttyACM0", "hci0" */
    int  known;             /* matched sys_usb_table[] */
} sys_hw_t;

typedef enum {
    SYS_SRC_CAPTURE = 0, SYS_SRC_MONITOR, SYS_SRC_BTMON, SYS_SRC_BTCAP,
    SYS_SRC_GNSS, SYS_SRC_ADSB, SYS_SRC_APRS,
    SYS_SRC_COUNT
} sys_src_id_t;

typedef enum {
    SYS_ST_NOT_CONFIGURED = 0, SYS_ST_OK, SYS_ST_STALE, SYS_ST_DOWN
} sys_src_state_t;

/* -1 never, 0 within SYS_SRC_STALE_S, 1 within SYS_SRC_OLD_S, 2 older. */
int         sys_age_band(long long age_s);
const char *sys_age_band_name(int band);
const char *sys_src_state_name(int state);

typedef struct {
    const char *name;       /* "capture", "monitor", "btmon", ... */
    const char *flag;       /* the option that enables it */
    const char *unit;       /* what `count` counts */
    char   kind[20];        /* "wifi-monitor", "wifi-managed", "ip-capture", "bluetooth", ... */
    char   endpoint[64];
    char   detail[96];      /* the reader's own word and error, no moving figure */
    char   desc[56];        /* from the tied receiver, "" when none */
    char   driver[24];
    char   hw[SYS_NAME_MAX + 4];   /* the tied receiver's key, "" when none */
    int    state;           /* sys_src_state_t */
    long long age_s;        /* since it last delivered, -1 never */
    uint64_t count, errors;
    int    has_reconnects;
    uint64_t reconnects;
} sys_source_t;

typedef struct {
    int       valid;        /* a sample has been taken */
    uint32_t  seq;          /* the batch last written, 0 none yet */
    int       has_cpu;      /* needs two samples */
    double    cpu_pct, iowait_pct;
    int       has_load;
    double    load1, load5, load15;
    int       has_mem;
    long long mem_total_kb, mem_avail_kb;
    int       has_uptime;
    long long uptime_s;
    long long rss_kb;       /* sloth's own, -1 not measured */
    int       has_disk;
    long long disk_free_mb, disk_total_mb;
    char      disk_for[8];  /* "db" or "jsonl": which output path */
    int       ntemp, hottest;        /* hottest: index, -1 none */
    sys_reading_t temp[SYS_MAX_TEMPS];
    int       nvolt;
    sys_reading_t volt[SYS_MAX_VOLTS];
    int       has_undervolt, undervolt;
    int       npower;
    sys_reading_t power[SYS_MAX_POWER];
    int       nhw;
    sys_hw_t  hw[SYS_MAX_HW];
    sys_source_t src[SYS_SRC_COUNT];
    /* The held bands; -1 when the reading is absent. */
    int       temp_band, cpu_band, mem_band, disk_band;
    /* The forgotten-BSSID memory behind EVIL_TWIN's late-arrival
     * signal (beacon_recall_stat()), sampled with the system. Its
     * overflow and its quiet spell are each a band of two: going to 1
     * writes a batch at once, as a band getting worse does. */
    int       has_recall;
    beacon_recall_stat_t recall;
} sys_snapshot_t;

/* The poll loop's hook (health stage, after the per-source polls so
 * s->gps, s->adsb and s->aprs are this tick's). Samples when due,
 * rescans the receivers when a batch is due, and re-derives every
 * source row. */
void sys_status_poll(const sloth_state_t *s, time_t wall, uint64_t mono_ms);

/* The JSONL hook (jsonl_emit_state_snapshots): writes a due batch, or
 * the source rows whose state changed. Nothing before the first poll. */
void sys_status_emit(const sloth_state_t *s);

/* The output path whose filesystem is reported (main.c: --db, else
 * -o). `what` is "db" or "jsonl". NULL or "" clears it. */
void sys_status_set_disk_path(const char *path, const char *what);

const sys_snapshot_t *sys_status_get(void);
void sys_status_reset(void);

/* ── Parsers, exposed for tests. Each returns 0 on success and -1 with
 * its outputs untouched-or-zero on anything else; none reads past len. */

typedef struct { uint64_t total, idle, iowait; } sys_cpu_t;
/* /proc/stat: the aggregate "cpu " line, proc(5). idle and iowait are
 * kept apart: iowait is idle time, and reported on its own. */
int sys_parse_cpu(const char *text, int len, sys_cpu_t *out);
/* The busy and iowait share of the interval a -> b, percent. -1 when
 * the counters did not advance or ran backwards. */
int sys_cpu_delta(const sys_cpu_t *a, const sys_cpu_t *b,
                  double *busy_pct, double *iowait_pct);
int sys_parse_loadavg(const char *text, int len, double *l1, double *l5, double *l15);
int sys_parse_meminfo(const char *text, int len, long long *total_kb, long long *avail_kb);
int sys_parse_uptime(const char *text, int len, long long *secs);
/* One signed decimal integer and nothing else but surrounding
 * whitespace, within [lo, hi]. The form of every sysfs reading here. */
int sys_parse_int(const char *text, int len, long long lo, long long hi, long long *out);
/* "KEY=value" out of a uevent file; the value is cleaned. */
int sys_parse_uevent(const char *text, int len, const char *key, char *out, int cap);
/* Exactly four hex digits ("0bda\n"), lower-cased into out[5]. */
int sys_parse_hex4(const char *text, int len, char out[5]);
/* The first line of a device-supplied string: trimmed, bounded, every
 * byte outside printable ASCII replaced by '?'. */
void sys_clean_str(const char *text, int len, char *out, int cap);

/* band of v against ascending edges[n]: 0 below edges[0] ... n at or
 * above edges[n-1]. Held: a move up is taken at once, a move down only
 * once v is `margin` below the edge it leaves. prev -1 is no history. */
int sys_held_band(int prev, double v, const double *edges, int n, double margin);

/* The known-receiver table. Every row's ID is from the USB ID
 * repository (linux-usb.org usb.ids, version 2024.03.18); see the table
 * for what each kind means. */
typedef struct {
    uint16_t    vid, pid;
    const char *kind;
    const char *name;
} sys_usb_id_t;
extern const sys_usb_id_t sys_usb_table[];
extern const int          sys_usb_table_count;
const sys_usb_id_t *sys_usb_lookup(unsigned vid, unsigned pid);

/* The path guard: 1 when path is under /proc/ or /sys/ and has no ".."
 * component. sys_rd / sys_ls call nothing for a path that fails it. */
int sys_path_ok(const char *path);

/* The real readers, for a platform whose /proc and /sys are Linux's
 * (src/platform/linux.c). Regular files only: a path that resolves to
 * a device node, a FIFO or a socket is refused by stat() before any
 * open, and again by fstat() on the descriptor before any read. */
int sys_io_read_file(const char *path, char *buf, int cap);
int sys_io_list_dir(const char *dir, char *names, int name_sz, int max);

#endif /* SLOTH_SYS_STATUS_H */
