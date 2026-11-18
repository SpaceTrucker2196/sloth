/* sloth-va — read the owner's Victron Energy devices over Bluetooth LE
 * and append what they report to a JSONL file sloth reads.
 *
 * THIS HELPER TRANSMITS. It is the first sloth-family component that
 * does, by the owner's decision of 2026-11-15, recorded with its scope
 * in docs/wiki/adr/0011-sloth-va-transmits.md. sloth itself is
 * unchanged: it links nothing from src/va/ (tests/test_va.c), reads
 * only the file this writes (`--victron PATH`), and its BT_OWN_TRANSMIT
 * alert reports these connections like any other from its host.
 *
 * What goes on the air, and only for devices the owner listed:
 *   - Instant Readout: nothing. The helper registers a BlueZ
 *     AdvertisementMonitor (pattern: manufacturer data starting with
 *     the Victron company id), which makes the kernel run a PASSIVE
 *     background scan with duplicate filtering off (net/bluetooth/
 *     hci_sync.c, hci_update_passive_scan_sync / hci_passive_scan_sync)
 *     — no SCAN_REQ. A device whose address is in victron.keys is
 *     decrypted with its key; every other advertisement is ignored
 *     unread.
 *   - GATT sessions: every --interval seconds per device listed in
 *     victron-va.conf (with a PIN), one at a time: LE connect, pair
 *     with the PIN if not bonded, write the keep-alive, read the values,
 *     disconnect. A session is bounded (SESSION_S) so the owner's phone
 *     app can connect in between. Only the 65970000 service Victron
 *     documented ([VCS] in va_victron.h) is read; a device without it
 *     gets one connection, its service list is recorded, and nothing is
 *     paired or written.
 *   - Learning: an address in victron.keys whose serial is unknown gets
 *     one unpaired connection so BlueZ reads its GAP name; a name that
 *     carries a configured serial maps the two (persisted in
 *     --state-dir). Nothing else is ever connected to.
 *
 * Secrets: the PINs and keys are read once at start from the files the
 * unit hands over with LoadCredential= (or --config/--keys), kept in
 * memory only, wiped at exit, and never printed: diagnostics name a
 * line number and a reason. The pairing agent answers only for the
 * device this helper is pairing right now, with that device's PIN, and
 * is never registered as the default agent.
 *
 * The decoding, the parsers and the record format are va_victron.c and
 * va_conf.c, tested without a radio. This file is the D-Bus glue and is
 * unverified until it meets the real devices (docs/wiki/victron.md).
 *
 * Exit: 0 stopped by SIGTERM/SIGINT, 1 failure, 2 usage or bad files. */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#include "va/va_aes.h"
#include "va/va_conf.h"
#include "va/va_victron.h"
#include "sloth_clock.h"

#define ME "sloth-va"

#define APP_ROOT      "/org/sloth/va"
#define MONITOR_PATH  "/org/sloth/va/m0"
#define AGENT_PATH    "/org/sloth/agent"

#define MAX_PEERS     (2 * VA_MAX_DEVICES)
#define SESSION_S     60          /* hard bound on one GATT session */
#define CALL_S        25          /* one D-Bus call to BlueZ */
#define TICK_S        5
#define LEARN_RETRY_S (6 * 3600)  /* an unmatched name, tried again */
#define FILE_MAX      (64 * 1024)

/* ── state ─────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t mac[6];
    char    path[96];
    int     conf;            /* index into g.dev, -1 unknown */
    int     key;             /* index into g.key, -1 none */
    int     learn_failed;    /* name read and unmatched */
    time_t  learn_after;
    time_t  next_gatt;
    time_t  last_write;      /* readout record */
    int     has_name;
    char    name[64];
    int     has_rssi;
    int     rssi;
    int     seen;            /* BlueZ has a Device1 object for it */
} peer_t;

typedef enum { S_IDLE = 0, S_CONNECT, S_RESOLVE, S_PAIR, S_KEEPALIVE, S_READ, S_DISCONNECT } sstate_t;

typedef struct {
    sstate_t  st;
    int       peer;
    int       learn;          /* name-only session */
    int       resolve_tries;
    time_t    started;
    const char *outcome;      /* JSONL session value */
    char      services[400];
    char      gatt_path[VA_MAX_VALUES][128];
    const va_gatt_char_t *gatt_char[VA_MAX_VALUES];
    int       ngatt, next_read;
    char      keepalive_path[128];
    va_value_t vals[VA_MAX_VALUES];
    int       nvals;
    int       paired;
    sd_bus_slot *pending;
    sd_event_source *deadline;
} session_t;

static struct {
    sd_bus   *bus;
    sd_event *ev;
    char      adapter[64];        /* /org/bluez/hciN */
    char      adapter_want[32];   /* as given */
    va_dev_conf_t dev[VA_MAX_DEVICES];
    int       ndev;
    va_key_t  key[VA_MAX_DEVICES];
    int       nkey;
    peer_t    peer[MAX_PEERS];
    int       npeer;
    session_t s;
    const char *out_path;
    const char *state_dir;
    unsigned  interval_s, readout_every_s, keepalive_ms;
    int       gatt_on;
    int       monitor_on;
    char      pair_path[96];      /* the one device the agent answers for */
} g;

static void logf_(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs(ME ": ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void mac_upper_path(const uint8_t m[6], char *out, size_t sz) {
    snprintf(out, sz, "%s/dev_%02X_%02X_%02X_%02X_%02X_%02X",
             g.adapter, m[0], m[1], m[2], m[3], m[4], m[5]);
}

static int peer_by_path(const char *path) {
    for (int i = 0; i < g.npeer; i++)
        if (!strcmp(g.peer[i].path, path)) return i;
    return -1;
}

static int peer_by_mac(const uint8_t m[6]) {
    for (int i = 0; i < g.npeer; i++)
        if (!memcmp(g.peer[i].mac, m, 6)) return i;
    return -1;
}

static const char *peer_serial(const peer_t *p) {
    return p->conf >= 0 ? g.dev[p->conf].serial : NULL;
}

/* ── files ─────────────────────────────────────────────────────────── */

/* Read a secret file whole. Refuses a world-readable one: a PIN or a
 * key another account can read is already leaked. */
static char *read_secret(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { logf_("cannot open %s: %s", path, strerror(errno)); return NULL; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > FILE_MAX) {
        logf_("%s: not a regular file under %d bytes", path, FILE_MAX);
        close(fd);
        return NULL;
    }
    if (st.st_mode & S_IROTH) {
        logf_("%s is world-readable; refusing it (chmod o-r)", path);
        close(fd);
        return NULL;
    }
    char *b = calloc(1, (size_t)st.st_size + 1);
    size_t got = 0;
    while (b && got < (size_t)st.st_size) {
        ssize_t r = read(fd, b + got, (size_t)st.st_size - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    return b;
}

static void free_secret(char *b) {
    if (!b) return;
    va_wipe(b, strlen(b));
    free(b);
}

typedef struct { const char *file; int bad; } diag_ctx_t;

static void diag(void *vctx, int line, va_conf_err_t why) {
    diag_ctx_t *c = vctx;
    c->bad++;
    /* The reason is fixed text; the line's content is never printed. */
    logf_("%s line %d ignored: %s", c->file, line, va_conf_err_name(why));
}

static void append_record(const va_record_t *r) {
    char line[2048];
    int n = va_record_jsonl(r, line, sizeof(line));
    if (n < 0) { logf_("record too long, dropped"); return; }
    int fd = open(g.out_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) { logf_("cannot open %s: %s", g.out_path, strerror(errno)); return; }
    ssize_t w = write(fd, line, (size_t)n);
    if (w != n) logf_("short write to %s", g.out_path);
    close(fd);
}

static void learned_path(char *out, size_t sz) {
    snprintf(out, sz, "%s/learned.map", g.state_dir);
}

/* learned.map: "MAC SERIAL" lines, written by this helper only. A line
 * naming a serial not in the config is ignored. */
static void load_learned(void) {
    char p[PATH_MAX];
    learned_path(p, sizeof(p));
    FILE *f = fopen(p, "r");
    if (!f) return;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        char mac_s[32], ser[32];
        uint8_t m[6];
        if (sscanf(line, "%31s %31s", mac_s, ser) != 2 || va_mac_parse(mac_s, m) != 0) continue;
        int pi = peer_by_mac(m);
        if (pi < 0 || g.peer[pi].conf >= 0) continue;
        for (int d = 0; d < g.ndev; d++)
            if (!strcmp(g.dev[d].serial, ser)) { g.peer[pi].conf = d; break; }
    }
    fclose(f);
}

static void save_learned(void) {
    char p[PATH_MAX], tmp[PATH_MAX + 8];
    learned_path(p, sizeof(p));
    snprintf(tmp, sizeof(tmp), "%s.tmp", p);
    FILE *f = fopen(tmp, "w");
    if (!f) { logf_("cannot write %s: %s", tmp, strerror(errno)); return; }
    for (int i = 0; i < g.npeer; i++) {
        const peer_t *pe = &g.peer[i];
        if (pe->conf < 0 || g.dev[pe->conf].has_mac) continue;
        char m[18];
        va_mac_str(pe->mac, m);
        fprintf(f, "%s %s\n", m, g.dev[pe->conf].serial);
    }
    if (fclose(f) != 0 || rename(tmp, p) != 0) logf_("cannot replace %s", p);
}

/* ── D-Bus property parsing ────────────────────────────────────────── */

typedef struct {
    int has_name;   char name[64];
    int has_paired; int paired;
    int has_conn;   int conn;
    int has_res;    int resolved;
    int has_rssi;   int rssi;
    int has_md;     uint8_t md[64]; size_t md_len;
    int has_uuid;   char uuid[48];
    int has_svc;    char svc[128];
} props_t;

/* Bounded copy, always terminated; a longer string is cut. */
static void copy_str(char *dst, size_t sz, const char *s) {
    size_t n = s ? strlen(s) : 0;
    if (n >= sz) n = sz - 1;
    if (n) memcpy(dst, s, n);
    dst[n] = '\0';
}

/* At an a{sv}: read what is known, skip the rest. */
static int read_props(sd_bus_message *m, props_t *p) {
    int r = sd_bus_message_enter_container(m, 'a', "{sv}");
    if (r < 0) return r;
    while ((r = sd_bus_message_enter_container(m, 'e', "sv")) > 0) {
        const char *k;
        if ((r = sd_bus_message_read(m, "s", &k)) < 0) return r;
        char t; const char *contents;
        if ((r = sd_bus_message_peek_type(m, &t, &contents)) < 0) return r;
        if (!strcmp(k, "Name") && contents && !strcmp(contents, "s")) {
            const char *s;
            if ((r = sd_bus_message_read(m, "v", "s", &s)) < 0) return r;
            p->has_name = 1; copy_str(p->name, sizeof(p->name), s);
        } else if ((!strcmp(k, "Paired") || !strcmp(k, "Connected") || !strcmp(k, "ServicesResolved"))
                   && contents && !strcmp(contents, "b")) {
            int b;
            if ((r = sd_bus_message_read(m, "v", "b", &b)) < 0) return r;
            if (k[0] == 'P')      { p->has_paired = 1; p->paired = b; }
            else if (k[0] == 'C') { p->has_conn = 1; p->conn = b; }
            else                  { p->has_res = 1; p->resolved = b; }
        } else if (!strcmp(k, "RSSI") && contents && !strcmp(contents, "n")) {
            int16_t v;
            if ((r = sd_bus_message_read(m, "v", "n", &v)) < 0) return r;
            p->has_rssi = 1; p->rssi = v;
        } else if (!strcmp(k, "UUID") && contents && !strcmp(contents, "s")) {
            const char *s;
            if ((r = sd_bus_message_read(m, "v", "s", &s)) < 0) return r;
            p->has_uuid = 1; copy_str(p->uuid, sizeof(p->uuid), s);
        } else if (!strcmp(k, "Service") && contents && !strcmp(contents, "o")) {
            const char *s;
            if ((r = sd_bus_message_read(m, "v", "o", &s)) < 0) return r;
            p->has_svc = 1; copy_str(p->svc, sizeof(p->svc), s);
        } else if (!strcmp(k, "ManufacturerData") && contents && !strcmp(contents, "a{qv}")) {
            if ((r = sd_bus_message_enter_container(m, 'v', "a{qv}")) < 0) return r;
            if ((r = sd_bus_message_enter_container(m, 'a', "{qv}")) < 0) return r;
            while ((r = sd_bus_message_enter_container(m, 'e', "qv")) > 0) {
                uint16_t cid;
                if ((r = sd_bus_message_read(m, "q", &cid)) < 0) return r;
                char t2; const char *c2;
                if ((r = sd_bus_message_peek_type(m, &t2, &c2)) < 0) return r;
                if (cid == VA_VICTRON_COMPANY_ID && c2 && !strcmp(c2, "ay")) {
                    const void *ptr; size_t len;
                    if ((r = sd_bus_message_enter_container(m, 'v', "ay")) < 0) return r;
                    if ((r = sd_bus_message_read_array(m, 'y', &ptr, &len)) < 0) return r;
                    if ((r = sd_bus_message_exit_container(m)) < 0) return r;
                    if (len <= sizeof(p->md)) {
                        memcpy(p->md, ptr, len);
                        p->md_len = len;
                        p->has_md = 1;
                    }
                } else if ((r = sd_bus_message_skip(m, "v")) < 0) return r;
                if ((r = sd_bus_message_exit_container(m)) < 0) return r;
            }
            if (r < 0) return r;
            if ((r = sd_bus_message_exit_container(m)) < 0) return r;
            if ((r = sd_bus_message_exit_container(m)) < 0) return r;
        } else if ((r = sd_bus_message_skip(m, "v")) < 0) return r;
        if ((r = sd_bus_message_exit_container(m)) < 0) return r;
    }
    if (r < 0) return r;
    return sd_bus_message_exit_container(m);
}

/* ── Instant Readout ───────────────────────────────────────────────── */

static void try_match_name(int pi) {
    peer_t *p = &g.peer[pi];
    if (p->conf >= 0 || !p->has_name) return;
    for (int d = 0; d < g.ndev; d++) {
        if (g.dev[d].has_mac) continue;          /* the owner placed it */
        int taken = 0;
        for (int j = 0; j < g.npeer; j++) if (g.peer[j].conf == d) taken = 1;
        if (taken || !va_name_has_serial(p->name, g.dev[d].serial)) continue;
        p->conf = d;
        char m[18];
        va_mac_str(p->mac, m);
        logf_("%s carries serial %s in its name: mapped", m, g.dev[d].serial);
        save_learned();
        return;
    }
}

static void on_device_props(const char *path, const props_t *pr) {
    int pi = peer_by_path(path);
    if (pi < 0) return;                       /* not the owner's: ignored unread */
    peer_t *p = &g.peer[pi];
    p->seen = 1;
    if (pr->has_name) { p->has_name = 1; copy_str(p->name, sizeof(p->name), pr->name); try_match_name(pi); }
    if (pr->has_rssi) { p->has_rssi = 1; p->rssi = pr->rssi; }
    if (!pr->has_md || p->key < 0) return;
    time_t now = sloth_wall();
    if (p->last_write && now - p->last_write < (time_t)g.readout_every_s) return;

    va_readout_t ro;
    va_ro_status_t st = va_readout_decode(pr->md, pr->md_len, g.key[p->key].key, &ro);
    if (st == VA_RO_NOT_PRODUCT_AD || st == VA_RO_TRUNCATED) return;
    if (st == VA_RO_KEY_MISMATCH) {
        if (!p->last_write) {
            char m[18];
            va_mac_str(p->mac, m);
            logf_("%s: key-check byte does not match the configured readout key; not decoding (changed with the device PIN?)", m);
        }
        p->last_write = now;
        return;
    }
    va_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.source = "readout";
    rec.t = (long long)now;
    memcpy(rec.mac, p->mac, 6);
    rec.serial = peer_serial(p);
    rec.label = p->has_name ? p->name : NULL;
    rec.has_model = 1;
    rec.model_id = ro.model_id;
    rec.record_type = ro.record_type;
    rec.has_rssi = p->has_rssi;
    rec.rssi = p->rssi;
    rec.nvals = ro.nvals;
    rec.vals = ro.vals;
    append_record(&rec);
    p->last_write = now;
}

static int on_props_changed(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)ud; (void)e;
    const char *iface;
    if (sd_bus_message_read(m, "s", &iface) < 0 || strcmp(iface, "org.bluez.Device1")) return 0;
    props_t pr;
    memset(&pr, 0, sizeof(pr));
    if (read_props(m, &pr) < 0) return 0;
    on_device_props(sd_bus_message_get_path(m), &pr);
    return 0;
}

static int on_ifaces_added(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)ud; (void)e;
    const char *path;
    if (sd_bus_message_read(m, "o", &path) < 0) return 0;
    if (sd_bus_message_enter_container(m, 'a', "{sa{sv}}") < 0) return 0;
    while (sd_bus_message_enter_container(m, 'e', "sa{sv}") > 0) {
        const char *iface;
        if (sd_bus_message_read(m, "s", &iface) < 0) return 0;
        if (!strcmp(iface, "org.bluez.Device1")) {
            props_t pr;
            memset(&pr, 0, sizeof(pr));
            if (read_props(m, &pr) < 0) return 0;
            on_device_props(path, &pr);
        } else if (sd_bus_message_skip(m, "a{sv}") < 0) return 0;
        if (sd_bus_message_exit_container(m) < 0) return 0;
    }
    return 0;
}

/* ── exported objects: the monitor and the agent ───────────────────── */

static int m_ack(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)ud; (void)e;
    return sd_bus_reply_method_return(m, "");
}

static int m_reject(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)ud; (void)m;
    return sd_bus_error_set(e, "org.bluez.Error.Rejected", "sloth-va answers only its own pairing");
}

/* The PIN for `path`, only when it is the device this helper is pairing
 * now; -1 otherwise. */
static long pin_for(const char *path) {
    if (!g.pair_path[0] || strcmp(path, g.pair_path)) return -1;
    int pi = peer_by_path(path);
    if (pi < 0 || g.peer[pi].conf < 0) return -1;
    return (long)g.dev[g.peer[pi].conf].pin;
}

static int m_passkey(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)ud;
    const char *dev;
    if (sd_bus_message_read(m, "o", &dev) < 0) return m_reject(m, ud, e);
    long pin = pin_for(dev);
    if (pin < 0) return m_reject(m, ud, e);
    return sd_bus_reply_method_return(m, "u", (uint32_t)pin);
}

static int m_pincode(sd_bus_message *m, void *ud, sd_bus_error *e) {
    const char *dev;
    if (sd_bus_message_read(m, "o", &dev) < 0) return m_reject(m, ud, e);
    long pin = pin_for(dev);
    if (pin < 0) return m_reject(m, ud, e);
    char s[8];
    unsigned long u = (unsigned long)pin % 1000000ul;   /* 6 digits by va_conf.c */
    for (int i = 5; i >= 0; i--) { s[i] = (char)('0' + u % 10); u /= 10; }
    s[6] = '\0';
    int r = sd_bus_reply_method_return(m, "s", s);
    va_wipe(s, sizeof(s));
    return r;
}

static const sd_bus_vtable agent_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Release", "", "", m_ack, 0),
    SD_BUS_METHOD("RequestPinCode", "o", "s", m_pincode, 0),
    SD_BUS_METHOD("DisplayPinCode", "os", "", m_ack, 0),
    SD_BUS_METHOD("RequestPasskey", "o", "u", m_passkey, 0),
    SD_BUS_METHOD("DisplayPasskey", "ouq", "", m_ack, 0),
    SD_BUS_METHOD("RequestConfirmation", "ou", "", m_reject, 0),
    SD_BUS_METHOD("RequestAuthorization", "o", "", m_reject, 0),
    SD_BUS_METHOD("AuthorizeService", "os", "", m_reject, 0),
    SD_BUS_METHOD("Cancel", "", "", m_ack, 0),
    SD_BUS_VTABLE_END
};

static int get_type(sd_bus *b, const char *p, const char *i, const char *pr,
                    sd_bus_message *reply, void *ud, sd_bus_error *e) {
    (void)b; (void)p; (void)i; (void)pr; (void)ud; (void)e;
    return sd_bus_message_append(reply, "s", "or_patterns");
}

/* One pattern: AD type 0xFF (manufacturer specific data) whose first
 * two bytes are the Victron company id, little endian. */
static int get_patterns(sd_bus *b, const char *p, const char *i, const char *pr,
                        sd_bus_message *reply, void *ud, sd_bus_error *e) {
    (void)b; (void)p; (void)i; (void)pr; (void)ud; (void)e;
    static const uint8_t cid[2] = { VA_VICTRON_COMPANY_ID & 0xFF, VA_VICTRON_COMPANY_ID >> 8 };
    int r;
    if ((r = sd_bus_message_open_container(reply, 'a', "(yyay)")) < 0) return r;
    if ((r = sd_bus_message_open_container(reply, 'r', "yyay")) < 0) return r;
    if ((r = sd_bus_message_append(reply, "yy", (uint8_t)0, (uint8_t)0xFF)) < 0) return r;
    if ((r = sd_bus_message_append_array(reply, 'y', cid, sizeof(cid))) < 0) return r;
    if ((r = sd_bus_message_close_container(reply)) < 0) return r;
    return sd_bus_message_close_container(reply);
}

/* RegisterMonitor's reply (or NULL when the call could not be sent). */
static int on_monitor_registered(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)ud; (void)e;
    if (m && !sd_bus_message_is_method_error(m, NULL)) return 0;
    const sd_bus_error *er = m ? sd_bus_message_get_error(m) : NULL;
    logf_("AdvertisementMonitorManager1.RegisterMonitor: %s", er && er->name ? er->name : "not sent");
    logf_("AdvertisementMonitorManager1 unavailable (bluetoothd needs Experimental = true "
          "in main.conf, or -E): no Instant Readout, and only devices BlueZ already "
          "knows are reached. This helper never falls back to discovery, which scans "
          "actively");
    return 0;
}

static int m_activate(sd_bus_message *m, void *ud, sd_bus_error *e) {
    logf_("advertisement monitor active: passive scan for Victron Instant Readout");
    g.monitor_on = 1;
    return m_ack(m, ud, e);
}

static int m_release(sd_bus_message *m, void *ud, sd_bus_error *e) {
    logf_("advertisement monitor released by BlueZ: Instant Readout stops");
    g.monitor_on = 0;
    return m_ack(m, ud, e);
}

static const sd_bus_vtable monitor_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Type", "s", get_type, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Patterns", "a(yyay)", get_patterns, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_METHOD("Release", "", "", m_release, 0),
    SD_BUS_METHOD("Activate", "", "", m_activate, 0),
    SD_BUS_METHOD("DeviceFound", "o", "", m_ack, 0),
    SD_BUS_METHOD("DeviceLost", "o", "", m_ack, 0),
    SD_BUS_VTABLE_END
};

/* ── calls ─────────────────────────────────────────────────────────── */

static int call_async(const char *path, const char *iface, const char *member,
                      sd_bus_message_handler_t cb, unsigned timeout_s,
                      const char *types, ...) {
    sd_bus_message *m = NULL;
    int r = sd_bus_message_new_method_call(g.bus, &m, "org.bluez", path, iface, member);
    if (r >= 0 && types) {
        va_list ap;
        va_start(ap, types);
        r = sd_bus_message_appendv(m, types, ap);
        va_end(ap);
    }
    if (r >= 0) {
        sd_bus_slot_unref(g.s.pending);
        g.s.pending = NULL;
        r = sd_bus_call_async(g.bus, &g.s.pending, m, cb, NULL, (uint64_t)timeout_s * 1000000ull);
    }
    sd_bus_message_unref(m);
    return r;
}

static void session_step(void);

/* Entry of every reply handler: the call is answered. sd-bus holds its
 * own reference on a slot while its callback runs, so dropping ours
 * here is safe. */
static void answered(void) {
    g.s.pending = sd_bus_slot_unref(g.s.pending);
}

static void session_finish(void) {
    session_t *s = &g.s;
    peer_t *p = &g.peer[s->peer];
    time_t now = sloth_wall();
    g.pair_path[0] = '\0';
    sd_bus_slot_unref(s->pending);
    s->pending = NULL;
    sd_event_source_unref(s->deadline);
    s->deadline = NULL;
    if (s->learn) {
        if (p->conf < 0) { p->learn_failed = 1; p->learn_after = now + LEARN_RETRY_S; }
    } else {
        p->next_gatt = now + (time_t)g.interval_s;
    }
    va_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.source = "gatt";
    rec.t = (long long)now;
    memcpy(rec.mac, p->mac, 6);
    rec.serial = peer_serial(p);
    rec.label = p->has_name ? p->name : NULL;
    rec.record_type = -1;
    rec.session = s->outcome ? s->outcome : "unknown";
    rec.services = s->services[0] ? s->services : NULL;
    rec.nvals = s->nvals;
    rec.vals = s->vals;
    append_record(&rec);
    char m[18];
    va_mac_str(p->mac, m);
    logf_("%s session %s: %s, %d values", m, s->learn ? "(learn)" : "", rec.session, s->nvals);
    int keep = s->peer;
    memset(s, 0, sizeof(*s));
    s->peer = keep;
    s->st = S_IDLE;
}

static int on_disconnected(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)m; (void)ud; (void)e;
    answered();
    session_finish();
    return 0;
}

/* Every path out of a session that connected goes through here, so the
 * link is always dropped and the phone app can have the device. */
static void session_disconnect(const char *outcome) {
    session_t *s = &g.s;
    if (!s->outcome) s->outcome = outcome;
    s->st = S_DISCONNECT;
    g.pair_path[0] = '\0';
    if (call_async(g.peer[s->peer].path, "org.bluez.Device1", "Disconnect",
                   on_disconnected, CALL_S, NULL) < 0)
        session_finish();
}

static int reply_failed(sd_bus_message *m, const char *what) {
    const sd_bus_error *err = sd_bus_message_get_error(m);
    if (!err) return 0;
    char mac[18];
    va_mac_str(g.peer[g.s.peer].mac, mac);
    logf_("%s: %s failed: %s", mac, what, err->name ? err->name : "error");
    return 1;
}

static int on_read(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)ud; (void)e;
    answered();
    session_t *s = &g.s;
    if (!reply_failed(m, "ReadValue")) {
        const void *ptr; size_t len;
        if (sd_bus_message_read_array(m, 'y', &ptr, &len) >= 0) {
            const va_gatt_char_t *c = s->gatt_char[s->next_read];
            double v;
            if (va_gatt_decode(c, ptr, len, &v) == 1 && s->nvals < VA_MAX_VALUES) {
                va_value_t *x = &s->vals[s->nvals++];
                x->name = c->name; x->unit = c->unit; x->v = v; x->integer = 0; x->text = NULL;
            }
        }
    }
    s->next_read++;
    session_step();
    return 0;
}

static int on_keepalive(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)ud; (void)e;
    answered();
    (void)reply_failed(m, "keep-alive write");   /* reads may still work */
    g.s.st = S_READ;
    session_step();
    return 0;
}

static int on_paired(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)ud; (void)e;
    answered();
    g.pair_path[0] = '\0';
    if (reply_failed(m, "Pair")) { session_disconnect("pair_failed"); return 0; }
    g.s.st = S_KEEPALIVE;
    session_step();
    return 0;
}

static void add_service(const char *uuid) {
    session_t *s = &g.s;
    size_t n = strlen(s->services);
    if (n + strlen(uuid) + 2 >= sizeof(s->services)) return;
    if (n) strcat(s->services, ",");
    strcat(s->services, uuid);
}

/* The device's GATT objects, from one GetManagedObjects. */
static int on_objects(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)ud; (void)e;
    answered();
    session_t *s = &g.s;
    peer_t *p = &g.peer[s->peer];
    if (reply_failed(m, "GetManagedObjects")) { session_disconnect("bluez_error"); return 0; }
    char svc_path[128] = "";
    props_t dev;
    memset(&dev, 0, sizeof(dev));
    s->services[0] = '\0';
    s->ngatt = 0;
    s->keepalive_path[0] = '\0';
    /* Two kinds of object matter: services under the device (first
     * pass collects them) and characteristics of the 6597 service. The
     * reply is walked once; a characteristic seen before its service is
     * matched by the service path prefix afterwards. */
    char cpath[VA_MAX_VALUES * 2][128];
    char cuuid[VA_MAX_VALUES * 2][48];
    char csvc[VA_MAX_VALUES * 2][128];
    int nc = 0;
    size_t plen = strlen(p->path);
    if (sd_bus_message_enter_container(m, 'a', "{oa{sa{sv}}}") < 0) { session_disconnect("bluez_error"); return 0; }
    while (sd_bus_message_enter_container(m, 'e', "oa{sa{sv}}") > 0) {
        const char *path;
        if (sd_bus_message_read(m, "o", &path) < 0) break;
        int mine = !strncmp(path, p->path, plen) && (path[plen] == '\0' || path[plen] == '/');
        if (sd_bus_message_enter_container(m, 'a', "{sa{sv}}") < 0) break;
        while (sd_bus_message_enter_container(m, 'e', "sa{sv}") > 0) {
            const char *iface;
            if (sd_bus_message_read(m, "s", &iface) < 0) break;
            props_t pr;
            memset(&pr, 0, sizeof(pr));
            if (mine && (!strcmp(iface, "org.bluez.Device1") || !strcmp(iface, "org.bluez.GattService1")
                         || !strcmp(iface, "org.bluez.GattCharacteristic1"))) {
                if (read_props(m, &pr) < 0) break;
                if (!strcmp(iface, "org.bluez.Device1")) dev = pr;
                else if (!strcmp(iface, "org.bluez.GattService1") && pr.has_uuid) {
                    add_service(pr.uuid);
                    if (!strcasecmp(pr.uuid, VA_GATT_SERVICE_UUID)) copy_str(svc_path, sizeof(svc_path), path);
                } else if (pr.has_uuid && pr.has_svc && nc < VA_MAX_VALUES * 2) {
                    copy_str(cpath[nc], sizeof(cpath[nc]), path);
                    copy_str(cuuid[nc], sizeof(cuuid[nc]), pr.uuid);
                    copy_str(csvc[nc], sizeof(csvc[nc]), pr.svc);
                    nc++;
                }
            } else if (sd_bus_message_skip(m, "a{sv}") < 0) break;
            sd_bus_message_exit_container(m);
        }
        sd_bus_message_exit_container(m);
        sd_bus_message_exit_container(m);
    }
    if (dev.has_name) { p->has_name = 1; copy_str(p->name, sizeof(p->name), dev.name); }
    if (!dev.has_res || !dev.resolved) {
        if (++s->resolve_tries < 10) {
            /* Not resolved yet: ask again next tick. */
            s->st = S_RESOLVE;
            return 0;
        }
        session_disconnect("services_unresolved");
        return 0;
    }
    if (s->learn) {
        try_match_name(s->peer);
        session_disconnect(p->conf >= 0 ? "learned" : "name_unmatched");
        return 0;
    }
    if (p->conf >= 0 && p->has_name && !va_name_has_serial(p->name, g.dev[p->conf].serial)) {
        char mac[18];
        va_mac_str(p->mac, mac);
        logf_("%s: its name does not carry serial %s (renamed?); using the owner's mapping",
              mac, g.dev[p->conf].serial);
    }
    if (!svc_path[0]) { session_disconnect("no_supported_service"); return 0; }
    for (int i = 0; i < nc; i++) {
        if (strcmp(csvc[i], svc_path)) continue;
        if (!strcasecmp(cuuid[i], VA_GATT_KEEPALIVE_UUID)) {
            copy_str(s->keepalive_path, sizeof(s->keepalive_path), cpath[i]);
            continue;
        }
        const va_gatt_char_t *c = va_gatt_find(cuuid[i]);
        if (c && s->ngatt < VA_MAX_VALUES) {
            copy_str(s->gatt_path[s->ngatt], sizeof(s->gatt_path[0]), cpath[i]);
            s->gatt_char[s->ngatt] = c;
            s->ngatt++;
        }
    }
    s->services[0] = '\0';               /* recorded only when unsupported */
    s->paired = dev.has_paired && dev.paired;
    s->st = s->paired ? S_KEEPALIVE : S_PAIR;
    session_step();
    return 0;
}

static int on_connected(sd_bus_message *m, void *ud, sd_bus_error *e) {
    (void)ud; (void)e;
    answered();
    if (reply_failed(m, "Connect")) { session_disconnect("connect_failed"); return 0; }
    g.s.st = S_RESOLVE;
    session_step();
    return 0;
}

static int on_deadline(sd_event_source *src, uint64_t usec, void *ud) {
    (void)src; (void)usec; (void)ud;
    if (g.s.st != S_IDLE && g.s.st != S_DISCONNECT) {
        sd_bus_slot_unref(g.s.pending);
        g.s.pending = NULL;
        session_disconnect("timeout");
    } else if (g.s.st == S_DISCONNECT) {
        session_finish();
    }
    return 0;
}

static void session_step(void) {
    session_t *s = &g.s;
    peer_t *p = &g.peer[s->peer];
    int r = 0;
    switch (s->st) {
    case S_IDLE:
    case S_DISCONNECT:
        return;
    case S_CONNECT:
        r = call_async(p->path, "org.bluez.Device1", "Connect", on_connected, CALL_S, NULL);
        break;
    case S_RESOLVE:
        r = call_async("/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects",
                       on_objects, CALL_S, NULL);
        break;
    case S_PAIR:
        copy_str(g.pair_path, sizeof(g.pair_path), p->path);
        r = call_async(p->path, "org.bluez.Device1", "Pair", on_paired, CALL_S, NULL);
        break;
    case S_KEEPALIVE: {
        uint8_t ka[2];
        if (!s->keepalive_path[0] || va_gatt_keepalive(g.keepalive_ms, ka) != 0) {
            s->st = S_READ;
            session_step();
            return;
        }
        sd_bus_message *m = NULL;
        r = sd_bus_message_new_method_call(g.bus, &m, "org.bluez", s->keepalive_path,
                                           "org.bluez.GattCharacteristic1", "WriteValue");
        if (r >= 0) r = sd_bus_message_append_array(m, 'y', ka, sizeof(ka));
        /* [VCS]: "a write request and not a write command". */
        if (r >= 0) r = sd_bus_message_append(m, "a{sv}", 1, "type", "s", "request");
        if (r >= 0) {
            sd_bus_slot_unref(s->pending);
            s->pending = NULL;
            r = sd_bus_call_async(g.bus, &s->pending, m, on_keepalive, NULL, (uint64_t)CALL_S * 1000000ull);
        }
        sd_bus_message_unref(m);
        break;
    }
    case S_READ:
        if (s->next_read >= s->ngatt) {
            session_disconnect(s->nvals > 0 ? "ok" : "no_values");
            return;
        }
        r = call_async(s->gatt_path[s->next_read], "org.bluez.GattCharacteristic1", "ReadValue",
                       on_read, CALL_S, "a{sv}", 0);
        break;
    }
    if (r < 0) {
        logf_("D-Bus call failed: %s", strerror(-r));
        session_disconnect("bluez_error");
    }
}

static void session_start(int pi, int learn) {
    session_t *s = &g.s;
    memset(s, 0, sizeof(*s));
    s->peer = pi;
    s->learn = learn;
    s->started = sloth_wall();
    s->st = S_CONNECT;
    char m[18];
    va_mac_str(g.peer[pi].mac, m);
    logf_("%s: GATT session (%s) - this transmits", m, learn ? "learn name" : "read values");
    sd_event_add_time_relative(g.ev, &s->deadline, CLOCK_MONOTONIC,
                               (uint64_t)SESSION_S * 1000000ull, 0, on_deadline, NULL);
    session_step();
}

/* Every TICK_S: start the next due session, one at a time. A device
 * BlueZ has never seen is skipped (nothing is sent to find it). */
static int on_tick(sd_event_source *src, uint64_t usec, void *ud) {
    (void)ud;
    sd_event_source_set_time(src, usec + (uint64_t)TICK_S * 1000000ull);
    sd_event_source_set_enabled(src, SD_EVENT_ON);
    if (g.s.st == S_RESOLVE && !g.s.pending) { session_step(); return 0; }
    if (g.s.st != S_IDLE || !g.gatt_on) return 0;
    time_t now = sloth_wall();
    for (int i = 0; i < g.npeer; i++) {
        peer_t *p = &g.peer[i];
        if (!p->seen) continue;
        if (p->conf < 0) {
            if (p->key >= 0 && !p->has_name && (!p->learn_failed || now >= p->learn_after)) {
                session_start(i, 1);
                return 0;
            }
            continue;
        }
        if (now >= p->next_gatt) { session_start(i, 0); return 0; }
    }
    return 0;
}

/* ── start-up ──────────────────────────────────────────────────────── */

static int on_signal(sd_event_source *src, const struct signalfd_siginfo *si, void *ud) {
    (void)si; (void)ud;
    return sd_event_exit(sd_event_source_get_event(src), 0);
}

/* The adapter BlueZ calls `want`: an address (AA:BB:CC:DD:EE:FF, the
 * stable name, since hciN follows probe order) or hciN. */
static int find_adapter(void) {
    sd_bus_message *reply = NULL;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    uint8_t want_mac[6];
    int by_mac = va_mac_parse(g.adapter_want, want_mac) == 0;
    int r = sd_bus_call_method(g.bus, "org.bluez", "/", "org.freedesktop.DBus.ObjectManager",
                               "GetManagedObjects", &err, &reply, "");
    if (r < 0) {
        logf_("cannot reach BlueZ (org.bluez): %s", err.message ? err.message : strerror(-r));
        sd_bus_error_free(&err);
        return -1;
    }
    g.adapter[0] = '\0';
    sd_bus_message_enter_container(reply, 'a', "{oa{sa{sv}}}");
    while (sd_bus_message_enter_container(reply, 'e', "oa{sa{sv}}") > 0) {
        const char *path;
        sd_bus_message_read(reply, "o", &path);
        sd_bus_message_enter_container(reply, 'a', "{sa{sv}}");
        while (sd_bus_message_enter_container(reply, 'e', "sa{sv}") > 0) {
            const char *iface;
            sd_bus_message_read(reply, "s", &iface);
            if (!strcmp(iface, "org.bluez.Adapter1")) {
                /* Address is read here by hand: read_props keeps only
                 * device fields. */
                sd_bus_message_enter_container(reply, 'a', "{sv}");
                while (sd_bus_message_enter_container(reply, 'e', "sv") > 0) {
                    const char *k;
                    sd_bus_message_read(reply, "s", &k);
                    char t; const char *c;
                    sd_bus_message_peek_type(reply, &t, &c);
                    if (!strcmp(k, "Address") && c && !strcmp(c, "s")) {
                        const char *a;
                        uint8_t am[6];
                        sd_bus_message_read(reply, "v", "s", &a);
                        if (by_mac && va_mac_parse(a, am) == 0 && !memcmp(am, want_mac, 6))
                            copy_str(g.adapter, sizeof(g.adapter), path);
                    } else sd_bus_message_skip(reply, "v");
                    sd_bus_message_exit_container(reply);
                }
                sd_bus_message_exit_container(reply);
                const char *base = strrchr(path, '/');
                if (!by_mac && base && !strcmp(base + 1, g.adapter_want))
                    copy_str(g.adapter, sizeof(g.adapter), path);
            } else if (!strcmp(iface, "org.bluez.Device1")) {
                props_t pr;
                memset(&pr, 0, sizeof(pr));
                read_props(reply, &pr);
                if (g.adapter[0]) on_device_props(path, &pr);
            } else sd_bus_message_skip(reply, "a{sv}");
            sd_bus_message_exit_container(reply);
        }
        sd_bus_message_exit_container(reply);
        sd_bus_message_exit_container(reply);
    }
    sd_bus_message_unref(reply);
    if (!g.adapter[0]) {
        logf_("no BlueZ adapter %s", g.adapter_want);
        return -1;
    }
    return 0;
}

static int bluez_call(const char *path, const char *iface, const char *member,
                      const char *types, const char *a1, const char *a2) {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    int r = types ? sd_bus_call_method(g.bus, "org.bluez", path, iface, member, &err, NULL, types, a1, a2)
                  : sd_bus_call_method(g.bus, "org.bluez", path, iface, member, &err, NULL, "");
    if (r < 0) logf_("%s.%s: %s", iface, member, err.name ? err.name : strerror(-r));
    sd_bus_error_free(&err);
    return r;
}

static void usage(void) {
    fprintf(stderr,
        "usage: " ME " [options]\n"
        "  --adapter ADDR|hciN   controller to use (default $SLOTH_VA_ADAPTER, else hci0);\n"
        "                        an address is stable across reboots, hciN is not\n"
        "  --config PATH         SERIAL PIN [MAC] lines (default $CREDENTIALS_DIRECTORY/victron-va.conf)\n"
        "  --keys PATH           MAC KEY lines (default $CREDENTIALS_DIRECTORY/victron.keys)\n"
        "  --out PATH            JSONL to append (default /var/lib/sloth-va/victron.jsonl)\n"
        "  --state-dir DIR       learned serial map (default /var/lib/sloth-va)\n"
        "  --interval SECS       GATT session per device every SECS (default 300, min 60)\n"
        "  --readout-every SECS  at most one Instant Readout record per device per SECS (default 30)\n"
        "  --keepalive-ms MS     keep-alive written in a session (default 30000)\n"
        "  --no-gatt             Instant Readout only: never connect\n"
        "  --check               parse the two files, report counts and bad lines, exit\n");
}

static unsigned num_arg(const char *s, unsigned lo, unsigned hi, int *bad) {
    char *end;
    unsigned long v = strtoul(s, &end, 10);
    if (*s == '\0' || *end != '\0' || v < lo || v > hi) { *bad = 1; return lo; }
    return (unsigned)v;
}

int main(int argc, char **argv) {
    static char cfg_def[PATH_MAX], keys_def[PATH_MAX];
    const char *cred = getenv("CREDENTIALS_DIRECTORY");
    const char *cfg = NULL, *keys = NULL;
    const char *ad = getenv("SLOTH_VA_ADAPTER");
    int check = 0, bad = 0;
    g.out_path = "/var/lib/sloth-va/victron.jsonl";
    g.state_dir = "/var/lib/sloth-va";
    g.interval_s = 300;
    g.readout_every_s = 30;
    g.keepalive_ms = 30000;
    g.gatt_on = 1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--check")) { check = 1; continue; }
        if (!strcmp(a, "--no-gatt")) { g.gatt_on = 0; continue; }
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(); return 0; }
        if (!v) { usage(); return 2; }
        if      (!strcmp(a, "--adapter"))       ad = v;
        else if (!strcmp(a, "--config"))        cfg = v;
        else if (!strcmp(a, "--keys"))          keys = v;
        else if (!strcmp(a, "--out"))           g.out_path = v;
        else if (!strcmp(a, "--state-dir"))     g.state_dir = v;
        else if (!strcmp(a, "--interval"))      g.interval_s = num_arg(v, 60, 86400, &bad);
        else if (!strcmp(a, "--readout-every")) g.readout_every_s = num_arg(v, 1, 3600, &bad);
        else if (!strcmp(a, "--keepalive-ms"))  g.keepalive_ms = num_arg(v, 1000, 60000, &bad);
        else { usage(); return 2; }
        i++;
    }
    if (bad) { usage(); return 2; }
    if (!cfg && cred) { snprintf(cfg_def, sizeof(cfg_def), "%s/victron-va.conf", cred); cfg = cfg_def; }
    if (!keys && cred) { snprintf(keys_def, sizeof(keys_def), "%s/victron.keys", cred); keys = keys_def; }
    copy_str(g.adapter_want, sizeof(g.adapter_want), ad && *ad ? ad : "hci0");

    /* Either file may be absent (readout-only, or GATT-only), not both. */
    diag_ctx_t dc = { "victron-va.conf", 0 }, kc = { "victron.keys", 0 };
    if (cfg && access(cfg, F_OK) == 0) {
        char *t = read_secret(cfg);
        if (!t) return 2;
        g.ndev = va_conf_parse_devices(t, g.dev, VA_MAX_DEVICES, diag, &dc);
        free_secret(t);
    }
    if (keys && access(keys, F_OK) == 0) {
        char *t = read_secret(keys);
        if (!t) return 2;
        g.nkey = va_conf_parse_keys(t, g.key, VA_MAX_DEVICES, diag, &kc);
        free_secret(t);
    }
    int with_mac = 0;
    for (int d = 0; d < g.ndev; d++) with_mac += g.dev[d].has_mac;
    logf_("%d device(s) with a PIN (%d with an address), %d readout key(s); %d bad line(s)",
          g.ndev, with_mac, g.nkey, dc.bad + kc.bad);
    if (check) return (dc.bad + kc.bad) ? 2 : 0;
    if (g.ndev == 0 && g.nkey == 0) { logf_("nothing configured"); return 2; }

    /* The peers: every address the owner listed, and nothing else. */
    for (int k = 0; k < g.nkey; k++) {
        peer_t *p = &g.peer[g.npeer++];
        memcpy(p->mac, g.key[k].mac, 6);
        p->conf = -1; p->key = k;
    }
    for (int d = 0; d < g.ndev; d++) {
        if (!g.dev[d].has_mac) continue;
        int pi = peer_by_mac(g.dev[d].mac);
        if (pi < 0) {
            pi = g.npeer++;
            memcpy(g.peer[pi].mac, g.dev[d].mac, 6);
            g.peer[pi].key = -1;
        }
        g.peer[pi].conf = d;
    }
    load_learned();

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGTERM);
    sigaddset(&ss, SIGINT);
    sigprocmask(SIG_BLOCK, &ss, NULL);

    int r = sd_bus_open_system(&g.bus);
    if (r < 0) { logf_("system bus: %s", strerror(-r)); return 1; }
    if (find_adapter() < 0) return 1;
    for (int i = 0; i < g.npeer; i++) mac_upper_path(g.peer[i].mac, g.peer[i].path, sizeof(g.peer[i].path));
    /* Re-read now that peer paths exist. */
    if (find_adapter() < 0) return 1;
    logf_("adapter %s (%s); output %s; GATT %s every %u s", g.adapter, g.adapter_want, g.out_path,
          g.gatt_on ? "on" : "off", g.interval_s);

    /* Powered on if it is not (main.conf AutoEnable=false leaves it
     * off). Powering an LE controller transmits nothing by itself. */
    {
        sd_bus_error err = SD_BUS_ERROR_NULL;
        r = sd_bus_set_property(g.bus, "org.bluez", g.adapter, "org.bluez.Adapter1", "Powered",
                                &err, "b", 1);
        if (r < 0) logf_("cannot power %s: %s", g.adapter, err.name ? err.name : strerror(-r));
        sd_bus_error_free(&err);
    }

    sd_event_default(&g.ev);
    sd_bus_attach_event(g.bus, g.ev, 0);
    sd_event_add_signal(g.ev, NULL, SIGTERM, on_signal, NULL);
    sd_event_add_signal(g.ev, NULL, SIGINT, on_signal, NULL);

    sd_bus_add_object_vtable(g.bus, NULL, AGENT_PATH, "org.bluez.Agent1", agent_vtable, NULL);
    sd_bus_add_object_manager(g.bus, NULL, APP_ROOT);
    sd_bus_add_object_vtable(g.bus, NULL, MONITOR_PATH, "org.bluez.AdvertisementMonitor1", monitor_vtable, NULL);
    sd_bus_match_signal(g.bus, NULL, "org.bluez", NULL, "org.freedesktop.DBus.Properties",
                        "PropertiesChanged", on_props_changed, NULL);
    sd_bus_match_signal(g.bus, NULL, "org.bluez", "/", "org.freedesktop.DBus.ObjectManager",
                        "InterfacesAdded", on_ifaces_added, NULL);

    /* Not RequestDefaultAgent: BlueZ uses the agent of whoever called
     * Pair(), so pairings this helper did not start never reach it. */
    if (g.gatt_on && bluez_call("/org/bluez", "org.bluez.AgentManager1", "RegisterAgent",
                                "os", AGENT_PATH, "KeyboardOnly") < 0)
        logf_("no pairing agent: sessions with an unbonded device will fail to pair");
    /* Always, keys or not: the monitor's passive scan is also how BlueZ
     * comes to hold a Device1 object for a GATT-only device (the
     * dongle), and a device it does not hold is never searched for. */
    /* Asynchronous: BlueZ answers RegisterMonitor and then calls this
     * helper's GetManagedObjects to find the monitor. A blocking call
     * left that request unanswered (seen on Beta-Site 2026-11-15: no
     * Activate, no scan), so the reply is handled in the event loop. */
    if (sd_bus_call_method_async(g.bus, NULL, "org.bluez", g.adapter,
                                 "org.bluez.AdvertisementMonitorManager1", "RegisterMonitor",
                                 on_monitor_registered, NULL, "o", APP_ROOT) < 0)
        on_monitor_registered(NULL, NULL, NULL);

    sd_event_source *tick = NULL;
    sd_event_add_time_relative(g.ev, &tick, CLOCK_MONOTONIC, (uint64_t)TICK_S * 1000000ull, 0,
                               on_tick, NULL);
    sd_event_source_set_enabled(tick, SD_EVENT_ON);

    r = sd_event_loop(g.ev);

    /* Stopping: drop any link, withdraw the monitor and the agent. */
    if (g.s.st != S_IDLE) {
        sd_bus_slot_unref(g.s.pending);
        g.s.pending = NULL;
        bluez_call(g.peer[g.s.peer].path, "org.bluez.Device1", "Disconnect", NULL, NULL, NULL);
    }
    bluez_call(g.adapter, "org.bluez.AdvertisementMonitorManager1", "UnregisterMonitor", "o", APP_ROOT, NULL);
    if (g.gatt_on)
        bluez_call("/org/bluez", "org.bluez.AgentManager1", "UnregisterAgent", "o", AGENT_PATH, NULL);
    va_wipe(g.dev, sizeof(g.dev));
    va_wipe(g.key, sizeof(g.key));
    sd_event_source_unref(tick);
    sd_bus_flush_close_unref(g.bus);
    sd_event_unref(g.ev);
    logf_("stopped");
    return r < 0 ? 1 : 0;
}
