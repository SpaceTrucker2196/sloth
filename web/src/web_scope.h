/* slothweb's capture scope (owner request 2026-10-26): the top bar's
 * Monitor / Hybrid / Local switch, and what each datum is tagged with so
 * every route can answer for one of them.
 *
 *   Hybrid   everything, as before the switch existed (the default).
 *   Monitor  what the passive monitor-mode radio heard over the air
 *            (src/capture/probe.c: beacons, probes, associations, EAPOL,
 *            the channel mix, the 802.11 detectors) and the BLE
 *            receivers (--bt-monitor, --bt-capture), which are passive
 *            radio too. Nothing the host's own interfaces carried.
 *   Local    what the host's own connected interfaces carried: the IP
 *            capture (src/capture/capture.c), ARP, DHCP, DNS, mDNS,
 *            NBNS, the flows, /proc, and the managed Wi-Fi card's own
 *            nl80211 station dump and scan (wifi_sta, wifi_ap: Wi-Fi
 *            through the local network, not the passive radio).
 *
 * sloth's records carry no per-record capture path, so a datum's scope
 * is decided by what it is: its record type, its alert type (the rule's
 * input, not the file the rule sits in: CAPTIVE_PORTAL is in
 * rules_twin.c and reads DNS/HTTP/TLS, CAM_SETUP_OUI is in
 * rules_camera.c and reads beacons), its metric, an interface's name,
 * a device's DEV_SRC_* bits. Each is tagged WEB_SC_M, WEB_SC_L, both,
 * or WEB_SC_META (sloth's own state, shown in every scope). A tag of 0
 * is shown under Hybrid only: a record type sloth adds later is not
 * claimed by either scope until it is classified here.
 *
 * WEB_SC_IPCAP marks a Local datum that came off the IP capture. While
 * the stream says that capture is itself a monitor radio (a radiotap
 * link type, or capture_iface == monitor_iface: capture.c decodes IP
 * from 802.11 data frames, #72), such a datum was heard over the air
 * and counts as Monitor instead (web_scope_eff()). sloth.db rows carry
 * no link type, so the database views keep them Local; the legend says
 * so.
 *
 * Pure: no SQLite, no locks. */
#ifndef SLOTHWEB_SCOPE_H
#define SLOTHWEB_SCOPE_H

#include <stddef.h>

/* The viewer's choice. 0 is Hybrid, so a zeroed struct means "as
 * before" everywhere a scope is carried. */
enum { WEB_SCOPE_HYBRID = 0, WEB_SCOPE_MONITOR = 1, WEB_SCOPE_LOCAL = 2,
       WEB_SCOPE_COUNT };

/* A datum's tag: bits. META is both, so it passes every scope. */
#define WEB_SC_M      1
#define WEB_SC_L      2
#define WEB_SC_META   3
#define WEB_SC_IPCAP  4     /* with L: off the IP capture */
/* Decided per record, not per type: an iface record by its name, a
 * device by its sources (web_scope_device()). */
#define WEB_SC_BYKEY  8

/* "monitor", "hybrid", "local" -> WEB_SCOPE_*, else -1. */
int         web_scope_find(const char *word);
const char *web_scope_word(int scope);

/* Is a datum tagged tag shown under scope? (radio already applied.) */
int         web_scope_pass(int scope, int tag);
/* tag with WEB_SC_IPCAP resolved: radio set turns an IP-capture datum
 * into a Monitor one. The result is M, L, META or 0. */
int         web_scope_eff(int tag, int radio);

/* The query's scope=... is taken out by the shared parameter parser,
 * web_scope_take() (web_series.h). */

/* A record type's tag (the JSONL types slothweb reads), 0 unknown.
 * "iface" and "device" are WEB_SC_BYKEY. */
int         web_scope_record(const char *type);

/* An alert type's tag, by sloth's ty (include/sloth_alerts.def row
 * order); 0 for a ty out of range. */
int         web_scope_alert(int ty);
/* The table itself, for the test that holds it to the .def. */
typedef struct { const char *name; int tag; } web_scope_alert_t;
extern const web_scope_alert_t web_scope_alerts[];
extern const int               web_scope_alerts_n;
/* The alert types shown under scope (radio applied) into out (max), in
 * ty order. Their count. Hybrid is every type. */
int         web_scope_alert_types(int scope, int radio, int *out, int max);

/* What a request is answered for: the viewer's scope and the stream's
 * facts the tags are resolved with (web_live_scope_ctx() fills them). */
#define WEB_SCOPE_MON_MAX   8
#define WEB_SCOPE_IFNAME    32
typedef struct {
    int  scope;               /* WEB_SCOPE_* */
    int  given;               /* the request named one */
    int  radio;               /* the IP capture is a monitor radio */
    int  nmon;
    char mon[WEB_SCOPE_MON_MAX][WEB_SCOPE_IFNAME + 1];   /* monitor radios */
} web_scope_ctx_t;

/* Is a datum tagged tag (WEB_SC_IPCAP not yet resolved) shown? */
int         web_scope_ok(const web_scope_ctx_t *c, int tag);

/* A metric's tag (web_rollup.h WM_*): iface.* are WEB_SC_BYKEY (by the
 * interface), alerts.fired is WEB_SC_BYKEY (by the alert type). */
int         web_scope_metric(int metric);
/* A metric's key's tag, resolved: an interface by web_scope_iface(),
 * an alert type (its decimal ty) by web_scope_alert(). */
int         web_scope_metric_key(int metric, const char *key,
                                 const web_scope_ctx_t *c);

/* An interface's tag: Monitor when its name is one of the monitor
 * radios slothweb has been told of (sensor_health.monitor_iface, a
 * `sensor` record of kind wifi) since it started, else Local. */
int         web_scope_iface(const char *name, const web_scope_ctx_t *c);
/* Note name as a monitor radio (the set keeps the first
 * WEB_SCOPE_MON_MAX). */
void        web_scope_note_mon(web_scope_ctx_t *c, const char *name);

/* A device's tag from sloth's DEV_SRC_* bits (include/sloth.h) and the
 * CAM_SIG_* mask (cam_signals, -1 unknown): ARP, DHCP, mDNS, STA and an
 * address are Local; BEACON and PROBE Monitor; CAMERA by which camera
 * signals it has (setup SSID and setup OUI are beacons, the rest are IP
 * discovery). */
#define WEB_SRC_LOCAL   (1 | 2 | 4 | 32)
#define WEB_SRC_MONITOR (8 | 16)
#define WEB_CAM_MONITOR (2 | 16)
#define WEB_CAM_LOCAL   (1 | 4 | 8 | 32)
int         web_scope_device(long long sources, long long cam_signals,
                             const char *ip);

/* sloth's device risk (src/device_risk.c) recomputed from the signals a
 * scope can see: RANDOM_MAC and UNKNOWN_VENDOR in both, NO_HOSTNAME,
 * CLEARTEXT_CRED and ALERT_TAGGED Local only, PROBE_ONLY Monitor only.
 * Hybrid keeps every bit. */
#define WEB_RISK_BOTH    (1 | 2)
#define WEB_RISK_LOCAL   (4 | 16 | 32)
#define WEB_RISK_MONITOR 8
long long   web_scope_risk_mask(int scope);
/* The weights and buckets, device_risk.c's: 1,1,1,1,3,3; 0 LOW, 1-2
 * MED, 3-4 HIGH, 5+ CRIT. */
int         web_scope_risk_level(long long signals);

/* What the IP capture is, from sensor_health: a monitor radio when its
 * link type is 802.11 (105, 119, 127, 163) or, with no link type, when
 * it is the monitor interface itself. */
int         web_scope_ip_on_radio(long long linktype, const char *capture_iface,
                                  const char *monitor_iface);

#endif
