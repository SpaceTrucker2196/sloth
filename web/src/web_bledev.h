/* slothweb's BLE Devices view (owner request 2026-11-02: "show a
 * waterfall similar to wifi for bluetooth devices"; "visualize in the
 * best way to convey ble in a similar style").
 *
 * The WiFi view's rows are channels. A BLE row cannot be: an HCI LE
 * Advertising Report carries no channel (Core v5.4 Vol 4 Part E
 * §7.7.65.2), so on the host controller every advertiser is channel -1,
 * and an Ubertooth's rows hop 37/38/39 on every advertising event. So
 * the two panels carry meaning BLE has:
 *
 *   "who is around": rows are device CLASSES, columns time buckets, a
 *   cell the top WEB_CHMIX_TOP advertisers of that class by advertising
 *   reports in the bucket plus "other" (the WiFi channel mix's engine,
 *   web_chmix.h, a second instance keyed by class slug), or, as a heat
 *   fallback, the class's advertisers (gauge) or reports (counter);
 *
 *   "how close": rows are the advertisers of the window, columns the
 *   same buckets, a cell the mean of rf.rssi.ble in it graded by the
 *   distance band sloth's estimator would put that signal in.
 *
 * ── the classes ─────────────────────────────────────────────────────
 *
 * One closed list, web_ble_classes[] (and its copy in web/ui/bledev.js,
 * held equal by web/tests/test_bledev.c). A device lands in exactly one
 * class: the rules are tried in MATCH order and the first that holds
 * wins; the DISPLAY order is the enum's. Each rule reads only fields
 * sloth's ble_device record carries, and each rests on a source quoted
 * in research/bluetooth/ble-device-classes.md:
 *
 *   1 b:tag   Trackers: a watch category (src/ble_watchlist.c's sourced
 *             matcher; its shipped table is empty), an Appearance of
 *             category Tag (0x008) or Keyring (0x009) (SIG Assigned
 *             Numbers §2.6.2), or a 16-bit UUID listed or carried as
 *             Service Data that the SIG registry assigns to Tile
 *             (0xFEED, 0xFEEC, 0xFD84) or CHIPOLO (0xFE33, 0xFE65) - the
 *             assignment, not a verified payload shape.
 *   2 b:hid   Input: sloth's HID bits (Appearance 0x03C0..0x03CA or the
 *             HID service 0x1812, src/ble_hci.c).
 *   3 b:bcn   Beacons: Eddystone, Service Data or a listed UUID 0xFEAA
 *             (google/eddystone protocol-specification.md).
 *   4 b:wear  Wearables & audio: Apple Continuity type 0x07 Proximity
 *             Pairing ("constantly transmitted by active Apple audio
 *             devices", Celosia & Cunche 2020) or 0x0B Magic Switch
 *             (watches only, ibid. and Martin et al. 2019); Fast Pair
 *             Service Data 0xFE2C (the Provider, the accessory side);
 *             Samsung 0x0075 first octet 0x42 or 0x01 (the buds and
 *             watch packets of the BLE Spam tool's easysetup.c); an
 *             Appearance of a worn, audio or personal-health category.
 *   5 b:phone Phones & computers: Apple Continuity 0x05 AirDrop, 0x0C
 *             Handoff, 0x0D / 0x0E Instant Hotspot, 0x0F Nearby Action,
 *             0x10 Nearby Info (Celosia & Cunche 2020 Table 3; Nearby
 *             Info "continuously transmitted by iPhones, iPads,
 *             MacBooks and Watches"); Microsoft 0x0006 first octet 0x01,
 *             the [MS-CDP] 2.2.2.2.3 beacon; Appearance Phone or
 *             Computer.
 *   6 b:iot   Vehicles & IoT: Apple Continuity 0x06 HomeKit ("constantly
 *             transmitted by powered HomeKit devices", ibid.); an
 *             Appearance of a fixed, home, vehicle or industrial
 *             category.
 *   7 b:unk   Unknown: none of the above; and every anonymous row
 *             (addr_type 255), whatever its fields: sloth keeps one row
 *             a sensor for all anonymous advertisers it hears, the first
 *             manufacturer pair for good and the HID bits and watch
 *             category only ever added (src/ble_hci.c), so the fields
 *             are several devices' and decide no class
 *             (docs/wiki/ble.md, "Anonymous trains collide").
 *
 * Left out, said so rather than guessed: iBeacon (Apple 0x004C type
 * 0x02; no primary text was read for it), AltBeacon (its 0xBEAC code is
 * two octets and the stream carries only the first), Apple Find My
 * (0x12) and Samsung SmartTag (0xFD59 / 0xFD5A), whose shapes the
 * watchlist page lists as unverified. mfr_id and mfr_subtype are the
 * FIRST pair sloth heard on the row, so an Apple device that rotates
 * Continuity types is classed by its first; an Apple Watch that sends
 * Nearby Info and no Appearance is a phone here. A row's fields are its
 * last report's (presence kept), so a class is decided per record: a
 * row whose two PDUs carry fields of two classes can be credited to
 * each in turn.
 *
 * The slugs are the keys of the class mix (chmix rows, kind
 * WEB_TX_BLE, web_store.h) and of the two series ble.class.advertisers
 * and ble.class.adv: slugs rather than indices, so reordering the
 * display never re-keys a stored row. "b:" can never be a channel key
 * (web_key_channel(): digits, or "6g" and digits).
 *
 * ── the proximity grade ─────────────────────────────────────────────
 *
 * src/rf_distance.c's model for a BLE advertiser that announces no
 * transmit power: P_tx 0 dBm (RF_PTX_BLE_ASSUMED), L(1 m) =
 * 20 log10(2440) - 28 dB (ITU-R P.1238 at the advertising channels'
 * middle), N = 2.8 (RF_N_2G_X10). The band edges 1, 3, 10 and 30 m
 * (RF_BAND_*_M) are then -39.75, -53.11, -67.75 and -81.11 dBm. A cell
 * is graded by where its mean falls. An advertiser that announces its
 * power is graded with that power instead, in rf_ctx_ble()'s order: the
 * extended report header's TxPower, else the TX Power Level AD, else
 * 0 dBm (web_ble_dev_ptx()), so the cell and the table's dist column
 * name the same band for the same reading. A tuned N (--tune
 * rf.path_loss_n_2g) and the band's hysteresis and hold can still make
 * sloth's own band differ, and the page says so. Not a location.
 *
 * ── the routes ──────────────────────────────────────────────────────
 *
 *   /api/ble/classes?from=&to=&cols=&metric=advertisers|adv
 *       the class x time grid of a series: ble.class.advertisers (a
 *       gauge, the distinct advertisers of the class heard in the last
 *       two fine buckets, sampled once a snapshot pass) or ble.class.adv
 *       (a counter, the class's advertising reports); the WiFi channel
 *       grid's tiers, bounds and cells (web_wifi.h).
 *   /api/ble/classes?from=&to=&cols=&mix=1
 *       the class mix, /api/wifi/channels?mix=1's answer with "rows" for
 *       "channels" and a BLE advertiser per tx entry. Anonymous
 *       advertising (addr_type 255: an extended advertisement with no
 *       AdvA, the address zeroed by sloth, one row per sensor for all
 *       of it) is one entry, {"id":"anonymous","kind":"anon"}, in
 *       Unknown alone (web_chmix.h WEB_TX_BLE_ANON), and
 *       ble.class.advertisers counts it there as one advertiser, so it
 *       never moves class as its row's fields accumulate. A named
 *       advertiser whose fields change class still can: its earlier
 *       bands stay in the class it left, so a bucket where one changes
 *       can draw it in both.
 *   /api/ble/proximity?from=&to=&cols=&n=12|24|48
 *       the advertisers slothweb holds that were heard in the window,
 *       merged by address (rf.rssi.ble is keyed by address), at most
 *       WEB_BLEDEV_CANDS of them read (every tracker in the window
 *       first, whatever its age, then the newest), the top n by
 *       trackers first, then the nearest by the signal in the window
 *       less the row's P_tx, then reports; each with its cells, the
 *       mean RSSI per cell or null, and its P_tx and band edges. No
 *       anonymous row: there is no address to key rf.rssi.ble by, and
 *       the one row's signal is whichever anonymous advertiser that
 *       sensor heard last, so its line would be several devices' at
 *       once. It takes none of the 256 read; "anonymous_heard" says
 *       whether any was left out; nor is it ever "nearest".
 * Every answer carries "now": advertisers heard in the last 60 s, the
 * trackers among them, the nearest (current RSSI less the row's P_tx,
 * so by the grade's estimate rather than raw signal) and the
 * reports per second (ble.adv_rate over the last minute). Monitor and
 * Hybrid serve them; under Local the router answers out_of_scope after
 * the query is checked, as /api/ble's. */
#ifndef SLOTHWEB_BLEDEV_H
#define SLOTHWEB_BLEDEV_H

#include <stddef.h>

#include "web_ble.h"
#include "web_devices.h"
#include "web_jsonl.h"

/* Display order. */
enum { WEB_BC_PHONE = 0, WEB_BC_WEAR, WEB_BC_TAG, WEB_BC_HID, WEB_BC_BCN,
       WEB_BC_IOT, WEB_BC_UNK, WEB_BC_COUNT };

typedef struct {
    const char *slug;      /* "b:phone": the mix and series key */
    const char *label;     /* "Phones & computers" */
    const char *glyph;     /* one ASCII letter for a row label */
    int         match;     /* its place in the match order, 1 first */
    const char *rule;      /* the field rule, in words, for the page */
} web_ble_class_def_t;

extern const web_ble_class_def_t web_ble_classes[WEB_BC_COUNT];

/* The fields a class reads, as a ble_device record carries them: -1 for
 * an absent number, hid sloth's bits, watch nonzero for a category. */
typedef struct {
    int mfr_id, mfr_subtype, uuid16, svc_data_uuid16, appearance, hid;
    int watch;
} web_ble_fields_t;

int web_ble_class_of(const web_ble_fields_t *f);
/* The same from a ble_device record. */
int web_ble_class_of_rec(const web_jrec_t *r);
/* The class of a slug, or -1. */
int web_ble_class_find(const char *slug);
/* The rollup's canonicaliser for keykind "bleclass": a slug of the list
 * copied to out, 0; anything else -1. */
int web_key_bleclass_text(const char *s, char *out);

/* The proximity grade (above): the edge in dBm below which a reading is
 * farther than RF_BAND_*_M metres, for m 1, 3, 10, 30; and the band
 * (WEB_BLE_BAND_IMMEDIATE .. WEB_BLE_BAND_FAR) of a mean in dBm. The
 * plain forms are for an advertiser announcing nothing (0 dBm); the
 * _at forms take the row's P_tx. */
#define WEB_BLE_PROX_FREQ_MHZ 2440
#define WEB_BLE_PROX_N_X10    28
#define WEB_BLE_PROX_PTX_DBM  0
double web_ble_prox_edge(double metres);
int    web_ble_prox_band(double dbm);
double web_ble_prox_edge_at(double metres, double ptx_dbm);
int    web_ble_prox_band_at(double dbm, double ptx_dbm);

/* The BLE class mix's fine ring: seven classes over the six hours the
 * fine tier serves (2160 buckets each) fit in 16384 rows, about 1.5 MB. */
#define WEB_BLEDEV_RING   16384
#define WEB_BLEDEV_N      24
#define WEB_BLEDEV_N_MAX  48
#define WEB_BLEDEV_CANDS  256
#define WEB_BLEDEV_NOW_S  60

int web_bledev_classes_route(const web_m4_t *m, web_ble_t *b, const char *query,
                             long long now_s, char *body, size_t cap, size_t *len,
                             int *status);
int web_bledev_proximity_route(const web_m4_t *m, web_ble_t *b, const char *query,
                               long long now_s, char *body, size_t cap, size_t *len,
                               int *status);

#endif
