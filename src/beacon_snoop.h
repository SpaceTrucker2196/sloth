#ifndef BEACON_SNOOP_H
#define BEACON_SNOOP_H

#include <stdint.h>
#include <stddef.h>
#include "sloth.h"
#include "reg_ie.h"
#include "rsn_ie.h"
#include "dot11_frame.h"

/* Cipher / AKM / MFP info extracted from the RSN IE of a beacon, plus
 * AP fingerprint info extracted from tag-221 vendor-specific IEs. The
 * name is kept as beacon_rsn_t for API stability; new fields land at
 * the bottom and are zero-initialised by beacon_parse on entry.
 *
 * Names are short strings ("CCMP", "PSK", "SAE", "Apple", "Cisco");
 * empty means absent. */
typedef struct {
    /* ── RSN inventory ──────────────────────────────────── */
    char pairwise[12];
    char group[12];
    char akm[24];       /* up to 3 AKMs joined by commas */
    int  mfp;           /* 0=off  1=capable  2=required */
    /* ── Vendor IE fingerprint ──────────────────────────── */
    char vendor[24];    /* "Apple", "Cisco", "Mikrotik", … or "" */
    int  has_wps;       /* Wi-Fi Protected Setup IE present */
    int  wps_state;     /* 0=unknown 1=NotConfigured 2=Configured */
    int  wps_locked;    /* 0=unknown 1=unlocked       2=locked    */
    /* Config Methods bitmap and Device Password ID (#82, WFA WPS 2.0
     * §12, attribute IDs 0x1008 / 0x1012 — same TLV table as the
     * Manufacturer/Model/Serial attributes below). hostapd-class
     * beacons carry Device Password ID on every beacon, not just
     * during an active session: 0x0000 (Default/PIN) at rest, 0x0004
     * (Push Button) for the walk-time window a real WPS PBC pairing
     * is in progress. That one value is the reason to track this at
     * all — it names a live, unauthenticated physical-proximity
     * pairing window, the same air pattern `mdk4 w` abuses by forcing
     * it open continuously. 0 for both fields means "not observed":
     * a beacon that omits the attribute and one that sends the
     * literal Default/empty value are indistinguishable, and read the
     * same way — no active exposure evidenced. Unlike the vendor
     * strings below, not sticky: overwritten every beacon so the flag
     * clears when the session ends. */
    uint16_t wps_config_methods;
    uint16_t wps_device_pwd_id;
/* The one Device Password ID value with a detection meaning (WFA WPS
 * 2.0 §12). Named here rather than spelled 0x0004 at each use, because
 * the WPS_PBC_RACE rule (#82 wave 8) keys the whole walk-time window
 * on it. */
#define WPS_DEV_PWD_ID_PBC 0x0004
    /* WPS vendor-string leakage (#77): Manufacturer / Model Name / Model
     * Number / Serial Number attributes inside the WPS IE (WFA WPS 2.0
     * §12, attribute IDs 0x1021/0x1023/0x1024/0x1042). Many SOHO routers
     * and default hostapd/OpenWrt builds broadcast these in plaintext on
     * every beacon — a fingerprinting/TSCM signal that needs no
     * attacker-tool attribution to be useful. "" = attribute absent.
     * Buffer sizes are the spec's own per-attribute length ceiling
     * (64/32/32/32) plus a NUL.
     *
     * Filtered to printable ASCII (0x20..0x7e) by wps_attr_str(), the
     * single writer of all four — §12 defines them as ASCII strings, and
     * these bytes reach a bare printf in the ANSI-fallback builds. The
     * stored value can therefore be shorter than what was on the air,
     * and "" also means every byte of a present attribute was
     * non-printable. */
    char wps_manufacturer[65];
    char wps_model_name[33];
    char wps_model_number[33];
    char wps_serial[33];
    /* Max PHY tier — "Wi-Fi 7" / "6" / "5" / "4" / "legacy" / "" */
    char phy[10];
    /* 802.11k Neighbor Report list (tag 52). Up to MAX_AP_NEIGHBORS;
     * later entries silently dropped on overflow. */
    ap_neighbor_t neighbors[MAX_AP_NEIGHBORS];
    int  neighbor_count;
    /* Evil-twin fingerprint — populated per beacon. The OUI is
     * filled from the BSSID by beacon_record (parser doesn't see the
     * BSSID assembled), so beacon_parse leaves fp.oui == {0,0,0}. */
    ap_fingerprint_t fp;
    /* QBSS Load IE (tag 11) — AP-reported occupancy. has_qbss=0 = IE absent
     * (distinguishes it from a genuine "0 stations / 0% utilisation"). */
    int  has_qbss;
    int  qbss_stations;   /* associated station count */
    int  qbss_chan_util;  /* channel utilisation, 0..255 (fraction of 255) */
    /* Malformed-IE signals for the mgmt-frame fuzz detector (#33). Set
     * per frame by beacon_parse; accumulated per BSSID by beacon_record.
     *   ie_overruns   an IE claimed a length that ran off the frame end
     *   oversize_ssid SSID IE length > 32 (invalid per 802.11)
     *   truncated_rsn RSN IE (tag 48) present but too short to be valid
     *                 (< 8 octets), or one whose declared suite/PMKID
     *                 count or fixed field ran past its length (#128,
     *                 rsn_ie_t.truncated) */
    int  ie_overruns;
    int  oversize_ssid;
    int  truncated_rsn;
    /* Suite-selector bitmaps: bit N set means 00-0F-AC suite type N was
     * advertised. `akm[]` above is display-oriented — it caps at three
     * entries and joins names — so it cannot answer "are PSK and SAE
     * both on offer?", which is the WPA3-transition and ask-vs-grant
     * downgrade question (#60, #62). Substring matching it is actively
     * wrong: "SAE" matches inside "FT-SAE" and "SAE-EXT-KEY", and a
     * fourth suite is silently dropped. These are the machine-readable
     * form; the strings stay for display. Suite types above 31 are not
     * representable and are skipped — none are defined today. */
    uint32_t akm_bits;
    uint32_t pairwise_bits;
    /* Legacy WPA1 vendor IE (00:50:F2 type 1). Tracked separately from
     * `enc` because the finding is WPA1 *alongside* RSN — an AP still
     * offering TKIP to anything that asks — and `enc` reports only the
     * strongest mode it found (#62). */
    int  has_wpa1;
    /* Wi-Fi Alliance OWE Transition Mode element (OUI 50:6F:9A type
     * 0x1C). Names the paired BSS an OWE network offers as its open
     * lane; presence is the signal, the pairing is checked by the rule
     * because one beacon cannot see the other BSS. */
    int  owe_trans;
    /* Channel Switch Announcement (#63): tag 37, or tag 60 when the AP
     * also names a new operating class. csa_present distinguishes "no
     * switch announced" from a switch to channel 0, which is not a
     * channel — the IE is absent far more often than it is present, so
     * conflating the two would report a pending switch on every AP. */
    int  csa_present;
    int  csa_new_channel;
    int  csa_new_op_class;   /* 0 when only tag 37 was present */
    int  csa_switch_mode;
    int  csa_switch_count;
    /* Operation-IE decode (#66). oper_width is a sloth_ch_width_t;
     * 0 means no operation IE was present and the caller should keep
     * whatever it had. */
    int  oper_primary_channel;
    int  oper_channel_source;   /* sloth_ch_source_t */
    int  oper_width;
    int  oper_secondary_offset;
    int  oper_center_seg0;
    int  oper_center_seg1;
    /* Multi-Link Element (#67). The element body is copied out rather
     * than parsed here, because the parser is shared with the nl80211
     * path and recording a device identity is not a parsing concern —
     * the capture path decides whether to observe it. 0 = absent. */
    const uint8_t *mle_body;
    int  mle_len;
    /* Beacon body Timestamp field (#77): the AP's own TSF timer value
     * at transmission, bytes 24..31 of the frame, little-endian (IEEE
     * 802.11-2020 §9.3.3.2 beacon frame body order 1; field
     * §9.4.1.10). Feeds the per-BSSID TBTT-jitter accumulator.
     *
     * `has_tsf` exists because 0 is a legal timestamp — a just-booted
     * AP emits it — and because beacon_parse_ies is also the
     * managed-mode nl80211 path, which is handed an IE blob with no
     * frame around it and therefore has no timestamp to report. Set by
     * beacon_parse *after* the IE walk, so that path correctly leaves
     * all three fields zero.
     *
     * The interval is carried here in TU rather than reusing the
     * caller's `beacon_ms`: that value is rounded to whole
     * milliseconds, and a 400 µs rounding error per TBTT accumulates
     * to more than a beacon interval over a gap of a few thousand
     * beacons — which would corrupt the very residual being measured. */
    uint64_t tsf;
    int      has_tsf;
    uint16_t tsf_bi_tu;
    /* Regulatory envelope parsed from this frame (#101 slice 2):
     * Country, Power Constraint, TPC Report. Carried here as well as
     * through beacon_parse_ies' own `reg_out` so that beacon_record —
     * which takes the rsn and nothing else — can retain it per BSSID
     * without widening its signature and every one of its ~50 existing
     * call sites. The two outputs are written from the same parse, so
     * they never disagree. */
    reg_ie_t reg;
} beacon_rsn_t;

/* RSN_SUITE_BIT, the RSN_AKM_* families and RSN_CIPHER_* live in
 * rsn_ie.h with the one RSNE parser that produces the bitmaps (#128);
 * included above so every reader of beacon_rsn_t still sees them. */

/* Short display label for an AKM suite bitmap — "SAE", "PSK",
 * "SAE+PSK" for a transition-mode BSS, "802.1X", "OWE", "open" when no
 * AKM is advertised, "?" for suites this build does not name.
 *
 * Lives here because this is where akm_bits is produced and akm_name()
 * already exists; the alternative was a second suite-to-name table in
 * whichever view needed one first. Families collapse — FT-SAE and
 * SAE-EXT-KEY both read "SAE" — because the question a row is
 * answering is which lane the client is on, not which roaming variant.
 * Writes at most `sz` bytes including the NUL. */
void rsn_akm_label(uint32_t akm_bits, char *out, size_t sz);

/* Walk an Information-Element blob and fill the same outputs
 * beacon_parse produces (roadmap B3b).
 *
 * Exposed so the managed-mode nl80211 path can reach this parser
 * instead of its own shallow one — nl80211 hands over
 * NL80211_BSS_INFORMATION_ELEMENTS, which is exactly this blob, so the
 * seam is the IE list rather than a frame. `privacy` is the capability
 * field's Privacy bit; `beacon_ms` only feeds the fingerprint and may
 * be 0 when the caller has no beacon interval.
 *
 * `rsn_out` is fully zeroed on entry. Returns 1.
 *
 * `reg_out` is the regulatory envelope (#101): Country, Power
 * Constraint and TPC Report. Optional and fully written before return
 * on the same terms as `rsn_out`, and a caller with no use for it
 * passes NULL — it is also published into `rsn_out->reg`, which is the
 * copy beacon_record retains per BSSID, so both outputs always carry
 * the same parse. It rides this seam rather than its own IE walk so the
 * monitor and nl80211 paths cannot diverge on it the way they once did
 * on RSN depth.
 *
 * Note the output conventions are this file's, not linux_wifi.c's:
 * a hidden SSID is "" (not "<hidden>") and open is "OPEN" (not
 * "Open"). Callers that publish into a format with the other
 * convention must map. */
int beacon_parse_ies(const uint8_t *ies, int ies_len, int privacy,
                     uint16_t beacon_ms,
                     char ssid_out[33], int *channel_out, char enc_out[10],
                     beacon_rsn_t *rsn_out, reg_ie_t *reg_out);

/* Parse a raw 802.11 beacon frame (after radiotap, starting at FC byte).
   Extracts SSID, BSSID, channel, encryption mode, beacon interval, and
   (if rsn_out != NULL) the RSN inventory.
   signal_dbm comes from the enclosing radiotap header.
   Returns 1 on success, 0 if frame is not a valid beacon. */
int beacon_parse(const uint8_t *dot11, int len, int8_t signal,
                 char ssid_out[33], uint8_t bssid_out[6],
                 int *channel_out, char enc_out[10], uint16_t *beacon_ms_out,
                 beacon_rsn_t *rsn_out);
/* The same, on a frame on_probe_frame() has already decoded (#130). */
int beacon_parse_frame(const dot11_frame_t *f, int8_t signal,
                       char ssid_out[33], uint8_t bssid_out[6],
                       int *channel_out, char enc_out[10],
                       uint16_t *beacon_ms_out, beacon_rsn_t *rsn_out);

/* Record or update an AP in the internal table (thread-safe). rsn may
 * be NULL — fields default to empty / mfp=0 in that case.
 *
 * `rsn->reg` is folded into the entry's retained regulatory envelope
 * per element (#101); see reg_ie_merge() for why a frame that omits an
 * element leaves the stored one alone instead of zeroing it. */
void beacon_record(const uint8_t *bssid, const char *ssid,
                   int8_t signal, int channel,
                   const char *enc, uint16_t beacon_ms,
                   const beacon_rsn_t *rsn);

/* Copy current table into s->beacon_aps[], aging out stale entries first.
   Sorts by signal strength descending. */
void beacon_snapshot(sloth_state_t *s);

/* If a beacon entry for `bssid` exists and its SSID is empty (hidden),
 * fill it in with `ssid` and mark the entry as revealed. Fed by
 * probe-response / (re)association-response frames captured in
 * monitor mode. NOP if bssid isn't tracked yet or SSID was already
 * known. */
void beacon_reveal_hidden_ssid(const uint8_t *bssid, const char *ssid);

/* Look up the SSID we've observed for `bssid`. Copies into `ssid_out`
 * (NUL-terminated, up to 33 chars) and returns 1 on hit, 0 on miss.
 * Used by the EAPOL module to label captured handshakes with the
 * network name. */
int  beacon_find_ssid(const uint8_t bssid[6], char ssid_out[33]);

/* Management-frame protection state this BSSID's beacon advertises:
 * 2 = required, 1 = capable but not required, 0 = off, -1 = the BSSID
 * has never been heard beacon.
 *
 * The -1 matters and is not the same as 0. On a hopping radio most
 * BSSIDs are unheard most of the time, and a detector that reads "no
 * beacon on file" as "MFP is off" fires on every network it has not
 * tuned to yet. Callers must distinguish. */
int  beacon_find_mfp(const uint8_t bssid[6]);

/* Beacon interval this BSSID advertises, in milliseconds, or 0 if the
 * BSSID has never been heard beacon. Used by PM_FORGE (#107) to size
 * its contradiction window from the AP's own schedule rather than a
 * guessed constant: §2 does not pick a number when the capture already
 * carries the right one. */
int  beacon_find_interval_ms(const uint8_t bssid[6]);

/* Derive the beacon TBTT jitter figures from an accumulator (#77).
 *
 * `stddev_us` is the population standard deviation of the per-beacon
 * TBTT residual in microseconds — the AP's medium-access deferral
 * spread. `mean_us` is the mean residual; it is offset by the unknown
 * deferral of whichever beacon happened to establish the baseline, so
 * it is diagnostic only and is not the published quantity.
 *
 * Returns 1 when at least TBTT_JITTER_MIN_SAMPLES residuals have been
 * accumulated, 0 otherwise (outputs zeroed). Either pointer may be
 * NULL. Reads a caller-owned snapshot struct, so it takes no lock. */
int beacon_tbtt_jitter(const ap_beacon_timing_t *t,
                       uint32_t *stddev_us, int64_t *mean_us);

/* ── AP-Setup-Locked transition ring readers (#82) ────────
 *
 * beacon_ap_t stores the ring as three bare fields indexed modulo
 * WPS_LOCK_RING (see include/sloth.h). These three readers are the
 * only code outside wps_lock_note() that is allowed to know that
 * layout: a second module doing its own modular arithmetic over
 * wps_lock_n is how the lifetime sequence and the slot order drift
 * apart. They take a caller-owned beacon_ap_t out of a snapshot, so
 * they take no lock.
 *
 * `to` is the lock state *entered* by the transition, matching
 * beacon_ap_t::wps_lock_to: 1 = unlocked, 2 = locked. 0 never
 * appears, because an unknown state on either side records nothing. */
typedef struct {
    time_t  ts;
    uint8_t to;
} wps_lock_evt_t;

/* Copy up to `max` of the most recent transitions into `out`, oldest
 * first, and return how many were written. Never writes more than
 * WPS_LOCK_RING entries, however large `max` is, because that is all
 * the ring holds. Returns 0 without writing for a NULL `ap`, a NULL
 * `out`, `max <= 0`, or an AP with no transitions. */
int wps_lock_history(const beacon_ap_t *ap, wps_lock_evt_t *out, int max);

/* Completed locked->unlocked transitions whose timestamp falls inside
 * the last `window_s` seconds.
 *
 * The ring stores transitions between *known* lock states only, so
 * they strictly alternate: an entry whose destination is unlocked was
 * necessarily preceded by one into locked. That is the same definition
 * of "cycle" the lifetime wps_lock_cycles counter uses, and it lives
 * here rather than in src/alerts/ so the WPS_LOCKOUT_CYCLING rule and the
 * beacon detail screen cannot disagree about the number they show the
 * operator. */
int wps_lock_cycles_in_window(const beacon_ap_t *ap, time_t now,
                              int window_s);

/* Transitions this AP has made that the ring no longer holds, i.e.
 * wps_lock_n minus its retained tail. Derived from ring capacity, not
 * from how many rows a caller chose to render: a view with a smaller
 * row budget than the ring must not report the rows it skipped as
 * evidence that aged out. 0 for a NULL `ap`. */
int wps_lock_dropped(const beacon_ap_t *ap);

/* Clear the internal AP table. */
void beacon_clear(void);

/* Number of distinct new BSSIDs first seen within the last `window_s`
 * seconds — the beacon-flood signal (roadmap B4). A legit RF neighbourhood
 * gains APs slowly; an mdk-style flood spikes this hard. Thread-safe. */
int  beacon_recent_new_bssids(time_t now, int window_s);

#endif /* BEACON_SNOOP_H */
