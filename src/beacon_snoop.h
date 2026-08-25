#ifndef BEACON_SNOOP_H
#define BEACON_SNOOP_H

#include <stdint.h>
#include <stddef.h>
#include "sloth.h"

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
     *   truncated_rsn RSN IE (tag 48) present but too short to be valid */
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
} beacon_rsn_t;

/* Suite-type bit for a 00-0F-AC selector (IEEE 802.11-2020 Table 9-151
 * for AKM, Table 9-149 for ciphers). */
#define RSN_SUITE_BIT(t)  (1u << (t))

/* AKM families worth naming, because the downgrade rules ask about the
 * family rather than one selector. Keep these in sync with akm_name(). */
#define RSN_AKM_PSK          RSN_SUITE_BIT(2)
#define RSN_AKM_FT_PSK       RSN_SUITE_BIT(4)
#define RSN_AKM_PSK_SHA256   RSN_SUITE_BIT(6)
#define RSN_AKM_SAE          RSN_SUITE_BIT(8)
#define RSN_AKM_FT_SAE       RSN_SUITE_BIT(9)
#define RSN_AKM_OWE          RSN_SUITE_BIT(18)
#define RSN_AKM_SAE_EXT      RSN_SUITE_BIT(24)
#define RSN_AKM_FT_SAE_EXT   RSN_SUITE_BIT(25)

/* Any PSK-based AKM — the WPA2 lane of a transition-mode BSS. */
#define RSN_AKM_PSK_FAMILY \
    (RSN_AKM_PSK | RSN_AKM_FT_PSK | RSN_AKM_PSK_SHA256)

/* Any SAE-based AKM — the WPA3 lane. */
#define RSN_AKM_SAE_FAMILY \
    (RSN_AKM_SAE | RSN_AKM_FT_SAE | RSN_AKM_SAE_EXT | RSN_AKM_FT_SAE_EXT)

/* Pairwise ciphers the posture rules care about. */
#define RSN_CIPHER_TKIP      RSN_SUITE_BIT(2)
#define RSN_CIPHER_CCMP      RSN_SUITE_BIT(4)

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
 * Note the output conventions are this file's, not linux_wifi.c's:
 * a hidden SSID is "" (not "<hidden>") and open is "OPEN" (not
 * "Open"). Callers that publish into a format with the other
 * convention must map. */
int beacon_parse_ies(const uint8_t *ies, int ies_len, int privacy,
                     uint16_t beacon_ms,
                     char ssid_out[33], int *channel_out, char enc_out[10],
                     beacon_rsn_t *rsn_out);

/* Parse a raw 802.11 beacon frame (after radiotap, starting at FC byte).
   Extracts SSID, BSSID, channel, encryption mode, beacon interval, and
   (if rsn_out != NULL) the RSN inventory.
   signal_dbm comes from the enclosing radiotap header.
   Returns 1 on success, 0 if frame is not a valid beacon. */
int beacon_parse(const uint8_t *dot11, int len, int8_t signal,
                 char ssid_out[33], uint8_t bssid_out[6],
                 int *channel_out, char enc_out[10], uint16_t *beacon_ms_out,
                 beacon_rsn_t *rsn_out);

/* Record or update an AP in the internal table (thread-safe). rsn may
 * be NULL — fields default to empty / mfp=0 in that case. */
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

/* Clear the internal AP table. */
void beacon_clear(void);

/* Number of distinct new BSSIDs first seen within the last `window_s`
 * seconds — the beacon-flood signal (roadmap B4). A legit RF neighbourhood
 * gains APs slowly; an mdk-style flood spikes this hard. Thread-safe. */
int  beacon_recent_new_bssids(time_t now, int window_s);

#endif /* BEACON_SNOOP_H */
