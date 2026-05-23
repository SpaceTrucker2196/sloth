#ifndef BEACON_SNOOP_H
#define BEACON_SNOOP_H

#include <stdint.h>
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
    /* Max PHY tier — "Wi-Fi 7" / "6" / "5" / "4" / "legacy" / "" */
    char phy[10];
} beacon_rsn_t;

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

#endif /* BEACON_SNOOP_H */
