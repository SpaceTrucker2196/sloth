#ifndef BEACON_SNOOP_H
#define BEACON_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* Parse a raw 802.11 beacon frame (after radiotap, starting at FC byte).
   Extracts SSID, BSSID, channel, encryption mode, and beacon interval.
   signal_dbm comes from the enclosing radiotap header.
   Returns 1 on success, 0 if frame is not a valid beacon. */
int beacon_parse(const uint8_t *dot11, int len, int8_t signal,
                 char ssid_out[33], uint8_t bssid_out[6],
                 int *channel_out, char enc_out[10], uint16_t *beacon_ms_out);

/* Record or update an AP in the internal table (thread-safe). */
void beacon_record(const uint8_t *bssid, const char *ssid,
                   int8_t signal, int channel,
                   const char *enc, uint16_t beacon_ms);

/* Copy current table into s->beacon_aps[], aging out stale entries first.
   Sorts by signal strength descending. */
void beacon_snapshot(sloth_state_t *s);

/* Clear the internal AP table. */
void beacon_clear(void);

#endif /* BEACON_SNOOP_H */
