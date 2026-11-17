#ifndef SLOTH_DF_RADIO_H
#define SLOTH_DF_RADIO_H

#include <stddef.h>
#include <stdint.h>

/* The --df-iface radios (2026-11-16, src/df.h): extra monitor-mode
 * interfaces whose frames are read for ONE thing, the transmitter
 * address and the level it was heard at, noted into df.c's table. A
 * frame from one of them reaches no parser, detector, counter, ring or
 * record of the 802.11 stream: sloth's sensor is still the one radio
 * probe.c opens, and a frame three radios hear is one frame.
 *
 * Receive-only, like the sensor radio. The one kernel write is the
 * retune that keeps these radios on the sensor radio's channel under
 * --hop (df_radio_follow()): a level is only comparable between radios
 * that listened to the same transmission. Without --hop nothing is
 * retuned and the operator parks them. */

/* Open `iface` (already registered with df_radio_add(), which gave it
 * `radio`) as a monitor capture. 1, or 0 with why in err: absent, not
 * radiotap, a raw HCI device, or the table is full. Before the
 * privilege drop, beside probe_open(). */
int  df_radio_open(int radio, const char *iface, char *err, size_t errsz);

/* Start / stop one reader thread per opened radio. */
void df_radio_run(void);
void df_radio_stop(void);

/* How many are open. */
int  df_radio_open_count(void);

/* Retune every open radio to freq_mhz through the platform's
 * set_channel; the number that refused. */
int  df_radio_follow(int freq_mhz);

typedef struct {
    char     iface[16];
    int      open, running;
    uint64_t frames;         /* admitted by the radiotap gate */
    uint64_t noted;          /* of those, with a transmitter and a level */
    uint64_t rejects;        /* refused by the gate */
    uint64_t retune_failures;
} df_radio_health_t;
int  df_radio_health(int i, df_radio_health_t *out);

#endif
