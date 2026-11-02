#ifndef SLOTH_POSITION_TRACK_H
#define SLOTH_POSITION_TRACK_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* Per-device position samples (2026-10-27, --gps).
 *
 * Where the SENSOR was when it heard a device, not where the device
 * is: sloth has one antenna and no bearing, so a series of these is a
 * drive-by record an analyst reads alongside the RSSI, never a fix on
 * the device. Only a moving sensor makes a series, so nothing is
 * sampled from a fixed --location (every sample would repeat it) or
 * without a fix younger than gps.max_fix_age_s.
 *
 * For each device heard in the last two seconds, a sample is queued
 * when the fix has moved gps.min_move_m since that device's previous
 * sample. At rest (moved less than that) one is queued only when the
 * device's RSSI 10 dB band has changed and gps.sample_s have passed, or
 * when gps.sample_s x 10 have passed: a parked sensor does not restate
 * its own position once a minute for every device it hears. The
 * sensor's own track is queued on a move or every gps.sample_s. The queues are drained by the --db writer into
 * device_positions / sensor_positions; with no sink attached nothing is
 * sampled. A queue that fills drops the oldest sample and counts it
 * (sensor_health gps_positions_dropped). */

#define POSTRACK_MAX_DEVICES 512   /* per-device "last sample" table, LRU */
#define POSTRACK_QUEUE       2048  /* device samples awaiting the writer */
#define POSTRACK_SENSOR_Q    256   /* sensor track samples awaiting it */

typedef struct {
    char    mac[18];
    time_t  ts;
    double  lat, lon;
    int     has_acc;
    double  acc_m;
    int     rssi;                  /* dBm, 0 none */
} postrack_sample_t;

typedef struct {
    time_t  ts;
    double  lat, lon;
    int     has_alt, has_acc;
    double  alt_m, acc_m;
    int     sats;
    double  hdop;
} postrack_sensor_t;

/* Attach (1) or detach (0) the consumer. db_open() attaches. */
void postrack_set_sink(int on);

/* PH_POST, after devices_update(). */
void postrack_tick(const sloth_state_t *s, time_t now);

/* Pop up to `max` queued samples, oldest first. Returns the count. */
int  postrack_drain_devices(postrack_sample_t *out, int max);
int  postrack_drain_sensor(postrack_sensor_t *out, int max);

/* Samples dropped because a queue was full. */
uint64_t postrack_dropped(void);

void postrack_clear(void);

#endif /* SLOTH_POSITION_TRACK_H */
