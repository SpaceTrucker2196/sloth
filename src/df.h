#ifndef SLOTH_DF_H
#define SLOTH_DF_H

#include <stdint.h>
#include <time.h>

/* Direction finding across monitor radios (2026-11-16, owner's request
 * for the beta-site row of Alfa adapters).
 *
 * What it is: a table of transmitters, each with the signal strength
 * every radio last heard it at. Radio 0 is sloth's own monitor radio
 * (probe.c); radios 1.. are the --df-iface ones (df_radio.c), which
 * feed this table and NOTHING else: no detector, counter or alert reads
 * a frame from them, so a frame three radios hear is still one frame to
 * every rule.
 *
 * What it can say: independent USB radios share no clock, so there is
 * no phase to compare and no angle of arrival. The only evidence is
 * that a nearer antenna hears a transmitter louder. From that:
 *   - which radio hears it loudest, and by how many dB over the
 *     quietest (the margin);
 *   - when the radios have a position on a baseline (--df-iface
 *     NAME@METRES), a point along that baseline, the power-weighted
 *     mean of the radio positions (`along_m`).
 * What it cannot say: which side of the line the transmitter is on, how
 * far off the line it is, or anything at all when the margin is inside
 * the fading a single antenna sees on its own (DF_MIN_MARGIN_DB). A
 * transmitter far away compared with the baseline is heard equally by
 * every radio and reads `weak`: that is the answer, not a fault.
 *
 * Calibration. Two radios do not read the same level for the same
 * signal: receiver, antenna, cable and port differ (the beta-site pair
 * sat 14 dB apart on every transmitter, 2026-11-16). Left in, that
 * difference is the whole margin and everything leans one way. So each
 * radio's bias against radio 0 is measured from the air: the median,
 * over the transmitters both hold a fresh level for, of the difference
 * in their means (df_snapshot() takes it, DF_CAL_MIN transmitters or
 * more, smoothed). With a baseline short beside the distance to most
 * transmitters, most of them are heard equally and the median is the
 * hardware. It is wrong where most transmitters really are nearer one
 * radio; a longer baseline or sector antennas need a measured offset
 * instead, which is not built. Levels are compared less the bias.
 *
 * A data point for an analyst. No alert rule reads it. */

#define DF_MAX_RADIOS     4
#define DF_MAX_EMITTERS   512
#define DF_FRESH_S        30     /* a radio's reading older than this is not used */
#define DF_MIN_SAMPLES    3      /* frames from a radio before its mean is used */
#define DF_MIN_MARGIN_DB  6.0    /* below this the radios agree: no lean */
#define DF_CAL_MIN        8      /* transmitters two radios share before a bias is taken */

typedef struct {
    char   iface[16];
    int    has_pos;
    double pos_m;                /* along the baseline, metres */
    uint64_t frames;             /* transmitter frames noted from it */
    int    calibrated;           /* bias_db is a measurement (radio 0: always 0) */
    double bias_db;              /* how much louder than radio 0 it reads */
} df_radio_t;

typedef enum {
    DF_NONE = 0,                 /* fewer than two radios hold a fresh mean */
    DF_WEAK,                     /* two or more, margin under DF_MIN_MARGIN_DB */
    DF_LEAN                      /* margin at or over it */
} df_quality_t;

typedef struct {
    uint8_t mac[6];
    time_t  last_seen;
    int     channel;             /* of the newest frame, 0 unknown */
    int     heard_by;            /* radios with a fresh, sampled mean */
    int     has[DF_MAX_RADIOS];  /* that radio is one of them */
    double  rssi[DF_MAX_RADIOS]; /* its mean as measured, dBm */
    double  level[DF_MAX_RADIOS];/* the same less the radio's bias: what is compared */
    int     best_radio;          /* loudest of them, -1 none */
    double  margin_db;           /* loudest minus quietest */
    df_quality_t quality;
    int     has_along;           /* every heard radio has a position, 2+ of them */
    double  along_m;
} df_est_t;

/* Forget every radio and transmitter. */
void df_reset(void);

/* Register a radio; its index (0 first), or -1 when the table is full,
 * the name is empty or too long, or already registered. */
int df_radio_add(const char *iface, int has_pos, double pos_m);
int df_radio_count(void);
int df_radio_get(int i, df_radio_t *out);
int df_radio_find(const char *iface);

/* One frame from `mac` heard by `radio` at rssi_dbm (negative; 0 or
 * above is "no reading" and ignored, as is a multicast address). The
 * per-radio mean is exponential, so a reading tracks a moving
 * transmitter and a burst of loud frames does not own it. Thread-safe:
 * every capture thread calls it. */
void df_note(int radio, const uint8_t mac[6], int rssi_dbm, int channel, time_t now);

/* The estimate for one transmitter, 1, or 0 when it is not in the table. */
int df_estimate(const uint8_t mac[6], time_t now, df_est_t *out);

/* Every transmitter two or more radios hold a fresh mean for, most
 * recently heard first, at most max. The count. */
int df_snapshot(df_est_t *out, int max, time_t now);

/* Transmitters in the table, and how many frames were dropped because
 * it was full of fresher ones. */
int      df_emitter_count(void);
uint64_t df_dropped(void);

/* Whether a second radio is registered: the one check the sensor
 * radio's frame path makes before noting anything. Set by
 * df_radio_add() before any capture thread starts. */
int df_active(void);

/* The transmitter of an 802.11 frame (after radiotap, FCS off): 1 and
 * ta filled for a management or data frame long enough to hold Address
 * 2; 0 for a control frame (an ACK or CTS has no transmitter address;
 * the ones that do are left out with them), a short frame, or a
 * protocol version other than 0. Pure. */
int  df_frame_ta(const uint8_t *dot11, int len, uint8_t ta[6]);

const char *df_quality_name(df_quality_t q);

/* "NAME" or "NAME@METRES" (--df-iface). 1 and the parts, 0 when the
 * name is empty, 16 bytes or longer, or the metres are not a finite
 * number within +/-1000. */
int df_parse_spec(const char *spec, char *iface, int iface_sz, int *has_pos, double *pos_m);

#endif
