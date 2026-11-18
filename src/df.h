#ifndef SLOTH_DF_H
#define SLOTH_DF_H

#include <stddef.h>
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
 * Radios off the line (2026-11-17, the owner's triangle of three Alfa
 * adapters, 2 m sides). With a position in two dimensions on every
 * radio (--df-iface NAME@X,Y: metres east, metres north) the symmetry
 * about the line is broken, and the same power-weighted mean of the
 * radio positions has a direction from the middle of the array:
 * `bearing_deg`, compass degrees (0 north, 90 east) from the centroid
 * of the radio positions. It is the direction the levels LEAN, not a
 * fix: the weighted mean always lies inside the array, so it is never
 * the transmitter's place and is not reported as one. The bearing is
 * withheld (df_est_t.has_bearing 0) unless
 *   - three or more radios have a 2D position and they are not on one
 *     line (the array's depth across its longest side is at least
 *     DF_MIN_ASPECT of that side);
 *   - every positioned radio holds a fresh level, and no radio without
 *     a position heard the transmitter;
 *   - the quality is `lean`: the same DF_MIN_MARGIN_DB the line form
 *     trusts, for the same reason (one antenna's own fading);
 *   - moving any one radio's level by DF_BEARING_WANDER_DB either way
 *     moves the direction by no more than DF_BEARING_MAX_ERR_DEG.
 * With a 2 m baseline that means a transmitter within about three
 * metres: at 10 m the radios differ by under 2 dB. Withheld is the
 * common case and the answer, not a fault. What is given is one of
 * eight compass points (DF_BEARING_STEP_DEG) with the largest of those
 * moves beside it (`bearing_err_deg`).
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
#define DF_POS_MAX_M      1000.0 /* a position, either form, is within +/- this */

/* The bearing (2D positions only; see above).
 * STEP: eight compass points. At the 6 dB floor a 3 dB wander on one
 * radio moves the direction 20 to 40 degrees, so a finer step would be
 * precision the levels do not have, and a coarser one (90) would throw
 * away the six directions three radios do tell apart.
 * HYST: the point held changes only once the direction is this far
 * past the edge of its sector, so a still transmitter sitting on an
 * edge does not write a line every time its mean moves a degree.
 * WANDER: half the margin floor, the size of error one radio's mean is
 * taken to carry. MAX_ERR: one step; past it the direction could be
 * two points away and is not given.
 * ERR_STEP: bearing_err_deg is rounded up to this. */
#define DF_BEARING_STEP_DEG     45
#define DF_BEARING_HYST_DEG     11.25
#define DF_BEARING_WANDER_DB    (DF_MIN_MARGIN_DB / 2.0)
#define DF_BEARING_MAX_ERR_DEG  45.0
#define DF_BEARING_ERR_STEP_DEG 15
#define DF_MIN_ASPECT           0.25

typedef struct {
    char   iface[16];
    int    has_pos;
    double pos_m;                /* along the baseline, metres */
    int    has_xy;               /* placed in two dimensions instead (never with has_pos) */
    double x_m, y_m;             /* metres east, metres north */
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
    /* 2D positions only. The direction the levels lean, from the
     * centroid of the radio positions; withheld unless it can mean
     * something (see the top of this file). Never with has_along. */
    int     has_bearing;
    int     bearing_deg;         /* 0, 45 .. 315: compass, 0 north, 90 east */
    int     bearing_err_deg;     /* 15, 30 or 45: how far a DF_BEARING_WANDER_DB
                                  * error on one radio moves it, rounded up */
} df_est_t;

/* Forget every radio and transmitter. */
void df_reset(void);

/* Register a radio; its index (0 first), or -1 when the table is full,
 * the name is empty or too long, or already registered. */
int df_radio_add(const char *iface, int has_pos, double pos_m);
/* The same with a position in two dimensions, metres east and north. */
int df_radio_add_xy(const char *iface, double x_m, double y_m);
/* Whether the registered radios can give a bearing at all: three or
 * more hold a 2D position and those are not on one line. */
int df_array_has_bearing(void);
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

/* The command line (--df-iface, --df-origin), kept apart from main()
 * so every refusal is a tested line. A position is one number (METRES
 * along a straight baseline) or two (X,Y: metres east, metres north);
 * one command line uses one form. */
typedef enum { DF_POS_NONE = 0, DF_POS_LINE, DF_POS_XY } df_pos_form_t;

typedef struct {
    df_pos_form_t form;
    double a, b;                 /* LINE: a. XY: a east, b north. */
} df_pos_t;

typedef struct {
    int      n;                              /* --df-iface given */
    char     name[DF_MAX_RADIOS - 1][16];
    df_pos_t pos[DF_MAX_RADIOS - 1];
    int      origin_set;                     /* --df-origin given */
    df_pos_t origin;
} df_cli_t;

/* "NAME", "NAME@METRES" or "NAME@X,Y". 1 and the parts; 0 on what
 * df_parse_spec() refuses, a missing or extra number, or one that is
 * not finite and within +/-DF_POS_MAX_M. */
int df_parse_place(const char *spec, char *iface, int iface_sz, df_pos_t *pos);

/* One --df-iface / the --df-origin argument. 1, or 0 with the line to
 * print in err (no newline). */
int df_cli_add(df_cli_t *c, const char *spec, char *err, size_t errsz);
int df_cli_origin(df_cli_t *c, const char *arg, char *err, size_t errsz);
/* The whole of it, once argv is read: 0 with the line when positions
 * of both forms were given. */
int df_cli_check(const df_cli_t *c, char *err, size_t errsz);
/* DF_POS_XY, DF_POS_LINE or DF_POS_NONE: the form the positions given
 * are in (checked: never both). */
df_pos_form_t df_cli_form(const df_cli_t *c);

#endif
