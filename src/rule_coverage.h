#ifndef SLOTH_RULE_COVERAGE_H
#define SLOTH_RULE_COVERAGE_H

#include <stddef.h>
#include "sloth_alert.h"

/* ── Coverage assessment (#242) ──────────────────────────────────────
 *
 * A quiet site and a blind sensor produce the same empty alert list.
 * This module answers, for each alert kind, whether the rule behind it
 * can fire in the sensor's present configuration:
 *
 *   observable   its input is delivering and nothing known stands
 *                between the evidence and the rule
 *   partly       it can fire, and the sensor is known to miss part of
 *                the evidence (a hopping radio is off the channel for
 *                most of any window)
 *   blind        it cannot fire, and the reason says what is missing
 *
 * Two halves. The declaration (include/sloth_alert_inputs.def) says
 * what each rule reads; it is a fact about the code. The environment
 * (cov_env_t) says what the sensor has; the caller fills it from the
 * source rows, the radios and the command line. cov_rule_status() is a
 * pure function of the two: no clock, no state, no I/O, so it links
 * into both daemons and is tested without either.
 *
 * WHAT "OBSERVABLE" DOES NOT CLAIM. For an 802.11 rule it means: on the
 * channels the radios visit. A transmitter on a channel that is in no
 * radio's plan is not heard, and the status does not say so; only the
 * band is checked (a rule about 5 GHz with no radio in 5 GHz is blind).
 * The channels and the time on each belong to the coverage record.
 *
 * The status is about the sensor, never about the site: `observable`
 * with no finding is "looked and found nothing", which is still not
 * "nothing is there". */

typedef enum {
    COV_IN_DOT11 = 0,   /* 802.11 frames, a radio in monitor mode */
    COV_IN_IP,          /* the IP capture */
    COV_IN_HOST,        /* the host's kernel tables */
    COV_IN_BLE_ADV,     /* BLE advertising: btmon or btcap */
    COV_IN_BLE_HCI,     /* the host controller's commands: btmon only */
    COV_IN_GNSS,
    COV_IN_ADSB,
    COV_IN_SYS,         /* sloth's own status sampler */
    COV_IN_COUNT
} cov_input_t;

/* 802.11 frame classes (FRAMES in the .def). */
#define COV_F_BEACON  0x001u   /* beacons and probe responses */
#define COV_F_PROBE   0x002u   /* probe requests */
#define COV_F_AUTH    0x004u
#define COV_F_ASSOC   0x008u   /* (re)association requests and responses */
#define COV_F_DEAUTH  0x010u   /* and disassociation */
#define COV_F_ACTION  0x020u
#define COV_F_CTRL    0x040u
#define COV_F_DATA    0x080u
#define COV_F_EAPOL   0x100u   /* EAPOL and EAP, in data frames */
#define COV_F_ALL     0x1ffu

/* Bands. The DFS channels of 5 GHz (52-64, 100-144) are their own bit:
 * the default --hop list visits none of them, and one rule is about
 * exactly those channels. */
#define COV_B_ANY     0u
#define COV_B_24      0x1u
#define COV_B_5       0x2u     /* 5 GHz outside the DFS channels */
#define COV_B_5DFS    0x4u
#define COV_B_6       0x8u
#define COV_B_ALL     0xfu

typedef enum {
    COV_SHAPE_NA = 0,   /* not an 802.11 rule */
    COV_SHAPE_STATE,
    COV_SHAPE_RATE,
    COV_SHAPE_EVENT,
    COV_SHAPE_EXCHANGE
} cov_shape_t;

/* Operator configuration a rule is silent without (NEEDS). */
#define COV_N_OWN_NET 0x1u     /* --my-ssid / --my-bssid */
#define COV_N_ROSTER  0x2u     /* --known-mac / --known-macs */
#define COV_N_DB      0x4u     /* --db */
#define COV_N_ALL     0x7u

typedef struct {
    cov_input_t input;
    unsigned    frames;   /* COV_F_*, 0 unless input is DOT11 */
    unsigned    bands;    /* COV_B_*, COV_B_ANY = every band */
    cov_shape_t shape;
    unsigned    needs;    /* COV_N_* */
} cov_inputs_t;

/* The declaration of `t`; NULL out of range. */
const cov_inputs_t *cov_inputs(alert_type_t t);

/* What the sensor has of one input. */
typedef enum {
    COV_AV_NONE = 0,    /* not configured, or not this daemon's */
    COV_AV_DOWN,        /* configured and not delivering */
    COV_AV_STALE,       /* delivering, nothing received lately */
    COV_AV_UP
} cov_avail_t;

typedef struct {
    cov_avail_t input[COV_IN_COUNT];
    /* The 802.11 radios, all of them together. */
    unsigned bands;     /* COV_B_* their channels lie in; 0 = not known,
                         * and the band check is then skipped */
    int      radios;    /* radios delivering frames */
    int      channels;  /* distinct channels over all their plans */
    int      hopping;   /* a radio is retuned on a schedule */
    unsigned config;    /* COV_N_* the operator has configured */
} cov_env_t;

typedef enum {
    COV_BLIND = 0,
    COV_PARTLY,
    COV_OBSERVABLE
} cov_status_t;

/* One word for why a status is not `observable`. Appended only: the
 * words are written to the stream. */
typedef enum {
    COV_R_NONE = 0,
    COV_R_NO_SOURCE,      /* blind: the input is not configured */
    COV_R_SOURCE_DOWN,    /* blind: configured, not delivering */
    COV_R_NO_OWN_NET,     /* blind: no designated network */
    COV_R_NO_ROSTER,      /* blind: no roster of known devices */
    COV_R_NO_DB,          /* blind: no database to read history from */
    COV_R_BAND,           /* blind: no radio in the rule's band */
    COV_R_SOURCE_STALE,   /* partly: nothing received lately */
    COV_R_FIXED_CHANNEL,  /* partly: the radios are not retuned */
    COV_R_HOP,            /* partly: off the channel for part of the evidence */
    COV_R_COUNT
} cov_reason_t;

/* The status of `t` under `env`. `why` (may be NULL) receives the
 * reason, COV_R_NONE when observable. A blind reason is reported in
 * preference to a partly one, and in the order of the enum, so the
 * first thing to fix is the one named. Out of range or NULL env:
 * COV_BLIND with COV_R_NO_SOURCE. */
cov_status_t cov_rule_status(alert_type_t t, const cov_env_t *env,
                             cov_reason_t *why);

const char *cov_input_name(cov_input_t in);     /* "dot11", "ip", ... */
const char *cov_shape_name(cov_shape_t sh);     /* "", "state", ... */
const char *cov_status_name(cov_status_t st);   /* "blind", "partly", "observable" */
const char *cov_reason_name(cov_reason_t r);    /* "", "no_source", ... */

/* Comma-joined names of a COV_F_* / COV_B_* / COV_N_* mask
 * ("beacon,eapol"; "5,5dfs"; "own_net,roster"), "" for 0. Returns the
 * length written, truncating at sz-1. */
int cov_frames_str(unsigned frames, char *out, size_t sz);
int cov_bands_str(unsigned bands, char *out, size_t sz);
int cov_needs_str(unsigned needs, char *out, size_t sz);

/* The COV_B_* bit a frequency lies in, 0 when it is in no band. */
unsigned cov_band_of_mhz(int mhz);

#endif /* SLOTH_RULE_COVERAGE_H */
