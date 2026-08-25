#ifndef CTRL_FRAMES_H
#define CTRL_FRAMES_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* 802.11 control frames (type 1) — issue #64.
 *
 * frame_type_label() has named RTS / CTS / ACK / BlockAck since the
 * first release, and sloth then dropped them. Two things that left
 * unbuilt:
 *
 *   Airtime. Control frames dominate a channel's real utilisation, so
 *   without counting them the QBSS Load IE is the AP's *self-reported*
 *   occupancy rather than the observed one.
 *
 *   RTS/CTS airtime denial of service. A flood of RTS carrying a large
 *   NAV silences a channel for the reservation period without
 *   transmitting anything a flood detector was watching for.
 *
 * Lives outside src/capture/probe.c for the reason action_snoop.c and
 * radiotap.c do: probe.c is compiled only under WITH_PCAP and is absent
 * from TEST_SRCS, so logic placed there cannot be tested.
 *
 * ── The addressing constraint that shapes this module ──
 *
 * RTS, PS-Poll and the Block-Ack pair carry a transmitter address. CTS
 * and ACK carry **only a Receiver Address** — no TA, no BSSID. They can
 * be attributed to the channel they were heard on and to nothing else.
 * Rather than invent an attribution the frame does not carry, the
 * per-source table holds only the frames that name a source, and the
 * per-channel totals hold everything. */

/* 802.11 control subtypes we count (Table 9-1). */
#define CTRL_SUB_BLOCKACK_REQ  8
#define CTRL_SUB_BLOCKACK      9
#define CTRL_SUB_PS_POLL      10
#define CTRL_SUB_RTS          11
#define CTRL_SUB_CTS          12
#define CTRL_SUB_ACK          13

/* The Duration/ID field is a NAV reservation in microseconds. 32767 is
 * the largest legal value (§9.2.4.2); anything above it is synthetic,
 * because no conforming radio will emit one. */
#define CTRL_NAV_MAX_LEGAL  32767

/* An RTS flood is a rate no legitimate sender reaches. mdk4 -m x sprays
 * thousands per second; a saturated AP stays far below. The sustain
 * requirement is what separates a flood from a burst of retries. */
#define RTS_FLOOD_RATE       500   /* frames per second from one source */
#define RTS_FLOOD_SUSTAIN_S    5   /* for at least this long           */

#define CTRL_MAX_SOURCES  64
#define CTRL_MAX_CHANNELS 64

/* ── Block-Ack paralysis (Bl0ck) — #70 ─────────────────────
 *
 * arXiv 2302.05899. A spoofed Block-Ack Request sent on behalf of a
 * legitimate station forces its peer to advance the Block-Ack receive
 * window past frames that are still queued. Everything inside the
 * skipped range is discarded, and the connection stalls.
 *
 * It is quiet: no deauth, no flood, nothing the rate rules watch for.
 * The operator sees a client that has stopped working.
 *
 * The passive signature is a BAR whose Starting Sequence Number jumps
 * forward far more than traffic could account for.
 *
 * ── The hazard that defines this module ──
 *
 * SSN is a **12-bit field that wraps**. A jump computed as a plain
 * subtraction is negative or enormous on every wrap, which on a busy
 * station happens constantly. The comparison must be modulo 4096, and
 * the wrap case needs its own test — get this wrong and the detector is
 * green in CI and a false-positive generator on the air. */
#define BAR_SSN_MODULUS         4096
#define BAR_SUSPICIOUS_JUMP      128   /* frames skipped, modulo the wrap */
#define BAR_MAX_PAIRS            128

typedef struct {
    uint8_t  bssid[6];        /* the receiver the BAR is aimed at */
    uint8_t  sta[6];          /* the transmitter it claims to be  */
    uint8_t  tid;
    uint16_t last_ssn;
    uint16_t last_jump;       /* size of the most recent suspicious jump */
    uint32_t suspicious_bars;
    uint32_t total_bars;
    time_t   first_seen;
    time_t   last_bar_ts;
} sloth_bar_state_t;

/* Forward distance from `from` to `to` in the 12-bit sequence space.
 * Exposed because the wrap arithmetic is the whole hazard and deserves
 * to be tested directly rather than only through the detector. */
int  bar_ssn_forward_distance(uint16_t from, uint16_t to);

/* Worst (BSSID, STA, TID) triple by suspicious BAR count inside
 * `window_s`. Returns that count; fills *out on a hit. */
int  bar_worst_offender(time_t now, int window_s, sloth_bar_state_t *out);

int  bar_find(const uint8_t bssid[6], const uint8_t sta[6], int tid,
              sloth_bar_state_t *out);
int  bar_pair_count(void);

/* Record one control frame. `dot11` starts at the FC byte, post
 * radiotap. `channel` is the channel it was heard on (0 = unknown).
 * Ignores anything that is not type 1. Thread-safe. */
void ctrl_observe(const uint8_t *dot11, int len, int channel, time_t now);

/* Per-channel totals across every control subtype, including the ones
 * with no source address. Returns 0 when the channel is untracked. */
int  ctrl_channel_total(int channel);
int  ctrl_channel_subtype(int channel, int subtype);

/* Per-source counts. Only subtypes that carry a transmitter address are
 * ever recorded here — see the addressing note above. */
int  ctrl_source_count(const uint8_t ta[6], int subtype);

/* Busiest RTS source inside `window_s`, when its rate reaches
 * `rate_per_s` sustained for at least `sustain_s`. Returns the observed
 * frame count (0 if none qualifies) and writes the source address plus
 * the highest NAV value seen from it. */
int  ctrl_rts_flood(time_t now, int window_s, int rate_per_s, int sustain_s,
                    uint8_t out_ta[6], int *max_nav, int *duration_s);

void ctrl_snapshot(sloth_state_t *s);
int  ctrl_source_table_count(void);
void ctrl_clear(void);

#endif /* CTRL_FRAMES_H */
