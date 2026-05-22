#ifndef SLOTH_SEQNUM_TRACK_H
#define SLOTH_SEQNUM_TRACK_H

#include <stdint.h>
#include "sloth.h"

/* Sequence-number-based device fingerprinting.
 *
 * 802.11 frames carry a 12-bit per-station sequence counter that
 * almost no stack actually randomises (it lives at the chipset level
 * below the OS's MAC-randomisation logic). If two "different" MACs
 * emit frames with sequence numbers that fall on the same monotonic
 * counter (within a small drift window), they are almost certainly
 * the same physical radio — a powerful deanonymisation primitive
 * against probe-request MAC randomisation.
 *
 * For each observed MAC we keep a small history of the most-recent
 * sequence numbers + timestamps. On snapshot the module emits
 * sniffer_correlation_t pairs whose seqnum trails overlap within
 * configurable thresholds.                                            */

/* seqnum_client_t, seqnum_correlation_t and the related capacities
 * live in sloth.h alongside the other data types embedded in
 * sloth_state_t. */

/* Record an observation. seqnum is the 12-bit value extracted from
 * the 802.11 SeqCtl field (bits 4..15 of the 16-bit SC). MAC must be
 * a 6-byte buffer. */
void seqnum_track_observe(const uint8_t mac[6], uint16_t seqnum);

/* Snapshot the per-MAC table + computed correlations into the state
 * vector. Correlations are sorted by ascending gap (smallest = most
 * likely match). */
void seqnum_snapshot(sloth_state_t *s);

/* Drop everything — tests only. */
void seqnum_clear(void);

/* Direct introspection for tests. */
int  seqnum_client_count(void);

#endif /* SLOTH_SEQNUM_TRACK_H */
