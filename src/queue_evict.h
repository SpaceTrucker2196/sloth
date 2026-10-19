#ifndef QUEUE_EVICT_H
#define QUEUE_EVICT_H

#include <stdint.h>
#include <time.h>

#include "dot11_frame.h"

/* ── Transmit-queue release after a session change ──
 *  #107 shape B, Framing Frames (CVE-2022-47522).
 *
 * Shape A (src/pm_forge.c) watches the *input* to the attack: the
 * unencrypted PwrMgt bit that makes an AP start buffering a station's
 * downlink traffic. This module watches the *output* — the moment the
 * AP hands that buffer over.
 *
 * Vanhoef & Schepers show the queue survives the security context it
 * was filled under. The standard says nothing about flushing a
 * station's pending frames when its session changes, so an AP will
 * release them across a (re)association — encrypted under whatever key
 * the new session negotiated, which an attacker who reassociated under
 * the victim's address holds — and some will release them after the
 * station is disconnected, when the key has already been torn out of
 * the key store, i.e. in the clear.
 *
 * Either route looks the same from a passive receiver: a session-change
 * frame for one (BSSID, STA), then an immediate burst of unicast
 * downlink frames to that same station. That is all sloth can see, and
 * it is deliberately not much — **ordinary roaming produces the same
 * shape**, because an AP that has just admitted a station naturally has
 * traffic for it. So this module only *records* the burst; deciding
 * whether it means anything is rule_queue_evict()'s job, and that rule
 * needs corroboration from shape A before it will use the word
 * "attack". See docs/views/alerts.md and research/cve/2022-47522.md.
 *
 * Why its own table rather than a read of assoc_track: assoc_forget()
 * deletes the (BSSID, STA) row on a disassoc/deauth (include/assoc_track.h),
 * which is precisely one of the two events that opens an eviction
 * window — the pair would already be gone by the time the burst
 * arrived.
 *
 * Bounded and LRU-evicted like every synthesis table
 * (SH_EVICT_QUEUE_EVICT). */

#define MAX_QUEUE_EVICT_ENTRIES 128

/* How long after a session change a downlink frame still counts as part
 * of the released queue.
 *
 * This is a chosen bound, not a protocol constant — unlike shape A's
 * window, which is read off the AP's own beacon. 802.11 fixes no
 * deadline for flushing a buffered frame, so there is nothing to
 * derive. It is short on purpose: a released queue is emptied as fast
 * as the radio will take it, whereas ordinary post-roam traffic keeps
 * arriving for seconds. A window wide enough to be "safe" would
 * therefore match every roam on every network. */
#define QUEUE_EVICT_WINDOW_MS   100

/* Frames inside that window before the burst is recorded as a release
 * at all. One or two downlink frames after an association is an ARP
 * reply and a DHCP ACK; it is not a queue being emptied. */
#define QUEUE_EVICT_MIN_FRAMES  3

/* How recently a release must have happened for the rule to still
 * report it. release_count is a lifetime figure that only resets in
 * queue_evict_clear(), so the rule needs its own recency bound or one
 * roam fires forever — see the comment at rule_queue_evict().
 *
 * Fifteen minutes: long enough that an operator glancing at the alert
 * view a few minutes after an incident still sees it, short enough that
 * a morning's roaming is not still on screen at lunch. The alert
 * engine's own dedup means a station that keeps doing this keeps
 * re-firing with a rising count rather than ageing out. */
#define QUEUE_EVICT_REPORT_SECS 900

/* What changed the station's session. The distinction is reported
 * rather than acted on: the reassociation route and the
 * post-disconnect route have different consequences (frames released
 * to a new key versus released with none), and sloth cannot tell which
 * it saw from the outside. */
typedef enum {
    QUEUE_EVICT_SRC_ASSOC      = 0,
    QUEUE_EVICT_SRC_REASSOC    = 1,
    QUEUE_EVICT_SRC_DISCONNECT = 2,
} queue_evict_src_t;

typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta[6];

    /* Microsecond-resolution combined (sec*1000000 + usec) stamps from
     * the frames' own capture timestamps, never time(NULL) — a 100 ms
     * window compared in whole seconds collapses to "the same second",
     * the trap shape A hit before it shipped. int64_t so the sub-second
     * term survives. */
    int64_t  event_us;            /* most recent session change, 0 = none */
    int      event_src;           /* queue_evict_src_t for that event */
    time_t   event_ts;

    /* The burst accumulating against the current event_us. Reset by the
     * next session change. */
    uint32_t burst_frames;
    int64_t  burst_first_us;
    int64_t  burst_last_us;
    /* The last sequence number counted into this burst, -1 for none.
     *
     * The threshold counts DISTINCT frames, not received frames. 802.11
     * retransmits an unacknowledged MSDU with the same Sequence Number
     * and the Retry bit set, so without this a single frame retried
     * twice on a lossy link reaches QUEUE_EVICT_MIN_FRAMES on its own —
     * which is Tuesday on a real radio, not a queued-frame release.
     * Review measured that as the defect that made the only
     * discriminating constant non-discriminating. */
    int      burst_last_seq;

    /* Lifetime: windows that reached QUEUE_EVICT_MIN_FRAMES, plus the
     * evidence from the most recent one. Held separately because a
     * later session change with one stray frame must not overwrite the
     * burst the rule is reporting. */
    uint32_t release_count;
    time_t   last_release_ts;
    int      last_release_src;
    uint32_t last_release_frames;
    int      last_release_span_ms;

    time_t   first_seen;
    time_t   last_seen;
    uint8_t  in_use;
} queue_evict_t;

/* One observed session change for this (BSSID, STA). Creates the row if
 * absent and resets the burst counters: each event opens a fresh
 * window. A group-addressed `sta` (a broadcast deauth) names no station
 * and is ignored. Capture thread. */
void queue_evict_note_session_change(const uint8_t bssid[6],
                                     const uint8_t sta[6], int src,
                                     time_t now_sec, long now_usec);

/* Feed one 802.11 data-type frame (type == 2) starting at Frame
 * Control, stamped from its own capture timestamp. Counts only
 * AP-to-station unicast frames carrying a payload, and only against a
 * row some session change already created — a downlink frame to a
 * station sloth never saw change session is ordinary traffic and must
 * not conjure a row, or the table churns through every client on the
 * air. Capture thread. */
void queue_evict_observe_downlink(const uint8_t *dot11, int len,
                                  time_t now_sec, long now_usec);
/* The same, on a frame on_probe_frame() has already decoded (#130). */
void queue_evict_observe_downlink_frame(const dot11_frame_t *f,
                                        time_t now_sec, long now_usec);

/* Copy the row for this pair into *out under the lock. 1 when found. */
int  queue_evict_lookup(const uint8_t bssid[6], const uint8_t sta[6],
                        queue_evict_t *out);

int  queue_evict_count(void);

/* Copy every live row into out[0..max-1]; returns how many were
 * written. One lock acquisition for the whole table. */
int  queue_evict_snapshot(queue_evict_t *out, int max);

/* Operator-facing name for a queue_evict_src_t, "" when out of range. */
const char *queue_evict_src_name(int src);

/* Drop everything. Tests. */
void queue_evict_clear(void);

#endif /* QUEUE_EVICT_H */
