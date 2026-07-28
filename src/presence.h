/* Presence classification — issue #53.
 *
 * Separates emitters that were *present* from emitters that were
 * *passing*. A surveyor 20 m from a road hears a few hundred client
 * MACs in an afternoon and only a fraction of them belong to the site;
 * without this the two are indistinguishable.
 *
 * The primitive is trajectory shape, not dwell. Dwell alone is
 * confounded by channel hopping — a resident device the radio happened
 * to hear once looks brief — whereas a vehicle passing through RF range
 * leaves an unmistakable signature: signal rises, peaks, and recedes
 * inside a short window.
 *
 *   passing                       arrived and stayed
 *    -40      ▁▃▅█▅▃▁              -40        ▁▃▅███████████
 *    -80  ▁▁▁▁       ▁▁▁▁          -80  ▁▁▁▁▁▁
 *         └── ~20 s ──┘                 └──── minutes ────┘
 *
 * Note the asymmetry in what each verdict requires. Dwell on its own
 * may promote an emitter to VISITOR or RESIDENT, because "was here a
 * while" is a weak claim that a long first_seen..last_seen span already
 * supports. Calling something TRANSIENT is the strong claim — it says
 * the device moved past — so it requires trajectory evidence. An
 * emitter heard once is UNKNOWN, never TRANSIENT.
 *
 * Deliberately pure: no state, no clock of its own, no radio. Every
 * input is a parameter so the classifier can be tested against
 * hand-built trajectories the way the protocol parsers are tested
 * against hand-built frames. */

#ifndef SLOTH_PRESENCE_H
#define SLOTH_PRESENCE_H

#include "sloth.h"

typedef enum {
    PRESENCE_UNKNOWN = 0,  /* too little evidence to say */
    PRESENCE_TRANSIENT,    /* approached, peaked, receded — passed by */
    PRESENCE_VISITOR,      /* present for minutes */
    PRESENCE_RESIDENT,     /* present a long time, no transit shape */
} presence_class_t;

/* Both the rise into the peak and the fall out of it must reach this,
 * in dB, before a trajectory counts as transit. Two-sided on purpose: a
 * one-sided rise is a device switching on or waking, and a one-sided
 * fall is one going to sleep — neither moved. */
#define PRESENCE_SWING_DBM        8

/* A transit episode is short by nature; a vehicle is inside a monitor
 * radio's usable range for seconds, not minutes. An emitter with a
 * transit-shaped trajectory but a long dwell is something else —
 * someone who walked past the window and came back, or an AP whose
 * signal is being blocked intermittently. */
#define PRESENCE_TRANSIENT_MAX_S  120

/* Above this dwell an emitter is at least a visitor... */
#define PRESENCE_VISITOR_MIN_S    120
/* ...and above this it is part of the furniture. */
#define PRESENCE_RESIDENT_MIN_S   900

/* Fewer samples than this and no trajectory claim is made. Three is the
 * minimum that can express rise-peak-fall at all. */
#define PRESENCE_MIN_SAMPLES      3

/* Classify an emitter from its RSSI history and observation span.
 *
 * `ring` may be NULL or empty — that yields UNKNOWN unless the dwell
 * alone justifies VISITOR/RESIDENT. Samples older than RSSI_WIN_SECS
 * relative to `now` are ignored, matching the ring's own window.
 *
 * `now` is a parameter rather than read from the clock so tests are
 * deterministic. */
presence_class_t presence_classify(const rssi_ring_t *ring,
                                   time_t first_seen, time_t last_seen,
                                   time_t now);

/* True when the ring holds a rise-peak-fall trajectory meeting
 * PRESENCE_SWING_DBM on both sides. Exposed because it is the
 * interesting half of the classification and deserves its own tests. */
int presence_has_transit_shape(const rssi_ring_t *ring, time_t now);

/* Short label for views and the JSONL/DB record: "resident",
 * "visitor", "passing", "?". Never NULL. */
const char *presence_label(presence_class_t c);

#endif /* SLOTH_PRESENCE_H */
