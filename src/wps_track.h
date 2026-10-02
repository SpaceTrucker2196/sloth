#ifndef WPS_TRACK_H
#define WPS_TRACK_H

#include <stdint.h>
#include <time.h>

/* ── WPS registration-session tracking (#82, wave 7) ──────────────
 *
 * Sequences the EAP-WSC opcode stream (eap_wsc_parse(), parse-only by
 * design) into per-(BSSID, STA) sessions, so the rate-based detectors
 * — WPS_PIN_BRUTE's M1→M3→NACK restart cycles, WPS_PBC_RACE's
 * concurrent walk-time sessions, Pixie-Dust's M1+M3-then-silence —
 * have a measured substrate to read. Measurement only: the alert rules
 * land in a later slice together with their research-corpus sources
 * (owner-accepted thresholds, 2026-09-30: ≥5 cycles/60 s, >2 PBC in
 * the 120 s walk time, each configurable).
 *
 * State machine over WSC 2.0 §7.7: IDLE →M1→ M1_SEEN →M3→ M3_SEEN
 * →NACK→ NACKED; a NACK from M3_SEEN completes one restart cycle (the
 * unit Reaver/Bully brute-force counting is defined in), and the next
 * M1 re-arms. WSC_Done or msg M8 marks DONE. Intermediate messages
 * update last_msg/msg_bits without changing the coarse state.
 *
 * Bounded and LRU-evicted like every synthesis table (an attacker
 * spraying forged M1s from rotating MACs must not allocate); an
 * eviction is a lost observation and lands in the sensor_health tally
 * (SH_EVICT_WPS_SESSION). UUID-E is kept because a rotating-MAC
 * attacker usually forgets to rotate it — constancy across STA
 * identities is the cross-session signal the brute detector keys on. */

#define MAX_WPS_SESSIONS 64
/* Completion timestamps kept per session, so "how many cycles" can be
 * asked of a *window* rather than of the session's whole life (#82
 * wave 8). cycle_count stays the lifetime total and doubles as the
 * ring cursor. Eight is comfortably above the owner-accepted
 * five-per-60 s threshold, which is all the rule has to resolve: a
 * brute force that overruns the ring has already fired. */
#define WPS_CYCLE_RING 8

typedef enum {
    WPS_S_IDLE = 0,
    WPS_S_M1_SEEN,
    WPS_S_M3_SEEN,
    WPS_S_NACKED,
    WPS_S_DONE
} wps_session_state_t;

typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta[6];
    uint8_t  uuid_e[16];    /* from M1; zero until seen */
    int      has_uuid;
    int      state;         /* wps_session_state_t */
    int      last_opcode;   /* WSC_OP_*  */
    int      last_msg;      /* WSC_MSG_*; -1 until a typed message */
    uint32_t msg_bits;      /* bit (1<<n) set when Mn seen, n=1..8.
                             * M2D/ACK/NACK/Done set no bit — the
                             * WSC_MSG_* values are not contiguous in
                             * M-order, so this is a mapping, not an
                             * offset. */
    int      cycle_count;   /* completed M1→M3→NACK restart cycles */
    /* When each of the last WPS_CYCLE_RING cycles completed; ring
     * index = (cycle_count - 1) % WPS_CYCLE_RING for the newest.
     * Read through wps_track_cycles_since() rather than directly. */
    time_t   cycle_ts[WPS_CYCLE_RING];
    time_t   first_seen;
    time_t   last_seen;
    uint8_t  in_use;
} wps_session_t;

/* Feed one EAP packet (starting at its Code byte) heard on the
 * (BSSID, STA) pair. Non-WSC frames are ignored. Capture thread. */
void wps_track_observe(const uint8_t bssid[6], const uint8_t sta[6],
                       const uint8_t *eap_pkt, int eap_len, time_t now);

/* Copy the session for the pair into *out under the lock. Returns 1
 * when found. */
int  wps_track_session(const uint8_t bssid[6], const uint8_t sta[6],
                       wps_session_t *out);

/* Sessions currently tracked. */
int  wps_track_count(void);

/* Copy every live session into out[0..max-1]; returns how many were
 * written. One lock acquisition for the whole table, so the rules see
 * a consistent set rather than a table that moved under them. */
int  wps_track_snapshot(wps_session_t *out, int max);

/* Completed restart cycles in `sess` whose NACK landed within the last
 * `window_s` seconds. Pure — it reads a *copy* taken by
 * wps_track_snapshot / wps_track_session, so it takes no lock and is
 * safe to call from a rule.
 *
 * The ring holds WPS_CYCLE_RING completions; a session that overran it
 * returns at most that many, which under-reports a very fast brute
 * force and never over-reports one. Deliberate: the threshold is a
 * floor, so saturating low is the safe direction. */
int  wps_track_cycles_since(const wps_session_t *sess, time_t now,
                            int window_s);

/* Drop everything. Tests. */
void wps_track_clear(void);

#endif /* WPS_TRACK_H */
