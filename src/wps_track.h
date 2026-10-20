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
 * have a measured substrate to read.
 *
 * WPS_PIN_BRUTE and WPS_PBC_RACE ship and read this table (d652502),
 * with their sources in research/ and their counts on the --tune
 * registry (≥5 cycles/60 s, >2 PBC in the 120 s walk time). The
 * Pixie-Dust shape — Bongard 2014's "do the WPS protocol up to message
 * M3", then stop — is read by WPS_PIXIE_PROBE and
 * WPS_PIXIE_LIKELY_SUCCESS (#82, 2026-10-20) through the per-attempt
 * fields below. The table is still not copied onto sloth_state_t; the
 * [b] detail screen reads it through wps_track_for_bssid(), a copy-out
 * under the lock like the rules' snapshot.
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
/* Opcode timeline kept per session for the [b] detail screen (#82).
 * Sixteen covers one complete registration — Start, M1..M8, Done, and
 * the ACKs between — with room to spare; a longer session keeps its
 * newest sixteen, and ev_n (lifetime) says how many aged out. */
#define WPS_EVT_RING 16

/* One observed EAP-WSC frame: when, the Op-Code, and the Message Type
 * attribute (-1 when the frame carried none). */
typedef struct {
    time_t  ts;
    int16_t op;
    int16_t msg;
} wps_evt_t;

/* Pixie-Dust windows (#82, owner ruling 2026-10-19, both on --tune).
 *
 * WPS_PIXIE_SILENCE_S: how long an attempt that reached M3 and nothing
 * past it must stay quiet before WPS_PIXIE_PROBE calls it abandoned.
 * An online exchange moves from M3 to M4 inside one EAP round trip, so
 * a minute of nothing is not a slow registrar; it is a registrar that
 * took M3 — E-Hash1 and E-Hash2 — and left.
 *
 * WPS_PIXIE_SUCCESS_WINDOW_S: how far back from a registration that
 * reached the credentials (M7/M8/Done) WPS_PIXIE_LIKELY_SUCCESS looks
 * for that abandoned attempt at the same AP. A day, because the offline
 * step can be run later against a saved M1/M3, and the PIN it yields
 * does not expire. */
#define WPS_PIXIE_SILENCE_S          60
#define WPS_PIXIE_SUCCESS_WINDOW_S   86400

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
    /* Per-attempt view (#82, Pixie-Dust). An attempt is everything from
     * one M1 to the next; msg_bits above is the session's lifetime
     * union and cannot say whether *this* run got past M3, which is the
     * whole distinction between Bongard's offline attack (stops after
     * M3: the registrar never sends M4) and the online brute force
     * (always sends M4, because R-Hash1 in M4 is the guess).
     *
     *   attempt_bits   Mn bits (1<<n) seen since the newest M1, plus
     *                  bit 0 for a Done in this attempt (no Mn uses it)
     *                  and bit 9 once cred_ts is stamped for it
     *   attempt_m3_ts  when M3 arrived in the current attempt; 0 none
     *   abandon_m3_ts  M3 time of the newest *closed* attempt that
     *                  reached M3 and never M4..M8 — closed meaning a
     *                  later M1 re-armed the session; 0 none
     *   abandon_quiet_s  silence between that attempt's last frame and
     *                  the M1 that closed it
     *   abandon_n      lifetime count of such closed attempts
     *   guess_n        lifetime count of closed attempts that reached
     *                  M4 and not the credentials: refused online PIN
     *                  guesses. Lets WPS_PIXIE_LIKELY_SUCCESS say when
     *                  the "abandoned" run sat inside an online brute
     *                  force, where one missed M4 makes a refused guess
     *                  look like an M3 abandon.
     *   cred_ts        when the newest attempt first reached M7, M8 or
     *                  Done — the enrollee has opened both commitments
     *                  and M7 carries the credentials (WSC 2.0 §7.7;
     *                  Bongard 2014 slide "E -> R M7"); 0 never
     * Read the abandon shape through wps_track_m3_abandon(), which also
     * answers for the current, still-open attempt. */
    uint32_t attempt_bits;
    time_t   attempt_m3_ts;
    time_t   abandon_m3_ts;
    int      abandon_quiet_s;
    int      abandon_n;
    int      guess_n;
    time_t   cred_ts;
    /* Opcode timeline, ring of WPS_EVT_RING; read through
     * wps_track_events() so the modular indexing lives in one place. */
    wps_evt_t ev[WPS_EVT_RING];
    int       ev_n;         /* lifetime frames recorded */
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

/* Sessions for one BSSID, newest activity first, copied out under the
 * lock into out[0..max-1]; returns how many. What the [b] detail
 * screen reads — the view gets a copy, never the live table. */
int  wps_track_for_bssid(const uint8_t bssid[6], wps_session_t *out,
                         int max);

/* The session's opcode timeline, oldest first, at most `max` (and at
 * most WPS_EVT_RING); returns how many. Pure, on a copy. */
int  wps_track_events(const wps_session_t *sess, wps_evt_t *out, int max);

/* The Pixie-Dust shape (Bongard 2014): an attempt that reached M3 and
 * never M4..M8. Returns 1 and fills *m3_ts (when M3 arrived) and
 * *quiet_s (seconds of silence after the attempt's last frame) for the
 * newest such attempt, else 0. The current attempt answers first when
 * it is still open in that shape — its silence is now - last_seen and
 * still growing; otherwise the newest closed one, whose silence was
 * measured when the next M1 closed it. A session that reached Done
 * after M3 without M4 is not the shape: a registration that finished
 * was not abandoned. Pure, on a copy. Either out pointer may be NULL. */
int  wps_track_m3_abandon(const wps_session_t *sess, time_t now,
                          time_t *m3_ts, int *quiet_s);

/* Drop everything. Tests. */
void wps_track_clear(void);

#endif /* WPS_TRACK_H */
