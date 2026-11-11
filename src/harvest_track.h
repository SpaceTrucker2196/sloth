#ifndef SLOTH_HARVEST_TRACK_H
#define SLOTH_HARVEST_TRACK_H

/* PMKID and 4-way-handshake harvesting (#172): the two shapes
 * hcxdumptool's README names, tracked passively.
 *
 *   PMKID_HARVEST — "Connecting to an ACCESS POINT to get a PMKID": one
 *   station sends (re)association requests to many BSSIDs, each answers
 *   with an M1 (often carrying a PMKID KDE, the material Steube's 2018
 *   disclosure showed is enough to attack the passphrase offline), and
 *   the station never sends the M2 that a station holding the key
 *   would. research/papers/steube-2018-pmkid.md,
 *   research/tools/hcxdumptool.md.
 *
 *   HANDSHAKE_HARVEST — "Disconnecting a CLIENT from an associated
 *   ACCESS POINT to get a complete handshake": deauthentication or
 *   disassociation frames claimed from a BSSID to a station, followed
 *   by that station's fresh M1/M2 pair with the same BSSID.
 *
 * Nothing here transmits, and nothing here touches the handshake
 * capture or the hashcat-22000 export (eapol_log.c's --collect-
 * handshakes path): this module only counts what those frames show.
 *
 * Fed from the monitor thread: assoc_request_observe() (assoc_track.c),
 * eapol_observe_frame() (eapol_log.c) and deauth_record()
 * (deauth_snoop.c). Its mutex is a leaf: it is taken with a caller's
 * own lock held and never takes another. Durations run on
 * sloth_mono_ms(); sloth_wall() stamps first/last seen for display. */

#include <stdint.h>
#include <time.h>
#include "sloth.h"
#include "tune.h"

/* ── Bounds, and what each evicts ─────────────────────────────
 *
 * Soliciting-station rows. A flood of random station MACs, each
 * sending one association request, would otherwise grow this without
 * limit; when full, the row with the fewest BSSIDs that answered it
 * with an M1 goes (the least harvest evidence), the least recently
 * active of those first. A harvester that rotates its own MAC per
 * target is not one station to this table and is not caught; that is a
 * limit of keying on the station, stated rather than hidden. */
#define HARVEST_MAX_STA      32
/* Target BSSIDs per station. Full: the least recently active target
 * the station answered (M2 seen) goes first, else the least recently
 * active of all, so the unanswered targets that are the finding are
 * the last to be lost. */
#define HARVEST_MAX_TGT      16
/* (BSSID, victim) deauthentication notes. Full: least recently hit. */
#define HARVEST_MAX_DEAUTH   64
/* Per-BSSID reconnect-chain rows and distinct victims per row. Full:
 * least recently active row; a victim past the per-row cap is left
 * out of the count (understates, never invents). */
#define HARVEST_MAX_CHAIN    16
#define HARVEST_MAX_VICTIMS   8
/* Evidence-ring IDs kept per exported row. */
#define HARVEST_EV_IDS        8

/* ── Thresholds (each argued here; registry rows in src/tune.c) ──
 *
 * None of these numbers comes from a source: hcxdumptool's README says
 * what the tool does, not how many targets it reaches or how fast, and
 * Steube's post describes one exchange. They are judgements, labelled
 * as such, and each is a --tune knob. */

/* How long a soliciting station's targets stay counted. The issue's
 * 60 s is what it says is missed today: a harvest paced under the
 * flood thresholds (ASSOC_FLOOD counts requests to ONE BSSID per
 * window; this counts DISTINCT BSSIDs per station) reaches a few APs a
 * minute on a hopping radio, or one every few minutes when paced
 * deliberately. 15 minutes holds three targets reached that slowly.
 * harvest.window_s. */
#define HARVEST_WINDOW_DEFAULT_S 900
#define HARVEST_WINDOW_S ((uint64_t)tune_val(TUNE_HARVEST_WINDOW_S))

/* Distinct BSSIDs that must have answered one station's association
 * request with an M1 that the station then left unanswered. The
 * issue's 3: two could be a station retrying its own AP and a
 * neighbour's; three distinct networks asked and abandoned is not a
 * device trying to join somewhere. harvest.min_bssids. */
#define HARVEST_MIN_BSSIDS_DEFAULT 3
#define HARVEST_MIN_BSSIDS ((int)tune_val(TUNE_HARVEST_MIN_BSSIDS))

/* Share of the M1-answering BSSIDs left without an M2, in percent: the
 * issue's (M1 - M2) / M1 >= 0.5. A roaming phone answers every M1, so
 * it sits near 0; a station whose M2s are sometimes lost to range sits
 * well under half; a harvester that never holds the key sits at 100.
 * harvest.unanswered_pct. */
#define HARVEST_UNANSWERED_PCT_DEFAULT 50
#define HARVEST_UNANSWERED_PCT ((int)tune_val(TUNE_HARVEST_UNANSWERED_PCT))

/* Distinct deauthentication / disassociation frames claimed from the
 * BSSID to a station (or to broadcast) before that station's fresh
 * M1/M2 counts as a harvested handshake. 2, under DEAUTH_FLOOD's 5 in
 * 5 s on purpose: one deauth followed by a reconnect is an AP doing
 * its job (an idle timeout, a band steer); two distinct frames in a
 * short burst followed by an immediate reconnect is what the tool
 * produces. Retransmissions are not distinct frames (deauth_snoop.c).
 * harvest.deauth_min. */
#define HARVEST_DEAUTH_MIN_DEFAULT 2
#define HARVEST_DEAUTH_MIN ((int)tune_val(TUNE_HARVEST_DEAUTH_MIN))

/* How soon after the last of those frames the fresh M1/M2 pair must
 * complete. A knocked-off station rescans and rejoins in seconds;
 * 30 s covers a slow rescan across bands and is too short to bridge to
 * an unrelated reconnect later. harvest.reconnect_s. */
#define HARVEST_RECONNECT_DEFAULT_S 30
#define HARVEST_RECONNECT_S ((uint64_t)tune_val(TUNE_HARVEST_RECONNECT_S))

/* Distinct victims of one BSSID's deauth-then-handshake chain for CRIT.
 * One victim has a benign reading — an AP band-steering a client with
 * repeated deauths, the client coming back to the same BSSID — two
 * different stations each knocked off and each captured reconnecting
 * is the harvesting run. Not tunable. */
#define HARVEST_CHAIN_CRIT_VICTIMS 2

/* One soliciting station, as the PMKID_HARVEST rule reads it. Every
 * count is over the BSSIDs this station sent a (re)association request
 * to inside the window: the request is what proves the station was
 * audible, so an M2 lost to range is not mistaken for one never sent. */
typedef struct harvest_sta_s {
    uint8_t  sta[6];
    int      solicited;         /* distinct BSSIDs asked */
    int      m1_bssids;         /* of those, answered with an M1 */
    int      unanswered;        /* M1, no M2 after EAPOL_PAIR_WINDOW_S */
    int      pmkid_unanswered;  /* of those, the M1 carried a PMKID KDE */
    int      answered;          /* BSSIDs this station sent an M2 to */
    int      dropped;           /* targets displaced by HARVEST_MAX_TGT */
    uint64_t ev[HARVEST_EV_IDS];/* newest M1 per unanswered BSSID */
    int      ev_n;
    time_t   first_seen;
    time_t   last_seen;
} harvest_sta_t;

/* One BSSID's deauth-then-handshake chain, as HANDSHAKE_HARVEST reads
 * it. */
typedef struct harvest_chain_s {
    uint8_t  bssid[6];
    int      victims;                          /* distinct, capped */
    uint8_t  victim[HARVEST_MAX_VICTIMS][6];
    int      deauth_frames;                    /* distinct, before them */
    int      dropped;
    uint64_t ev[HARVEST_EV_IDS];               /* the deauth frames */
    int      ev_n;
    time_t   first_seen;
    time_t   last_seen;
} harvest_chain_t;

/* A (re)association request from `sta` to `bssid`. Opens the station's
 * row: nothing else does. */
void harvest_note_assoc_req(const uint8_t sta[6], const uint8_t bssid[6]);

/* An EAPOL-Key message the collector classified. `msg` 1..4; `pmkid`
 * when an M1 carried a PMKID KDE; `fresh_pair` when an M2 just
 * completed a new M1/M2 pair (the collector's candidate_message_pair,
 * replay counter checked), once per attempt; `ev` the frame's
 * evidence-ring ID or 0. */
void harvest_note_eapol(const uint8_t bssid[6], const uint8_t sta[6],
                        int msg, int pmkid, int fresh_pair, uint64_t ev);

/* One distinct (non-retransmitted) deauthentication or disassociation
 * frame. Only frames whose transmitter address is the BSSID count —
 * frames claimed from the AP, which is what a forced disconnect spoofs;
 * a station leaving its own AP is not a harvest. `victim` may be the
 * broadcast address. */
void harvest_note_deauth(const uint8_t bssid[6], const uint8_t src[6],
                         const uint8_t victim[6], uint64_t ev);

/* Age out and publish: points s->harvest_sta / s->harvest_chain at this
 * module's per-poll copies (pointers, for the stack reason
 * s->karma_forge is one). */
void harvest_snapshot(sloth_state_t *s);
void harvest_clear(void);
/* Rows, targets, notes and victims displaced by the bounds since the
 * last clear. */
unsigned long harvest_evictions(void);

#endif /* SLOTH_HARVEST_TRACK_H */
