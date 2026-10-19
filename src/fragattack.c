#include <string.h>
#include <pthread.h>

#include "fragattack.h"
#include "dot11_data.h"
#include "eapol_log.h"
#include "stab.h"
#include "sensor_health.h"

#define ETHERTYPE_EAPOL 0x888E

/* One lock for every table in this file (#111). frag_observe() and
 * frag_note_association() run on the monitor-capture thread
 * (probe.c:on_probe_frame); frag_snapshot(), frag_bss_count() and the
 * per-row readers run on main, once per poll and from rule_fragattack().
 * Until #111 this was the one capture-fed module with no mutex at all,
 * and the 2026-10 architecture review named it the one known data race.
 *
 * The public entry points take g_mu and call a *_locked() body; the
 * static helpers below assume it is held and never take it themselves,
 * so there is exactly one place per entry point where the lock is
 * visible. eapol_key_generation() is called with g_mu held: eapol_log's
 * own mutex is a leaf (eapol_log.c never calls back into this file), so
 * the order frag -> eapol is the only one that exists. */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* The five tables are stab_t since #110, every one STAB_OLDEST with its
 * own SH_EVICT_FRAG_* tally. stab's own mutex is NULL on all of them:
 * g_mu above already serialises every get-and-update, and the row
 * pointers stab hands back are only safe to write under that lock
 * anyway (stab.h, "Locking"). Before this they were five copies of the
 * same evict-the-stalest loop, none of which told sensor_health. */

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

static int bss_key_eq(const void *row, const void *key) {
    return mac_eq(((const frag_bss_t *)row)->bssid, (const uint8_t *)key);
}

/* Evicts the stalest row when full rather than dropping the new one. A
 * table that stops learning after 64 BSSes is worse on a hopping radio
 * than one that forgets the BSS it has not heard from in longest. */
STAB_DECL(g_bss, frag_bss_t, FRAG_MAX_BSS, last_seen, STAB_OLDEST,
          SH_EVICT_FRAG_BSS, NULL, bss_key_eq);

/* Stations witnessed installing a key, as (bssid, sta). Separate from
 * the BSS table because the gate is per-station: one client still
 * associating must not make another client's plaintext look like an
 * attack. */
typedef struct {
    uint8_t bssid[6];
    uint8_t sta[6];
    time_t  last_seen;
} frag_sta_t;

/* Key for every (bssid, sta)-keyed table below: key_eq is handed this
 * explicit pair so no table depends on another row type's layout. */
typedef struct { const uint8_t *bssid, *sta; } pair_key_t;

static int sta_key_eq(const void *row, const void *key) {
    const frag_sta_t *r = row; const pair_key_t *k = key;
    return mac_eq(r->bssid, k->bssid) && mac_eq(r->sta, k->sta);
}

STAB_DECL(g_sta, frag_sta_t, FRAG_MAX_STATIONS, last_seen, STAB_OLDEST,
          SH_EVICT_FRAG_STA, NULL, sta_key_eq);

/* ── Slice 2: fragment sessions + association timing ──────── */

/* One open reassembly, keyed on all four of (bssid, sa, da, tid).
 * sa/da rather than a resolved "station" identity: they are exactly
 * the transmitter/receiver pair a real defragmentation buffer is keyed
 * on, in either direction, with no need to resolve which one is the AP
 * (see dot11_data.h's addressing table — that resolution is what goes
 * wrong when done unconditionally). */
typedef struct {
    uint8_t bssid[6];
    uint8_t sa[6];
    uint8_t da[6];
    uint8_t tid;
    time_t  start_seen;       /* when fragment 0 opened this session */
    int     start_protected;  /* its Protected bit */
    /* PTK generation eapol_log.c had observed for (bssid, sa) when this
     * session opened — CVE-2020-24587 (#75 slice 4). 0 means no install
     * was witnessed for this pair, not "generation zero" — see
     * frag_track's use of it. */
    int     start_generation;
    /* The previous fragment's CCMP PN and fragment number, for
     * CVE-2020-26146. -1 when the fragment carried no readable PN —
     * unprotected, or WEP/original-TKIP with no Extended IV. */
    int64_t last_pn;
    int     last_fn;
    /* Sequence Control of the MSDU this session is reassembling. All
     * fragments of one MSDU share it (§9.2.4.4), so it is what tells a
     * continuation of *this* MSDU from the first fragment of the next
     * one that happened to reuse the (bssid, sa, da, tid) key. Only the
     * PN check consults it: the cache-poison and mixed-protect
     * detectors are about the receiver's buffer, which is keyed on the
     * address tuple alone. */
    uint16_t seq_ctrl;
    time_t  last_seen;
} frag_session_t;

typedef struct {
    const uint8_t *bssid, *sa, *da;
    uint8_t        tid;
} sess_key_t;

static int sess_key_eq(const void *row, const void *key) {
    const frag_session_t *s = row; const sess_key_t *k = key;
    return mac_eq(s->bssid, k->bssid) && mac_eq(s->sa, k->sa) &&
           mac_eq(s->da, k->da) && s->tid == k->tid;
}

/* A session that completes is retired with stab_del() (sess_close), so
 * the tally counts only reassemblies dropped while still open — the
 * ones whose continuation sloth can then no longer judge. */
STAB_DECL(g_sess, frag_session_t, FRAG_MAX_SESSIONS, last_seen, STAB_OLDEST,
          SH_EVICT_FRAG_SESSION, NULL, sess_key_eq);

/* One (bssid, sta) pair's most recent (re)association. Separate from
 * assoc_track.c's table on purpose: that one is keyed by evidence
 * *strength* (EAPOL beats assoc-response) for the "who is on the
 * network" view, which is the wrong merge rule here — a plain
 * assoc-response *is* the fragment-cache-clearing event this detector
 * cares about, and waiting for EAPOL would miss an open network
 * entirely. */
typedef struct {
    uint8_t bssid[6];
    uint8_t sta[6];
    time_t  last_assoc;
} frag_assoc_evt_t;

static int assoc_key_eq(const void *row, const void *key) {
    const frag_assoc_evt_t *r = row; const pair_key_t *k = key;
    return mac_eq(r->bssid, k->bssid) && mac_eq(r->sta, k->sta);
}

/* last_assoc is the recency stamp: it is the only time this row keeps,
 * and the oldest association is the one least likely to straddle a
 * session still open. */
STAB_DECL(g_assoc_evt, frag_assoc_evt_t, FRAG_MAX_ASSOC_EVT, last_assoc,
          STAB_OLDEST, SH_EVICT_FRAG_ASSOC, NULL, assoc_key_eq);

/* EtherType of a frame that carries an LLC/SNAP header, or -1.
 *
 * Not dot11_data_payload(): that rejects *any* fragment, because for
 * #72's purpose — feeding the IP decoder — a partial packet is
 * undecodable. Here the first fragment is the interesting one and it
 * does carry its LLC header, which is the only way to tell a plaintext
 * EAPOL frame (legal) from a plaintext data frame (CVE-2020-26143).
 * The header arithmetic is still dot11_data.c's; only the eight-byte
 * SNAP check is repeated. */
static int first_frag_ethertype(const dot11_frame_t *f) {
    if (f->frag_num != 0) return -1;

    /* An A-MSDU body is subframes, not one LLC-encapsulated packet, so
     * there is no single EtherType to read. Plaintext A-MSDU on a
     * protected network is CVE-2020-26144 and its own detector.
     * Via the helper rather than a local copy of the QoS Control offset
     * arithmetic — see dot11_data_payload(). */
    if (dot11_frame_amsdu(f) == 1) return -1;

    /* hdr_len, not dot11_frame_payload(): the Protected and fragment
     * rules here are this detector's own (see above), and the body is
     * read where the header ends, as it always was here. */
    int hdr = f->type == 2 ? f->hdr_len : -1;
    if (hdr < 0 || hdr + 8 > f->len) return -1;
    const uint8_t *llc = f->p + hdr;
    if (llc[0] != 0xaa || llc[1] != 0xaa || llc[2] != 0x03) return -1;
    return (llc[6] << 8) | llc[7];
}

/* EtherType claimed by the first A-MSDU subframe of a plaintext frame,
 * or -1. CVE-2020-26144: the case first_frag_ethertype() above declines
 * — an A-MSDU body has no single LLC header, only a run of subframes
 * each with its own — but here plaintext is exactly what makes reading
 * one meaningful. An encrypted A-MSDU's subframe headers sit inside the
 * ciphertext (that is why -24588 above is detected by PN replay
 * instead); a plaintext one puts them in the clear.
 *
 * The subframe header is DA(6) SA(6) Length(2), then a body with the
 * same LLC/SNAP shape dot11_data_payload() reads for an unaggregated
 * frame. Only the first subframe is read: it is the one a spoofed
 * EAPOL claim would occupy, and the ones after it are unreachable
 * without trusting the very length field this bug is about. */
static int first_amsdu_subframe_ethertype(const dot11_frame_t *f) {
    if (f->frag_num != 0) return -1;
    if (dot11_frame_amsdu(f) != 1) return -1;

    int hdr = f->type == 2 ? f->hdr_len : -1;
    if (hdr < 0) return -1;
    int llc = hdr + 14;   /* subframe DA(6) + SA(6) + Length(2) */
    if (llc + 8 > f->len) return -1;
    const uint8_t *p = f->p + llc;
    if (p[0] != 0xaa || p[1] != 0xaa || p[2] != 0x03) return -1;
    return (p[6] << 8) | p[7];
}

/* Slot index, because frag_find()'s callers pair it with frag_bss_at().
 * stab_find() answers with a row pointer; the walk is the same one. */
static int find_locked(const uint8_t bssid[6]) {
    if (!bssid) return -1;
    for (int i = 0; i < stab_count(&g_bss); i++)
        if (bss_key_eq(stab_at(&g_bss, i), bssid)) return i;
    return -1;
}

int frag_find(const uint8_t bssid[6]) {
    pthread_mutex_lock(&g_mu);
    int i = find_locked(bssid);
    pthread_mutex_unlock(&g_mu);
    return i;
}

static frag_bss_t *bss_get(const uint8_t bssid[6], time_t now) {
    int created;
    frag_bss_t *b = stab_get(&g_bss, bssid, now, &created);
    if (created) {
        memcpy(b->bssid, bssid, 6);
        b->first_seen = now;
    }
    b->last_seen = now;
    return b;
}

static int sta_known(const uint8_t bssid[6], const uint8_t sta[6]) {
    pair_key_t key = { bssid, sta };
    return stab_find(&g_sta, &key) != NULL;
}

static void sta_mark_protected(const uint8_t bssid[6], const uint8_t sta[6],
                               time_t now) {
    pair_key_t key = { bssid, sta };
    int created;
    frag_sta_t *r = stab_get(&g_sta, &key, now, &created);
    if (created) {
        memcpy(r->bssid, bssid, 6);
        memcpy(r->sta,   sta,   6);
    }
    r->last_seen = now;
}

static void note_association_locked(const uint8_t bssid[6],
                                    const uint8_t sta[6], time_t now) {
    if (!bssid || !sta) return;
    pair_key_t key = { bssid, sta };
    int created;
    frag_assoc_evt_t *r = stab_get(&g_assoc_evt, &key, now, &created);
    if (created) {
        memcpy(r->bssid, bssid, 6);
        memcpy(r->sta,   sta,   6);
    }
    r->last_assoc = now;
}

void frag_note_association(const uint8_t bssid[6], const uint8_t sta[6],
                           time_t now) {
    pthread_mutex_lock(&g_mu);
    note_association_locked(bssid, sta, now);
    pthread_mutex_unlock(&g_mu);
}

/* Did (bssid, mac) complete a (re)association strictly after `since`?
 * Strict: a session that opens the same second an association lands is
 * not reported as straddling it, since sloth's clock resolution cannot
 * order the two. */
static int frag_assoc_after(const uint8_t bssid[6], const uint8_t mac[6],
                            time_t since) {
    pair_key_t key = { bssid, mac };
    const frag_assoc_evt_t *r = stab_find(&g_assoc_evt, &key);
    return r && r->last_assoc > since;
}

static frag_session_t *sess_find(const uint8_t bssid[6], const uint8_t sa[6],
                                 const uint8_t da[6], uint8_t tid) {
    sess_key_t key = { bssid, sa, da, tid };
    return stab_find(&g_sess, &key);
}

/* Opens a fresh session under (bssid, sa, da, tid), replacing any
 * unfinished one under the same key — a reassembly that never
 * completed before a new fragment 0 arrived was abandoned, and is not
 * itself evidence of anything. */
static void sess_open(const uint8_t bssid[6], const uint8_t sa[6],
                      const uint8_t da[6], uint8_t tid,
                      int protected_bit, int generation,
                      int64_t pn, int fn, uint16_t sc, time_t now) {
    sess_key_t key = { bssid, sa, da, tid };
    int created;
    frag_session_t *s = stab_get(&g_sess, &key, now, &created);
    if (created) {
        memcpy(s->bssid, bssid, 6);
        memcpy(s->sa,    sa,    6);
        memcpy(s->da,    da,    6);
        s->tid = tid;
    }
    s->start_seen       = now;
    s->start_protected  = protected_bit;
    s->start_generation = generation;
    s->last_pn          = pn;
    s->last_fn          = fn;
    s->seq_ctrl         = (uint16_t)(sc & 0xfff0);   /* sequence, not fragment */
    s->last_seen        = now;
}

static void sess_close(frag_session_t *s) {
    stab_del(&g_sess, s);
}

/* Fragment-session bookkeeping — issue #75 slice 2. Runs for every
 * fragmented data frame regardless of its Protected bit: the
 * defragmentation buffer this family of bugs abuses exists before
 * decryption, so cache poisoning and mixed reassembly are not gated on
 * the RSN-witnessed state slice 1's plaintext detectors use. */
static void frag_track(frag_bss_t *b, const uint8_t bssid[6],
                       const uint8_t sa[6], const uint8_t da[6],
                       uint8_t tid, int fn, int more, int protected_bit,
                       int64_t pn, uint16_t sc, time_t now) {
    if (fn == 0) {
        int gen = eapol_key_generation(bssid, sa);
        sess_open(bssid, sa, da, tid, protected_bit, gen, pn, fn, sc, now);
        return;
    }

    /* Continuation with no fragment 0 on file: sloth joined the
     * exchange mid-stream (a hopped-away-and-back radio, most likely),
     * and there is nothing to compare it against. */
    frag_session_t *s = sess_find(bssid, sa, da, tid);
    if (!s) return;

    /* CVE-2020-24586: the receiving side's fragment cache should be
     * empty immediately after a (re)association. A continuation that
     * arrives after one we witnessed for either endpoint completes a
     * reassembly that should not have been possible. */
    if (frag_assoc_after(bssid, sa, s->start_seen) ||
        frag_assoc_after(bssid, da, s->start_seen)) {
        b->cache_poison++;
        memcpy(b->last_sa, sa, 6);
        memcpy(b->last_da, da, 6);
        b->last_hit = now;
    }

    /* CVE-2020-26147: neither half is wrong alone — an encrypted
     * fragment and a plaintext one are each ordinary in isolation. The
     * bug is combining them into one MSDU. */
    if (protected_bit != s->start_protected) {
        b->mixed_protect++;
        memcpy(b->last_sa, sa, 6);
        memcpy(b->last_da, da, 6);
        b->last_hit = now;
    }

    /* CVE-2020-24587 (#75 slice 4): the reassembly spans a completed PTK
     * rotation. Meaningful only when both fragments are encrypted — a
     * Protected-bit mismatch is mixed_protect's finding, not this one —
     * and only when a generation was actually observed when the session
     * opened: 0 means sloth never witnessed an install for this pair,
     * and reporting a rekey without that evidence would be a guess
     * dressed as a detection, the same rule every plaintext detector in
     * this file follows for its own gate. */
    if (protected_bit && s->start_protected && s->start_generation > 0 &&
        eapol_key_generation(bssid, sa) > s->start_generation) {
        b->mixed_key++;
        memcpy(b->last_sa, sa, 6);
        memcpy(b->last_da, da, 6);
        b->last_hit = now;
    }

    /* CVE-2020-26146: §12.5.3.4.4 requires the fragments of one MSDU to
     * carry consecutive packet numbers, so a gap means the reassembly
     * is stitching together fragments from different bursts — which is
     * the attack.
     *
     * Compared against the *fragment-number* delta rather than expecting
     * exactly +1. A fragment sloth did not hear — a hopped radio, a
     * missed frame on a busy channel — advances both by the same amount
     * and is not an attack; only a PN that moves by a different step
     * than the fragment number is. A repeat of the same fragment
     * carries the same PN and the same FN, so a retry is excluded by
     * the same arithmetic rather than by a special case.
     *
     * Both sides need a readable PN: unprotected fragments have none,
     * and a WEP or original-TKIP IV is not a 48-bit PN at all. */
    if (pn >= 0 && s->last_pn >= 0 && fn > s->last_fn &&
        (uint16_t)(sc & 0xfff0) == s->seq_ctrl) {
        int64_t pn_step = pn - s->last_pn;
        int64_t fn_step = (int64_t)(fn - s->last_fn);
        if (pn_step != fn_step) {
            b->pn_gap++;
            memcpy(b->last_sa, sa, 6);
            memcpy(b->last_da, da, 6);
            b->last_hit = now;
        }
    }
    if (pn >= 0) s->last_pn = pn;
    if (fn > s->last_fn) s->last_fn = fn;

    s->last_seen = now;
    if (!more) sess_close(s);   /* reassembly complete */
}


/* ── A-MSDU flip (CVE-2020-24588) ────────────────────────────────────
 *
 * Keyed on (transmitter, CCMP PN). A PN is never legitimately reused
 * under one key, so a repeat is already an anomaly; a repeat whose
 * A-MSDU Present bit differs is the aggregation attack. See the long
 * note in fragattack.h for why this is keyed on the PN and not the
 * sequence number. */
typedef struct {
    uint8_t ta[6];
    uint8_t bssid[6];
    int64_t pn;
    uint16_t sc;
    uint8_t amsdu;
    time_t  ts;
} frag_mpdu_t;

typedef struct { const uint8_t *ta; int64_t pn; } mpdu_key_t;

static int mpdu_key_eq(const void *row, const void *key) {
    const frag_mpdu_t *m = row; const mpdu_key_t *k = key;
    return m->pn == k->pn && mac_eq(m->ta, k->ta);
}

STAB_DECL(g_mpdu, frag_mpdu_t, FRAG_MAX_MPDUS, ts, STAB_OLDEST,
          SH_EVICT_FRAG_MPDU, NULL, mpdu_key_eq);

/* Returns 1 when this MPDU is a replay of one already recorded whose
 * A-MSDU bit differs. Records it otherwise. */
static int mpdu_note(const uint8_t bssid[6], const uint8_t ta[6],
                     int64_t pn, uint16_t sc, int amsdu, time_t now) {
    /* Aged-out rows are dropped rather than compared. A PN that
     * matches across a key rotation is not a replay — after a rekey
     * they legitimately restart from zero. Dropping them first is also
     * what keeps the tally honest: an eviction stab_get() then performs,
     * and counts, is of a record still inside the window. */
    stab_expire(&g_mpdu, now, FRAG_MPDU_WINDOW_S);

    mpdu_key_t key = { ta, pn };
    int created;
    frag_mpdu_t *m = stab_get(&g_mpdu, &key, now, &created);
    if (!created) {
        if (m->amsdu != (uint8_t)amsdu) {
            /* Do not update the stored bit. The attacker may replay the
             * same MPDU repeatedly, and each one is a separate
             * transmission worth counting — overwriting would make only
             * the first count and the rest look like the new normal. */
            m->ts = now;
            return 1;
        }
        m->ts = now;                        /* a plain retransmission */
        return 0;
    }

    memcpy(m->ta,    ta,    6);
    memcpy(m->bssid, bssid, 6);
    m->pn    = pn;
    m->sc    = sc;
    m->amsdu = (uint8_t)amsdu;
    m->ts    = now;
    return 0;
}

static void observe_locked(const dot11_frame_t *f, time_t now) {
    if (!f || !f->p || f->len < 24) return;
    if (f->type != 2) return;                       /* data frames only */

    /* Null / QoS-Null carry no body. They are sent unprotected as a
     * matter of course — they are how a station signals power-save
     * state — so counting them would fire on every idle client. */
    if (f->subtype & 0x04) return;

    /* A four-address frame crosses two BSSes and has no single BSSID.
     * Skipped rather than attributed to a guess. */
    if (f->has_addr4 || !f->bssid || !f->sa || !f->da) return;
    const uint8_t *bssid = f->bssid, *sa = f->sa, *da = f->da;

    int protected_bit = f->protected_;
    int fn   = f->frag_num;
    int more = f->more_frag;
    if (fn < 0) return;
    int fragmented = (fn > 0) || (more == 1);
    /* Sequence Control as transmitted, rebuilt from the two fields the
     * view split it into: both are inside the 24 octets checked above. */
    const uint16_t sc = (uint16_t)((f->seq_num << 4) | f->frag_num);

    frag_bss_t *b = bss_get(bssid, now);

    /* A-MSDU flip (#75 slice 3). Runs before every gate below: it needs
     * no witnessed key install — the CCMP PN it keys on is itself proof
     * the frame is protected — and it is the one detector here that
     * only ever looks at encrypted frames. */
    int64_t pn = dot11_frame_ccmp_pn(f);
    int amsdu  = dot11_frame_amsdu(f);
    if (pn >= 0 && amsdu >= 0) {
        /* addr2 is the transmitter in every frame long enough to have
         * one, independent of the DS bits. */
        if (mpdu_note(bssid, f->ta, pn, sc, amsdu, now)) {
            b->amsdu_flip++;
            memcpy(b->last_sa, sa, 6);
            memcpy(b->last_da, da, 6);
            b->last_hit = now;
        }
    }

    /* CVE-2020-26139: an EAPOL frame the AP forwarded between two
     * stations.
     *
     * On an infrastructure BSS, EAPOL only ever travels between a
     * station and the authenticator — it is not a peer-to-peer
     * protocol. So a frame carrying EtherType 0x888E where *neither*
     * address is the BSSID is one the AP relayed on behalf of a sender
     * it should not have, which is the bug.
     *
     * Structural, and that is the point: every other plaintext
     * detector here needs a witnessed key install because "we did not
     * see the association" is indistinguishable from "there was none".
     * This one needs no history at all — the frame is wrong on its own
     * addressing.
     *
     * Requires ToDS or FromDS. In an IBSS there is no AP, addr3 is the
     * BSSID and both stations are peers, so every EAPOL frame would
     * match and mean nothing. Unicast only, for the same reason: a
     * group address can never equal the BSSID, so including broadcast
     * would fire on a shape the CVE does not describe. */
    if ((f->to_ds || f->from_ds) && !dot11_is_group_addr(da) &&
        !mac_eq(sa, bssid) && !mac_eq(da, bssid) &&
        first_frag_ethertype(f) == ETHERTYPE_EAPOL) {
        b->eapol_relay++;
        memcpy(b->last_sa, sa, 6);
        memcpy(b->last_da, da, 6);
        b->last_hit = now;
    }

    /* Session bookkeeping runs before the protected/plaintext branch
     * below and regardless of it — see frag_track's comment. */
    if (fragmented) {
        int tid = dot11_frame_tid(f);
        if (tid >= 0)
            frag_track(b, bssid, sa, da, (uint8_t)tid, fn, more,
                      protected_bit, pn, sc, now);
    }

    if (protected_bit) {
        b->protected_frames++;
        /* The transmitter is the one whose key install we witnessed.
         * For a downlink frame that is the AP, which is exactly right:
         * a later plaintext frame *from the AP* is the -26140 case. */
        sta_mark_protected(bssid, sa, now);
        return;
    }

    /* Everything below is Protected=0 on a BSS we may or may not have
     * evidence about. Without a prior protected frame from this
     * station, an unprotected frame is an open network or a client
     * mid-association — the overwhelmingly common case, and not a
     * signal. */
    if (!sta_known(bssid, sa)) return;

    if (dot11_is_group_addr(da)) {
        /* CVE-2020-26145. Broadcast reassembly is not permitted in a
         * protected network, so a fragmented group-addressed plaintext
         * frame is already wrong before anything reassembles it — which
         * is why this fires on the fragment rather than waiting for a
         * completion that only the victim can perform. */
        if (!fragmented) return;
        b->plaintext_bcast_frag++;
    } else if (amsdu == 1) {
        /* CVE-2020-26144, slice 4. first_frag_ethertype() above
         * declines an A-MSDU frame outright — no single LLC header to
         * read — which is right for the encrypted case but leaves this
         * plaintext one silently uncounted. EAPOL is never legitimately
         * aggregated, so a subframe claiming to be one has no benign
         * reading, unlike the plain-unicast branch below where EAPOL is
         * an expected exemption. */
        int et = first_amsdu_subframe_ethertype(f);
        if (et != ETHERTYPE_EAPOL) return;
        b->amsdu_eapol_spoof++;
    } else {
        /* CVE-2020-26140 / -26143. EAPOL is legitimately unprotected
         * even after key install — that is how rekeying works — so it
         * has to be excluded, and the EtherType is only readable on the
         * first fragment. A later fragment's payload could be anything,
         * and calling it an attack because we cannot see what it is
         * would be a guess dressed as a detection. Counted only when
         * the frame says what it carries. */
        int et = first_frag_ethertype(f);
        if (et < 0 || et == ETHERTYPE_EAPOL) return;
        b->plaintext_unicast++;
    }

    memcpy(b->last_sa, sa, 6);
    memcpy(b->last_da, da, 6);
    b->last_hit = now;
}

/* The byte entry point stays for the tests and fuzz harnesses written
 * against it (#130); it decodes once and hands the view on. */
void frag_observe(const uint8_t *dot11, int len, time_t now) {
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    frag_observe_frame(&f, now);
}

void frag_observe_frame(const dot11_frame_t *f, time_t now) {
    pthread_mutex_lock(&g_mu);
    observe_locked(f, now);
    pthread_mutex_unlock(&g_mu);
}

int frag_bss_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = stab_count(&g_bss);
    pthread_mutex_unlock(&g_mu);
    return n;
}

int frag_mpdu_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = stab_count(&g_mpdu);
    pthread_mutex_unlock(&g_mu);
    return n;
}

const frag_bss_t *frag_bss_at(int i) {
    pthread_mutex_lock(&g_mu);
    const frag_bss_t *b = stab_at(&g_bss, i);
    pthread_mutex_unlock(&g_mu);
    return b;
}

int frag_bss_copy(int i, frag_bss_t *out) {
    if (!out) return 0;
    pthread_mutex_lock(&g_mu);
    const frag_bss_t *b = stab_at(&g_bss, i);
    int ok = b != NULL;
    if (ok) *out = *b;
    pthread_mutex_unlock(&g_mu);
    return ok;
}

int frag_session_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = stab_count(&g_sess);
    pthread_mutex_unlock(&g_mu);
    return n;
}

static void snapshot_locked(sloth_state_t *s) {
    int total = stab_count(&g_bss);
    int n = total < MAX_FRAG_ROWS ? total : MAX_FRAG_ROWS;
    const frag_bss_t *bss = g_bss_rows;

    /* Sorted by last_hit DESC, same rule probe_pnl_snapshot uses for
     * PNL clients: the BSS that just produced a finding belongs at the
     * top, not wherever bss_get() happened to insert it. */
    int order[FRAG_MAX_BSS];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++)
            if (bss[order[j]].last_hit > bss[order[best]].last_hit)
                best = j;
        if (best != i) { int t = order[i]; order[i] = order[best]; order[best] = t; }
    }

    for (int i = 0; i < n; i++) {
        const frag_bss_t *b = &bss[order[i]];
        frag_bss_row_t   *r = &s->frag_rows[i];
        memcpy(r->bssid, b->bssid, 6);
        r->protected_frames     = b->protected_frames;
        r->plaintext_unicast    = b->plaintext_unicast;
        r->plaintext_bcast_frag = b->plaintext_bcast_frag;
        r->cache_poison         = b->cache_poison;
        r->mixed_protect        = b->mixed_protect;
        r->amsdu_flip           = b->amsdu_flip;
        r->amsdu_eapol_spoof    = b->amsdu_eapol_spoof;
        r->mixed_key            = b->mixed_key;
        r->pn_gap               = b->pn_gap;
        r->eapol_relay          = b->eapol_relay;
        memcpy(r->last_sa, b->last_sa, 6);
        memcpy(r->last_da, b->last_da, 6);
        r->last_hit = b->last_hit;
    }
    s->frag_row_count = n;
    if (s->frag_sel >= n) s->frag_sel = n > 0 ? n - 1 : 0;
}

void frag_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    snapshot_locked(s);
    pthread_mutex_unlock(&g_mu);
}

void frag_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_bss);
    stab_clear(&g_sta);
    stab_clear(&g_sess);
    stab_clear(&g_assoc_evt);
    stab_clear(&g_mpdu);
    pthread_mutex_unlock(&g_mu);
}
