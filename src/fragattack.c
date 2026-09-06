#include <string.h>

#include "fragattack.h"
#include "dot11_data.h"
#include "eapol_log.h"

#define ETHERTYPE_EAPOL 0x888E

static frag_bss_t g_bss[FRAG_MAX_BSS];
static int        g_bss_n;

/* Stations witnessed installing a key, as (bssid, sta). Separate from
 * the BSS table because the gate is per-station: one client still
 * associating must not make another client's plaintext look like an
 * attack. */
typedef struct {
    uint8_t bssid[6];
    uint8_t sta[6];
    time_t  last_seen;
} frag_sta_t;

static frag_sta_t g_sta[FRAG_MAX_STATIONS];
static int        g_sta_n;

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
    time_t  last_seen;
} frag_session_t;

static frag_session_t g_sess[FRAG_MAX_SESSIONS];
static int            g_sess_n;

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

static frag_assoc_evt_t g_assoc_evt[FRAG_MAX_ASSOC_EVT];
static int              g_assoc_evt_n;

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

/* EtherType of a frame that carries an LLC/SNAP header, or -1.
 *
 * Not dot11_data_payload(): that rejects *any* fragment, because for
 * #72's purpose — feeding the IP decoder — a partial packet is
 * undecodable. Here the first fragment is the interesting one and it
 * does carry its LLC header, which is the only way to tell a plaintext
 * EAPOL frame (legal) from a plaintext data frame (CVE-2020-26143).
 * The header arithmetic is still dot11_data.c's; only the eight-byte
 * SNAP check is repeated. */
static int first_frag_ethertype(const uint8_t *dot11, int len) {
    if (dot11_frag_num(dot11, len) != 0) return -1;

    int sub = (dot11[0] >> 4) & 0x0f;
    /* An A-MSDU body is subframes, not one LLC-encapsulated packet, so
     * there is no single EtherType to read. Plaintext A-MSDU on a
     * protected network is CVE-2020-26144 and its own detector. */
    if (sub & 0x08) {
        int qos_off = 24 + (((dot11[1] & 0x01) && ((dot11[1] >> 1) & 0x01))
                            ? 6 : 0);
        if (qos_off + 1 < len && (dot11[qos_off] & 0x80)) return -1;
    }

    int hdr = dot11_data_header_len(dot11, len);
    if (hdr < 0 || hdr + 8 > len) return -1;
    const uint8_t *llc = dot11 + hdr;
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
static int first_amsdu_subframe_ethertype(const uint8_t *dot11, int len) {
    if (dot11_frag_num(dot11, len) != 0) return -1;
    if (dot11_amsdu_present(dot11, len) != 1) return -1;

    int hdr = dot11_data_header_len(dot11, len);
    if (hdr < 0) return -1;
    int llc = hdr + 14;   /* subframe DA(6) + SA(6) + Length(2) */
    if (llc + 8 > len) return -1;
    const uint8_t *p = dot11 + llc;
    if (p[0] != 0xaa || p[1] != 0xaa || p[2] != 0x03) return -1;
    return (p[6] << 8) | p[7];
}

int frag_find(const uint8_t bssid[6]) {
    if (!bssid) return -1;
    for (int i = 0; i < g_bss_n; i++)
        if (mac_eq(g_bss[i].bssid, bssid)) return i;
    return -1;
}

/* Evicts the stalest row when full rather than dropping the new one. A
 * table that stops learning after 64 BSSes is worse on a hopping radio
 * than one that forgets the BSS it has not heard from in longest. */
static frag_bss_t *bss_get(const uint8_t bssid[6], time_t now) {
    int i = frag_find(bssid);
    if (i >= 0) { g_bss[i].last_seen = now; return &g_bss[i]; }

    if (g_bss_n < FRAG_MAX_BSS) {
        i = g_bss_n++;
    } else {
        i = 0;
        for (int k = 1; k < g_bss_n; k++)
            if (g_bss[k].last_seen < g_bss[i].last_seen) i = k;
    }
    memset(&g_bss[i], 0, sizeof(g_bss[i]));
    memcpy(g_bss[i].bssid, bssid, 6);
    g_bss[i].first_seen = g_bss[i].last_seen = now;
    return &g_bss[i];
}

static int sta_find(const uint8_t bssid[6], const uint8_t sta[6]) {
    for (int i = 0; i < g_sta_n; i++)
        if (mac_eq(g_sta[i].bssid, bssid) && mac_eq(g_sta[i].sta, sta))
            return i;
    return -1;
}

static void sta_mark_protected(const uint8_t bssid[6], const uint8_t sta[6],
                               time_t now) {
    int i = sta_find(bssid, sta);
    if (i >= 0) { g_sta[i].last_seen = now; return; }
    if (g_sta_n < FRAG_MAX_STATIONS) {
        i = g_sta_n++;
    } else {
        i = 0;
        for (int k = 1; k < g_sta_n; k++)
            if (g_sta[k].last_seen < g_sta[i].last_seen) i = k;
    }
    memcpy(g_sta[i].bssid, bssid, 6);
    memcpy(g_sta[i].sta,   sta,   6);
    g_sta[i].last_seen = now;
}

void frag_note_association(const uint8_t bssid[6], const uint8_t sta[6],
                           time_t now) {
    if (!bssid || !sta) return;
    for (int i = 0; i < g_assoc_evt_n; i++) {
        if (mac_eq(g_assoc_evt[i].bssid, bssid) &&
            mac_eq(g_assoc_evt[i].sta, sta)) {
            g_assoc_evt[i].last_assoc = now;
            return;
        }
    }
    int i;
    if (g_assoc_evt_n < FRAG_MAX_ASSOC_EVT) {
        i = g_assoc_evt_n++;
    } else {
        i = 0;
        for (int k = 1; k < g_assoc_evt_n; k++)
            if (g_assoc_evt[k].last_assoc < g_assoc_evt[i].last_assoc) i = k;
    }
    memcpy(g_assoc_evt[i].bssid, bssid, 6);
    memcpy(g_assoc_evt[i].sta,   sta,   6);
    g_assoc_evt[i].last_assoc = now;
}

/* Did (bssid, mac) complete a (re)association strictly after `since`?
 * Strict: a session that opens the same second an association lands is
 * not reported as straddling it, since sloth's clock resolution cannot
 * order the two. */
static int frag_assoc_after(const uint8_t bssid[6], const uint8_t mac[6],
                            time_t since) {
    for (int i = 0; i < g_assoc_evt_n; i++) {
        if (mac_eq(g_assoc_evt[i].bssid, bssid) &&
            mac_eq(g_assoc_evt[i].sta, mac) &&
            g_assoc_evt[i].last_assoc > since)
            return 1;
    }
    return 0;
}

static frag_session_t *sess_find(const uint8_t bssid[6], const uint8_t sa[6],
                                 const uint8_t da[6], uint8_t tid) {
    for (int i = 0; i < g_sess_n; i++) {
        frag_session_t *s = &g_sess[i];
        if (mac_eq(s->bssid, bssid) && mac_eq(s->sa, sa) &&
            mac_eq(s->da, da) && s->tid == tid)
            return s;
    }
    return NULL;
}

/* Opens a fresh session under (bssid, sa, da, tid), replacing any
 * unfinished one under the same key — a reassembly that never
 * completed before a new fragment 0 arrived was abandoned, and is not
 * itself evidence of anything. */
static void sess_open(const uint8_t bssid[6], const uint8_t sa[6],
                      const uint8_t da[6], uint8_t tid,
                      int protected_bit, int generation, time_t now) {
    frag_session_t *s = sess_find(bssid, sa, da, tid);
    if (!s) {
        if (g_sess_n < FRAG_MAX_SESSIONS) {
            s = &g_sess[g_sess_n++];
        } else {
            s = &g_sess[0];
            for (int k = 1; k < g_sess_n; k++)
                if (g_sess[k].last_seen < s->last_seen) s = &g_sess[k];
        }
        memcpy(s->bssid, bssid, 6);
        memcpy(s->sa,    sa,    6);
        memcpy(s->da,    da,    6);
        s->tid = tid;
    }
    s->start_seen       = now;
    s->start_protected  = protected_bit;
    s->start_generation = generation;
    s->last_seen        = now;
}

static void sess_close(frag_session_t *s) {
    int idx = (int)(s - g_sess);
    if (idx != g_sess_n - 1) g_sess[idx] = g_sess[g_sess_n - 1];
    g_sess_n--;
}

/* Fragment-session bookkeeping — issue #75 slice 2. Runs for every
 * fragmented data frame regardless of its Protected bit: the
 * defragmentation buffer this family of bugs abuses exists before
 * decryption, so cache poisoning and mixed reassembly are not gated on
 * the RSN-witnessed state slice 1's plaintext detectors use. */
static void frag_track(frag_bss_t *b, const uint8_t bssid[6],
                       const uint8_t sa[6], const uint8_t da[6],
                       uint8_t tid, int fn, int more, int protected_bit,
                       time_t now) {
    if (fn == 0) {
        int gen = eapol_key_generation(bssid, sa);
        sess_open(bssid, sa, da, tid, protected_bit, gen, now);
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

static frag_mpdu_t g_mpdu[FRAG_MAX_MPDUS];
static int         g_mpdu_n;

/* Returns 1 when this MPDU is a replay of one already recorded whose
 * A-MSDU bit differs. Records it otherwise. */
static int mpdu_note(const uint8_t bssid[6], const uint8_t ta[6],
                     int64_t pn, uint16_t sc, int amsdu, time_t now) {
    int slot = -1;
    for (int i = 0; i < g_mpdu_n; i++) {
        frag_mpdu_t *m = &g_mpdu[i];
        /* Aged-out rows are reused rather than compared. A PN that
         * matches across a key rotation is not a replay — after a
         * rekey they legitimately restart from zero. */
        if (now - m->ts > FRAG_MPDU_WINDOW_S) { if (slot < 0) slot = i; continue; }
        if (m->pn != pn || !mac_eq(m->ta, ta)) continue;
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

    if (slot < 0) {
        if (g_mpdu_n < FRAG_MAX_MPDUS) {
            slot = g_mpdu_n++;
        } else {
            slot = 0;
            for (int k = 1; k < g_mpdu_n; k++)
                if (g_mpdu[k].ts < g_mpdu[slot].ts) slot = k;
        }
    }
    frag_mpdu_t *m = &g_mpdu[slot];
    memset(m, 0, sizeof(*m));
    memcpy(m->ta,    ta,    6);
    memcpy(m->bssid, bssid, 6);
    m->pn    = pn;
    m->sc    = sc;
    m->amsdu = (uint8_t)amsdu;
    m->ts    = now;
    return 0;
}

void frag_observe(const uint8_t *dot11, int len, time_t now) {
    if (!dot11 || len < 24) return;
    if (((dot11[0] >> 2) & 0x03) != 2) return;      /* data frames only */

    int sub = (dot11[0] >> 4) & 0x0f;
    /* Null / QoS-Null carry no body. They are sent unprotected as a
     * matter of course — they are how a station signals power-save
     * state — so counting them would fire on every idle client. */
    if (sub & 0x04) return;

    uint8_t bssid[6], sa[6], da[6];
    int rc = dot11_data_addrs(dot11, len, bssid, sa, da);
    /* A four-address frame crosses two BSSes and has no single BSSID.
     * Skipped rather than attributed to a guess. */
    if (rc != 1) return;

    int protected_bit = (dot11[1] & 0x40) != 0;
    int fn   = dot11_frag_num(dot11, len);
    int more = dot11_more_frags(dot11, len);
    if (fn < 0 || more < 0) return;
    int fragmented = (fn > 0) || (more == 1);

    frag_bss_t *b = bss_get(bssid, now);

    /* A-MSDU flip (#75 slice 3). Runs before every gate below: it needs
     * no witnessed key install — the CCMP PN it keys on is itself proof
     * the frame is protected — and it is the one detector here that
     * only ever looks at encrypted frames. */
    int64_t pn = dot11_ccmp_pn(dot11, len);
    int amsdu  = dot11_amsdu_present(dot11, len);
    if (pn >= 0 && amsdu >= 0) {
        /* addr2 is the transmitter in every frame long enough to have
         * one, independent of the DS bits. */
        uint16_t sc = (uint16_t)(dot11[22] | (dot11[23] << 8));
        if (mpdu_note(bssid, dot11 + 10, pn, sc, amsdu, now)) {
            b->amsdu_flip++;
            memcpy(b->last_sa, sa, 6);
            memcpy(b->last_da, da, 6);
            b->last_hit = now;
        }
    }

    /* Session bookkeeping runs before the protected/plaintext branch
     * below and regardless of it — see frag_track's comment. */
    if (fragmented) {
        int tid = dot11_data_tid(dot11, len);
        if (tid >= 0)
            frag_track(b, bssid, sa, da, (uint8_t)tid, fn, more,
                      protected_bit, now);
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
    if (sta_find(bssid, sa) < 0) return;

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
        int et = first_amsdu_subframe_ethertype(dot11, len);
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
        int et = first_frag_ethertype(dot11, len);
        if (et < 0 || et == ETHERTYPE_EAPOL) return;
        b->plaintext_unicast++;
    }

    memcpy(b->last_sa, sa, 6);
    memcpy(b->last_da, da, 6);
    b->last_hit = now;
}

int frag_bss_count(void) { return g_bss_n; }

int frag_mpdu_count(void) { return g_mpdu_n; }

const frag_bss_t *frag_bss_at(int i) {
    return (i >= 0 && i < g_bss_n) ? &g_bss[i] : NULL;
}

int frag_session_count(void) { return g_sess_n; }

void frag_clear(void) {
    memset(g_bss,  0, sizeof(g_bss));
    memset(g_sta,  0, sizeof(g_sta));
    memset(g_sess, 0, sizeof(g_sess));
    memset(g_assoc_evt, 0, sizeof(g_assoc_evt));
    memset(g_mpdu, 0, sizeof(g_mpdu));
    g_bss_n       = 0;
    g_sta_n       = 0;
    g_sess_n      = 0;
    g_assoc_evt_n = 0;
    g_mpdu_n      = 0;
}
