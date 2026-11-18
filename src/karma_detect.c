#include "karma_detect.h"
#include "sloth_clock.h"
#include "beacon_snoop.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

void karma_alert_key(const uint8_t bssid[6], char *out, size_t sz) {
    if (!out || sz == 0) return;
    if (!bssid) { out[0] = '\0'; return; }
    snprintf(out, sz, "karma:%02x:%02x:%02x:%02x:%02x:%02x",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}

/* How many of this BSSID's advertised SSIDs appear in one station's
 * preferred-network list. The per-station primitive both PNL measures
 * below are built from, and the one the deauth-then-lure chain already
 * needed — extracted rather than written a third time (#90). */
static int sta_pnl_hits(const beacon_ap_t *a, const pnl_client_t *cli) {
    int hits = 0;
    for (int h = 0; h < a->ssid_history_n && h < MAX_AP_SSID_HISTORY; h++) {
        const char *name = a->ssid_history[h];
        if (!name[0]) continue;
        for (int k = 0; k < cli->ssid_count &&
                        k < MAX_PNL_SSIDS_PER_CLI; k++) {
            if (strcmp(name, cli->ssids[k]) == 0) { hits++; break; }
        }
    }
    return hits;
}

/* Union measure — see the declaration in karma_detect.h. */
int karma_pnl_union_hits(const sloth_state_t *s, const beacon_ap_t *a) {
    if (!s || !a) return 0;
    int hits = 0;
    for (int h = 0; h < a->ssid_history_n && h < MAX_AP_SSID_HISTORY; h++) {
        const char *name = a->ssid_history[h];
        if (!name[0]) continue;
        for (int c = 0; c < s->pnl_count; c++) {
            const pnl_client_t *cli = &s->pnl_clients[c];
            for (int k = 0; k < cli->ssid_count &&
                            k < MAX_PNL_SSIDS_PER_CLI; k++) {
                if (strcmp(name, cli->ssids[k]) == 0) { hits++; goto next; }
            }
        }
        next:;
    }
    return hits;
}

/* Single-station measure — see the declaration in karma_detect.h. */
int karma_pnl_client_hits(const sloth_state_t *s, const beacon_ap_t *a,
                          uint8_t best_sta_out[6]) {
    if (best_sta_out) memset(best_sta_out, 0, 6);
    if (!s || !a) return 0;
    int best = 0;
    for (int c = 0; c < s->pnl_count; c++) {
        const pnl_client_t *cli = &s->pnl_clients[c];
        int hits = sta_pnl_hits(a, cli);
        if (hits > best) {
            best = hits;
            if (best_sta_out) memcpy(best_sta_out, cli->mac, 6);
        }
    }
    return best;
}

/* Size of the union of all nearby clients' PNL SSID sets — the |B| in
 * the Jaccard denominator. Deduplicated across clients. */
static int pnl_union_size(const sloth_state_t *s) {
    int n = 0;
    for (int c = 0; c < s->pnl_count; c++) {
        const pnl_client_t *cli = &s->pnl_clients[c];
        for (int k = 0; k < cli->ssid_count && k < MAX_PNL_SSIDS_PER_CLI; k++) {
            const char *name = cli->ssids[k];
            if (!name[0]) continue;
            int seen = 0;
            for (int pc = 0; pc <= c && !seen; pc++) {
                const pnl_client_t *p = &s->pnl_clients[pc];
                int klim = (pc == c) ? k : p->ssid_count;
                for (int j = 0; j < klim && j < MAX_PNL_SSIDS_PER_CLI; j++)
                    if (strcmp(name, p->ssids[j]) == 0) { seen = 1; break; }
            }
            if (!seen) n++;
        }
    }
    return n;
}

/* Jaccard similarity between the BSSID's advertised SSID set (A) and the
 * client-PNL union (B), in parts-per-million: 1e6 * |A∩B| / |A∪B|.
 * PineAP Beacon Response drives this toward 1.0 (1e6) — it advertises
 * exactly the union of what clients probe for. `inter` is the already-
 * computed intersection (karma_pnl_union_hits). */
static int jaccard_ppm(int a_count, int b_count, int inter) {
    int uni = a_count + b_count - inter;
    if (uni <= 0) return 0;
    return (int)((long)inter * 1000000L / uni);
}

/* Distinct IE fingerprints across the advertised SSIDs — see the
 * declaration in karma_detect.h for why an incomplete set answers 0
 * rather than counting what it has. */
int karma_ie_distinct_fp(const beacon_ap_t *a) {
    if (!a) return 0;
    int n = a->ssid_history_n;
    if (n > MAX_AP_SSID_HISTORY) n = MAX_AP_SSID_HISTORY;
    if (n < 1) return 0;

    int distinct = 0;
    for (int i = 0; i < n; i++) {
        uint32_t fp = a->ssid_history_fp[i];
        if (fp == 0) return 0;          /* set not fully observed */
        int seen = 0;
        for (int j = 0; j < i && !seen; j++)
            if (a->ssid_history_fp[j] == fp) seen = 1;
        if (!seen) distinct++;
    }
    return distinct;
}

/* The collapse judgement — see the declaration in karma_detect.h for
 * what it is and is not evidence of. */
int karma_ie_collapsed(const beacon_ap_t *a) {
    if (!a || a->ssid_history_n < 2) return 0;
    return karma_ie_distinct_fp(a) == 1;
}

/* Deauth-then-lure with a shared victim (#90) — see the declaration in
 * karma_detect.h for why a global "some flood happened recently" check
 * was replaced. */
int karma_deauth_lure_victim(const sloth_state_t *s,
                             const beacon_ap_t *candidate, time_t now,
                             uint8_t victim_out[6]) {
    if (!s || !candidate) return 0;

    for (int k = 0; k < s->deauth_victim_count; k++) {
        const deauth_victim_t *v = &s->deauth_victims[k];
        /* When the threshold was last met, not when the last frame came
         * (#88): trailing frames after a flood do not extend it. */
        if (!v->flood_last || now - v->flood_last > KARMA_DEAUTH_WIN_SECS)
            continue;
        /* Deauthed from the candidate itself isn't a lure — a rogue
         * flooding its own clients isn't luring them to itself. */
        if (memcmp(v->bssid, candidate->bssid, 6) == 0) continue;

        int interest = 0;
        /* One hit is enough here, unlike the KARMA_PNL_CORROB_MIN the
         * standalone PNL escalator demands: the victim is already tied
         * to this candidate by the flood, so the PNL entry only has to
         * name a network the candidate is answering, not carry the
         * whole correlation on its own. */
        for (int c = 0; c < s->pnl_count && !interest; c++) {
            const pnl_client_t *cli = &s->pnl_clients[c];
            if (memcmp(cli->mac, v->victim, 6) != 0) continue;
            if (sta_pnl_hits(candidate, cli) > 0) interest = 1;
        }
        if (!interest) {
            /* Or the lure already worked and the victim is sitting on
             * the candidate, seen no earlier than the flood that
             * knocked it off its real AP. */
            for (int as = 0; as < s->assoc_count; as++) {
                const assoc_t *as_e = &s->assocs[as];
                if (memcmp(as_e->bssid, candidate->bssid, 6) == 0 &&
                    memcmp(as_e->sta_mac, v->victim, 6) == 0 &&
                    as_e->last_seen >= v->flood_last) {
                    interest = 1;
                    break;
                }
            }
        }
        if (!interest) continue;

        if (victim_out) memcpy(victim_out, v->victim, 6);
        return 1;
    }
    return 0;
}

const sloth_tool_sig_t *karma_tool_match(const sloth_state_t *s,
                                         const beacon_ap_t *candidate,
                                         sloth_tool_conf_t *conf,
                                         int *pmkid_out) {
    if (conf)      *conf      = TOOL_CONF_NONE;
    if (pmkid_out) *pmkid_out = 0;
    if (!s || !candidate) return NULL;

    /* A protocol observable, unlike a tool's beacon quirks (#68), and
     * informational only (#90): legitimate 802.11r/PMK-caching roaming
     * produces one too. */
    int pmkid = 0;
    for (int e = 0; e < s->eapol_count; e++)
        if (s->eapol_events[e].has_pmkid &&
            memcmp(s->eapol_events[e].bssid, candidate->bssid, 6) == 0) {
            pmkid = 1;
            break;
        }
    if (pmkid_out) *pmkid_out = pmkid;

    sloth_tool_obs_t obs;
    memset(&obs, 0, sizeof(obs));
    obs.vendor_ie_hash     = candidate->fp.vendor_ies_hash;
    obs.beacon_interval_ms = candidate->beacon_ms;
    obs.fp_flags           = candidate->fp.flags;
    /* Every caller asks about a BSSID already over KARMA_SSID_THRESH, or
     * one answering directed probes for names it never beaconed (#187
     * S2): either way it answers to many names. */
    obs.karma_echo         = 1;
    obs.pmkid_seen         = pmkid;
    return tool_fingerprint_match_row(&obs, conf);
}

void karma_update(sloth_state_t *s) {
    time_t now = sloth_wall();
    int b_count = pnl_union_size(s);   /* |PNL union| — same for every BSSID */
    s->karma_count = 0;

    for (int i = 0; i < s->beacon_count &&
                    s->karma_count < MAX_KARMA_APS; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        /* A row on either signal (#187 S2): the beacon fan-out, or
         * answers to directed probes for names this BSSID never
         * beaconed — the classic KARMA radio, which beacons one name
         * and so never reaches the fan-out threshold. */
        int forged = 0, forge_sta = 0;
        for (int f = 0; s->karma_forge && f < s->karma_forge_count; f++)
            if (memcmp(s->karma_forge[f].bssid, a->bssid, 6) == 0) {
                forged = karma_forged_ssids(s, &s->karma_forge[f],
                                            &forge_sta, NULL, 0, NULL);
                break;
            }
        int forging = forged >= KARMA_FORGE_SSID_MIN;
        if (a->ssid_history_n < KARMA_SSID_THRESH && !forging) continue;

        karma_ap_t *k = &s->karma_aps[s->karma_count++];
        memset(k, 0, sizeof(*k));
        memcpy(k->bssid, a->bssid, 6);
        k->ssid_count   = a->ssid_history_n;
        k->pnl_overlap  = karma_pnl_union_hits(s, a);
        k->pnl_best     = karma_pnl_client_hits(s, a, NULL);
        k->pnl_jaccard_ppm = jaccard_ppm(k->ssid_count, b_count, k->pnl_overlap);
        k->ie_uniform     = karma_ie_collapsed(a);
        k->ie_fp_distinct = karma_ie_distinct_fp(a);
        k->deauth_chain = karma_deauth_lure_victim(s, a, now, NULL);
        /* The PNL bonus keys on pnl_best, not pnl_overlap (#90): the
         * union is a description, only a single station asking for
         * KARMA_PNL_CORROB_MIN of these names is evidence. Same rule
         * as the KARMA_AP alert's CRIT gate, so the [y] score and the
         * alert severity cannot disagree about one BSSID. */
        k->forged         = forged;
        k->forge_stations = forge_sta;
        /* Forging weighs what the deauth chain does: like it, it is an
         * act observed against stations, not a property of the
         * beacons, and the KARMA_PROBE_FORGE rule fires on it alone. */
        k->score        = 1 + (k->pnl_best >= KARMA_PNL_CORROB_MIN ? 2 : 0)
                            + (k->ie_uniform ? 1 : 0)
                            + (k->deauth_chain ? 3 : 0)
                            + (forging ? 3 : 0);
        k->last_seen    = a->last_seen;
        /* Display only: the score is left alone, since an UNVERIFIED
         * row is not corroboration (#90) and none other ships. */
        sloth_tool_conf_t tconf = TOOL_CONF_NONE;
        const sloth_tool_sig_t *trow = karma_tool_match(s, a, &tconf, NULL);
        tool_attribution_format(k->tool, sizeof(k->tool), trow, tconf);
        snprintf(k->top_ssid, sizeof(k->top_ssid), "%s",
                 a->ssid[0] ? a->ssid : a->ssid_history[0]);
    }

    /* Rank strongest-first (insertion sort — the table is small and
     * near-sorted poll to poll). Ties keep beacon order. */
    for (int i = 1; i < s->karma_count; i++) {
        karma_ap_t tmp = s->karma_aps[i];
        int j = i - 1;
        while (j >= 0 && s->karma_aps[j].score < tmp.score) {
            s->karma_aps[j + 1] = s->karma_aps[j];
            j--;
        }
        s->karma_aps[j + 1] = tmp;
    }

    if (s->karma_sel >= s->karma_count)
        s->karma_sel = s->karma_count > 0 ? s->karma_count - 1 : 0;
}

/* ── Directed probe-response forgery (#187 S2) ─────────────────
 *
 * Capture-side state: the recent directed probe requests, and per
 * answering BSSID the names it answered that were not its own. See
 * karma_detect.h for what is and is not recorded, and why. */

typedef struct {
    uint8_t  sta[6];
    char     ssid[33];
    uint64_t ms;          /* 0 = empty slot */
} karma_preq_t;

typedef struct {
    karma_forge_t row;                         /* the exported part */
    uint64_t      ssid_ms[KARMA_FORGE_MAX_SSIDS];
    uint64_t      last_ms;
} forge_slot_t;

static pthread_mutex_t g_forge_mu = PTHREAD_MUTEX_INITIALIZER;
static karma_preq_t    g_preq[KARMA_PREQ_RING];
static int             g_preq_head;
static forge_slot_t    g_forge[KARMA_FORGE_MAX_BSS];
static int             g_forge_n;
static unsigned long   g_forge_evict;
static karma_forge_t   g_forge_copy[KARMA_FORGE_MAX_BSS];

static int mac_is_group(const uint8_t m[6]) { return (m[0] & 0x01) != 0; }

static int mac_is_zero(const uint8_t m[6]) {
    for (int i = 0; i < 6; i++) if (m[i]) return 0;
    return 1;
}

void karma_forge_clear(void) {
    pthread_mutex_lock(&g_forge_mu);
    memset(g_preq, 0, sizeof(g_preq));
    g_preq_head = 0;
    memset(g_forge, 0, sizeof(g_forge));
    g_forge_n = 0;
    g_forge_evict = 0;
    pthread_mutex_unlock(&g_forge_mu);
}

unsigned long karma_forge_evictions(void) {
    pthread_mutex_lock(&g_forge_mu);
    unsigned long n = g_forge_evict;
    pthread_mutex_unlock(&g_forge_mu);
    return n;
}

/* Did `sta` send a directed probe for `ssid` within the pairing window?
 * Caller holds g_forge_mu. */
static int preq_matches(const uint8_t sta[6], const char *ssid,
                        uint64_t now_ms) {
    uint64_t pair_ms = (uint64_t)KARMA_FORGE_PAIR_S * 1000u;
    for (int i = 0; i < KARMA_PREQ_RING; i++) {
        const karma_preq_t *q = &g_preq[i];
        if (!q->ms || q->ms > now_ms || now_ms - q->ms > pair_ms) continue;
        if (memcmp(q->sta, sta, 6) == 0 && strcmp(q->ssid, ssid) == 0)
            return 1;
    }
    return 0;
}

/* Record one answer on its BSSID's row. Caller holds g_forge_mu. */
static void forge_note(const uint8_t bssid[6], const uint8_t sta[6],
                       const char *ssid, uint64_t ev, uint64_t now_ms,
                       time_t wall) {
    forge_slot_t *f = NULL;
    for (int i = 0; i < g_forge_n; i++)
        if (memcmp(g_forge[i].row.bssid, bssid, 6) == 0) {
            f = &g_forge[i];
            break;
        }
    if (!f) {
        /* The least recently answering row goes. Rows exist only for
         * answers naming something other than the BSSID's own SSID,
         * which honest APs do not produce, so a full table means
         * several answering radios at once, and the freshest are the
         * ones an alert can still be about. */
        if (g_forge_n < KARMA_FORGE_MAX_BSS) {
            f = &g_forge[g_forge_n++];
        } else {
            f = &g_forge[0];
            for (int i = 1; i < g_forge_n; i++)
                if (g_forge[i].last_ms < f->last_ms) f = &g_forge[i];
            g_forge_evict++;
        }
        memset(f, 0, sizeof(*f));
        memcpy(f->row.bssid, bssid, 6);
        f->row.first_seen = wall;
    }
    karma_forge_t *r = &f->row;
    f->last_ms   = now_ms;
    r->last_seen = wall;

    /* The station, as an index into the row's station list. A full list
     * keeps its stations and leaves the newcomer out of the mask: the
     * distinct-station count then understates, the direction that
     * withholds CRIT rather than invents it. */
    int si = -1;
    for (int i = 0; i < r->n_sta; i++)
        if (memcmp(r->sta[i], sta, 6) == 0) { si = i; break; }
    if (si < 0) {
        if (r->n_sta < KARMA_FORGE_MAX_STA) {
            si = r->n_sta++;
            memcpy(r->sta[si], sta, 6);
        } else {
            r->dropped++;
            g_forge_evict++;
        }
    }

    int k = -1;
    for (int i = 0; i < r->n_ssids; i++)
        if (strcmp(r->ssids[i], ssid) == 0) { k = i; break; }
    if (k < 0) {
        if (r->n_ssids < KARMA_FORGE_MAX_SSIDS) {
            k = r->n_ssids++;
        } else {
            /* Replace the name answered longest ago: the row is about
             * this radio's current behaviour. */
            k = 0;
            for (int i = 1; i < r->n_ssids; i++)
                if (f->ssid_ms[i] < f->ssid_ms[k]) k = i;
            r->dropped++;
            g_forge_evict++;
        }
        snprintf(r->ssids[k], sizeof(r->ssids[k]), "%s", ssid);
        r->ssid_ev[k]       = 0;
        r->ssid_sta_mask[k] = 0;
        memset(r->ans_first[k], 0, sizeof(r->ans_first[k]));
        memset(r->ans_last[k], 0, sizeof(r->ans_last[k]));
    }
    f->ssid_ms[k]   = now_ms;
    r->ssid_last[k] = wall;
    if (ev) r->ssid_ev[k] = ev;
    if (si >= 0) {
        r->ssid_sta_mask[k] |= (uint8_t)(1u << si);
        if (!r->ans_first[k][si]) r->ans_first[k][si] = wall;
        r->ans_last[k][si] = wall;
    }
}

void karma_observe_frame(const dot11_frame_t *f, const char *ssid) {
    if (!f || !ssid || f->proto != 0 || f->type != 0) return;
    if (f->subtype != 4 && f->subtype != 5) return;
    const uint8_t *body; int blen;
    /* No readable header, or a Protected body: the caller's SSID did
     * not come from plaintext elements, so it is not used. */
    if (!dot11_frame_body(f, &body, &blen)) return;

    if (f->subtype == 4) {
        /* Probe Request (§9.3.3.10). A wildcard (zero-length) SSID asks
         * for nobody in particular, so there is nothing to forge an
         * answer to. */
        if (!f->sa || mac_is_group(f->sa) || mac_is_zero(f->sa)) return;
        if (!ssid[0]) return;
        uint64_t now_ms = sloth_mono_ms();
        pthread_mutex_lock(&g_forge_mu);
        karma_preq_t *q = &g_preq[g_preq_head];
        g_preq_head = (g_preq_head + 1) % KARMA_PREQ_RING;
        memcpy(q->sta, f->sa, 6);
        snprintf(q->ssid, sizeof(q->ssid), "%s", ssid);
        q->ms = now_ms ? now_ms : 1;
        pthread_mutex_unlock(&g_forge_mu);
        return;
    }

    /* Probe Response (§9.3.3.11): Timestamp(8) Beacon Interval(2)
     * Capability(2), then elements. Shorter than the fixed part is not
     * a probe response. A group DA answers nobody's directed probe. */
    if (blen < 12) return;
    if (!f->da || !f->bssid) return;
    if (mac_is_group(f->da) || mac_is_zero(f->da)) return;
    if (mac_is_group(f->bssid) || mac_is_zero(f->bssid)) return;
    if (!ssid[0]) return;

    /* The BSSID's own name, beaconed or revealed from a hidden beacon,
     * is the honest answer. Read before this module's lock is taken:
     * the beacon table has its own, and the two are never held
     * together. */
    char own[33];
    if (beacon_find_ssid(f->bssid, own) && strcmp(own, ssid) == 0) return;

    uint64_t now_ms = sloth_mono_ms();
    time_t   wall   = sloth_wall();
    pthread_mutex_lock(&g_forge_mu);
    if (preq_matches(f->da, ssid, now_ms))
        forge_note(f->bssid, f->da, ssid, f->event_id, now_ms, wall);
    pthread_mutex_unlock(&g_forge_mu);
}

void karma_forge_snapshot(sloth_state_t *s) {
    if (!s) return;
    uint64_t now_ms = sloth_mono_ms();
    uint64_t win_ms = (uint64_t)KARMA_FORGE_WINDOW_S * 1000u;
    pthread_mutex_lock(&g_forge_mu);
    /* Names answered longer ago than the window go, then rows left with
     * none. */
    int i = 0;
    while (i < g_forge_n) {
        forge_slot_t  *f = &g_forge[i];
        karma_forge_t *r = &f->row;
        int k = 0;
        while (k < r->n_ssids) {
            if (now_ms > f->ssid_ms[k] && now_ms - f->ssid_ms[k] > win_ms) {
                int last = r->n_ssids - 1;
                if (k != last) {
                    memcpy(r->ssids[k], r->ssids[last], sizeof(r->ssids[k]));
                    r->ssid_last[k]     = r->ssid_last[last];
                    r->ssid_ev[k]       = r->ssid_ev[last];
                    r->ssid_sta_mask[k] = r->ssid_sta_mask[last];
                    memcpy(r->ans_first[k], r->ans_first[last],
                           sizeof(r->ans_first[k]));
                    memcpy(r->ans_last[k], r->ans_last[last],
                           sizeof(r->ans_last[k]));
                    f->ssid_ms[k]       = f->ssid_ms[last];
                }
                memset(r->ans_first[last], 0, sizeof(r->ans_first[last]));
                memset(r->ans_last[last], 0, sizeof(r->ans_last[last]));
                r->n_ssids--;
            } else {
                k++;
            }
        }
        if (r->n_ssids == 0) {
            g_forge[i] = g_forge[--g_forge_n];
            memset(&g_forge[g_forge_n], 0, sizeof(g_forge[g_forge_n]));
        } else {
            i++;
        }
    }
    /* Written only here, on the poll thread that also reads it, so the
     * copy needs no lock of its own once taken. */
    for (i = 0; i < g_forge_n; i++) g_forge_copy[i] = g_forge[i].row;
    s->karma_forge       = g_forge_copy;
    s->karma_forge_count = g_forge_n;
    pthread_mutex_unlock(&g_forge_mu);
}

/* The beacon row `forged` is judged against, or NULL when "never
 * beaconed" cannot be said: no beacon on file (this radio never heard
 * the BSSID beacon at all), or a saturated history (a name past the cap
 * was dropped unrecorded, not unbeaconed). */
static const beacon_ap_t *forge_beacon_row(const sloth_state_t *s,
                                           const karma_forge_t *r) {
    const beacon_ap_t *a = NULL;
    for (int i = 0; i < s->beacon_count; i++)
        if (memcmp(s->beacon_aps[i].bssid, r->bssid, 6) == 0) {
            a = &s->beacon_aps[i];
            break;
        }
    if (!a || a->ssid_history_n >= MAX_AP_SSID_HISTORY) return NULL;
    return a;
}

/* 1 when `name` counts as forged against beacon row `a`: neither the
 * BSSID's current name nor anywhere in its beacon history. */
static int forge_name_forged(const beacon_ap_t *a, const char *name) {
    if (!name[0]) return 0;
    if (a->ssid[0] && strcmp(a->ssid, name) == 0) return 0;
    for (int h = 0; h < a->ssid_history_n; h++)
        if (strcmp(a->ssid_history[h], name) == 0) return 0;
    return 1;
}

int karma_forge_captured(const sloth_state_t *s, const karma_forge_t *r,
                         uint8_t sta_out[6]) {
    if (sta_out) memset(sta_out, 0, 6);
    if (!s || !r) return 0;
    const beacon_ap_t *a = forge_beacon_row(s, r);
    if (!a) return 0;
    time_t win = KARMA_FORGE_ASSOC_S;
    int nn = r->n_ssids < KARMA_FORGE_MAX_SSIDS ? r->n_ssids
                                                : KARMA_FORGE_MAX_SSIDS;
    int ns = r->n_sta < KARMA_FORGE_MAX_STA ? r->n_sta : KARMA_FORGE_MAX_STA;
    for (int k = 0; k < nn; k++) {
        if (!forge_name_forged(a, r->ssids[k])) continue;
        for (int si = 0; si < ns; si++) {
            /* 0 = this station was never sent an answer naming this
             * SSID (set with its ssid_sta_mask bit, cleared with it). */
            time_t first = r->ans_first[k][si], last = r->ans_last[k][si];
            if (!first) continue;
            /* The ask: this station, this BSSID, under the forged name,
             * no earlier than the first forged answer it received and no
             * later than the window after the newest. */
            int asked = 0;
            for (int q = 0; q < s->assoc_req_count && !asked; q++) {
                const assoc_req_t *rq = &s->assoc_reqs[q];
                if (memcmp(rq->bssid, r->bssid, 6) != 0) continue;
                if (memcmp(rq->sta, r->sta[si], 6) != 0) continue;
                if (strcmp(rq->requested_ssid, r->ssids[k]) != 0) continue;
                if (rq->ts < first || rq->ts > last + win) continue;
                asked = 1;
            }
            if (!asked) continue;
            /* The grant: an association response with status 0, or the
             * AP installing a key (assoc_t), seen no earlier than the
             * first answer. A request alone is the station trying; the
             * AP accepting it is the station captured. */
            for (int g = 0; g < s->assoc_count; g++) {
                const assoc_t *as = &s->assocs[g];
                if (memcmp(as->bssid, r->bssid, 6) != 0) continue;
                if (memcmp(as->sta_mac, r->sta[si], 6) != 0) continue;
                if (as->source == ASSOC_SRC_UNKNOWN) continue;
                if (as->last_seen < first) continue;
                if (sta_out) memcpy(sta_out, r->sta[si], 6);
                return 1;
            }
        }
    }
    return 0;
}

int karma_forged_ssids(const sloth_state_t *s, const karma_forge_t *r,
                       int *sta_n_out, uint64_t *ev_out, int ev_max,
                       int *ev_n) {
    if (sta_n_out) *sta_n_out = 0;
    if (ev_n) *ev_n = 0;
    if (!s || !r) return 0;
    const beacon_ap_t *a = forge_beacon_row(s, r);
    if (!a) return 0;

    int forged = 0;
    unsigned sta_mask = 0;
    int nn = r->n_ssids < KARMA_FORGE_MAX_SSIDS ? r->n_ssids
                                                : KARMA_FORGE_MAX_SSIDS;
    for (int k = 0; k < nn; k++) {
        const char *name = r->ssids[k];
        if (!forge_name_forged(a, name)) continue;
        forged++;
        sta_mask |= r->ssid_sta_mask[k];
        if (ev_out && ev_n && r->ssid_ev[k] && *ev_n < ev_max)
            ev_out[(*ev_n)++] = r->ssid_ev[k];
    }
    if (sta_n_out) {
        int n = 0;
        for (int b = 0; b < KARMA_FORGE_MAX_STA; b++)
            if (sta_mask & (1u << b)) n++;
        *sta_n_out = n;
    }
    return forged;
}
