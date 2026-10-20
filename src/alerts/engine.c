/* The alert engine (#118): the deduped incident ring, fire() and its
 * variants, eviction, the incident side table, the tainted-BSSID
 * tracker, snapshot and per-alert pcap export, and alerts_update(),
 * which runs src/alerts/rules_table.c's rules in that table's order.
 * The rules themselves live in src/alerts/rules_<domain>.c. */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "alerts.h"
#include "sloth_compat.h"
#include "tune.h"   /* operator-tunable thresholds (#82) */
#include "sensor_health.h"
#include "wifi_assess.h"
#include "tool_fingerprint.h"
#include "jsonl.h"
#include "alert_pcap.h"
#include "evidence_export.h"
#include "secure_file.h"   /* SFILE_ERR_MAX */
#include "wired_attach.h"
#include "event_wake.h"
#include "sloth_clock.h"
#include "rules.h"
#include "engine_internal.h"

/* Engine state: deduped alert ring.
 *
 * Each alerts_update() call walks the trigger sources (scan/deauth/dns_log
 * /conns), and for each condition produces a stable dedup key. Existing
 * alerts under that key get count++ and last_seen=now; new keys append.
 * On overflow the oldest entry (lowest last_seen) is evicted.
 *
 * Incident lifecycle (#98). A run of one dedup key is an *incident*:
 * it opens with `alert.create`, carries one `incident_id` through every
 * `alert.update` / `alert.escalate`, and closes with exactly one
 * `alert.resolve`. Before #98 only the create was visible downstream —
 * a WARN→CRIT escalation changed the engine in place and emitted
 * nothing, so a consumer paging on CRIT never saw it.
 *
 * What is emitted is a *material* change, never a poll:
 *   - severity moved              → escalate (up) / update (down), always
 *   - the rendered evidence moved → update, at most once per
 *                                   ALERT_UPDATE_MIN_S
 *   - no rule re-asserted the key for ALERT_RESOLVE_AFTER_S → resolve
 * A resolved entry stays in the view (the operator's history is not
 * the stream's business) but is evicted first under pressure, and a key
 * that fires again after its resolve opens a *new* incident.
 *
 * Durations run on CLOCK_MONOTONIC through the sloth_clock seam
 * (#109); wall clock is evidence only. An NTP step must not
 * resolve a live incident or hold a dead one open. */

static alert_t engine[MAX_ALERTS];
static int     engine_count;

/* Monotonically increasing across the process, never reset — it is what
 * keeps two incidents on one key in one second distinguishable. */
static uint64_t g_incident_seq;

#define ALERT_FNV64_OFFSET  0xcbf29ce484222325ULL
#define ALERT_FNV64_PRIME   0x100000001b3ULL

static uint64_t alert_fnv1a(const void *data, size_t n, uint64_t h) {
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= ALERT_FNV64_PRIME; }
    return h;
}

/* Signature of the evidence a rule rendered this tick. Two fire() calls
 * with the same detail describe the same observation; a different
 * detail is a different one. This is the only handle the engine has —
 * fire() is called from 50-odd rules and none of them tells it whether
 * a frame arrived or a retained row was simply re-read. */
static uint64_t alert_detail_sig(const char *detail) {
    return alert_fnv1a(detail, strlen(detail), ALERT_FNV64_OFFSET);
}

/* Opaque, collision-resistant, stable for the incident's life. Not a
 * UUID and not claimed to be one: the counter makes construction
 * collisions impossible, leaving only a 64-bit hash collision. */
static void incident_id_make(alert_t *a, time_t when) {
    uint64_t h = alert_fnv1a(a->key, strlen(a->key), ALERT_FNV64_OFFSET);
    uint64_t t = (uint64_t)when;
    uint64_t n = ++g_incident_seq;
    h = alert_fnv1a(&t, sizeof(t), h);
    h = alert_fnv1a(&n, sizeof(n), h);
    snprintf(a->incident_id, sizeof(a->incident_id), "%016llx",
             (unsigned long long)h);
}

/* Monotonic time never runs backwards, but a zeroed entry (or a caller
 * mixing clocks) must not turn that into a huge unsigned age. */
static uint64_t alert_age_ms(uint64_t now_ms, uint64_t then_ms) {
    return now_ms > then_ms ? now_ms - then_ms : 0;
}

/* Close an incident: one resolve, once. `reason` is why. */
static void alert_resolve(alert_t *a, time_t now, const char *reason) {
    if (a->resolved || !a->incident_id[0]) return;
    a->resolved = 1;
    a->event_seq++;
    jsonl_emit_alert_event(a, "alert.resolve", now, -1, reason);
}

/* ── Tainted-BSSID tracker (evil-twin Phase 4) ────────────── */

typedef struct {
    uint8_t bssid[6];
    time_t  marked_at;
} taint_entry_t;

/* The alert engine marks from the main loop; eapol_log.c queries from
 * the probe thread (append_22000_line_for_bssid, under its own g_mu).
 * g_taint_mu is a leaf: nothing is called out to while it is held, so
 * taking it under another module's lock cannot close a cycle. Callers
 * of the static helpers below must hold it. */
static pthread_mutex_t g_taint_mu = PTHREAD_MUTEX_INITIALIZER;
static taint_entry_t   g_taint[EVIL_TWIN_TAINT_MAX];
static int             g_taint_count;

static int taint_find_slot(const uint8_t bssid[6]) {
    for (int i = 0; i < g_taint_count; i++) {
        if (memcmp(g_taint[i].bssid, bssid, 6) == 0) return i;
    }
    return -1;
}

static void taint_mark_locked(const uint8_t bssid[6], time_t now) {
    int slot = taint_find_slot(bssid);
    if (slot >= 0) { g_taint[slot].marked_at = now; return; }
    if (g_taint_count < EVIL_TWIN_TAINT_MAX) {
        slot = g_taint_count++;
    } else {
        /* Evict the oldest entry. */
        slot = 0;
        time_t oldest = g_taint[0].marked_at;
        for (int i = 1; i < EVIL_TWIN_TAINT_MAX; i++) {
            if (g_taint[i].marked_at < oldest) {
                oldest = g_taint[i].marked_at;
                slot   = i;
            }
        }
    }
    memcpy(g_taint[slot].bssid, bssid, 6);
    g_taint[slot].marked_at = now;
}

void taint_mark(const uint8_t bssid[6], time_t now) {
    pthread_mutex_lock(&g_taint_mu);
    taint_mark_locked(bssid, now);
    pthread_mutex_unlock(&g_taint_mu);
}

int evil_twin_bssid_is_tainted(const uint8_t bssid[6]) {
    /* Same clock as the mark (alerts_update stamps via the seam). Read
     * straight from libc here, an injected clock never matched and an
     * NTP step mis-aged the TTL (#109). */
    time_t now = sloth_wall();
    int tainted = 0;
    pthread_mutex_lock(&g_taint_mu);
    int slot = taint_find_slot(bssid);
    if (slot >= 0 && now - g_taint[slot].marked_at <= EVIL_TWIN_TAINT_TTL_SECS)
        tainted = 1;
    pthread_mutex_unlock(&g_taint_mu);
    return tainted;
}

void evil_twin_taint_clear(void) {
    pthread_mutex_lock(&g_taint_mu);
    g_taint_count = 0;
    memset(g_taint, 0, sizeof(g_taint));
    pthread_mutex_unlock(&g_taint_mu);
}

void evil_twin_taint_mark_for_test(const uint8_t bssid[6]) {
    taint_mark(bssid, sloth_wall());
}

/* FNV-1a of each live slot's key, kept beside engine[] (#112).
 *
 * find_by_key() runs once per fire(), and fire() runs for every rule
 * condition every poll, so the old 128-way strcmp over 192-byte keys was
 * the engine's inner loop. Comparing a 64-bit hash first rejects every
 * non-matching slot with one integer compare.
 *
 * The hash only filters. strcmp still decides, because two keys can
 * collide and a collision that merged two findings into one incident is
 * exactly the class of bug #112 exists to remove. tests/test_alert_key.c ::
 * test_find_by_key_still_compares_the_full_key forces every hash to one
 * value through alerts_test_key_hash_mask() to prove that. */
static uint64_t engine_hash[MAX_ALERTS];

/* ~0 in production. A test narrows it (to 0, so every key collides) to
 * show the strcmp is load-bearing, which a real 64-bit FNV collision
 * would be needed to show otherwise. Reset by alerts_clear(). */
static uint64_t g_key_hash_mask = ~(uint64_t)0;

static uint64_t key_hash(const char *key) {
    return alert_fnv1a(key, strlen(key), ALERT_FNV64_OFFSET) & g_key_hash_mask;
}

void alerts_test_key_hash_mask(uint64_t mask) { g_key_hash_mask = mask; }

/* Find existing alert with this key; returns index or -1. */
static int find_by_key(const char *key, uint64_t h) {
    for (int i = 0; i < engine_count; i++) {
        if (engine_hash[i] == h && strcmp(engine[i].key, key) == 0) return i;
    }
    return -1;
}

/* ── Incident side state (#112) ─────────────────────────────
 *
 * What a finding needs to remember across engine slot reuse. fire_inv()
 * memsets a slot when it opens a new incident there, which is right for
 * the incident (its counters and id are its own) and wrong for three
 * things that belong to the *key*:
 *
 *   - the per-alert pcap export: when this key last wrote a file, and
 *     which file. Before this table the memset cleared pcap_dumped, so
 *     every evict-then-refire exported the same frames again — 16.1M
 *     files on a live sensor (#96). pcap_cool[] was added to survive
 *     that memset and nothing else; it is this table now.
 *   - first_seen, half of the `--db` alerts table's primary key. A key
 *     evicted under pressure and re-fired a tick later is the same
 *     finding, and minting a new first_seen gave it a new row per
 *     eviction. Restored only when the previous incident was closed by
 *     eviction: a key whose evidence went quiet for the full resolve
 *     period and then came back IS a new episode, and keeps its own.
 *   - how many incidents the key has had (`reopen_count`), which a
 *     consumer otherwise has to reconstruct by joining create events.
 *
 * incident_id is deliberately NOT carried over. A re-fired key is a new
 * incident with a new id (#98); the side row records the last one only
 * so that "this key had an incident before" has a cheap answer.
 *
 * Bounded at ALERT_SIDE_MAX rows, LRU by a touch counter. This bounds
 * memory, not cardinality: the engine's per-type fair eviction still
 * decides which findings hold slots. A dropped row costs a possible
 * duplicate pcap (tallied as SH_EVICT_PCAP_COOLDOWN — the name is the
 * JSONL contract and kept, and it counts only rows that held an export,
 * so its meaning has not moved) or a reopen_count restarting at 0.
 * Sized at 4x MAX_ALERTS so the steady state never evicts. */
#define ALERT_SIDE_MAX 512

typedef struct {
    uint64_t key_hash;
    char     key[ALERT_KEY_LEN];
    time_t   last_pcap_export;      /* wall time of the last real file; 0 = none */
    int      pcap_write_failures;
    char     pcap_path[ALERT_PCAP_PATH_LEN];
    char     last_incident_id[ALERT_INCIDENT_ID_LEN];
    time_t   last_first_seen;
    uint32_t reopen_count;
    uint8_t  evicted;               /* last incident closed by eviction */
    uint64_t touch;                 /* LRU stamp */
} alert_side_t;

static alert_side_t g_side[ALERT_SIDE_MAX];
static int          g_side_n;
static uint64_t     g_side_clock;

static alert_side_t *side_find(const char *key, uint64_t h) {
    if (!key || !key[0]) return NULL;
    for (int i = 0; i < g_side_n; i++) {
        if (g_side[i].key_hash == h && strcmp(g_side[i].key, key) == 0) {
            g_side[i].touch = ++g_side_clock;
            return &g_side[i];
        }
    }
    return NULL;
}

static alert_side_t *side_get(const char *key, uint64_t h) {
    alert_side_t *r = side_find(key, h);
    if (r || !key || !key[0]) return r;
    int slot;
    if (g_side_n < ALERT_SIDE_MAX) {
        slot = g_side_n++;
    } else {
        slot = 0;
        for (int i = 1; i < ALERT_SIDE_MAX; i++)
            if (g_side[i].touch < g_side[slot].touch) slot = i;
        if (g_side[slot].last_pcap_export > 0)
            sh_evict_note(SH_EVICT_PCAP_COOLDOWN);
    }
    r = &g_side[slot];
    memset(r, 0, sizeof(*r));
    r->key_hash = h;
    snprintf(r->key, sizeof(r->key), "%s", key);
    r->touch = ++g_side_clock;
    return r;
}

/* Evict an entry and return its slot.
 *
 * Resolved incidents go first — their stream lifecycle is already
 * complete, so dropping one costs a consumer nothing, while dropping a
 * live one would strand an incident with no resolve. Within that class,
 * lowest last_seen. An evicted live incident is resolved on the way out
 * so the stream stays closed (#98).
 *
 * ── Among LIVE incidents, the victim comes from whichever TYPE holds
 * the most slots, not from whichever entry is globally oldest (#96).
 *
 * Globally-oldest is why the same bug kept recurring. The engine is
 * MAX_ALERTS entries shared by every rule, and nothing bounded how many
 * one rule could hold, so a prolific rule filled it and then every
 * other rule's findings were evicted the moment they fired. Four
 * instances in one session, each found separately and each "fixed" in
 * its own rule:
 *
 *   #105  a dedup key with a remote-chosen component — 200 addresses
 *         from one benign host produced 127 incidents and filled the
 *         engine, evicting real findings
 *   #107  release_count unbounded in time — one roam fired forever, and
 *         128 roams saturated the engine
 *   #96   128 beaconing tracks firing every tick against 128 slots,
 *         which churned the engine continuously and (via a cleared
 *         export latch) wrote 16.1M duplicate pcaps
 *
 * Each of those was a rule bounding its own cardinality better. None of
 * them stopped the NEXT rule from doing the same thing, because the
 * engine had no opinion about fairness at all — a grep for a per-type
 * budget across 200-odd ALERT_TYPE_* references found nothing.
 *
 * Evicting from the largest holder is work-conserving, which is why it
 * is preferred to a fixed per-type cap: with 75 types and 128 slots a
 * hard equal share would be one or two each, and since most types hold
 * nothing most of the time that would waste most of the engine. Here a
 * single rule may still use every slot when nothing else needs one, and
 * gives a slot back as soon as another rule fires. Repeated firing by a
 * quiet rule therefore converges toward a fair share instead of being
 * refused.
 *
 * It does NOT guarantee any rule a reserved slot, and it is not meant
 * to: the guarantee is the weaker and more useful one that no rule can
 * hold the engine against another indefinitely. */
static int evict_oldest(time_t now) {
    int slot = -1;
    time_t oldest = 0;
    for (int i = 0; i < engine_count; i++) {
        if (!engine[i].resolved) continue;
        if (slot < 0 || engine[i].last_seen < oldest) {
            oldest = engine[i].last_seen;
            slot   = i;
        }
    }
    if (slot < 0) {
        /* How many live slots each type holds. */
        int held[ALERT_TYPE_COUNT];
        memset(held, 0, sizeof(held));
        for (int i = 0; i < engine_count; i++) {
            int t = (int)engine[i].type;
            if (t >= 0 && t < (int)ALERT_TYPE_COUNT) held[t]++;
        }
        int most = 0;
        for (int t = 0; t < (int)ALERT_TYPE_COUNT; t++)
            if (held[t] > most) most = held[t];

        /* The oldest entry among the types tied for most-held. Ties
         * broken by age so the choice is deterministic and still
         * prefers stale evidence over fresh. */
        slot   = -1;
        oldest = 0;
        for (int i = 0; i < engine_count; i++) {
            int t = (int)engine[i].type;
            if (t < 0 || t >= (int)ALERT_TYPE_COUNT) continue;
            if (held[t] != most) continue;
            if (slot < 0 || engine[i].last_seen < oldest) {
                oldest = engine[i].last_seen;
                slot   = i;
            }
        }
        /* Defensive: an engine_count > 0 always has a most-held type, so
         * slot is set. Falling back to 0 rather than returning -1 keeps
         * the caller's contract (it indexes the result) if that ever
         * stops being true. */
        if (slot < 0) slot = 0;
        alert_resolve(&engine[slot], now, "evicted");
        /* The finding did not end; the engine ran out of room. A
         * re-fire of this key restores its first_seen (side table). */
        alert_side_t *sd = side_find(engine[slot].key, engine_hash[slot]);
        if (sd) sd->evicted = 1;
    }
    /* Counted whichever class was picked: a resolved incident dropped
     * early is still an observation the consumer will not see again
     * (#91 slice 3). */
    sh_evict_note(SH_EVICT_ALERT);
    return slot;
}

/* Either bumps an existing alert under `key`, or appends a fresh one.
 * `detail` may be regenerated each tick — we always overwrite it so the
 * latest observation wins. `match_ip`/`match_port` are set only on new
 * alerts (so the criteria represent the first time we saw this key). */
/* `ap_class` / `wired` are the #89 slice 3 pair axes — twin_class_t and
 * wired_attach_t, passed as ints so this signature does not pull the
 * enums in ahead of their headers. Zero on every rule that is not about
 * an AP pair. They are stamped inside fire_inv rather than by the
 * caller afterwards because the lifecycle events (`alert.create`,
 * `alert.escalate`) are emitted from in here — a post-hoc stamp would
 * send the first event with the fields still zero.
 *
 * `tool_row` is the signature that shaped the finding (#90), or NULL.
 * Stamped in here for the same reason: `alert.create` must already
 * carry `validated`, or the first record a socket consumer sees for an
 * UNVERIFIED attribution is the one that omits it. */
static void stamp_signature(alert_t *a, const sloth_tool_sig_t *tool_row) {
    a->sig_id[0] = a->sig_version[0] = a->sig_evidence[0] = '\0';
    a->sig_validated = 0;
    if (!tool_row || !tool_row->id || !tool_row->id[0]) return;
    snprintf(a->sig_id, sizeof(a->sig_id), "%s", tool_row->id);
    snprintf(a->sig_version, sizeof(a->sig_version), "%s",
             tool_row->version ? tool_row->version : "");
    snprintf(a->sig_evidence, sizeof(a->sig_evidence), "%s",
             tool_row->evidence ? tool_row->evidence : "");
    a->sig_validated = tool_row->unverified ? 0 : 1;
}

/* Evidence-ring citations (#92). Stamped in here for the same reason as
 * the two above: fire_inv() is where an incident comes into existence,
 * so a post-hoc stamp would leave the opening moment uncited.
 *
 * `alert.create` and the legacy `alert` record both now carry these IDs
 * (jsonl.c's emit_evidence()) — the detector-to-alert half built here
 * and the alert-to-export half are both wired. See the field's comment
 * in include/sloth.h for why this sentence is deliberately terse.
 *
 * Rewritten on every evaluation, not set once. The detector hands over
 * the newest IDs it holds, and those are the ones whose records are
 * still in the ring — an incident that keeps re-firing should cite
 * frames an operator can still pull back, not the first ones the ring
 * has since evicted. `ev_n` is clamped rather than trusted: the caller
 * is a detector with its own array size. */
static void stamp_evidence(alert_t *a, const uint64_t *ev_ids, int ev_n) {
    memset(a->evidence_ids, 0, sizeof(a->evidence_ids));
    a->evidence_id_count = 0;
    if (!ev_ids || ev_n <= 0) return;
    if (ev_n > ALERT_EVIDENCE_IDS) ev_n = ALERT_EVIDENCE_IDS;
    for (int i = 0; i < ev_n; i++) a->evidence_ids[i] = ev_ids[i];
    a->evidence_id_count = (uint8_t)ev_n;
}

void fire_inv(alert_type_t type, alert_sev_t sev, int confidence,
              const char *inv_hash, int ap_class, int wired,
              const sloth_tool_sig_t *tool_row,
              const uint64_t *ev_ids, int ev_n,
              const char *title, const char *detail,
              const char *key,
              const char *match_ip, uint16_t match_port,
              time_t now) {
    /* An empty key is a builder overflow (alert_key.h) that the rule
     * did not check. Every such fire would share one incident, which is
     * the merge the builder exists to prevent — drop it instead. */
    if (!key || !key[0]) return;
    uint64_t mono = sloth_mono_ms();
    uint64_t sig  = alert_detail_sig(detail);
    /* Looked up as it will be stored. Before #112 an over-long key was
     * truncated into the slot but compared in full, so it never matched
     * its own entry and opened a new incident every tick. The typed
     * builder (alert_key.h) keeps keys inside the bound; this keeps the
     * engine honest for any caller that does not. */
    char kbuf[ALERT_KEY_LEN];
    snprintf(kbuf, sizeof(kbuf), "%s", key);
    key = kbuf;
    uint64_t kh   = key_hash(key);
    int idx = find_by_key(key, kh);
    if (idx >= 0 && !engine[idx].resolved) {
        alert_t    *a    = &engine[idx];
        alert_sev_t prev = a->sev;

        a->evaluations++;
        a->count          = (int)a->evaluations;   /* compat alias */
        a->last_seen      = now;
        a->last_evaluated = now;
        a->last_eval_ms   = mono;

        /* An evaluation is an observation only when the evidence moved.
         * This is what makes a retained condition cost nothing: 100
         * polls of an unchanged row render one detail and count once. */
        if (sig != a->detail_sig || sev != prev) {
            a->observations++;
            a->last_observed = now;
        }
        a->sev        = sev;
        a->confidence = (uint8_t)confidence;
        snprintf(a->detail, sizeof(a->detail), "%s", detail);
        /* Refreshed with the detail: the inventory cannot change under
         * a running process (there is no reload path, deliberately), so
         * this only ever rewrites the same value — but an incident that
         * began before a rule started consulting the anchor should not
         * keep claiming it never did. */
        snprintf(a->inventory, sizeof(a->inventory), "%s",
                 inv_hash ? inv_hash : "");
        /* Refreshed for the same reason, and because both can legitimately
         * move inside one incident: an operator's inventory cannot change
         * under a running process, but a correlator registering mid-run
         * turns `wired` from UNKNOWN into an answer, and that is exactly
         * the transition the hook exists to deliver. */
        a->ap_class     = (uint8_t)ap_class;
        a->wired_attach = (uint8_t)wired;
        /* Refreshed, not sticky: the match can appear or vanish inside
         * one incident (an AP that later negotiates HT stops matching
         * the Marauder row), and a stale id would attribute the current
         * evidence to a signature it no longer satisfies. The tool
         * note in `detail` moves with it, so the change is emitted. */
        stamp_signature(a, tool_row);
        stamp_evidence(a, ev_ids, ev_n);

        if (sev != prev) {
            /* Severity is what a consumer pages on — never throttled,
             * in either direction. */
            a->detail_sig    = sig;
            a->last_event_ms = mono;
            a->event_seq++;
            jsonl_emit_alert_event(a,
                                   sev > prev ? "alert.escalate"
                                              : "alert.update",
                                   now, (int)prev, NULL);
            if (sev > prev) event_wake_signal();
        } else if (sig != a->detail_sig &&
                   alert_age_ms(mono, a->last_event_ms) >= ALERT_UPDATE_MIN_MS) {
            /* Evidence moved and the floor has passed. The event carries
             * the *current* detail, so the renderings the floor
             * suppressed are summarised, not lost. `detail_sig` is left
             * alone while throttled, so the next change past the floor
             * still fires. */
            a->detail_sig    = sig;
            a->last_event_ms = mono;
            a->event_seq++;
            jsonl_emit_alert_event(a, "alert.update", now, -1, NULL);
        }
        return;
    }

    int slot;
    if (idx >= 0) {
        /* Resolved entry under this key: the slot is reused, the
         * identity is not — this is a new incident. */
        slot = idx;
    } else if (engine_count < MAX_ALERTS) {
        slot = engine_count++;
    } else {
        slot = evict_oldest(now);
    }
    alert_t *a = &engine[slot];
    memset(a, 0, sizeof(*a));
    a->type       = type;
    a->sev        = sev;
    a->confidence = (uint8_t)confidence;
    a->count      = 1;
    a->first_seen = now;
    a->last_seen  = now;
    a->evaluations    = 1;
    a->observations   = 1;
    a->first_detected = now;
    a->last_evaluated = now;
    a->first_observed = now;
    a->last_observed  = now;
    a->last_eval_ms   = mono;
    a->last_event_ms  = mono;
    a->detail_sig     = sig;
    snprintf(a->title,  sizeof(a->title),  "%s", title);
    snprintf(a->detail, sizeof(a->detail), "%s", detail);
    snprintf(a->key,    sizeof(a->key),    "%s", key);
    engine_hash[slot] = kh;
    if (inv_hash && inv_hash[0])
        snprintf(a->inventory, sizeof(a->inventory), "%s", inv_hash);
    a->ap_class     = (uint8_t)ap_class;
    a->wired_attach = (uint8_t)wired;
    stamp_signature(a, tool_row);
    stamp_evidence(a, ev_ids, ev_n);
    if (match_ip && match_ip[0])
        snprintf(a->match_ip, sizeof(a->match_ip), "%s", match_ip);
    a->match_port = match_port;
    snprintf(a->technique, sizeof(a->technique), "%s", alert_technique(type));
    incident_id_make(a, now);
    a->event_seq = 1;
    /* Hand back what belongs to the key, before alert.create goes out
     * so the opening record already carries it. */
    alert_side_t *sd = side_get(a->key, kh);
    if (sd) {
        if (sd->last_incident_id[0]) sd->reopen_count++;
        if (sd->evicted && sd->last_first_seen) a->first_seen = sd->last_first_seen;
        a->reopen_count        = sd->reopen_count;
        a->pcap_write_failures = sd->pcap_write_failures;
        snprintf(a->pcap_path, sizeof(a->pcap_path), "%s", sd->pcap_path);
        snprintf(sd->last_incident_id, sizeof(sd->last_incident_id), "%s",
                 a->incident_id);
        sd->last_first_seen = a->first_seen;
        sd->evicted         = 0;
    }
    /* New alert keys are interesting enough to log AND to break the
     * TUI's blocking wait so the dashboard updates immediately
     * instead of on the next tick. event_wake_signal is a no-op
     * when the wake pipe wasn't initialised (e.g. unit tests).
     *
     * Both records go out: `alert` is the legacy shape every existing
     * consumer codes against and is unchanged bar the additive
     * `incident_id`; `alert.create` opens the lifecycle stream (#98). */
    jsonl_emit_alert(a);
    jsonl_emit_alert_event(a, "alert.create", now, -1, NULL);
    event_wake_signal();
}

/* No inventory consulted, and not a finding about an AP pair. Only the
 * rules that actually read the approved inventory stamp its hash (#89
 * slice 2) and only the twin family classifies a pair (#89 slice 3); a
 * blanket stamp would claim the anchor backed findings it never
 * touched, and a blanket class would label rules that are not about an
 * AP at all. */
void fire_conf(alert_type_t type, alert_sev_t sev, int confidence,
               const char *title, const char *detail,
               const char *key,
               const char *match_ip, uint16_t match_port,
               time_t now) {
    fire_inv(type, sev, confidence, NULL,
             TWIN_CLASS_UNKNOWN, WIRED_ATTACH_UNKNOWN, NULL, NULL, 0,
             title, detail, key, match_ip, match_port, now);
}

/* A rule that cites retained frames by evidence-ring event ID (#92).
 * Calls fire_inv() directly rather than going through fire_conf(),
 * which exists to say "no inventory, no pair class" and has no business
 * growing an evidence parameter it would only ever pass through. */
void fire_ev(alert_type_t type, alert_sev_t sev,
             const uint64_t *ev_ids, int ev_n,
             const char *title, const char *detail,
             const char *key,
             const char *match_ip, uint16_t match_port,
             time_t now) {
    fire_inv(type, sev, 0, NULL,
             TWIN_CLASS_UNKNOWN, WIRED_ATTACH_UNKNOWN, NULL, ev_ids, ev_n,
             title, detail, key, match_ip, match_port, now);
}

/* Confidence 0 — "the rule did not qualify this finding". Most rules
 * assert a condition they observed directly (a flood counted, a
 * cleartext credential seen) and have nothing to be unsure about, so
 * they keep this signature. Rules whose finding is an *inference* from
 * circumstantial RF — the evil-twin family (#89) — call fire_conf and
 * report how sure they are separately from how bad it would be. */
void fire(alert_type_t type, alert_sev_t sev,
          const char *title, const char *detail,
          const char *key,
          const char *match_ip, uint16_t match_port,
          time_t now) {
    fire_conf(type, sev, 0, title, detail, key, match_ip, match_port, now);
}

void alerts_fire_for_test(alert_type_t type, alert_sev_t sev,
                          const char *key, const char *detail,
                          const char *match_ip, uint16_t match_port) {
    fire(type, sev, "TEST", detail ? detail : "", key ? key : "",
         match_ip, match_port, sloth_wall());
}

void alerts_fire_ev_for_test(alert_type_t type, alert_sev_t sev,
                             const char *key, const char *detail,
                             const char *match_ip, uint16_t match_port,
                             const uint64_t *ev_ids, int ev_n) {
    fire_ev(type, sev, ev_ids, ev_n, "TEST", detail ? detail : "",
            key ? key : "", match_ip, match_port, sloth_wall());
}

/* ── Per-type tables ────────────────────────────────────────
 * Both generated from include/sloth_alerts.def (#117), which also
 * carries the technique-mapping policy and the reasoning behind every
 * deliberately empty technique. They replace two hand-kept switches
 * that had to be edited beside the enum and were held total only by
 * -Wswitch under CI's -Werror.
 *
 * Designated initialisers, so a row lands at its own enum value
 * whatever order the expansion runs in; the size assertions catch a
 * table that grew a stray entry past ALERT_TYPE_COUNT. */
static const char *const alert_names[] = {
#define X(id, technique) [ALERT_TYPE_##id] = "ALERT_TYPE_" #id,
#include "sloth_alerts.def"
#undef X
};
SLOTH_STATIC_ASSERT(sizeof(alert_names) / sizeof(*alert_names) ==
                    ALERT_TYPE_COUNT, alert_names_cover_every_type);

static const char *const alert_techniques[] = {
#define X(id, technique) [ALERT_TYPE_##id] = technique,
#include "sloth_alerts.def"
#undef X
};
SLOTH_STATIC_ASSERT(sizeof(alert_techniques) / sizeof(*alert_techniques) ==
                    ALERT_TYPE_COUNT, alert_techniques_cover_every_type);

const char *alert_technique(alert_type_t type) {
    if ((int)type < 0 || type >= ALERT_TYPE_COUNT) return "";
    return alert_techniques[type];
}

const char *alert_type_name(alert_type_t type) {
    if ((int)type < 0 || type >= ALERT_TYPE_COUNT) return "";
    return alert_names[type];
}

/* ── Snapshot ────────────────────────────────────────────── */

/* Copy engine into s->alerts newest-first. */
static void snapshot(sloth_state_t *s) {
    /* selection sort by last_seen desc — engine_count <= MAX_ALERTS=128
       so O(n^2) is fine. */
    int order[MAX_ALERTS];
    for (int i = 0; i < engine_count; i++) order[i] = i;

    for (int i = 0; i < engine_count - 1; i++) {
        int max = i;
        for (int j = i + 1; j < engine_count; j++) {
            if (engine[order[j]].last_seen > engine[order[max]].last_seen)
                max = j;
        }
        int tmp = order[i]; order[i] = order[max]; order[max] = tmp;
    }

    for (int i = 0; i < engine_count; i++) {
        s->alerts[i] = engine[order[i]];
    }
    s->alert_count = engine_count;

    if (s->alert_sel >= s->alert_count)
        s->alert_sel = s->alert_count > 0 ? s->alert_count - 1 : 0;
    if (s->alert_sel < 0) s->alert_sel = 0;
}

/* Export an incident's cited evidence-ring frames (#92 slice 1).
 *
 * Same contract as alert_pcap_dump(): frames written (> 0), 0 when
 * nothing is left to write (every cited frame aged out of the ring, so
 * no file and nothing to retry), -1 on a failure worth retrying — plus
 * EVX_REFUSED, a failure that retrying cannot clear. The name is
 * evidence_export_alert_name()'s, suffixed "-N" if an earlier process
 * already used it (evidence_export_pcap_unique() says how that
 * happens), and the path recorded is under --eapol-dir — or the bare
 * name when that does not fit, never a truncated path. */
static int dump_alert_evidence(const alert_t *a, char *path, size_t pathsz) {
    char name[128], err[SFILE_ERR_MAX];
    path[0] = '\0';
    /* "DEAUTH_FLOOD", not "ALERT_TYPE_DEAUTH_FLOOD": the kind as JSONL's
     * `title` and the docs name it, without the C enum's prefix. */
    const char *rule = alert_type_name(a->type);
    if (!rule) rule = "UNKNOWN";
    static const char pfx[] = "ALERT_TYPE_";
    if (strncmp(rule, pfx, sizeof(pfx) - 1) == 0) rule += sizeof(pfx) - 1;
    if (evidence_export_alert_name(a->incident_id, a->evidence_ids[0],
                                   rule,
                                   name, sizeof(name)) != 0)
        return -1;
    int n = a->evidence_id_count;
    if (n > ALERT_EVIDENCE_IDS) n = ALERT_EVIDENCE_IDS;
    char used[sizeof(name) + 8];
    int written = evidence_export_pcap_unique(name, a->evidence_ids, n,
                                              NULL, a->incident_id, rule,
                                              used, sizeof(used),
                                              err, sizeof(err));
    if (written > 0 && evidence_export_path(used, path, pathsz) != 0)
        snprintf(path, pathsz, "%s", used);
    return written;
}

/* For any engine entry that has frames to export and hasn't yet had
 * them dumped, write a per-alert pcap. Two sources, one policy:
 *
 *   - an alert citing evidence-ring IDs (evidence_id_count > 0) writes
 *     those raw 802.11 frames through evidence_export_pcap(), gated as
 *     the 2026-10-08 owner ruling on #92 says: --collect-handshakes AND
 *     --eapol-dir, because a raw frame carries EAPOL/PMKID material.
 *     Not --pcap-dir: an operator who set that months ago for IP alerts
 *     would otherwise start collecting crackable bytes on upgrade.
 *   - otherwise an alert with a match_ip walks s->packets[] through
 *     alert_pcap_dump(), gated on --pcap-dir.
 *
 * An alert with both whose evidence gate is closed falls back to the IP
 * path; one with both and the gate open writes the evidence, which is
 * the stronger record — and if every cited frame has aged out of the
 * ring (the evidence export returns 0), it still falls back to the IP
 * path, because --pcap-dir may hold packets the ring no longer does.
 * No detector sets both today; the fallback is so the first one that
 * does is not silently left with nothing. Before this, a DEAUTH_FLOOD
 * CRIT had evidence IDs and no match_ip, so it was skipped here and
 * wrote zero frames even with every flag set.
 *
 * A failed write (-1) does NOT set pcap_dumped (#92): the export
 * keeps retrying on the next tick, the same "a full disk may drain"
 * philosophy jsonl.c's emit_line() already applies, rather than
 * permanently losing this incident's evidence to one transient error.
 * EVX_REFUSED is the exception: every candidate name is already taken,
 * which no later tick changes, so it is counted once and the incident
 * is done. Retrying it was a per-tick write, fsync, unlink and failure
 * count for the incident's whole life (#92 review).
 * Zero frames (0, no failure) IS terminal — the ring already doesn't
 * hold anything for this alert and never will retroactively. */
/* ── Per-alert pcap export policy (#96) ───────────────────
 *
 * `pcap_dumped` on the alert says "export has nothing left to do for
 * THIS incident". Whether the finding's frames are already on disk is a
 * question about the KEY, because one finding can be several incidents:
 * the engine holds MAX_ALERTS entries, a segment with more concurrent
 * findings than that churns, and every evict-then-refire opens a fresh
 * incident whose pcap_dumped is 0. Measured on a live sensor before the
 * cooldown existed: 16,131,622 files holding roughly 191 distinct
 * (destination, port) pairs.
 *
 * So the cooldown reads the key's side row (g_side, #112), which
 * outlives the slot.
 *
 * Check and record are SEPARATE, and that split is the whole subtlety.
 * A first attempt stamped the key on the attempt. That silently broke
 * #92's retry: a write that fails on a full disk leaves pcap_dumped at
 * 0 so the next tick tries again, but a cooldown started by the failed
 * attempt blocked that retry for an hour and the evidence was lost —
 * precisely what the retry exists to prevent. The existing test
 * test_dump_retries_after_transient_failure caught it.
 *
 * So the cooldown records only a SUCCESSFUL export. "Do not write this
 * finding's frames twice" is a statement about files that exist, not
 * about attempts that were made. */
static int pcap_cooldown_active(const alert_side_t *sd, time_t now, int secs) {
    if (secs <= 0 || !sd) return 0;
    return sd->last_pcap_export > 0 && now >= sd->last_pcap_export &&
           now - sd->last_pcap_export < secs;
}

static void dump_new_alert_pcaps(const sloth_state_t *s, time_t now) {
    const int ip_on = alert_pcap_enabled();
    const int ev_on = evidence_export_enabled();
    if (!ip_on && !ev_on) return;
    const int min_sev = (int)tune_val(TUNE_PCAP_MIN_SEVERITY);
    const int cool    = (int)tune_val(TUNE_PCAP_KEY_COOLDOWN_SECS);
    for (int i = 0; i < engine_count; i++) {
        alert_t *a = &engine[i];
        if (a->pcap_dumped) continue;
        const int ev = ev_on && a->evidence_id_count > 0;
        if (!ev && !(ip_on && a->match_ip[0])) continue;
        /* Severity first: it is the cheapest test and the one that
         * makes this feature match what `--help` has always claimed. */
        if ((int)a->sev < min_sev) continue;
        alert_side_t *sd = side_find(a->key, engine_hash[i]);
        if (pcap_cooldown_active(sd, now, cool)) {
            /* Done for this entry. Not a failure, so it must not touch
             * pcap_write_failures or the !persist badge — nothing
             * failed, the evidence is simply already on disk. */
            a->pcap_dumped = 1;
            continue;
        }
        int written = ev
            ? dump_alert_evidence(a, a->pcap_path, sizeof(a->pcap_path))
            : alert_pcap_dump(s, a, a->pcap_path, sizeof(a->pcap_path));
        if (ev && written == 0 && ip_on && a->match_ip[0])
            written = alert_pcap_dump(s, a, a->pcap_path, sizeof(a->pcap_path));
        if (written < 0) {
            a->pcap_write_failures++;
            a->pcap_path[0] = '\0';
            sd = side_get(a->key, engine_hash[i]);
            if (sd) sd->pcap_write_failures = a->pcap_write_failures;
            if (written == EVX_REFUSED) a->pcap_dumped = 1;
            continue;
        }
        a->pcap_dumped = 1;
        /* Only a real file starts the cooldown. written == 0 means the
         * ring held nothing for this alert and no file was created, so
         * there is nothing to avoid duplicating. */
        if (written > 0) {
            sd = side_get(a->key, engine_hash[i]);
            if (sd) {
                sd->last_pcap_export = now;
                snprintf(sd->pcap_path, sizeof(sd->pcap_path), "%s", a->pcap_path);
            }
        }
    }
}

/* Close every incident no rule has re-asserted for the quiet period.
 *
 * The test is `last_evaluated`, not `last_observed`: rules re-derive
 * their conditions from retained state every poll, so a key that stops
 * being *evaluated* is a key whose evidence aged out of the source ring
 * — the condition is gone. Keying on last_observed instead would
 * resolve a standing condition that is still true (NO_MONITOR_MODE
 * renders the same detail forever) and then immediately re-create it,
 * which is a resolve/create pair every five minutes for nothing. */
static void expire_incidents(time_t now, uint64_t mono) {
    for (int i = 0; i < engine_count; i++) {
        alert_t *a = &engine[i];
        if (a->resolved) continue;
        if (alert_age_ms(mono, a->last_eval_ms) < ALERT_RESOLVE_AFTER_MS)
            continue;
        alert_resolve(a, now, "expired");
    }
}

void alerts_update(sloth_state_t *s) {
    if (!s) return;
    /* Evidence clock — the #88 seam, so the whole engine can be driven
     * deterministically from tests without sleeping. */
    time_t now = sloth_wall();
    /* Derive posture before any rule reads it (#62). */
    wifi_downgrade_update(s);
    /* Every rule, in src/alerts/rules_table.c's order. That order is
     * load-bearing (JSONL order within a tick, the twin taint, the
     * posture above) and the table says why (#118). */
    for (int i = 0; i < g_alert_rule_count; i++)
        g_alert_rules[i].fn(s, now);
    expire_incidents(now, sloth_mono_ms());
    dump_new_alert_pcaps(s, now);
    snapshot(s);
}

void alerts_clear(void) {
    /* The operator dropping their view is still the end of every open
     * incident as far as the stream is concerned — leaving them open
     * would strand a consumer waiting for a resolve that can never
     * come (#98). */
    time_t now = sloth_wall();
    for (int i = 0; i < engine_count; i++)
        alert_resolve(&engine[i], now, "cleared");
    engine_count = 0;
    memset(engine, 0, sizeof(engine));
    memset(engine_hash, 0, sizeof(engine_hash));
    g_key_hash_mask = ~(uint64_t)0;
    /* The side table is engine state too (#96, #112): a test that
     * clears the engine and re-fires the same key expects a fresh
     * export and reopen_count 0, and a long-lived process that clears
     * is starting over. Leaving it populated would make alerts_clear()
     * non-deterministic from a caller's point of view. */
    memset(g_side, 0, sizeof(g_side));
    g_side_n     = 0;
    g_side_clock = 0;
    /* Reset per-rule history too so tests (and the user pressing 'c')
     * get a fully clean slate. */
    rules_wired_forget();
    evil_twin_taint_clear();
}
