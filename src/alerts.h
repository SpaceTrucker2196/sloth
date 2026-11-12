#ifndef ALERTS_H
#define ALERTS_H

#include "sloth.h"

/* Walk the current state for trigger conditions, dedupe against any
 * previously-fired alerts, and copy the resulting set into s->alerts.
 * Safe to call once per poll. */
void alerts_update(sloth_state_t *s);

/* Drop all known alerts (clears engine state, not just the snapshot). */
void alerts_clear(void);

/* Incident lifecycle hook (#175). Called by the engine, on the thread
 * that runs alerts_update() / alerts_clear(), as an incident opens and
 * each time its severity moves (`reason` NULL both times), and as it
 * closes (`reason` the alert.resolve reason: "expired", "evicted",
 * "cleared" or a rule's own; "" for none). `a` is the engine's entry,
 * valid for the call only; on a close it carries the incident's final
 * figures, which the snapshot may never show: an incident evicted
 * between two --db ticks leaves the engine inside one alerts_update().
 * One hook; NULL removes it. src/db.c is the one user (db_open() sets
 * it, db_close() clears it), so alert_incidents gets the close of every
 * incident the run had while the file was open. It must not call back
 * into the engine. */
typedef void (*alerts_incident_hook_fn)(const alert_t *a, time_t now,
                                        const char *reason);
void alerts_set_incident_hook(alerts_incident_hook_fn fn);

/* Test-only: fire one finding through the engine's real dedup path
 * (fire → fire_inv), stamped with sloth_wall(). The rules are the only
 * production callers; this exists so engine properties — key lookup,
 * slot reuse, side state (#112) — can be pinned without contriving a
 * rule's trigger for each one. The next alerts_update() snapshots it. */
void alerts_fire_for_test(alert_type_t type, alert_sev_t sev,
                          const char *key, const char *detail,
                          const char *match_ip, uint16_t match_port);
/* Test-only: the same, citing evidence-ring IDs (fire_ev). No detector
 * fires with both a match_ip and evidence IDs yet; this is how the
 * engine's handling of that combination is pinned before one does. */
void alerts_fire_ev_for_test(alert_type_t type, alert_sev_t sev,
                             const char *key, const char *detail,
                             const char *match_ip, uint16_t match_port,
                             const uint64_t *ev_ids, int ev_n);
/* Test-only: AND every key hash with `mask` (0 → every key collides),
 * to prove find_by_key() still compares the full key. alerts_clear()
 * restores ~0; call this after it. */
void alerts_test_key_hash_mask(uint64_t mask);

/* ── Tainted-BSSID tracker (evil-twin Phase 4) ─────────────────
 *
 * Maintained by rule_evil_twin_attack_chain when it correlates a
 * twin-fp pair with a DEAUTH_FLOOD targeting one half. The other
 * half (the rogue) is recorded here so downstream forensic exports
 * — currently the hashcat .22000 EAPOL writer — can mark the
 * provenance of any subsequent handshake against the tainted BSSID.
 *
 * Entries expire after EVIL_TWIN_TAINT_TTL_SECS. The tracker is
 * read-only outside src/alerts/; the API is exposed here so eapol_log.c
 * can query it without taking a dep on alert internals.
 *
 * Thread-safe: the table sits behind a leaf mutex private to src/alerts/engine.c,
 * because the query runs on the probe thread while the alert engine
 * marks from the main loop (#95). The lock is never held while calling
 * out, so these may be called with any other module lock held. */
#define EVIL_TWIN_TAINT_TTL_SECS 300
/* Table capacity; the oldest mark is evicted beyond it. */
#define EVIL_TWIN_TAINT_MAX      32

int  evil_twin_bssid_is_tainted(const uint8_t bssid[6]);
/* Test-only: drop all tainted entries. */
void evil_twin_taint_clear(void);
/* Test-only: mark a BSSID tainted with the current wall clock — gives
 * tests a way to exercise downstream code paths (eapol provenance,
 * Twins view glyphs) without driving the full chain rule. */
void evil_twin_taint_mark_for_test(const uint8_t bssid[6]);

/* ── Canonical pair key (#89) ──────────────────────────────────
 *
 * Two APs are one finding whichever of them sloth heard first, so the
 * dedup key is built from the *pair*, not from the SSID. Before #89
 * every BSSID pair under one SSID collapsed onto `twin:<ssid>` /
 * `twin-fp:<ssid>`, so a second candidate pair on the same name
 * overwrote the first one's detail instead of standing beside it.
 *
 * Shape: `<rule_id>:<bssid_lo>:<bssid_hi>:<site>:<security_profile>`,
 * BSSIDs in memcmp order so (A,B) and (B,A) produce one key. Shares
 * the engine's dedup/incident keying from #98 — there is one keying
 * scheme in this file, not two.
 *
 * `site` is the operator's label for where this sensor is. Since #89
 * slice 2 it comes from `--site` or the inventory file's `site` field —
 * inventory_site() — and from NOTHING else. It must NEVER be derived
 * from an observed SSID, a BSSID or the uplink association: a trust
 * input taken from unauthenticated over-the-air data is the whole bug
 * class #89 exists to remove, and a site that re-keyed on every roam
 * would fragment one physical impersonator into several incidents.
 * Unset is still the empty string and the key shape does not change. */
#define TWIN_SITE_UNSET ""

void alert_pair_key(char *out, size_t n, const char *rule_id,
                    const uint8_t bssid_a[6], const uint8_t bssid_b[6],
                    const char *site, const char *security_profile);

/* ── Weighted twin evidence (#89) ──────────────────────────────
 *
 * Every signal below is *context*. None of them removes a finding on
 * its own, which is precisely what an 802.11k neighbour report and a
 * matching vendor OUI used to do: a neighbour advertisement is an
 * unauthenticated frame, so an attacker could name the AP it was
 * impersonating and erase the finding outright, and a clone can copy
 * an OUI in one line of config.
 *
 * `positive` is impersonation evidence; `context` is benign
 * explanation, subtracted from confidence. The pair is a candidate
 * when `positive` is non-zero — a same-OUI pair with nothing else is
 * not *trusted*, it is evidence-free, which is how a legitimate
 * multi-BSSID deployment stays quiet without any observed value being
 * treated as proof of ownership.
 *
 * `hard` marks a signal an attacker cannot advertise away (an
 * attacker-tool OUI, a BTM steer aimed at the pair). A neighbour claim
 * may demote a severity that rests only on soft signals; it may never
 * demote one backed by a hard signal, or advertising your target
 * becomes a severity lever.
 *
 * ── The one exception: the approved inventory (#89 slice 2) ──
 *
 * `inv_mismatch` and `inv_approved` are the only inputs here that did
 * not come off the air, and they are the only ones allowed to settle a
 * pair outright. An operator wrote them in a file, out-of-band; an
 * attacker cannot beacon its way into one. So:
 *
 *   - `inv_mismatch` (a half is not approved for an SSID the file
 *     declares) is positive evidence AND `hard` — which is what makes a
 *     spoofed neighbour claim unable to erase it.
 *   - `inv_approved` (both halves approved) makes the pair a
 *     non-candidate: twin_evidence_score returns 0 whatever else is
 *     set. This is the mixed-vendor-infrastructure case, where the
 *     strongest observed signals in this file — differing OUI,
 *     contradicting vendor-IE hashes — are both simply wrong about a
 *     deployment the operator has told sloth about.
 *
 * That last one is a sole suppressor, deliberately, and it is not the
 * pre-#89 behaviour wearing a new name: what #89 removed were
 * suppressors sourced from *frames the attacker writes*. The test is
 * not "does anything suppress" but "can the adversary reach the input".
 * Here they cannot.
 *
 * `confidence` is how sure sloth is, in percent, clamped to
 * [TWIN_CONF_MIN, TWIN_CONF_MAX]. It is never 100 and it is *not* the
 * severity: severity is how bad the finding is if true, confidence is
 * how likely it is to be true. They are different numbers that move
 * independently and the operator needs both.
 *
 * ── One device is not a pair (#188) ──────────────────────────
 *
 * Every weight above assumes the two BSSIDs are two transmitters. On a
 * field sensor 33 of 38 CRIT pairs were the 2.4 GHz and 5 GHz radios of
 * one box, so four things are checked before any weight is added:
 *
 *   - `sibling`: BSSIDs at most TWIN_SIBLING_MAX_DIFF_BYTES apart, on
 *     different known bands, first heard within TWIN_SIBLING_WINDOW_S
 *     of each other. That is one device coming into earshot, and it
 *     carries no weight in either direction: twin_evidence_score
 *     returns 0. Only `inv_mismatch` survives it, for the reason the
 *     inventory outranks everything else here.
 *   - an OUI is read only from two globally administered addresses. A
 *     locally administered BSSID (bit 0x02 of the first octet) has no
 *     OUI, so neither `diff_oui` nor `same_oui` is set and no weight
 *     moves. Vehicle hotspots derive their second-band address by
 *     complementing octets 1-2, which the old three-byte memcmp scored
 *     as a second vendor.
 *   - `hashes_differ` is read only within one known band. A dual-band
 *     AP's two radios advertise band-dependent vendor IEs, so a
 *     cross-band mismatch says "two bands", not "two firmwares".
 *   - a BTM steer whose steering BSSID is a sibling address of the
 *     candidate it names is the device band-steering its own clients.
 *     It sets `self_steer` and nothing else: not `steered`, not `hard`,
 *     no weight.
 *
 * And CRIT is gated on confidence: a severity resting only on soft
 * signals needs TWIN_CRIT_MIN_CONF. With the weights below the only
 * soft combination that reaches it is a vendor-IE mismatch together
 * with a different globally administered OUI (35 + 20), which is the
 * "cross-device signal" the mismatch needs before it may be critical.
 * A `hard` signal is exempt, for the reason a neighbour claim cannot
 * demote one: a gate an attacker can advertise a finding under is a
 * severity lever.
 *
 * ── The copy arrives after the original (#188, ruling 3b) ────
 *
 * Masking the U/L bit left a rogue on a locally administered address
 * with one soft signal to its name: a same-band vendor-IE mismatch is
 * 35, under the gate, and there is no OUI to add. The issue names the
 * cross-device signal that does not need one: "spoofing an existing
 * SSID implies the twin's first_seen comes well after the original's".
 *
 * `late_arrival` is that, and it is deliberately hard to earn. It is
 * set only when all of these hold:
 *
 *   - both halves carry a first_seen, and the later one is at least
 *     `twin.late_arrival_s` (TWIN_LATE_ARRIVAL_S, 120) after the
 *     earlier. Sensor start needs no clock of its own: the beacon table
 *     is empty at start, so nothing in it is older than the process and
 *     a gap of N is also N seconds of the sensor listening;
 *   - the earlier half was heard again at or after the later one's
 *     first_seen. "Later" otherwise only means the table had not
 *     forgotten the first AP yet (BEACON_AGE_SECS is 300), which is
 *     what a sensor driven past two APs a kilometre apart sees;
 *   - the later half was first heard at least that long after the
 *     sensor was last known to be moving (a GNSS fix at
 *     TWIN_PROX_MOVING_MPS or more). Arrival order on a moving sensor
 *     is the route, not the transmitters, and it stays the route after
 *     the sensor parks, so this is remembered rather than read off the
 *     current fix. No GNSS is "not known to be moving", as in #189;
 *   - the later half's name is new on its address this session
 *     (beacon_ap_t.arrival). The table rebuilds an entry it dropped,
 *     for age or for room, under a new first_seen, so it keeps a
 *     memory of what it has dropped (src/beacon_snoop.c) and an AP
 *     that comes back as the same radio (band, enc, vendor IEs; #194)
 *     is a return, not an arrival. An entry that
 *     memory cannot vouch for, because it has overflowed, is not
 *     counted either;
 *   - the pair already has positive evidence. It corroborates and never
 *     nominates: every same-SSID pair whose halves were heard two
 *     minutes apart (a mesh node at the edge of earshot, a guest SSID
 *     switched on later) would otherwise become a row, a Twins episode
 *     and a proximity candidate, which is the noise #188 was opened on.
 *     So the flag means "counted", and is never set without its weight;
 *   - a half is locally administered (owner ruling on review). The
 *     signal exists for the pair that has no OUI to compare. Two
 *     globally administered addresses are scored on their OUIs as
 *     before and get neither the weight nor the flag: a same-vendor
 *     mesh pair or an OUI-only pair heard two minutes apart stays at
 *     20 %, inside slothweb's mute, and a two-vendor pair with a
 *     vendor-IE mismatch stays at 55 rather than 75.
 *
 * What it cannot see. "New this session" is new to this sensor: an AP
 * that was out of earshot until now and one that was switched on now
 * look the same, which is why the weight is soft and why it is 20 and
 * not more. And the memory is the table's, so a transmitter that sent
 * the name it means to copy once, at a time the gap did not count
 * (inside the wait after the original was first heard, or while the
 * sensor moved), then fell silent for BEACON_AGE_SECS, is a return when
 * it starts in earnest.
 *
 * ── Two devices that are meant to be there (#188, 2026-11-12) ─
 *
 * The sibling test answers "one device or two". Two of the issue's
 * five non-sibling CRIT pairs were two devices, and benign anyway:
 *
 *   - `carrier_ssid`: a carrier's offload or roaming SSID ("Spectrum
 *     Mobile" from two customers' Spectrum routers). Every subscriber's
 *     gateway broadcasts it by design, so a second vendor, a second
 *     firmware and a late arrival are what the next customer's router
 *     looks like, and they cannot tell it from a copy. Context, not a
 *     suppressor: TWIN_C_CARRIER_SSID comes off the confidence, which
 *     leaves every soft combination under TWIN_CRIT_MIN_CONF and inside
 *     slothweb's 20 % mute, and a hard signal still carries the row to
 *     CRIT. Exact names only (rules_twin.c), so a home network called
 *     "XFINITY-Den" is scored like any other.
 *   - `faint`: a half whose strongest reading in the window is at or
 *     under TWIN_PROX_FLOOR_DBM, or that the table has heard on fewer
 *     than `twin.crit_min_beacons` beacons (the issue's ISP pair: -100
 *     dBm, one or two frames each). Not evidence either way, so it
 *     moves no weight; it keeps a soft signal from carrying the row to
 *     CRIT. A copy sloth can barely hear is no threat to the clients
 *     around sloth, and a fingerprint read off one or two frames at
 *     the decode margin is not one sloth has been able to read twice.
 *     0 in a reading (the table's "unseen") is "cannot say" and does
 *     not count as faint, the convention first_seen follows. */
#define TWIN_W_DIFF_OUI      20   /* cross-vendor: weak, and forgeable */
#define TWIN_W_IE_HASH       35   /* vendor-IE fingerprints disagree */
#define TWIN_W_ATTACKER_OUI  40   /* Hak5 / Espressif OUI present */
#define TWIN_W_BTM_STEER     25   /* 802.11v steer aimed at the pair */
/* Worth what a second vendor's OUI is worth, because it stands in for
 * one where there is no OUI to read: 35 + 20 clears TWIN_CRIT_MIN_CONF
 * exactly as a vendor-IE mismatch plus a different OUI does. The floor
 * is pinned: under 15 a locally administered rogue stays below the
 * gate. It has no ceiling to pin since it was restricted to pairs with
 * a locally administered half, where nothing deducts but a neighbour
 * claim, and that demotes a soft CRIT whatever the sum. */
#define TWIN_W_LATE_ARRIVAL 20   /* the copy came after the original */
#define TWIN_W_WEAK_CLONE    85   /* OPEN/WEP beside strong under one SSID —
                                   * no vendor-diversity explanation exists */
#define TWIN_W_INV_MISMATCH  50   /* a half is not in the approved inventory —
                                   * operator-supplied, so not forgeable */
#define TWIN_C_NBR_CLAIM     30   /* 802.11k neighbour claim — unauthenticated */
#define TWIN_C_SAME_OUI      15   /* same vendor, or a copied OUI */
/* Enough to take the strongest soft sum a pair can reach with a
 * locally administered half or two vendors (35 + 20 = 55) to 20, the
 * mute line, and no further: the row stays, it is not CRIT. */
#define TWIN_C_CARRIER_SSID  35   /* a carrier SSID every subscriber's
                                   * gateway broadcasts (#188) */
#define TWIN_CONF_MIN         5
#define TWIN_CONF_MAX        95
/* The least confidence a soft-signal CRIT may carry (#188). 50 is the
 * issue's figure and the point below which the finding is, by sloth's
 * own number, more likely wrong than right. */
#define TWIN_CRIT_MIN_CONF   50
/* Sibling test (#188). Two bytes covers every pair in the field data:
 * adjacent addresses (one byte, including an :ef -> :f0 carry), a
 * flipped nibble, and the complemented octets 1-2 of a vehicle hotspot.
 * A carry across three octets is missed and falls to the other checks. */
#define TWIN_SIBLING_MAX_DIFF_BYTES 2
/* The field pairs first appeared 1-3 s apart on a parked sensor: the
 * gap is how long the hopper takes to reach the other band, since each
 * radio beacons every ~100 ms. 10 s is three times the worst observed,
 * and still far short of the minutes it takes anyone to notice an SSID
 * and stand up a copy of it. It cannot tell the two apart at sensor
 * start, when everything in range is first heard together; the address
 * and band conditions are what carry the test then. */
#define TWIN_SIBLING_WINDOW_S 10
/* Shipped default of `twin.late_arrival_s`, the least first-heard gap
 * that counts as "the copy came later" (#188). Three numbers bound it
 * from below. The issue's own radios appear 1-3 s apart and the sibling
 * window is 10 s. A sensor start is one pass of the hop list before
 * everything in steady earshot has been heard: the default list is 11
 * channels at 100-2000 ms each, 22 s at worst, so 120 s is five worst
 * passes and an AP missed on the first has had four more. And parking
 * is a second start, so the same figure is the wait after the sensor
 * last moved. From above it costs little: a copy is missed as "late"
 * only when it is stood up inside two minutes of the sensor first
 * hearing the original. The knob's floor is 30 s so it cannot be set
 * under one worst hop pass or into the sibling window. */
#define TWIN_LATE_ARRIVAL_DEFAULT_S 120
/* The beacon floor of a soft-signal CRIT: `twin.crit_min_beacons`
 * (#188). Below the decode margin is TWIN_PROX_FLOOR_DBM's argument;
 * the count is the other way to be barely heard. An AP in steady
 * earshot is heard on at least one beacon a pass of the hop list (a
 * dwell is 100 ms or more and APs beacon every 102.4 ms), so 5 is five
 * passes, under two minutes at the default list's worst 22 s. A copy
 * that has stood on the air that long has given far more; the issue's
 * ISP pair had given one or two. */
#define TWIN_CRIT_MIN_BEACONS_DEFAULT 5
/* Floor under which an RSSI reading is "barely heard" (#189, and since
 * 2026-11-12 the `faint` test above). The reasoning is beside its use
 * in rule_evil_twin_proximity (src/alerts/rules_twin.c). */
#define TWIN_PROX_FLOOR_DBM (-92)

typedef struct {
    int diff_oui;
    int same_oui;
    int hashes_differ;
    int late_arrival;    /* the later half was first heard well after the
                          * earlier, on a gap that can be trusted, and
                          * the pair had other positive evidence (#188) */
    int attacker_oui;
    int steered;         /* a steer aimed at the pair from another device */
    int self_steer;      /* a steer from a sibling address of its own
                          * candidate: band steering, no weight (#188) */
    int sibling;         /* one device's radios on two bands (#188) */
    int nbr_claim;       /* either side advertises the other (802.11k) */
    int carrier_ssid;    /* a carrier SSID many gateways share (#188) */
    int faint;           /* a half barely heard: no soft CRIT (#188) */
    int inv_mismatch;    /* a half is not approved for an inventoried SSID */
    int inv_approved;    /* both halves approved for an inventoried SSID */
    int inv_consulted;   /* an inventory file was loaded at all (#89 slice 3) —
                          * distinguishes "the operator declared an estate and
                          * this SSID is not in it" from "there is no estate to
                          * compare against", which are different facts and
                          * support different claims about the pair */
    int positive;        /* summed impersonation evidence */
    int context;         /* summed benign explanation */
    int hard;            /* a signal an attacker cannot advertise away */
    int confidence;      /* percent, TWIN_CONF_MIN..TWIN_CONF_MAX */
} twin_evidence_t;

/* Score a same-SSID AP pair. Returns 1 when the pair is a candidate
 * (`positive` non-zero), 0 when there is no impersonation evidence.
 * `out` is always filled when non-NULL. */
int  twin_evidence_score(const sloth_state_t *s, const beacon_ap_t *a,
                         const beacon_ap_t *b, time_t now,
                         twin_evidence_t *out);

/* Deterministic pair ordering — memcmp on the BSSID. Shared so the
 * alert key, the Twins view and the `twin_episodes` primary key all
 * order a pair the same way. */
void twin_pair_order(const beacon_ap_t *a, const beacon_ap_t *b,
                     const beacon_ap_t **lo, const beacon_ap_t **hi);

/* Which half of a pair is the impostor, and whether that is known at
 * all. Returns 1 when the assignment rests on evidence, 0 when the pair
 * is merely ordered (`*real_out` / `*twin_out` then hold it in
 * canonical BSSID order and neither half is accused).
 *
 * Ranked by what the signal actually establishes:
 *   1. An operator-designated BSSID (--my-bssid, #52) is never the
 *      impostor, and neither is one the approved inventory declares for
 *      this SSID (#89 slice 2). Both are a human asserting ownership
 *      out-of-band, so they outrank anything inferred from the air.
 *   2. A BSSID the deauth chain tainted is the impostor.
 *   3. An OUI in the Hak5 / Espressif attacker tables is the impostor.
 *   4. Otherwise unattributed.
 *
 * What is deliberately absent is rule 4's pre-#89 predecessor, "the
 * stronger signal is the impostor". RSSI is a fact about distance and
 * antennas, and in the commonest case it is backwards, because the
 * operator's own AP is the closest radio in the room.
 *
 * Lives here rather than in twins.c (#89 slice 3) so the rule and the
 * [x] Twins view read one implementation — they already share
 * twin_evidence_score, and a second copy of the attribution ladder is
 * how the alert and the view start disagreeing about which half of a
 * pair is accused. */
int  twin_choose_sides(const beacon_ap_t *a, const beacon_ap_t *b,
                       const beacon_ap_t **real_out,
                       const beacon_ap_t **twin_out);

/* ── What kind of AP is this? (#89 slice 3) ────────────────────
 *
 * The issue's last fix bullet asks the UI to distinguish an
 * over-the-air impersonator from a neighbouring AP from an unauthorized
 * AP attached to the wired network. Two of those three are decidable
 * from RF plus the approved inventory. The third is not decidable from
 * RF at all, so it is not in this enum: wired attachment is a separate
 * axis carried by wired_attach_t (src/wired_attach.h), it defaults to
 * UNKNOWN, and nothing in this file can set it. Folding "rogue on the
 * wire" in here as a fourth class would make an RF-only detector able
 * to assert the one claim RF cannot support — precisely the
 * overstatement #89 exists to remove.
 *
 * This is a *label*, never a gate. It does not suppress a pair, change
 * a severity, or move a confidence: an operator with no inventory sees
 * exactly the findings they saw before slice 3, with one more column
 * that reads `?`. Classification that could silence a finding would be
 * a new sole suppressor, which is the bug this issue opened on. */
typedef enum {
    /* No basis to place the pair. The default, and what every pair
     * reports when no inventory file is loaded — with nothing declared,
     * "not yours" is not a statement sloth can make. */
    TWIN_CLASS_UNKNOWN = 0,
    /* Over-the-air impersonator. Either the inventory declares this
     * SSID and one half is not an approved BSSID for it, or the pair
     * carries a hard RF signal (an attacker-tool OUI, a BTM steer aimed
     * at the pair). Hard RF signals are admissible *here* and not on
     * the wired axis because impersonation is an over-the-air
     * behaviour: it is the thing RF observes. */
    TWIN_CLASS_IMPERSONATOR = 1,
    /* An AP outside the declared estate. Requires a loaded inventory
     * that does not list this SSID, and no hard signal. The claim is
     * "this is somebody else's network", which is a real and useful
     * answer to the noise half of this issue — a mixed-vendor cafe
     * deployment two floors down is not an attack on anything. */
    TWIN_CLASS_NEIGHBOR = 2,
    /* Both halves declared by the operator: their own infrastructure.
     * Reachable only from the weak/strong branch, which still reports a
     * downgrade lane under a single SSID whoever owns it — the
     * inventory answers "whose radio is that", never "is that
     * configuration safe". */
    TWIN_CLASS_DECLARED = 3,
} twin_class_t;

/* Classify a scored pair. `ev` may be NULL (→ UNKNOWN). */
twin_class_t twin_classify(const twin_evidence_t *ev);

/* Column/export label: "?", "impostor", "neighbor", "declared". */
const char  *twin_class_label(twin_class_t c);

/* ── KARMA_AP confidence (#90) ──────────────────────────────
 *
 * A bare SSID count crossing KARMA_SSID_THRESH is a candidate signal,
 * not a finding: a long-lived AP that legitimately renamed itself a
 * few times over a session accumulates the same count as an active
 * PineAP lure. Severity therefore escalates to CRIT only when
 * something ties the pattern to this *specific* candidate rather than
 * coincidence — see rule_karma_ap() in src/alerts/rules_twin.c for which signals
 * qualify. `confidence` is the separate, non-gating number: how sure
 * sloth is, not how bad it would be if true. */
#define KARMA_W_SSID_THRESH   20   /* base: SSID count met the threshold */
#define KARMA_W_PNL_OVERLAP   25   /* >= KARMA_PNL_CORROB_MIN of this BSSID's
                                    * SSIDs in ONE station's PNL (#90) — the
                                    * union over all clients is reported but
                                    * neither scores nor escalates */
#define KARMA_W_DEAUTH_VICTIM 30   /* shared-victim deauth-then-lure chain */
#define KARMA_W_IE_COLLAPSE   10   /* every advertised SSID came back with one
                                    * IE fingerprint (#187 S4) — see
                                    * karma_ie_collapsed() for the scope.
                                    *
                                    * Deliberately in the low, informational
                                    * tier with PMKID rather than beside the
                                    * PNL and deauth weights, and deliberately
                                    * not a severity escalator. The contrast
                                    * usually claimed for this signal — one
                                    * spoofing radio versus multi-VAP gear
                                    * that varies RSN/vendor IEs per VAP — is
                                    * not the contrast sloth can draw: a VAP
                                    * has its own BSSID and so never reaches
                                    * this rule, and the Multiple BSSID set's
                                    * nontransmitted profiles are not decoded.
                                    * The benign case that DOES cross the
                                    * threshold is a BSS renamed over a
                                    * session, which keeps one posture and
                                    * collapses identically. So this earns a
                                    * little confidence and proves nothing on
                                    * its own. */
#define KARMA_W_IE_VARIETY    15   /* SUBTRACTED (#187, owner decision
                                    * 2026-11-12): the advertised SSIDs came
                                    * back with 2 or more distinct, all-known
                                    * IE fingerprints. A PineAP-style radio
                                    * answers every name with one IE set; an
                                    * address presenting a different security
                                    * posture per name looks like a genuine
                                    * multi-SSID AP. The converse of the
                                    * collapse and the better-founded half
                                    * (research/papers/mbssid-per-bss-ie-
                                    * variation.md), so it outweighs the
                                    * collapse's +10. Confidence only, never
                                    * severity: a corroborated lure that
                                    * varies its IEs is still corroborated. */
#define KARMA_W_TOOL_VERIFIED 30   /* a capture-backed tool signature match */
#define KARMA_W_TOOL_UNVERIF  10   /* an UNVERIFIED signature guess only */
#define KARMA_W_PMKID         10   /* PMKID observed — informational, not
                                    * an attack implication: legitimate
                                    * 802.11r/PMK-caching also produces one */
#define KARMA_CONF_MIN         5
#define KARMA_CONF_MAX        95

/* ── WPS attack thresholds (#82 wave 8) ────────────────────
 *
 * The owner settled these numbers on 2026-09-30 — the issue's own
 * proposal, each behind a knob. The knob is a `#define` default plus a
 * CLI override, following KARMA_W_* for the constant and
 * seqnum_corr_set_retain_secs() / db_set_retain_days() for the setter:
 * there is no runtime configuration struct in sloth and inventing a
 * config-file format to hold three integers would add a parser, a
 * search path and a reload question for no gain.
 *
 * Only the *counts* are tunable. The windows are not operator policy:
 * 60 s is the rate the issue defines the brute-force unit over, one
 * hour is the period the lockout sawtooth is stated in, and 120 s is
 * the PBC Walk Time the WSC protocol itself fixes (hostapd's
 * WPS_PBC_WALK_TIME) — a site that shortened it would be measuring
 * something the protocol does not do. Counts are what a noisy estate
 * needs to move; windows are what the protocol is.
 *
 * The two Pixie-Dust rules (2026-10-19 ruling) are the exception the
 * other way: they have no count, and their two windows are --tune rows
 * — see WPS_PIXIE_SILENCE_S in src/wps_track.h.
 *
 * Every threshold is a *floor*: the rule fires at or above the count,
 * so raising one only ever quiets sloth and can never invent a
 * finding. */
#define WPS_PIN_BRUTE_CYCLES     5     /* M1→M3→NACK restart cycles ... */
#define WPS_PIN_BRUTE_WINDOW_S  60     /* ... inside this many seconds  */
#define WPS_LOCKOUT_CYCLES       2     /* locked→unlocked cycles ...    */
#define WPS_LOCKOUT_WINDOW_S  3600     /* ... inside this many seconds  */
#define WPS_PBC_CONCURRENT       2     /* fires when EXCEEDED (">2") ... */
#define WPS_PBC_WALK_TIME_S    120     /* ... inside the WSC walk time  */

/* Set the tunable counts. Return 1 when the value was accepted, 0 when
 * it was rejected and the previous value stands — the caller (main.c)
 * turns a rejection into a usage error, the same shape
 * ownership_add_bssid() already uses. A threshold of zero or less is
 * rejected rather than read as "disabled": a rule that fires on every
 * observation is not an off switch, and silently meaning the opposite
 * of what was typed is worse than refusing. */
int alerts_set_wps_pin_brute_cycles(int cycles);
int alerts_set_wps_lockout_cycles(int cycles);
int alerts_set_wps_pbc_concurrent(int sessions);

/* Current values — the defaults above until a setter moved them. */
int alerts_wps_pin_brute_cycles(void);
int alerts_wps_lockout_cycles(void);
int alerts_wps_pbc_concurrent(void);

#endif /* ALERTS_H */
