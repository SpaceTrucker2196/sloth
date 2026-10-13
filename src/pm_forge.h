#ifndef PM_FORGE_H
#define PM_FORGE_H

#include <stdint.h>
#include <time.h>

/* ── PM-bit forgery (#107 shape A, Framing Frames CVE-2022-47522) ──
 *
 * Vanhoef & Bhupathiraju show that an AP decides whether to *buffer*
 * a station's frames purely from the Power Management bit the station
 * itself sets in the clear MAC header — ToDS/FromDS/PwrMgt are never
 * encrypted, even on a protected BSS (IEEE 802.11-2020 §9.2.4.1.7).
 * An attacker who spoofs a victim's address can therefore tell the AP
 * "I am going to sleep" with a forged PM=1 Null/QoS-Null, and the AP
 * starts queuing the real victim's downlink traffic — while the real
 * victim keeps transmitting PM=0 uplink data, because it never agreed
 * to sleep. Two frames claiming one source address, in two
 * incompatible power states, within one radio's reach, is not
 * something one honest half-duplex station can produce.
 *
 * Sloth cannot tell attacker from victim from the air alone — it has
 * no key and no location fix — so this reports the *contradiction*,
 * not an identity. Severity escalates only on corroborating evidence
 * sloth does have (operator ownership of the BSSID), per MISSION §2.3
 * and the wording discipline #90 established: "pattern consistent
 * with", never "attacker is".
 *
 * Bounded and LRU-evicted like every synthesis table (SH_EVICT_PM_FORGE).
 * Keyed by station MAC alone, not (BSSID, STA): PwrMgt is a per-station
 * declaration to whichever AP it is associated with, and the forgery is
 * visible in the clear MAC header regardless of which AP eventually
 * acts on it. */

#define MAX_PM_FORGE_ENTRIES 128

typedef struct {
    uint8_t  sta[6];
    uint8_t  bssid[6];          /* most recently seen BSSID for this STA */
    /* Microsecond-resolution, combined (sec*1000000 + usec) from the
     * frame's own capture timestamp — never time(NULL), same
     * discipline #92 established. Beacon intervals are commonly
     * ~100 ms; a window built from whole-second timestamps would
     * round every real interval down to "the same second", which
     * silently narrows the check to something stricter than what the
     * comment at the call site claims. int64_t, not time_t, so the
     * sub-second term survives. */
    int64_t  last_pm1_null_us;  /* most recent PM=1 Null/QoS-Null, 0 = none */
    int      last_pm1_null_tid; /* TID carried by that frame (0 for plain Null) */
    int64_t  last_pm0_data_us;  /* most recent PM=0 data frame, 0 = none */
    int      last_pm0_data_tid;
    uint32_t contradiction_count; /* lifetime: PM=0 data seen after a PM=1
                                    * Null, within the AP's own beacon
                                    * interval, on a different TID */
    time_t   last_contradiction_ts;
    time_t   first_seen;
    time_t   last_seen;
    uint8_t  in_use;
} pm_forge_t;

/* Feed one 802.11 data-type frame (type == 2), starting at the Frame
 * Control field, as heard on the monitor radio, stamped from the
 * frame's own capture timestamp. Only station-to-AP frames (ToDS set,
 * FromDS clear) carry a meaningful PwrMgt declaration from the
 * station being tracked; every other direction is ignored. Capture
 * thread. */
void pm_forge_observe(const uint8_t *dot11, int len,
                      time_t now_sec, long now_usec);

/* Copy the entry for `sta` into *out under the lock. Returns 1 when found. */
int  pm_forge_lookup(const uint8_t sta[6], pm_forge_t *out);

/* Entries currently tracked. */
int  pm_forge_count(void);

/* Copy every live entry into out[0..max-1]; returns how many were
 * written. One lock acquisition for the whole table. */
int  pm_forge_snapshot(pm_forge_t *out, int max);

/* Drop everything. Tests. */
void pm_forge_clear(void);

#endif /* PM_FORGE_H */
