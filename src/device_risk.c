/* Passive device risk scoring — roadmap #16 phase 4.
 *
 * Reads a device_t plus the current sloth_state_t and returns:
 *   - a bucket (LOW / MED / HIGH / CRIT)
 *   - a bitmask of the signals that contributed
 *
 * Every signal is independently observable from the tables sloth
 * already maintains — no new capture surface. An operator can always
 * answer "why is this device HIGH?" by inspecting the bit pattern.
 *
 * Two families (#191). The first four signals say only that the device
 * is anonymous, and they are near-collinear: a randomised MAC has no
 * OUI to resolve and almost never a hostname, and a phone walking past
 * a passive sensor probes without associating. Summed, they put 97% of
 * a field sensor's devices in HIGH, so together they are one point,
 * and anonymity alone never passes MED:
 *   RANDOM_MAC         locally-administered MAC (bit 1 of octet 0)
 *   UNKNOWN_VENDOR     a registered OUI that is not in the embedded table
 *   NO_HOSTNAME        no DHCP/mDNS/NBNS resolution
 *   PROBE_ONLY         probe frames observed, no association
 * The evidence signals are three points each:
 *   CLEARTEXT_CRED     we saw this device leak a credential
 *   ALERT_TAGGED       an active alert names this device's IP
 *
 * Bucket thresholds:
 *   0    → LOW
 *   1-2  → MED    (anonymous, no evidence)
 *   3-4  → HIGH   (one evidence signal)
 *   5+   → CRIT   (both)
 *
 * SELF is not a risk: one of the host's own interfaces, or a device on
 * the operator's roster, is not anonymous, so it carries SELF in place
 * of the first family and scores on evidence alone. */

#include <string.h>
#include "sloth.h"
#include "ownership.h"

static int mac_is_locally_administered(const uint8_t mac[6]) {
    /* Bit 1 of the first octet is the "locally administered" bit —
     * randomized MACs (Apple/Android privacy MACs, monlib) always set
     * it. Broadcast/multicast MACs also have unusual first octets;
     * we already filter those upstream. */
    return (mac[0] & 0x02) != 0;
}

static int device_has_cleartext_cred(const device_t *d,
                                     const sloth_state_t *s)
{
    if (!d->ip[0]) return 0;
    for (int i = 0; i < s->cleartext_cred_count; i++)
        if (strcmp(s->cleartext_creds[i].src, d->ip) == 0) return 1;
    return 0;
}

static int device_has_active_alert(const device_t *d,
                                   const sloth_state_t *s)
{
    if (!d->ip[0]) return 0;
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].match_ip[0]
            && strcmp(s->alerts[i].match_ip, d->ip) == 0) return 1;
    return 0;
}

const char *device_risk_label(device_risk_level_t l) {
    switch (l) {
    case DEV_RISK_LOW:  return "LOW";
    case DEV_RISK_MED:  return "MED";
    case DEV_RISK_HIGH: return "HIGH";
    case DEV_RISK_CRIT: return "CRIT";
    }
    return "?";
}

device_risk_level_t device_risk_score(const device_t *d,
                                      const sloth_state_t *s,
                                      int *signals_out)
{
    if (!d || !s) {
        if (signals_out) *signals_out = 0;
        return DEV_RISK_LOW;
    }

    int signals = 0;

    /* The sensor's own adapter was HIGH in the field report: its
     * background scans are heard while its association sits on another
     * channel, which is PROBE_ONLY, on a card with no hostname. A
     * device the host or the operator can name is not anonymous, so
     * none of that family is recorded for it. The evidence signals
     * still are: a rostered laptop leaking a password is the finding. */
    if (ownership_is_own_device(d->mac)) {
        signals |= DEV_RISK_SELF;
    } else if (mac_is_locally_administered(d->mac)) {
        signals |= DEV_RISK_RANDOM_MAC;
    } else if (!d->vendor[0]) {
        /* A randomised address has no OUI to be unknown. */
        signals |= DEV_RISK_UNKNOWN_VENDOR;
    }
    if (!(signals & DEV_RISK_SELF) && !d->hostname[0])
        signals |= DEV_RISK_NO_HOSTNAME;
    /* Probe-only: we saw probe frames but never a beacon or STA row.
     * DEV_SRC_STA covers the "seen associated" case; DEV_SRC_BEACON
     * covers "seen advertising an AP" (also disqualifies as a client).
     * Passive-only observers (no assoc, no advert) is the signal. */
    if (!(signals & DEV_RISK_SELF)
        && (d->sources & DEV_SRC_PROBE)
        && !(d->sources & DEV_SRC_STA)
        && !(d->sources & DEV_SRC_BEACON))
        signals |= DEV_RISK_PROBE_ONLY;
    if (device_has_cleartext_cred(d, s))
        signals |= DEV_RISK_CLEARTEXT_CRED;
    if (device_has_active_alert(d, s))
        signals |= DEV_RISK_ALERT_TAGGED;

    int score = (signals & DEV_RISK_ANON_MASK) ? 1 : 0;
    if (signals & DEV_RISK_CLEARTEXT_CRED) score += 3;
    if (signals & DEV_RISK_ALERT_TAGGED)   score += 3;

    device_risk_level_t level;
    if      (score >= 5) level = DEV_RISK_CRIT;
    else if (score >= 3) level = DEV_RISK_HIGH;
    else if (score >= 1) level = DEV_RISK_MED;
    else                 level = DEV_RISK_LOW;

    if (signals_out) *signals_out = signals;
    return level;
}
