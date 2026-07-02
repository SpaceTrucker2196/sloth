/* Passive device risk scoring — roadmap #16 phase 4.
 *
 * Reads a device_t plus the current sloth_state_t and returns:
 *   - a bucket (LOW / MED / HIGH / CRIT)
 *   - a bitmask of the signals that contributed
 *
 * Every signal is independently observable from the tables sloth
 * already maintains — no new capture surface. The score is a
 * transparent weighted sum so an operator can always answer "why
 * is this device HIGH?" by inspecting the bit pattern.
 *
 * Weights (points, summed → bucket):
 *   RANDOM_MAC     1   locally-administered MAC (bit 1 of octet 0)
 *   UNKNOWN_VENDOR 1   OUI not in the embedded table
 *   NO_HOSTNAME    1   no DHCP/mDNS/NBNS resolution
 *   PROBE_ONLY     1   probe frames observed, no association
 *   CLEARTEXT_CRED 3   we saw this device leak a credential
 *   ALERT_TAGGED   3   an active alert names this device's IP
 *
 * Bucket thresholds:
 *   0    → LOW
 *   1-2  → MED
 *   3-4  → HIGH
 *   5+   → CRIT */

#include <string.h>
#include "sloth.h"

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
    int score   = 0;

    if (mac_is_locally_administered(d->mac)) {
        signals |= DEV_RISK_RANDOM_MAC;    score += 1;
    }
    if (!d->vendor[0]) {
        signals |= DEV_RISK_UNKNOWN_VENDOR; score += 1;
    }
    if (!d->hostname[0]) {
        signals |= DEV_RISK_NO_HOSTNAME;   score += 1;
    }
    /* Probe-only: we saw probe frames but never a beacon or STA row.
     * DEV_SRC_STA covers the "seen associated" case; DEV_SRC_BEACON
     * covers "seen advertising an AP" (also disqualifies as a client).
     * Passive-only observers (no assoc, no advert) is the signal. */
    if ((d->sources & DEV_SRC_PROBE)
        && !(d->sources & DEV_SRC_STA)
        && !(d->sources & DEV_SRC_BEACON)) {
        signals |= DEV_RISK_PROBE_ONLY;    score += 1;
    }
    if (device_has_cleartext_cred(d, s)) {
        signals |= DEV_RISK_CLEARTEXT_CRED; score += 3;
    }
    if (device_has_active_alert(d, s)) {
        signals |= DEV_RISK_ALERT_TAGGED;  score += 3;
    }

    device_risk_level_t level;
    if      (score >= 5) level = DEV_RISK_CRIT;
    else if (score >= 3) level = DEV_RISK_HIGH;
    else if (score >= 1) level = DEV_RISK_MED;
    else                 level = DEV_RISK_LOW;

    if (signals_out) *signals_out = signals;
    return level;
}
