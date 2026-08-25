#ifndef MLE_H
#define MLE_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* Multi-Link Element decode — issue #67, IEEE 802.11be §9.4.2.312.
 *
 * The MLE has been read only to flip the Wi-Fi 7 PHY-tier bit. Its real
 * value is the **MLD MAC address**: the stable identity a Multi-Link
 * Device presents, underneath the several per-link addresses its radios
 * use simultaneously.
 *
 * That matters because MLO breaks sequence-number correlation
 * structurally. seqnum_track links a radio's randomised addresses by
 * their shared monotonic counter; an MLD's radios are simultaneously
 * live with independent sequence spaces, so one handset reads as two or
 * three devices. This is not a missing feature — it is a live
 * mis-count in something already shipped.
 *
 * ── Layout ──
 *
 *   ExtID(1) = 107
 *   Multi-Link Control(2)  — bits 0-2 Type, bits 4-15 Presence Bitmap
 *   Common Info Length(1)  — covers itself and everything after it
 *   MLD MAC Address(6)     — present for the Basic variant
 *   ... optional Common Info fields, per the Presence Bitmap
 *   Link Info: zero or more Per-STA Profile subelements (ID 0)
 *
 * The Common Info Length field is what makes this parseable without
 * decoding every optional field: skip to Common Info start + that
 * length and the Link Info begins there. Computing the offset by
 * summing the present optionals instead means a new optional field in a
 * later amendment silently shifts every link address. */

#define MLE_EXT_ID          107
#define MLE_TYPE_BASIC        0
#define MLE_SUBELEM_PER_STA   0

/* Parse a Multi-Link Element body (starting at the ext ID byte) into
 * *out. Returns 1 on a Basic-variant MLE carrying an MLD MAC address,
 * 0 otherwise. `out` is zeroed on entry.
 *
 * Only the Basic variant (type 0) is decoded. Probe Request, Reconfig
 * and Priority Access MLEs share the container and mean different
 * things; reading one as a Basic MLE would take an MLD address from a
 * field that is not one. */
int mle_parse(const uint8_t *ie_body, int len, sloth_mld_t *out);

/* Record a parsed MLD. Merges by MLD MAC: a device seen advertising
 * different subsets of its links across frames accumulates them rather
 * than replacing. Thread-safe. */
void mle_observe(const sloth_mld_t *m, time_t now);

/* Resolve a per-link address to its MLD identity. Returns 1 and writes
 * the MLD MAC when `mac` is a known affiliated link address. */
int  mle_canonical(const uint8_t mac[6], uint8_t out[6]);

void mle_snapshot(sloth_state_t *s);
int  mle_count(void);
void mle_clear(void);

#endif /* MLE_H */
