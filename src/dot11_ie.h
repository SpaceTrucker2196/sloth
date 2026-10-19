/* 802.11 element helpers, written once (#127).
 *
 * Before this module the SSID was copied out of an element list inline
 * in three places, the PHY tier was classified twice, and the vendor-IE
 * OUI table existed in two forms. The two PHY classifiers had already
 * drifted: probe_pnl.c read Element ID Extension 81 as Multi-Link and
 * ignored 106 and 107, while mle.h (and IEEE 802.11be) put Multi-Link
 * at 107 — so a Wi-Fi 7 client probing with only a Multi-Link element
 * was labelled by one path and missed by the other.
 *
 * Every walk here is on the shared iterator (src/bytes.h) and follows
 * its single policy: an element that does not fit ends the walk, and
 * the walk is tallied once in SH_PF_IE_OVERRUN. A helper that stops at
 * a match (find, ssid) only sees — and so only counts — a fault ahead
 * of the match, the same as the hand walks it replaces.
 *
 * Callers that already walk the list for other reasons (beacon_parse_ies)
 * use the per-element forms, dot11_ie_ssid_copy() and dot11_ie_phy_note(),
 * so a frame is still walked once there. */

#ifndef SLOTH_DOT11_IE_H
#define SLOTH_DOT11_IE_H

#include <stdint.h>

/* First element with Element ID `tag`. `body` and `blen` are its body (after
 * the 2-octet header). Returns 1 when found, 0 otherwise. */
int dot11_ie_find(const uint8_t *ies, int len, uint8_t tag,
                  const uint8_t **body, int *blen);

/* First Element ID 255 whose Element ID Extension is `ext_id`
 * (IEEE 802.11-2020 §9.4.2.1). `body` and `blen` exclude the extension octet,
 * i.e. they are the element's own content. */
int dot11_ie_find_ext(const uint8_t *ies, int len, uint8_t ext_id,
                      const uint8_t **body, int *blen);

/* SSID element body → C string (§9.4.2.2: 0..32 octets). Copies
 * min(blen, 32) octets through netstr_copy() (#138): C0 and DEL become
 * '?', a NUL ends the string (a hidden SSID reads as ""), octets above
 * 0x7f are kept as they are. Returns 1 when the element claimed more
 * than 32 octets — invalid, and a fuzz signal. */
int dot11_ie_ssid_copy(const uint8_t *body, int blen, char out[33]);

/* The first SSID element of a list. `out` is "" when there is none.
 * Returns 1 when an SSID element was found. `oversize` may be NULL. */
int dot11_ie_ssid(const uint8_t *ies, int len, char out[33], int *oversize);

/* Which PHY generations the capability elements advertise. */
typedef struct { int ht, vht, he, eht; } dot11_phy_t;

/* Fold one element into `p`:
 *   45            HT Capabilities          (802.11n)
 *   191           VHT Capabilities         (802.11ac)
 *   255 ext 35    HE Capabilities          (802.11ax)
 *   255 ext 106   EHT Operation            (802.11be)
 *   255 ext 107   Multi-Link               (802.11be; MLE_EXT_ID)
 *   255 ext 108   EHT Capabilities         (802.11be)
 * Any one of the three 802.11be elements is enough: the capability
 * element is the usual one, but a Multi-Link element is only emitted by
 * an EHT implementation. */
void dot11_ie_phy_note(dot11_phy_t *p, uint8_t tag,
                       const uint8_t *body, int blen);

/* Walk a whole list into `out` (zeroed first). */
void dot11_ie_phy(const uint8_t *ies, int len, dot11_phy_t *out);

/* Highest tier: "Wi-Fi 7", "Wi-Fi 6", "Wi-Fi 5", "Wi-Fi 4" or "legacy".
 * NULL reads as "legacy". Static string. */
const char *dot11_phy_tier(const dot11_phy_t *p);

/* Vendor name for the OUI of a Vendor Specific element (tag 221), or
 * NULL when the OUI is not in the table. Static string. Includes
 * Microsoft (00:50:F2), which nearly every AP emits for WMM and WPS, so
 * a caller naming an AP's vendor must skip it itself. */
const char *dot11_oui_vendor(const uint8_t oui[3]);

#endif /* SLOTH_DOT11_IE_H */
