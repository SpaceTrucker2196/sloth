/* Operator-designated networks — issue #52.
 *
 * sloth's inputs have until now been observations (what the radio and
 * the kernel report) and display preferences. This is a third kind:
 * **context the operator supplies about the world**, namely which
 * networks are theirs.
 *
 * It exists because the most common surveillance-detection question —
 * "is anyone probing *my* network?" — could not previously be posed.
 * The observation was always there (`pnl_client_t.ssids[]` is exactly
 * "which networks does this device remember"); what was missing was any
 * way to say *that one is mine*.
 *
 * Deliberately not part of sloth_state_t. State is a record of what was
 * observed; a designation is an assertion by the operator. Keeping them
 * apart means no view can mistake one for the other, and the rules
 * consult this the same way they consult the OUI tables.
 *
 * Nothing here changes capture behaviour and nothing is transmitted —
 * this is a labelling input only, so it stays inside MISSION §2. */

#ifndef SLOTH_OWNERSHIP_H
#define SLOTH_OWNERSHIP_H

#include <stdint.h>

/* Bounded like every other table in the tree. A surveyor designates a
 * handful of networks per engagement, not hundreds. */
#define MAX_MY_SSIDS   16
#define MAX_MY_BSSIDS  16

/* The roster is per-engagement, not per-fleet. A site with more than
 * this many devices is one where the operator wants an inventory
 * system, not a CLI flag. */
#define MAX_KNOWN_MACS 512

/* Register a designation. Returns 1 on success, 0 if the input was
 * empty/malformed or the table is full (diagnostic on stderr). Both are
 * idempotent — designating the same value twice is not an error and
 * does not consume a second slot. */
int ownership_add_ssid(const char *ssid);

/* `str` is "aa:bb:cc:dd:ee:ff" (also accepts '-' separators and upper
 * case). Rejects anything that isn't six hex octets. */
int ownership_add_bssid(const char *str);

/* Membership tests. Both are false when nothing has been designated,
 * so every caller degrades to today's behaviour automatically. SSID
 * comparison is exact and case-sensitive: 802.11 SSIDs are opaque
 * octet strings, and two SSIDs differing only in case are two
 * different networks on the air. */
int ownership_is_my_ssid(const char *ssid);
int ownership_is_my_bssid(const uint8_t bssid[6]);

/* ── known-device roster (#55) ────────────────────────────
 *
 * "Which devices are mine" sits beside "which networks are mine"
 * because they are the same kind of input: context the operator has and
 * the radio cannot infer. Without it sloth can only score a device as
 * *intrinsically odd* (randomised MAC, unknown vendor, no hostname) —
 * and with randomisation default on every handset, that fires on the
 * operator's own staff, which is precisely the population they wanted
 * filtered out.
 *
 * Reliability note worth knowing before rostering anything: per-*probe*
 * MAC randomisation rotates constantly, so a roster cannot follow a
 * device that is only probing. Per-SSID randomisation used for
 * *association* is stable — iOS and Android derive one MAC per network
 * and keep it across reconnects — so a device rostered while on the
 * network keeps that address. The roster is therefore reliable for the
 * population it targets (associated devices) and not for passing
 * probers, which #53/#54 cover instead. */

/* Register one MAC. Same format and strictness as ownership_add_bssid.
 * Idempotent. */
int ownership_add_known_mac(const char *str);

/* Load a roster file: one MAC per line, `#` comments, blank lines
 * skipped, trailing comments allowed. Returns the number added, or -1
 * if the file could not be opened. Malformed lines are reported with
 * their line number and skipped — a roster that silently rostered
 * nothing would leave the operator believing their devices were
 * recognised while every one of them alerted. */
int ownership_load_known_macs(const char *path);

int ownership_is_known_device(const uint8_t mac[6]);
int ownership_known_count(void);

/* True when the operator designated anything at all. Rules use this to
 * skip work entirely in the common unconfigured case. */
int ownership_any(void);

/* Counts, for the startup banner and tests. */
int ownership_ssid_count(void);
int ownership_bssid_count(void);

/* Drop all designations — tests only. */
void ownership_clear(void);

#endif /* SLOTH_OWNERSHIP_H */
