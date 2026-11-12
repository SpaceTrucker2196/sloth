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

/* For iface_stat_t, which the self roster (#183) reads. State still
 * does not belong here — the self roster takes the interface records as
 * an argument and keeps no pointer into sloth_state_t. */
#include "sloth.h"

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

/* The shared strictness behind every operator-supplied MAC: exactly six
 * hex octets, ':' or '-' separated, either case. Returns 1 and fills
 * `out` on success, 0 otherwise; writes nothing on failure.
 *
 * Exported so the JSON inventory (#89 slice 2) validates addresses the
 * same way the flags and the roster do rather than carrying a second
 * copy that could drift. Deliberately strict everywhere: a typo'd
 * address designates nothing, and the operator concludes their own AP
 * is not being recognised. */
int ownership_parse_mac(const char *str, uint8_t out[6]);

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

/* ── the sensor's own addresses (#183) ─────────────────────
 *
 * The operator's roster answers "which devices are mine". This answers
 * the question nobody had to ask, because the host already knows it:
 * **which addresses are this sensor's own**. Every rule that treats an
 * emitter as a third party was reading the host's own Wi-Fi card as
 * one, and on the reference host that produced 330 WARN incidents of
 * MY_NETWORK_RECON against the managed card's background scan — the
 * sensor reporting itself as reconnaissance against the network it is
 * sitting on. `--known-mac` cleared it, but only if the operator
 * thought to roster the sensor.
 *
 * It is a roster and not a lookup through sloth_state_t on purpose:
 * `get_ifaces()` is a poll that can come back short for a tick (a
 * renamed, replugged or momentarily absent interface), and an
 * exoneration that blinks is worse than one that is slightly stale —
 * the address does not stop being the host's own because one read of
 * /sys missed it. Entries are therefore never removed because they went
 * missing; the one way out is the bound below.
 *
 * Kept separate from the operator's roster rather than folded into it,
 * because `ownership_known_count()` is a *gate*: rule_unknown_device is
 * deliberately inert until the operator rosters something, and a sensor
 * that rostered itself would switch that rule on for every deployment
 * that had designated only an SSID. */

/* A host carries more addresses than it has radios — bridges, veths and
 * docker interfaces all report one, and a Wi-Fi phy lists an address
 * pool besides. Bounded like every other table here. When full, the
 * address confirmed least recently makes room: per-connection MAC
 * randomisation gives the managed card a new address on every
 * association, and over a long run the address in use now matters
 * more than one the card dropped a month ago. (Until #183's second
 * slice the bound refused the newcomer, which on that host is the
 * card's current address.) */
#define MAX_SELF_MACS 128

/* Register one of the host's own addresses. Rejects an all-zero address
 * (iface_stat_t.mac uses it for "unknown", and loopback really is zero)
 * and any address with the multicast bit set, which a host's own
 * unicast address can never have. Idempotent; returns 1 when the
 * address is rostered, 0 when it was rejected or the table is full. */
int ownership_self_add(const uint8_t mac[6]);

/* Sync from one poll's worth of interface records — the call the
 * PLATFORM phase makes right after get_ifaces(), which is "at startup
 * and on every iface change" without a second source of truth. NULL or
 * a non-positive count is a no-op. */
int ownership_self_sync_ifaces(const iface_stat_t *ifaces, int count);

int ownership_is_self_mac(const uint8_t mac[6]);
int ownership_self_count(void);

/* Register a list of addresses from g_platform.get_self_macs(): the
 * permanent addresses, phy pools and netdev-less wireless devices that
 * the iface rows do not carry. Same rules as ownership_self_add().
 * Returns how many are rostered. */
int ownership_self_add_list(const uint8_t (*macs)[6], int n);

/* Whether the PLATFORM phase should ask get_self_macs() this tick: on
 * the first call, whenever the interface set (names and addresses)
 * differs from the last call that said yes, and otherwise every
 * SELF_RESCAN_MS — a P2P device or a phy has no row in the interface
 * set, so a change to one is only seen on the timer. Two netlink dumps
 * and a few sysfs reads are cheap, but not per tick for an answer that
 * changes a few times a day. ownership_clear() resets it. */
#define SELF_RESCAN_MS 30000u
int ownership_self_scan_due(const iface_stat_t *ifaces, int count,
                            uint64_t mono_ms);

/* "Ours": on the operator's roster, or one of the sensor's own
 * addresses. This is what the exonerations consult, so that the two
 * answers to "this is not a stranger" are indistinguishable at the call
 * site — which is the whole of #183 item 1. Rules that consult the
 * roster to *escalate* (BTM_ABUSE, PEAP_NO_SERVER_CERT: "the operator's
 * own device fell for this") deliberately keep asking
 * ownership_is_known_device(), because the sensor's own card is not
 * what the operator wrote down and a CRIT about it would be the
 * opposite of the point. */
int ownership_is_own_device(const uint8_t mac[6]);

/* True when the operator designated anything at all. Rules use this to
 * skip work entirely in the common unconfigured case. */
int ownership_any(void);

/* Counts, for the startup banner and tests. */
int ownership_ssid_count(void);
int ownership_bssid_count(void);

/* The i-th designation, 0 <= i < the count; NULL out of range. For the
 * `ownership` record (src/jsonl.c), which exports the rosters so a
 * consumer can mark the operator's networks: the designated SSIDs and
 * BSSIDs, and the known-device roster as a count only. */
const char    *ownership_ssid_at(int i);
const uint8_t *ownership_bssid_at(int i);

/* Drop all designations — tests only. */
void ownership_clear(void);

#endif /* SLOTH_OWNERSHIP_H */
