/* Wired-attachment correlation seam — issue #89 slice 3.
 *
 * The third category in #89's fix list is "unauthorized AP attached to
 * the wired network". It is the one an enterprise operator most wants,
 * and it is the one sloth cannot answer.
 *
 * ── Why RF cannot answer it ───────────────────────────────
 *
 * Everything the twin family reads — SSID, BSSID, cipher, vendor IEs,
 * RSSI, 802.11k neighbour reports — is carried in beacons a radio
 * transmits. None of it says anything about what that radio is plugged
 * into. A Pineapple in a backpack with an LTE uplink and a rogue AP
 * bridged onto the operator's access VLAN emit indistinguishable
 * beacons. The distinction lives entirely on the wire: a CAM/MAC
 * table entry on a switch port, a controller's rogue-on-wire
 * classification, a DHCP lease handed to the AP's Ethernet MAC.
 *
 * So the answer here is UNKNOWN, and it stays UNKNOWN until something
 * that can actually see the wire says otherwise. That is not a gap to
 * be closed with a heuristic. A heuristic here would be the same
 * mistake #89 exists to remove — slice 1 deleted three "trust anchors"
 * (matching OUI, RSSI, an unauthenticated neighbour report) that were
 * each an inference dressed as a fact, and inferring wired attachment
 * from RF would reintroduce exactly that, on the claim with the
 * heaviest operational consequences: "there is a rogue on your LAN"
 * gets a switch port shut.
 *
 * ── What this is ──────────────────────────────────────────
 *
 * An in-process registration seam and nothing else. A future in-tree
 * correlator (a switch CAM reader, a controller export parser, a
 * consumer of sloth's own passive DHCP snoop) registers a callback and
 * every surface that renders a twin — the [x] Twins view, the
 * `EVIL_TWIN` alert detail, the `twin_episode` JSONL record — starts
 * carrying its verdict. Until one does, `wired_attach_lookup()`
 * returns WIRED_ATTACH_UNKNOWN for every BSSID and the UI says so.
 *
 * ── What this is NOT (MISSION §4) ─────────────────────────
 *
 * Not a plugin loader: no dlopen, no path, no file, no symbol lookup.
 * Not a control surface: nothing reaches this from the network, the
 * data socket, or the CLI — the only caller is C code compiled into
 * the same binary. Not an active probe: registering a correlator does
 * not authorise it to transmit; a correlator that scanned a switch
 * would violate MISSION §2 the same way any other active step does,
 * and the seam neither grants nor implies that permission. The
 * function-pointer indirection exists so the twin surfaces do not have
 * to know which module answers, not so an outside party can inject
 * one.
 *
 * There is exactly one registration slot and no stacking. Two
 * correlators disagreeing about a BSSID is an unresolved question, not
 * a vote to be tallied, and quietly picking a winner would be another
 * inference dressed as a fact. */

#ifndef SLOTH_WIRED_ATTACH_H
#define SLOTH_WIRED_ATTACH_H

#include <stdint.h>

/* Values are part of the `twin_episode_t` / `alert_t` field contract —
 * those structs store the state as a plain uint8_t because include/sloth.h
 * is the shared header and does not include module headers from src/.
 * tests/test_wired_attach.c pins the numbering. */
typedef enum {
    WIRED_ATTACH_UNKNOWN      = 0,  /* not established — the only value RF can produce */
    WIRED_ATTACH_ATTACHED     = 1,  /* a correlator saw this radio on the wired network */
    WIRED_ATTACH_NOT_ATTACHED = 2,  /* a correlator looked and it is not there */
} wired_attach_t;

/* Answer for one BSSID. `ctx` is whatever was registered alongside.
 * A correlator that does not know must return WIRED_ATTACH_UNKNOWN —
 * "I have no record of it" is not the same claim as "it is not on the
 * wire", and only the correlator can tell those apart. */
typedef wired_attach_t (*wired_attach_fn)(const uint8_t bssid[6], void *ctx);

/* Install the correlator. A second call replaces the first; passing
 * NULL is the same as wired_attach_clear(). */
void wired_attach_register(wired_attach_fn fn, void *ctx);

/* Remove it. Every lookup goes back to UNKNOWN. */
void wired_attach_clear(void);

/* 1 when a correlator is installed. The Twins view shows this so an
 * operator can tell "nothing is attached" from "nobody is looking" —
 * two very different readings of a column full of `?`. */
int  wired_attach_have_correlator(void);

/* UNKNOWN when no correlator is registered, when `bssid` is NULL, or
 * when the registered correlator returns a value outside the enum. The
 * last one is deliberate: a correlator is ordinary in-tree code, but
 * defaulting to UNKNOWN on a value sloth does not recognise keeps a
 * future bug from manufacturing a wired-attachment claim. */
wired_attach_t wired_attach_lookup(const uint8_t bssid[6]);

/* Short label for the UI and the exports: "?", "yes", "no". */
const char *wired_attach_label(wired_attach_t v);

#endif /* SLOTH_WIRED_ATTACH_H */
