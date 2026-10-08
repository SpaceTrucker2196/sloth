#ifndef SLOTH_EVIDENCE_EXPORT_H
#define SLOTH_EVIDENCE_EXPORT_H

#include <stddef.h>
#include <stdint.h>

/* ── Gated evidence export (#92) ──────────────────────────────────
 *
 * Writes raw 802.11 frames out of the in-memory evidence ring as a
 * libpcap savefile, so an alert can be re-examined frame by frame
 * instead of trusted on the strength of its own summary.
 *
 * ── The gate ──
 *
 * Only when `--collect-handshakes` is set AND an export directory is
 * configured. Owner ruling 2026-10-08, after the ring deliberately
 * landed memory-only so the question could be asked properly.
 *
 * The reason is the payload, not tidiness: a raw 802.11 frame carries
 * the EAPOL 4-way and PMKID, which is crackable offline by whoever gets
 * a copy. #87 put exactly that material behind this flag, with a
 * retention sweep. Exporting it through any other flag would have made
 * that gate half-decorative — the same bytes reachable by two switches,
 * one protected and one not.
 *
 * So the files go in #87's export directory, through its pinned
 * descriptor (eapol_export_create()), which means they inherit its
 * 0600 mode, its symlink-safe creation, and its retention window for
 * free. eapol_sweep() walks every regular file there by mtime, so an
 * evidence pcap expires on the same clock as a handshake.
 *
 * Three consequences of that choice, accepted rather than hidden:
 *
 *   1. The flag is named for handshakes. Gating a deauth-flood evidence
 *      export behind `--collect-handshakes` is not self-explanatory,
 *      and it welds two intents to one switch.
 *   2. "Evidence without crackable material" is unreachable. There is
 *      no way to ask for it. If anyone does, that is a second flag and
 *      a second retention policy, which the flag matrix did not need
 *      speculatively.
 *   3. Evidence expires on a handshake schedule — 7 days by default,
 *      `--handshake-retention`. Older frames are gone whether or not
 *      the incident they belong to is closed. The alternative was no
 *      sweep at all, which is the gap #87 closed.
 *
 * ── What it does not do ──
 *
 * Nothing here decides WHICH frames matter: the caller supplies event
 * IDs. Wiring the alert engine to record the IDs that triggered it is a
 * separate slice, deliberately — the gate was the blocked question, and
 * bundling the two is how an earlier #92 slice came to claim more than
 * it delivered. */

/* Write the frames for `ids` (n of them) as a libpcap savefile named
   `name` in the gated export directory.
 *
 * DLT is IEEE 802.11 plus radiotap, matching what the ring stores: the
 * radiotap header is part of each record, because it carries the
 * frequency, the FCS verdict and the signal an analyst needs in order
 * to judge the frame.
 *
 * An ID that was never issued or has been evicted is SKIPPED, not
 * fatal, and counted in *skipped: an incident whose oldest frame aged
 * out is still worth the frames that remain, and a partial export that
 * says so beats no export. A record is never substituted for another.
 *
 * Returns frames written (>= 0), or -1 with a reason in `err`:
 * the gate is closed, no export directory, bad arguments, the file
 * already exists, or a write failed. On -1 nothing partial is left
 * behind that a reader could mistake for a complete export. */
int evidence_export_pcap(const char *name,
                         const uint64_t *ids, int n,
                         int *skipped,
                         char *err, size_t errsz);

#endif /* SLOTH_EVIDENCE_EXPORT_H */
