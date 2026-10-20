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
 * ── Who calls it ──
 *
 * The alert engine (#92 slice 1): dump_new_alert_pcaps() in
 * src/alerts/engine.c exports every incident that carries evidence IDs,
 * under the same severity floor and per-key cooldown #96 put on IP
 * alert pcaps, named by evidence_export_alert_name() and written
 * through evidence_export_pcap_unique(). Nothing here
 * decides WHICH frames matter: the detector picks the IDs and fire_inv()
 * stamps them. */

/* Is export possible right now — the gate open AND a directory set?
 * For a caller that must not count "switched off" as a failure. */
int evidence_export_enabled(void);

/* "<incident_id>-<event_id>-<rule>.pcap": the incident (#98), the first
 * evidence-ring event ID the incident cites, and the alert kind. All
 * three are needed for the name to identify the file: one incident can
 * be exported once, a key re-fired after a cooldown is a new incident,
 * and the rule makes a directory listing readable without JSONL.
 * `incident_id` must be lowercase hex (what incident_id_make() writes)
 * and `event_id` non-zero; `rule` is reduced to [A-Za-z0-9_]. Returns
 * 0, or -1 with out = "" when an input is malformed or it does not fit. */
int evidence_export_alert_name(const char *incident_id, uint64_t event_id,
                               const char *rule, char *out, size_t outsz);

/* "<--eapol-dir>/<name>" for reporting (pcap_path). 0, or -1 with
 * out = "" when export is off or the path does not fit. */
int evidence_export_path(const char *name, char *out, size_t outsz);

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
 * `name` is a bare file name inside the export directory: empty, ".",
 * ".." or anything containing '/' is refused before any syscall
 * (sfile_open(), #134), so a caller-supplied name cannot leave the
 * pinned directory.
 *
 * Returns frames written (>= 1), 0 when every ID had been evicted (no
 * file is created: a header with no records is not evidence of
 * anything), or -1 with a reason in `err`: the gate is closed, no
 * export directory, bad arguments, a name that is not bare, the file
 * already exists, or a write failed.
 *
 * ── Nothing partial under the final name (#92 slice 2) ──
 *
 * The frames go to ".<name>.tmp" (O_EXCL, same pinned directory), are
 * fsync'ed, and only then renamed to `name` — and only if nothing is
 * there. Every failure path, header, allocation, record, fsync and
 * commit, unlinks the temp. So a file under `name` is always a complete
 * export, and a reader never has to guess whether a short file is a
 * truncated one. Until this, three of those paths only closed the
 * descriptor and left a zero-length or truncated file at the final
 * name, while this comment promised the opposite. A temp that survives
 * a crash is a dotted .tmp, which eapol_sweep() expires. */
int evidence_export_pcap(const char *name,
                         const uint64_t *ids, int n,
                         int *skipped,
                         char *err, size_t errsz);

/* evidence_export_pcap(), except that a name already on disk is not a
 * refusal: the export commits under "<stem>-2<ext>", "<stem>-3<ext>" ..
 * up to EVX_UNIQUE_MAX, and the name actually used is written to
 * name_out ("" on failure). The alert engine uses this one.
 *
 * Why it exists (#92 review): the alert name is unique only within one
 * process. incident_id hashes the key, the wall second and a sequence
 * that restarts at 0, and evidence IDs restart at 1, so a restart that
 * re-fires the same key in the same wall second — an RTC-less sensor
 * booting to a saved clock, say, with the earlier file still inside the
 * retention window — rebuilds the identical name. Under the plain
 * refusal the engine retried that every tick for the incident's life:
 * a full write, fsync and unlink per tick, a failure counted per tick,
 * and sensor_health re-emitted per tick through storage_fail.
 *
 * Returns as evidence_export_pcap() does, plus EVX_REFUSED when every
 * candidate is taken. That one is terminal — retrying cannot free a
 * name — and is counted once, like any other failure here. */
#define EVX_UNIQUE_MAX 99
#define EVX_REFUSED    (-2)
int evidence_export_pcap_unique(const char *name,
                                const uint64_t *ids, int n,
                                int *skipped,
                                char *name_out, size_t name_outsz,
                                char *err, size_t errsz);

/* Test seam: make the nth occurrence of one failure point fail, so each
 * cleanup path is driven without a full disk. WRITE counts write(2)
 * calls through write_all() — 1 is the global header, 2 and 3 the first
 * record's header and body. ALLOC, FSYNC and COMMIT fail on their first
 * occurrence whatever nth says. Cleared after it fires, and by
 * EVX_FAULT_NONE. Not reachable from the CLI. */
typedef enum {
    EVX_FAULT_NONE = 0,
    EVX_FAULT_WRITE,
    EVX_FAULT_ALLOC,
    EVX_FAULT_FSYNC,
    EVX_FAULT_COMMIT,
} evx_fault_t;
void evidence_export_test_fault(evx_fault_t where, int nth);

#endif /* SLOTH_EVIDENCE_EXPORT_H */
