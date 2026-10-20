#ifndef SLOTH_EVIDENCE_MANIFEST_H
#define SLOTH_EVIDENCE_MANIFEST_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* ── Per-session hashed manifest (#92 slice 3, plan #145) ─────────
 *
 * One JSON Lines file per sloth run per output directory, listing every
 * file sloth committed there: the IP alert pcaps under --pcap-dir, and
 * under --eapol-dir the alert evidence pcaps, the per-handshake pcaps
 * and the eapol.22000 lines file. Each line names the file relative to
 * the manifest's own directory, its size and the SHA-256 of its bytes,
 * the sink that wrote it, the alert incident and rule where there is
 * one, when it was written, and whether sloth reconstructed it.
 *
 * ── One manifest per directory, not one per run ──
 *
 * A name in a manifest is only meaningful next to the directory it is
 * relative to. Keeping the manifest inside that directory means a
 * directory copied off the sensor carries its own record, and nothing
 * in it refers to a path that does not exist where it landed. When
 * --pcap-dir and --eapol-dir are the same directory (same st_dev and
 * st_ino) the two sinks share one manifest, so there is never a second
 * file describing the same directory differently.
 *
 * ── Hash the committed bytes, by re-reading them ──
 *
 * The hash is taken by opening the file through the same pinned dirfd
 * after it is committed (closed, or renamed into place) and reading it
 * back, not by hashing on the way through write(2). Two reasons. It
 * hashes what is under the final name — the bytes a later verifier
 * reads — rather than what sloth believed it handed the kernel, so a
 * writer path that drops a buffer cannot produce a hash for bytes that
 * are not there. And the four sinks write four ways (a FILE*, raw
 * write(2), temp + rename, append), so one read-back is one hashing
 * path instead of four stream wrappers. The cost is one extra read of a
 * file that is still in the page cache. For eapol.22000, which appends
 * across runs, each line hashes the whole file as it stood after that
 * append.
 *
 * ── Crash shape ──
 *
 * Lines are appended as files commit and each is fsync'ed before the
 * call returns, so a crash leaves a valid prefix: every newline-
 * terminated line parses. A failed append is truncated back off, so a
 * half line never sits in front of the next good one.
 *
 * ── What it is not ──
 *
 * A hash says the bytes have not changed since sloth hashed them. It
 * says nothing about who held the file since, and sloth can rewrite
 * its own manifest as easily as anything else in the directory. Chain
 * of custody is a procedure around the files, not a property of them
 * (docs/wiki/pcap-export.md).
 *
 * ── Failure ──
 *
 * evidence_manifest_record() reports failure to its caller, which
 * counts it on its own sink's sfile_fail counter (so it reaches the
 * !persist badge and sensor_health's storage_* fields), and never
 * undoes or blocks the evidence write the line describes. */

#define EVM_PREFIX "sloth-manifest-"
#define EVM_EXT    ".jsonl"
#define EVM_SESSION_MAX 128

typedef enum {
    EVM_SINK_ALERT_PCAP = 0,   /* --pcap-dir, src/alert_pcap.c          */
    EVM_SINK_EVIDENCE_PCAP,    /* --eapol-dir, src/evidence_export.c    */
    EVM_SINK_HANDSHAKE_PCAP,   /* --eapol-dir, per-(BSSID, STA) pcap    */
    EVM_SINK_HASHCAT_22000,    /* --eapol-dir, eapol.22000              */
    EVM_SINK_COUNT
} evm_sink_t;

typedef struct {
    evm_sink_t  sink;
    const char *incident_id;   /* NULL or "" when the file has no alert */
    const char *rule;          /* NULL or "" likewise                   */
} evm_meta_t;

/* "alert_pcap", "evidence_pcap", "handshake_pcap", "hashcat_22000". */
const char *evidence_manifest_sink_name(evm_sink_t s);

/* 1 for what sloth assembled rather than copied from the capture: the
 * per-handshake pcap (M1..M4 in message order, not arrival order) and
 * the hashcat lines derived from them. 0 for the two alert pcaps,
 * whose records are captured frames in capture order. */
int evidence_manifest_reconstructed(evm_sink_t s);

/* Fix the session: its start time names every manifest this run
 * writes. Called once from main() at startup; without it the first
 * record starts the session at sloth_wall(). A second call while a
 * session is open is ignored. */
void evidence_manifest_session_begin(time_t start);

/* Copy "<YYYYmmddTHHMMSSZ>-<16 hex>" into out, or "" before the
 * session starts. EVM_SESSION_MAX is enough. */
void evidence_manifest_session(char *out, size_t outsz);

/* Append one line for `name`, a bare file name already committed under
 * `dirfd`. Creates this session's manifest in that directory on first
 * use (O_EXCL through `dirfd`, 0600, secure_file rules; a name already
 * taken moves on to "-2", "-3" ...). Returns 0, or -1 with a reason in
 * err — the caller counts it. */
int evidence_manifest_record(int dirfd, const char *name,
                             const evm_meta_t *meta,
                             char *err, size_t errsz);

/* This session's manifest name in `dirfd`'s directory, if one has been
 * created: 0, or -1 with out = "". */
int evidence_manifest_name(int dirfd, char *out, size_t outsz);

/* 1 if `name` has the manifest shape (EVM_PREFIX ... EVM_EXT): what the
 * --eapol-dir retention sweep matches on. */
int evidence_manifest_is_name(const char *name);

/* Close every manifest and forget the session, so the next record
 * starts a new one. Tests, through sloth_reset_all(). */
void evidence_manifest_reset(void);

/* Test seams. force_suffix makes the next session use `suffix` instead
 * of a random one (on = 0 restores random), so a test can make two
 * sessions collide. fail_next makes the next record fail at its append,
 * after the manifest exists. Neither is reachable from the CLI. */
void evidence_manifest_test_force_suffix(int on, uint64_t suffix);
void evidence_manifest_test_fail_next(void);

#endif /* SLOTH_EVIDENCE_MANIFEST_H */
