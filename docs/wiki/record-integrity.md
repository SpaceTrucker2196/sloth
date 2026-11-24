---
name: record-integrity
description: What sloth hashes, when and by whom, for the JSONL file, sloth.db and the evidence captures; the --jsonl-chain hash chain over the -o file, pcap_sha256 on the alert records, and sloth --verify
type: reference
---

# Record integrity: the JSONL chain and `--verify`

**Summary**: Before #251 the evidence captures under `--pcap-dir` and `--eapol-dir` were each listed with their SHA-256 in a per-session manifest, and nothing else sloth writes was hashed: a line of the `-o` JSONL file, a row of `sloth.db` or a report could be changed after capture and nothing in sloth's output would show it. `--jsonl-chain N` puts a hash chain over the `-o` file: a `chain` record after every `N` records with the SHA-256 of the block and of the previous chain record, and, under the same flag, `pcap_sha256` on the alert records that name a capture. `sloth --verify PATH` checks a chained file, or an evidence directory's manifests, and names the first break. `--report` prints the chain head. Off by default; with it off no byte of any output changes. No signing key: the issue makes signing optional and this slice does not build it (§5).

**Sources**: issue #251 (from #241 item 18); FM 6-02.43 (2009) 3-19 (information assurance: availability, integrity, authentication, confidentiality, non-repudiation; integrity is "the protection from unauthorized change"); FIPS 180-4 (SHA-256); `src/jsonl_chain.h`, `src/jsonl_chain.c` (the writer), `src/jsonl_verify.c` (`--verify`), `src/jsonl_core.c` (the sink), `src/alerts/engine.c` (`alerts_pcap_sha256()`), `src/posture.c` (the report's head), `src/evidence_manifest.h` (#92 slice 3), `src/secure_file.h` (#87), `src/inventory.c` (`inventory_hash()`), `src/intel_pack.c`; `tests/test_jsonl_chain.c`, `tests/test_alert_pcap.c :: test_pcap_sha256_only_under_the_chain`, `make replay-check`.

**Last updated**: 2026-11-24 (#251: the page; step 0, the chain, `--verify`, the report's head).

---

## 1. Step 0: what existed before #251

The issue's step 0, read from the tree at `20a0d94e`. "Who" is the
process that computes the value; "a verifier" is anyone holding the
files afterwards.

| What | Hashed? | When, by whom | What a verifier could check |
|---|---|---|---|
| Evidence captures: `--pcap-dir` alert pcaps, `--eapol-dir` evidence pcaps, handshake pcaps, `eapol.22000` | Yes: SHA-256 and size of each committed file, one line in `sloth-manifest-<start>-<16 hex>.jsonl` in the same directory ([[pcap-export]] § 5) | by the sensor, right after each file is committed: the file is re-opened through the pinned directory descriptor and read back, so the hash is of the bytes under the final name; the line is appended with one `pwrite` and `fsync`ed | that a listed file still has the bytes its line names (sloth-mesh's evidence page does this and sends `X-Sloth-SHA256` with a download; `sha256sum` by hand). `seq` runs 1, 2, 3 … per manifest, so a removed line leaves a gap. The manifest itself is not hashed, chained or signed: a file and its line changed together are not detectable, and neither is a whole manifest replaced |
| The `w` export from the packets view | No | — | nothing; it goes to the working directory and is in no manifest |
| `-o` JSONL file | No | — | nothing. The file is `0600`, owned by the run's account, one link, never a symlink (`src/secure_file.h`), which limits who can change it on the sensor and not what a copy holds |
| Alert records naming a capture (`pcap_path`) | No hash on the record | — | the name only; joining the record to a manifest line by `incident_id` gives the hash the manifest holds, which is no stronger than the manifest |
| `sloth.db` | No | — | nothing beyond SQLite's own consistency (`PRAGMA integrity_check` finds corruption, not a deliberate edit). Created `0600` by descriptor before SQLite opens it (`src/db.c`) |
| `--report` / `--report-json`, `--snapshot-out`, the handoff packet (#250) | No | — | nothing; files `0600`, the packet's directory `0700`, every packet file `O_EXCL` |
| `--inventory` file | SHA-256 of its bytes, the first 16 hex characters, as `inventory` on records that consulted it (#89 slice 2) | by the sensor at load | which inventory file a finding used (identity, not integrity: 64 bits, and nothing ties the file to a time) |
| The intel pack | A SHA-256 over the pack, compiled into the binary (`SLOTH_INTEL_PACK_HASH`), on `sensor_health` and alert records as `intel_pack` (#231) | by the pack build | which pack a build's tables came from |
| Signing of anything | None | — | — |

So the one thing a verifier could check was an evidence file against
its manifest line. The JSONL file, which holds every finding and the
`pcap_path` that names the capture, had no integrity at all. That is
what part 1 adds. Nothing above is rebuilt: the manifest stays as it
was, and `--verify` reads it.

## 2. The chain (`--jsonl-chain N`)

With `--jsonl-chain N` (1..100000, both daemons, needs `-o` and
`--out-format jsonl`), the file sink writes a `chain` record
([[jsonl-schema]] § chain):

```json
{"type":"chain","ts":1700000000,"v":1,"seq":2,"lines":3,"block_sha256":"…","prev_sha256":"…"}
```

- `block_sha256` is the SHA-256 of the exact bytes of the `lines` lines
  between the previous chain record and this one, each with its `\n`:
  what a reader reads back, not what a builder meant.
- `prev_sha256` is the SHA-256 of the previous chain record's line with
  its `\n`. A change anywhere before a chain record changes its
  `block_sha256` or, through the records after it, a `prev_sha256`.
- **Segments.** The `-o` file is appended to across runs and a run does
  not read back what an earlier one wrote. Each open writes a
  **genesis** (`seq` 1, `lines` 0, `block_sha256` of nothing,
  `prev_sha256` 64 zeros) before the run's first record. Lines between
  one segment's last chain record and the next genesis (an earlier
  run's tail after a crash, or a run without the flag) are in no block;
  `--verify` counts them and gives the first line, and does not call
  them a break.
- **Seals.** A block is closed after `N` records, at exit, and when a
  report is written. So a clean stop ends on a chain record, and the
  head a report prints is a line already in the file. A crash leaves
  up to `N - 1` records after the head, which `--verify` calls pending.
- **File only.** The data socket gets no chain record: a client that
  joins mid-block could not check it, and the socket is not a record.
- **Off is unchanged.** Without the flag nothing is hashed and nothing
  written. `tests/test_jsonl_chain.c :: test_off_is_byte_identical`
  compares the file byte for byte (seen red with the genesis written
  whatever the flag); `make replay-check` runs the replay both ways and
  compares the chained file, chain records taken out, to the plain run,
  then runs `--verify` on it.
- **A write failure** (a full disk) counts in `storage_jsonl_failures`
  like any record, and the block it fell in fails `--verify`: the file
  does not hold the bytes the chain describes, which is the truth.

Choosing `N`: a smaller `N` names a changed line more closely and costs
one ~200-byte record per `N`; at the reference sensor's rate (a few
hundred records a minute) `--jsonl-chain 1000` is a record every few
minutes.

### The capture's hash on the alert record

Under the same flag, an `alert.*` record that carries `pcap_path` also
carries `pcap_sha256`, the SHA-256 of that file read back after the
export wrote it (the engine's side table keeps it beside the path, for
the key). The chained record then binds the capture's bytes, not only
its name: the manifest alone cannot show a capture and its line changed
together, a chained `pcap_sha256` can. Absent when the file could not be
read back (a path too long, recorded as the bare name). Off, the engine
reads nothing and the record has no such field.

## 3. `sloth --verify PATH`

Reads PATH and nothing else, writes nothing, exits.

**A regular file** is read as a chained JSONL file. Each chain record
must be exactly what the writer makes (it is re-rendered from its
values and compared byte for byte); each non-genesis record must follow
the previous one in `seq`, name it in `prev_sha256`, cover exactly the
lines since it, and match their bytes. The first record that does not
is the break, named by segment, block (`seq`) and line range:

```
verify: out.jsonl: JSONL hash chain (--jsonl-chain)
  lines 52, chain records 1 in 1 segment, blocks checked 0
  BREAK at line 52: segment 1 block 2 (lines 2-51): the lines do not match block_sha256: changed after capture
  intact up to the chain record at line 1 (segment 1 seq 1)
  result: break
```

Intact, it prints the head (segment, `seq`, line and the SHA-256 of the
head's line), the pending lines after it and the lines no segment
covers. Exit `0` intact, `1` a break, `2` cannot verify (unreadable, or
no chain record: a file written without the flag).

**A directory** is read as an evidence directory: every
`sloth-manifest-*.jsonl` in it, each line parsed and `seq` without a
gap (a final fragment is a crash tail and skipped), and every file a
line names hashed. A file is intact when its bytes match any of its
lines (a handshake pcap is replaced and `eapol.22000` appended to, so
their earlier lines name bytes that are gone by design; the rule is the
one sloth-mesh's evidence page uses). A listed file that is not there is
reported as missing (the `--pcap-dir` and `--eapol-dir` sweeps remove
them), and a file no line lists as unlisted; neither is a break.

### What `--verify` cannot show

- **The end cut off at a chain record, or a whole segment removed**,
  leaves a file that verifies: nothing after the cut refers to what was
  cut. The defence is a copy of the head kept off the file: `--report`
  prints it (§4), and the head `--verify` prints should be that one or
  a later head whose chain passes through it.
- **A file rewritten whole**, chain and all, by someone who can run the
  writer, verifies. Only a key the rewriter does not hold could show
  that (§5).
- **The manifests are not chained.** A capture and its manifest line
  changed together verify in a directory check; the chained alert
  record's `pcap_sha256` is what catches that. Comparing the two is not
  automated yet.
- **`sloth.db` and the reports are not hashed.** The chain covers the
  JSONL file, which carries every finding; the database is a working
  store that retention rewrites by design.

## 4. The head in `--report`

With the chain on, `--report` gains a **Record integrity** section
before the footer, and `--report-json` a `jsonl_chain` member
(`{"seq","sha256"}`, before `exposure`):

```
## Record integrity

- **JSONL chain head**: seq `3`, sha256 `d470613b…`
```

Asking for the head seals the pending block first, so the head is a
line the file holds when the report is written. A printed report
therefore names one point of the file; anything up to that point that
is later changed fails `--verify`, and a file that ends before that
point no longer contains the head the report names.

## 5. Not built: signing

The issue proposes, as optional, signing the head each hour with a key
on the sensor and putting the public key in the handoff packet, for
proof of origin. Not in this slice. A key on a sensor that can be
stolen signs for whoever holds the sensor ([[sensor-compromise]]), so a
signature proves less than it seems unless the key is revoked the
moment the sensor is lost, and sloth has no key handling at all yet
(the per-installation keys of #184 Stage 6 are not built). The chain
and a head kept off the sensor (the report, the handoff packet) give
integrity against later change without one.

## 6. Checking by hand

The chain is plain SHA-256 over lines, so it can be checked without
sloth: for a block whose chain record is at line `L` and covers `n`
lines,

```sh
sed -n "$((L-n)),$((L-1))p" out.jsonl | sha256sum   # = block_sha256
sed -n "$((L-n-1))p" out.jsonl | sha256sum          # = prev_sha256 (the record before)
```

`sed -n Np` prints the line with its newline, which is what the chain
hashes. This was run on a `--jsonl-chain 50` replay when the slice was
built and agreed with both fields.

## Related pages

- [[jsonl-schema]] — the `chain` record and `pcap_sha256`.
- [[pcap-export]] § 5 — the evidence manifest `--verify` reads.
- [[sensor-compromise]] — what a lost sensor holds, and why no key here.
- [[cli-reference]] — `--jsonl-chain`, `--verify`.
- [[posture-report]] · [[handoff]] — where a head is kept off the file.
- [[threat-model]]
