---
name: release-checklist
description: The steps that cut a sloth release — version bump, dependency floors, SBOM, SHA256SUMS, signed tag, attestation — and which of them are automated
type: runbook
---

# Release checklist

**Summary**: Cutting a `vMAJOR.MINOR.PATCH` release of sloth, in order.
Most of it is mechanical and runs from the Makefile; signing the tag
needs the owner's key and is a manual step that no workflow can do on
the owner's behalf (owner ruling on #142, 2026-10-15). Build provenance
is attested by `.github/workflows/release-attest.yml` on every `v*` tag
(it also writes `SHA256SUMS`), and CI's `sbom` job produces a CycloneDX
SBOM artifact on every push; `make sbom` remains the offline fallback.
Verify a release binary with
`gh attestation verify ./sloth --repo SpaceTrucker2196/sloth`.
Rolling back to the previous tag, and what on-disk state survives it,
is section 5.

**Sources**: `Makefile` (`check-deps`, `sbom`), `tools/sbom.sh`,
`src/libver.c`, `src/db.c`, `research/query.c`, `include/sloth.h`
(`SLOTH_VERSION`), `tests/test_version.c`, `tests/test_libver.c`,
`tests/test_ci_pins.c`, `SECURITY.md`, `RELEASE_v*.md`, `src/db.c`
(`check_version`), `src/db.h`, `packaging/systemd/sloth-sensor.service`,
`.github/workflows/release-attest.yml`, issues #95, #142.

**Last updated**: 2026-10-19 (#95 rollback, #142 CI half)

---

## 1. Before the tag

1. **Bump `SLOTH_VERSION`** in `include/sloth.h`. It is the single
   source of truth for what a build calls itself; `SECURITY.md`
   "Supported versions" names it too and must agree. Add the outgoing
   version to the `shipped[]` list in `tests/test_version.c ::
   test_baked_version_orders_after_every_released_tag`.
2. **Write `RELEASE_v<version>.md`** at the repo root, in the shape of
   the previous one: what moved, any JSONL fields added (the schema is
   additive — nothing is renamed or removed), any CVE fixed.
3. **Full gate on the release commit**: `make test`,
   `make test-capture-path`, both again under
   `EXTRA_CFLAGS="-Werror -fsanitize=address,undefined
   -fno-omit-frame-pointer -fno-sanitize-recover=all"`, the six
   `-Werror` configs, `make fuzz FUZZ_SECONDS=1`, `make cppcheck`. CI
   green on the pushed SHA, not on a local tree.
4. **Dependency floors**: `make check-deps`. `all` runs it too; this is
   the explicit read. Fatal when pkg-config reports sqlite below
   3.31.0 or libpcap below 1.9.0; prints a notice and continues when
   pkg-config or a library's `.pc` file is absent, because "cannot
   tell" is not "too old".

## 2. The artefacts

5. **Build** the release binary from a clean tree: `make clean && make`.
6. **SBOM**: `make sbom > sloth-<version>.cdx.json`. CycloneDX 1.5,
   naming sloth at `SLOTH_VERSION` and the five libraries the default
   build links (`ncursesw`, `libpcap`, `sqlite3`, `libpthread`, `libm`)
   at the versions the build host reports. Deterministic — no
   timestamp, no random serial — so two runs on one host diff clean.
   These are **build-host** versions. A binary copied elsewhere loads
   that host's libraries; `sloth --version` and the `libs` field of
   every `sensor_health` record report what was actually loaded
   ([[jsonl-schema]]).
7. **Checksums**: `sha256sum sloth sloth-<version>.cdx.json >
   SHA256SUMS`, and paste the file's contents into
   `RELEASE_v<version>.md` under a `## SHA256SUMS` heading, so the
   checksums travel with the notes rather than only beside the binary.

## 3. The tag — manual, owner only

8. **Sign the tag with the owner's key**:

   ```sh
   git tag -s v<version> -m "sloth v<version>"
   git tag -v v<version>          # verify before pushing
   git push origin v<version>
   ```

   This step cannot be automated in this repo. No workflow holds the
   owner's signing key, by design: a key a runner can use is a key any
   compromised action in that runner can use. An unsigned tag is a
   release that cannot be verified against the owner, so the
   verification step is not optional.

## 4. After the tag

9. **Publish the GitHub release** for the tag with the notes from step
   2 and attach `sloth`, the SBOM and `SHA256SUMS`. Publishing triggers
   `mirror-release.yml`, which mirrors the tag and release.
10. **Provenance.** `.github/workflows/release-attest.yml` (landed in
    `9131b8e`, #142) builds `sloth`, writes `SHA256SUMS` and attests the
    binary with `actions/attest-build-provenance` on every `v*` tag push;
    CI's `sbom` job produces the CycloneDX SBOM with `anchore/sbom-action`
    on every push. Both are pinned by full commit SHA. No tag has been
    pushed since it landed, so no released version carries an
    attestation yet; the first will be the tag after v1.8.4. Verify with
    `gh attestation verify sloth --repo SpaceTrucker2196/sloth`.

## 5. Rolling back to the previous tag

A sensor is rolled back by replacing the binary, not by any in-place
downgrade logic — sloth has none. What decides whether the old binary
starts is the state it finds on disk, so the state section below is the
part to read first.

### Get and verify the previous release

For a tag cut after `release-attest.yml` landed (`9131b8e`, 2026-10-19),
that is, every tag after v1.8.4:

```sh
git fetch --tags
git tag -v v<prev>                 # owner's signature on the tag (step 8)
gh release download v<prev> --repo SpaceTrucker2196/sloth \
    --pattern sloth --pattern SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify ./sloth --repo SpaceTrucker2196/sloth
```

Compare `SHA256SUMS` with the copy pasted into `RELEASE_v<prev>.md`
(step 7) as well: the release asset and the notes are two places an
attacker would have to change. Any of the four checks failing means the
artefact is not the one that was released — stop rather than build
around it.

**v1.8.4 and earlier cannot be verified this way.** Checked on
2026-10-19: the v1.8.4 tag is annotated but carries no signature
(`git cat-file -p v1.8.4` shows no signature block), `RELEASE_v1.8.4.md`
has no `## SHA256SUMS` section, and no attestation exists because the
workflow did not. The only anchor is the tag's commit
(`d774229`): build from it on the sensor —

```sh
git checkout v1.8.4 && make clean && make
```

— and treat that as "built from the tagged source", not as "the
released binary".

Then install it over the current one (`make install` from that tree, or
copy the verified binary to `/usr/local/bin/sloth`) and restart the
unit.

### What state survives the downgrade

| State | Survives? | Why, and what to do |
|---|---|---|
| `--db` file (`/var/lib/sloth/sloth.db` in the shipped unit) | **No, if the schema version changed** | `db_open()` refuses any file whose `meta.schema_version` is not exactly the build's `DB_SCHEMA_VERSION` ("db schema vN, this build writes vM — use a separate file") and `main()` exits 1 rather than running without the DB. The exception is forward and additive: this tree writes v7 and migrates a v5 or v6 file in place, one step at a time, by adding the `devices` camera columns (v5 -> v6, #106 round 2) and the classifier and DHCP option columns (v6 -> v7, #155; [[sqlite-schema]]). There is no downgrade: once a v7 build has opened a file, a v5 or v6 build refuses it. v1.8.4 writes v4 (the v5 bump is `6031b30`, #90) and a v4 file is refused, not migrated. Under the shipped unit's `Restart=always` the refused start loops until `StartLimitBurst` stops it. **Move the file aside** (`sloth.db`, `sloth.db-wal`, `sloth.db-shm` together) before starting the old binary; it starts a fresh file. Keep the moved one: rolling forward again reads it, and the file the old binary wrote in the meantime will in turn be refused by the newer one. Check before and after with `sqlite3 sloth.db "SELECT value FROM meta WHERE key='schema_version'"` and the `DB_SCHEMA_VERSION` line of each tree's `src/db.h`. |
| JSONL output (`-o FILE`, `--data-socket`) | **Yes, mixed** | The file is opened append-only, so the old binary keeps appending to it. The schema is additive (fields are added, never renamed or removed — [[jsonl-schema]]), so the old build's records are a subset of the new build's shape for the same type; record types introduced after the old tag simply stop appearing. No record names the sloth version that wrote it, so a consumer that needs to know where the boundary is should rotate the file at the rollback, or note the time. A consumer that relies on a field newer than the old tag sees it go missing. |
| `--snapshot-out` / `--baseline-in` file | Yes | Same tab-separated line format at v1.8.4 and this tree (only the header-label handling changed). |
| `--with-research` database | Yes | Carries no version stamp; the ingest that builds it is unchanged between v1.8.4 and this tree. |
| `--pcap-dir`, alert pcaps, EAPOL / 22000 exports, `--report` outputs | Yes | Write-only artefacts; no build reads them back. |
| Shipped systemd unit (`make install-service`) | Yes for v1.8.4 | Every flag in `ExecStart` already existed at v1.8.4 (checked against its argument parser), and the unit's `User=sloth` with ambient capabilities does not depend on the in-binary privilege drop. A unit that adds `--user`, `--no-privdrop`, `--replay` or `--ticks` through `SLOTH_ARGS` will fail on v1.8.4, which does not know them. |

This list is from reading the two trees on 2026-10-19, not from running
a downgrade on a sensor. The next rollback that happens should replace
"checked against" with "done", or correct it.

## What is enforced, and where

| Property | Enforced by |
|---|---|
| sqlite ≥ 3.31.0 at compile time | `#error` in `src/db.c`, `research/query.c` (#134) |
| sqlite ≥ 3.31.0 at run time | `db_open()` / `rq_open()` refuse; `tests/test_libver.c` (#142) |
| sqlite / libpcap floors before compiling | `make check-deps`, run by `all` (#142) |
| every workflow action pinned to a 40-hex commit | `tests/test_ci_pins.c` (#95) |
| no `-latest` runner image | classifier in `tests/test_ci_pins.c`; the tree-wide assertion follows the workflow change (#142) |
| `SLOTH_VERSION` orders after every shipped tag | `tests/test_version.c` |
| signed tag | the owner, by hand (step 8) |

libpcap has no runtime floor on purpose: `src/capture/capture.c`
already degrades on an older libpcap rather than refusing, and a
refusal would trade a degraded sensor for a blind one. Neither library
is vendored (#142's design): the distribution is the patch channel, and
a vendored copy would make sloth the party responsible for tracking
and shipping every upstream CVE fix in two parsers it did not write.

## Related pages

- [[version-checkin]] — how a deployed sensor learns a newer release
  exists.
- [[manifest-format]] — the manifest `--check-manifest` reads.
- [[deployment]] — `make install` and the shipped unit.
- [[jsonl-schema]] — the `sensor_health.libs` field.
- [[threat-model]] — the supply-chain threats this answers.
