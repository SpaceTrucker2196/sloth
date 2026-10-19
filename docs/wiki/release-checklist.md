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
attestation and the CI SBOM job are approved and not yet in the
workflows; until they land, the SBOM comes from `make sbom` and the
checksums are computed by hand as below.

**Sources**: `Makefile` (`check-deps`, `sbom`), `tools/sbom.sh`,
`src/libver.c`, `src/db.c`, `research/query.c`, `include/sloth.h`
(`SLOTH_VERSION`), `tests/test_version.c`, `tests/test_libver.c`,
`tests/test_ci_pins.c`, `SECURITY.md`, `RELEASE_v*.md`, issue #142.

**Last updated**: 2026-10-18 (#142)

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
10. **Provenance — pending.** The owner approved, on #142, a
    `release-attestation` CI job on `v*` tag pushes using
    `actions/attest-build-provenance` pinned by full commit SHA, plus
    an `sbom` job using `anchore/sbom-action` pinned the same way. Neither is in
    `.github/workflows/` yet: the workflow edit did not land with the
    first #142 slice. Until it does there is no GitHub attestation to
    verify, and this checklist does not claim one. When it lands, the
    verification is `gh attestation verify sloth --repo
    SpaceTrucker2196/sloth`.

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
