# Security Policy

## Supported versions

**Current release: `1.8.4`** — the value of `#define SLOTH_VERSION` in
[`include/sloth.h`](include/sloth.h), which is the single source of
truth for what a build calls itself. If this file and that `#define`
ever disagree, the `#define` is right and this file is stale; please
report it.

sloth is developed and released from **one branch** (`main`). There are
no maintenance branches, no LTS line, and no backports. Concretely:

| What | Status |
|------|--------|
| `main` | ✅ where every fix lands, security or otherwise |
| the newest tag (`v1.8.4`) | ✅ supported — "supported" means the next fix ships in the next tag cut from `main` |
| every tag before the newest | ❌ archived at that commit; receives nothing |

There is **no patch SLA and no support window** — this is a
single-maintainer project and promising either would be a promise we
cannot keep. See "Reporting a vulnerability" below for the response
behaviour we will actually stand behind, which is a best-effort
acknowledgement target, not a remediation deadline.

If you are pinned to an older tag, treat it as end-of-life: no CVE will
be backported to it, and the upgrade path is to move to the newest tag.
That upgrade cost is deliberately kept small — the JSONL schema is
additive, the CLI grows flags but doesn't remove them, and each release
ships a `RELEASE_v*.md` note describing what moved.

Versioning follows semver *for the external contracts* (the CLI flags
and the JSONL schema); a minor bump is feature work, not an
API break.

### What an operator should take from this

An organisation evaluating sloth should plan to track `main` or the
newest tag, not to pin a version and receive patches for it. If your
change-control process requires a fixed, supported version with a
defined maintenance window, sloth does not offer one today, and you
should say so in your own risk write-up rather than infer one from this
file.

### Minimum library versions

| Library | Floor | Enforced |
|---------|-------|----------|
| sqlite3 | **3.31** | compile time (`#error` in `src/db.c`, `research/query.c`, #134); build time (`make check-deps`); **run time** — `db_open()` and `rq_open()` refuse a loaded library below the floor (#142) |
| libpcap | **1.9** | build time only (`make check-deps`). No runtime floor: the capture path degrades on an older libpcap rather than refusing, by design |
| ncursesw | none | — |

3.31 is the sqlite release that added `SQLITE_OPEN_NOFOLLOW` and
`SQLITE_DBCONFIG_TRUSTED_SCHEMA`, which the `--db` store and the
research corpus depend on. The runtime check exists because the library
the dynamic linker loads is not necessarily the one the binary was
built against. `make check-deps` (run by `make`) fails when pkg-config
reports a version below the floor and prints a one-line notice instead
when pkg-config or the library's `.pc` file is absent.

Neither library is vendored: the distribution is the patch channel. To
see what a deployed sensor actually loaded, run `sloth --version`
(lines 2–3), or read the `libs` field of any `sensor_health` JSONL
record.

### SBOM and release integrity

- **SBOM**: `make sbom` writes a CycloneDX 1.5 document naming sloth
  and the five libraries the default build links, at the build host's
  versions. A CI SBOM job (`anchore/sbom-action`, pinned by commit SHA)
  is approved and **not yet in the workflows**.
- **Checksums**: the release checklist puts a `SHA256SUMS` block for
  the binary and the SBOM into each `RELEASE_v*.md`. Releases cut
  before #142 predate it and carry none.
- **Signed tags**: release tags are signed by the owner with
  `git tag -s`, by hand — no workflow holds the key. Verify with
  `git tag -v v<version>`. Tags cut before #142 are annotated but
  unsigned.
- **Build provenance**: GitHub artifact attestation
  (`actions/attest-build-provenance`, pinned by commit SHA) on `v*`
  tags is approved and **not yet in the workflows**. Until it lands
  there is no attestation to verify, and this file does not claim one.

The procedure is [`docs/wiki/release-checklist.md`](docs/wiki/release-checklist.md).

## Version awareness

sloth carries its own version in `#define SLOTH_VERSION` in
`include/sloth.h` and exposes it in the help view and JSONL banner.
The optional `--check-manifest FILE` flag consumes a locally-
maintained release manifest and surfaces "update available" in
the UI — see [`docs/wiki/version-checkin.md`](docs/wiki/version-checkin.md)
for the checker's design and [`docs/wiki/manifest-format.md`](docs/wiki/manifest-format.md)
for the file format. The checker never touches the network directly;
fetching the manifest is the operator's responsibility (e.g. via a
systemd timer that runs the reference script in
`examples/updater/`). This keeps sloth's passive-only guarantee
intact — every network read still comes from the tap.

## Reporting a vulnerability

Open a GitHub security advisory at
<https://github.com/SpaceTrucker2196/sloth/security/advisories/new>
or, if the finding is sensitive enough that a public issue would
leak the vector, email the maintainer directly (contact via the
GitHub profile).

Please include:

- the exact commit hash you tested against
- reproduction steps, ideally a hand-built pcap or JSONL sample
- what a fix would look like from your perspective (this is optional
  but usually accelerates triage)

Acknowledgement is **best-effort, typically within a week** — a target,
not a contractual SLA. Fixes for confirmed issues land on `main` with a
`RELEASE_v*.md` note calling out the CVE identifier if one is assigned.
Coordinated disclosure timing is negotiated per-report.

## Embedded threat-intelligence data

The IOC lists compiled into the binary (`src/threat_intel.c`) are
**synthetic demo data**, not a threat feed. They are four RFC 5737
documentation addresses and six obviously-fake sentinel domains. Their
only job is to let the alert pipeline be exercised in tests and to show
the shape an operator's own list would take.

`THREAT_DOMAIN` and `THREAT_IP` therefore detect **nothing in
production** until the lists are replaced. Sloth ships no feed, fetches
no feed, and has no feed-update mechanism — fetching one would be a
network write, which [`MISSION.md`](MISSION.md) §2 forbids. See
[`docs/wiki/threat-intel.md`](docs/wiki/threat-intel.md).

## Data retention

`--db` retains observations, entity inventory and findings on tiered
windows; `-o` JSONL, `--pcap-dir`, `--eapol-dir` and the `--report`
outputs have **no retention mechanism at all**. Row deletion in the
database is logical, not secure erasure. The exact behaviour, and the
list of artifact classes retention does and does not cover, is in
[`docs/wiki/retention.md`](docs/wiki/retention.md). Read it before
citing sloth in a data-handling or evidence-lifecycle document.

## Passive-only guarantee

The mission statement in [`MISSION.md`](MISSION.md) §2 is the
canonical list of things sloth doesn't do. Any code change that
violates one of those rules is by definition a security issue and
should be reported through the same channel.
