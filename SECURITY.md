# Security Policy

## Supported versions

sloth follows semver. Security fixes are applied to the current minor
release line only; older minors are archived at their last tag and do
not receive further updates.

| Version | Supported |
|---------|-----------|
| 1.4.x   | ✅ current |
| 1.3.x   | ❌ archived |
| 1.2.x   | ❌ archived |
| 1.1.x   | ❌ archived |
| 1.0.x   | ❌ archived |
| < 1.0   | ❌ pre-release |

If you're pinned to an older release, treat it as end-of-life: no
CVEs will be backported. The upgrade cost between minors is
deliberately kept small — the JSONL schema is additive, the CLI
grows flags but doesn't remove them, and each release ships a
`RELEASE_v*.md` note describing what moved.

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

Expect an acknowledgement within a week. Fixes for confirmed issues
land on `main` with a `RELEASE_v*.md` note calling out the CVE
identifier if one is assigned. Coordinated disclosure timing is
negotiated per-report.

## Passive-only guarantee

The mission statement in [`MISSION.md`](MISSION.md) §2 is the
canonical list of things sloth doesn't do. Any code change that
violates one of those rules is by definition a security issue and
should be reported through the same channel.
