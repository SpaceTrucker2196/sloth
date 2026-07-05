---
name: version-checkin
description: Architecture recommendation for periodic release checks and a safe self-update handoff
type: architecture
---

# Version check-in

**Summary**: sloth can support low-interruption version awareness, but the safe design is a split system: an in-process checker that only discovers newer releases, and a separate update path that downloads, builds, installs, and restarts outside the capture loop.

**Sources**: `include/sloth.h`, `src/main.c`, `src/event_wake.c`, `src/data_socket.c`, `README.md`, `RELEASE_v1.4.0.md`, `SECURITY.md`.

**Last updated**: 2026-07-02.

---

## Requirement

Issue #18 asks for an automated version check-in that regularly checks for
new releases and updates sloth with minimal interruption by downloading the
latest source and building it.

## Current state

- The running version is compile-time state only:
  `#define SLOTH_VERSION "1.4.0"` in `include/sloth.h`.
- The current upgrade story is manual. `RELEASE_v1.4.0.md` documents:
  `git pull` then `make`.
- `src/main.c` runs a tight poll/render/key loop. Blocking network I/O in
  that loop would stall the TUI.
- `src/event_wake.c` already provides the right wake-up pattern for async
  work that needs to refresh the screen early.
- `src/data_socket.c` shows the style sloth already uses for bounded,
  non-blocking, mutex-protected side channels.

## Design goals

- **Low interruption**: version checks must not freeze the interface.
- **Safe install boundary**: building and replacing the binary must not
  happen inside the render loop.
- **Explicit trust model**: the updater must verify what it downloads.
- **Graceful offline behaviour**: no network reachability must degrade into
  "do nothing" rather than break capture.
- **Minimal blast radius**: the new logic should sit behind a narrow module
  boundary instead of spreading through protocol or view code.

## Recommended architecture

### 1. Checker inside sloth

The first component should only answer one question: "is a newer version
available?"

- Run on a timer in a background thread or helper process.
- Fetch release metadata only (latest tag, release URL, checksum manifest).
- Compare it against `SLOTH_VERSION`.
- Store a small immutable snapshot: current version, latest version, last
  checked time, release URL, error state.
- Signal completion through the existing wake pattern so the UI can redraw
  without waiting for the full poll interval.

This keeps the main loop's contract intact: poll state, draw, wait for
input, wake early if a side event happened.

### 2. Updater outside the capture loop

The second component should do the disruptive work:

- download a release tarball or source archive
- verify integrity/authenticity
- unpack into a staging directory
- build with the project's existing `make` targets
- replace the installed binary atomically
- restart sloth or defer activation until next launch

That step should not overwrite the currently running executable from inside
the main UI path. A separate helper keeps failure handling clear and avoids
mixing package-management concerns with passive packet observation.

### 3. Operator-facing behaviour

The least noisy default UX is:

1. periodic background check (for example every 6-24 hours)
2. passive "update available" indicator in the UI
3. optional manual trigger to check now
4. optional explicit "apply update on next clean exit" action

That matches the issue's "minimal interruptions" requirement better than an
immediate forced rebuild while the user is monitoring traffic.

## Safe boundaries

- **No blocking network calls in `src/main.c`**.
- **No self-overwrite in-place while the binary is still running**.
- **No unauthenticated download/build path**.
- **No silent privilege expansion**: if install needs elevated rights, keep
  that step explicit.
- **No hard dependency on the check service**: GitHub down, DNS down, or no
  network should leave sloth usable.

## Recommended implementation phases

1. ✅ **Policy + docs** *(landed)*
   - Supported-version policy in `SECURITY.md`.
   - Check cadence: `updater_tick` re-reads at most once every 60 s.
   - Release source: locally-populated manifest file (see [[manifest-format]]),
     because the safest first landing is one where sloth itself never
     touches the network — a helper process (systemd timer, cron)
     produces the file. That satisfies the "background thread OR
     helper process" wording of the original recommendation.
2. ✅ **Version model** *(landed)*
   - `src/version.{c,h}` — semver parse + compare, RFC-ish, with the
     `1.10.0` > `1.9.0` trap covered by unit tests.
3. ✅ **Notify-only checker** *(landed, phase 3.1)*
   - `src/updater.{c,h}` reads the manifest, compares to
     `SLOTH_VERSION`, exposes status through the existing
     poll-and-snapshot pattern.
   - `--check-manifest FILE` CLI flag; omitted → checker disabled.
   - Status surfaces in the help view — no dashboard clutter until
     the operator explicitly enables checks.
   - Reference producer: `examples/updater/check-latest.sh`.
4. ⏳ **Manual apply path** *(deferred — separate landing)*
   - Implement a separate updater helper or exec path that stages a
     source build outside the render loop.
5. ⏳ **Optional unattended mode** *(deferred — after phase 4)*
   - Only after the manual path is stable.
   - Keep it opt-in and policy-controlled.

## Integrity model

The updater should prefer a release tarball plus an authenticated manifest
or checksum file over a raw `git pull`. The current manual upgrade text in
`RELEASE_v1.4.0.md` is fine for a human, but an automated path needs an
artifact-oriented trust decision, not "whatever the current branch tip is".

## Test plan for a future implementation

- unit tests for version parsing/comparison
- tests for "newer version available" vs "already current"
- tests that failed network checks only update error state
- tests that the UI loop remains responsive while a check is in flight
- tests for staged build/install failure paths
- tests for restart/defer semantics

## Open questions

- What is the trusted release source: GitHub API, signed manifest, or both?
- Should default behaviour be "notify only" or "download and stage"?
- When an update is ready, should sloth restart itself or prompt for restart?
- Where should staged source/build artifacts live?
- Should auto-apply be allowed when sloth is running as root for capture?

## Recommendation

For sloth specifically, the safest plan is **check in-process, apply
out-of-process**. That delivers regular version awareness with minimal user
interruption, while keeping network fetch, source build, install, and
restart concerns outside the passive-monitoring hot path.

## Related pages

- [[architecture]]
- [[sloth]]
- [[platform-vtable]]
- [[jsonl-schema]]
