---
name: replay-integration
description: --replay / --ticks and the replay-check CI gate — the one test that executes the shipped sloth binary, on savefiles generated at run time
type: reference
---

# Replay integration (`--replay`, `make replay-check`)

**Summary**: `sloth --replay FILE[,FILE] --ticks N` reads libpcap
savefiles instead of opening an interface and exits after `N` poll
ticks. `make replay-check` uses it to run the shipped binary end to end
in CI — `main()`, the poll loop, the alert engine, the JSONL and SQLite
sinks — on two savefiles generated at test time from hand-built byte
arrays, and diffs the normalised JSONL against a committed golden. It is
the only gate that executes `sloth`; `sloth_test` has its own `main()`
and links none of `src/main.c`.

**Sources**: issue #119 (owner ruling 2026-10-15), `src/capture/replay.c`,
`src/main.c` (argv loop, startup, poll loop), `tests/replay/gen_replay.c`,
`tests/replay/normalise.sh`, `tests/replay/golden.jsonl`, `Makefile`
(`replay-check`), `.github/workflows/ci.yml` (`replay`, `sanitize`),
`.github/scripts/mutate.py` (`--target`), `tests/test_replay.c`,
`tests/test_build_recipe.c` (suite "replay gate").

**Last updated**: 2026-10-19.

---

## Why it exists

Before #119, `ci.yml` said it plainly: "nothing here executes the
binary". MISSION §2 forbids running sloth against an interface and CI
has none, so `sloth` was compiled and linked — under ASan too — and never
run. Argument parsing, the startup ordering (#85's scope seal, #140's
privilege drop, sink opening) and the poll loop were reachable only by
hand. `make mutate` had the same blind spot: its oracle was `make test`,
so a mutant in `src/main.c` could only ever survive.

## The flags

Full table: [[cli-reference]] ("Replay"). In short:

- **Routing is by the file's datalink**, the way the live handles split
  the world: Ethernet (1) and Linux cooked v1/v2 (113/276) go through
  `on_packet()`, radiotap (127) through the monitor path's
  `on_probe_frame()`. Anything else is refused at startup, before a sink
  opens, so a bad file leaves no JSONL, DB session or socket behind.
- **Each record keeps its own capture time and wire length.** The
  dispatch seams default both (synthetic stamps, `len == caplen`);
  `--replay` passes the file's values through. The one loss: the
  sub-second part is not carried on either path — the savefile builder
  both seams share writes a synthetic `ts_usec` (record index × 1000
  within a batch), so `packet.ts_usec` in a replay is not the file's.
- **Decoded synchronously, before the first tick.** Tick 1 sees every
  file in full, so a run is a function of its inputs rather than of how
  a decode thread raced the poll loop.
- **No host state.** `replay_platform_install()` points every platform
  op at an empty source: no interfaces, sockets, ARP, DHCP or Wi-Fi scan.
  A replay describes its files, not the machine that ran it — which is
  also what lets one golden pass on every host.
- `sensor_health` reports `capture_iface` / `monitor_iface` as `replay`
  ([[jsonl-schema]]).
- Refused with `--iface`, `--monitor-only` and `--hop`, which name live
  capture and would otherwise be silently inert.

## The gate

```
make replay-check      # generate → replay → normalise → diff
make replay-golden     # rewrite tests/replay/golden.jsonl from this tree
```

1. `build/replay/gen_replay` (from `tests/replay/gen_replay.c` and
   `src/pcap_format.c`, the production savefile writer) writes
   `wired.pcap` and `monitor.pcap` into `REPLAY_DIR`. Every frame is
   built field by field with `tests/frame_build.h`, checksums computed
   per RFC 791/768/793/792: a DNS query and answer for a name on the
   synthetic IOC list, a TCP SYN, an HTTP request carrying Basic
   credentials, an ICMP echo pair; three beacons, a probe request and
   twelve deauthentications. Addresses are RFC 5737 and
   locally-administered only.
2. `sloth --headless --replay … -o … --db … --ticks 3` runs them.
3. `tests/replay/normalise.sh` replaces timestamps with `"T"` (non-zero)
   so 0 and -1 stay distinguishable, per-run incident/event IDs with
   `"ID"`, and per-host process facts (RSS, heap, descriptors, library
   versions, stale-seconds) with `"X"`, then sorts.
4. `diff -u` against the golden.

**No savefile is committed.** `tests/` holds no `.pcap` and the
generator is the audit trail for the input ([[sloth]], AGENTS.md "No
pcap fixtures"). Only the normalised **output** is committed, so a
behaviour change arrives as a diff of records in the PR that made it.

### What the golden does and does not pin

- It pins the multiset of records over three ticks: a record that
  changes, appears or disappears is red.
- It does **not** pin which tick a record came from. Records carry no
  tick number, so there is no boundary to sort within; the whole stream
  is sorted.
- Wall-clock-dependent behaviour is exercised only at "now": the
  generator stamps frames from the current time because sloth ages its
  tables against the wall clock, and a fixed historical epoch would
  replay into empty tables. The output was checked identical across
  repeated runs and at `--refresh-ms` 100 and 1000 before the golden was
  first committed.

### Updating the golden

Run `make replay-golden`, read the diff, and commit it with the change
that caused it, saying in the message why the records moved. A golden
rewritten to make a red job green without that sentence is the failure
this gate exists to catch.

## CI

- Job `replay` (`ubuntu-24.04`, `-Werror`): `make replay-check`.
- Job `sanitize`, step "Replay under ASan + UBSan": the same with the
  binary instrumented, `-fno-sanitize-recover=all`, and leak detection
  on, so sloth's shutdown path is checked too.

## Mutation testing

`mutate.py --target replay-check` judges each mutant by the replay gate
instead of `make test`; `--target all` requires both to stay green for a
mutant to survive. Use it for `src/main.c`:

```
make mutate MUTATE_FLAGS="--files src/main.c --target replay-check --limit 20"
```

The gate's own mutation proof (#119): changing the deauth-flood rule's
non-owned severity from WARN to LOW in `src/alerts.c` turns
`make replay-check` red on the `DEAUTH_FLOOD` records; restoring it
turns it green.

## Related pages

- [[cli-reference]] — the `--replay` / `--ticks` rows and exit codes.
- [[mutation-testing]] — the harness `--target` extends.
- [[jsonl-schema]] — the records the golden is made of.
- [[architecture]] — the capture seams `--replay` drives.
