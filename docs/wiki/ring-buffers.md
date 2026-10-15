---
name: ring buffer architecture
description: The bounded-history pattern shared by every per-protocol log file
type: architecture
---

# Ring-buffer architecture

The per-protocol log files
(`src/dns_log.c`, `src/tls_log.c`, `src/quic_log.c`,
`src/http_log.c`, `src/ntp_log.c`, `src/icmp_log.c`) and the more
specialised event logs
(`src/deauth_snoop.c`, `src/eapol_log.c`, `src/scan.c`, etc.) all
share a single bounded-history pattern: a fixed-size ring of
recent records, a head pointer marking the next write slot, and a
saturating count of populated entries.

Documenting it once here lets per-file commentary stay focused on
the protocol parsing instead of repeating the buffer mechanics, and
it grounds the mutation-testing equivalence classes
([[mutation-testing]]) that ignore the boundary mutations on this
shape.

## The pattern

```c
static <type> g_log[MAX_<PROTO>_LOG];     // fixed-size ring
static int    g_head  = 0;                // next write slot
static int    g_count = 0;                // entries populated (≤ MAX)
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
```

Three operations are exposed:

### record

```c
void <proto>_log_record(const <type> *e) {
    pthread_mutex_lock(&g_mu);
    g_log[g_head] = *e;
    g_head = (g_head + 1) % MAX_<PROTO>_LOG;
    if (g_count < MAX_<PROTO>_LOG) g_count++;
    pthread_mutex_unlock(&g_mu);
    jsonl_emit_<proto>(e);          // mirror to the JSONL stream
    // optional: feed other caches (e.g. dns_log_record → host_cache_add)
}
```

Three invariants matter:

1. `g_head` is the index of the *next* write — already-written
   slots are at `g_head - 1`, `g_head - 2`, … (modulo `MAX`).
2. Once `g_count == MAX`, the increment becomes a no-op. The
   ring's capacity is the cap; new writes overwrite the oldest.
3. The JSONL emit runs **outside** the mutex hold for emitters
   that themselves take other locks (jsonl uses its own mutex
   plus the data-socket's broadcast lock). Holding the
   per-protocol mutex during the emit would invite deadlock with
   a consumer that triggers a record from the broadcast path.

### snapshot

```c
void <proto>_log_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = g_count < MAX_<PROTO>_LOG ? g_count : MAX_<PROTO>_LOG;
    for (int i = 0; i < n; i++) {
        int idx = ((g_head - 1 - i) % MAX_<PROTO>_LOG +
                   MAX_<PROTO>_LOG) % MAX_<PROTO>_LOG;
        s-><proto>_log[i] = g_log[idx];
    }
    s-><proto>_log_count = n;
    s-><proto>_log_head  = g_head;
    if (s-><proto>_log_sel >= n) s-><proto>_log_sel = n > 0 ? n - 1 : 0;
    pthread_mutex_unlock(&g_mu);
}
```

Properties:

- Writes the most-recently-recorded entry into `s->log[0]`, so the
  views render newest-first without extra sorting.
- The `((idx) % MAX + MAX) % MAX` dance is the standard C
  workaround for negative-modulo: `(g_head - 1 - i)` can go
  negative when `g_count < MAX`; the outer `+ MAX` lifts it back
  into range before the second `% MAX` normalises.
- The `n > 0 ? n - 1 : 0` selection clamp is a real semantic
  invariant — tests must verify both branches (see
  `tests/test_<proto>_log.c::test_snapshot_clamps_sel_at_boundary_and_empty`).

### clear

```c
void <proto>_log_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_head  = 0;
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
```

Test helper plus the `[c] Clear` key binding. Resetting `g_head`
isn't strictly required for correctness — old entries past the
new `g_count` are unreachable until overwritten — but doing so
makes the ring contents deterministic at the start of any test.

## Variations

### NTP and ICMP omit the snapshot clamp

`ntp_log_snapshot` and `icmp_log_snapshot` read `n = ntp_count` /
`n = icmp_count` directly, without the
`count < MAX ? count : MAX` ternary the other four use. Both
maintain the saturating-count invariant in their `*_record`
functions, so `count` is already bounded by `MAX_*_LOG`. The
explicit ternary in `dns_log`/`tls_log`/`quic_log`/`http_log` is
defence-in-depth.

This matters for mutation testing: the snapshot-clamp mutation
class (`<` → `<=` on the ternary's comparison) is in the
equivalence file for the four-file family but not for NTP/ICMP,
because there's no ternary on those lines to mutate.

### The evidence ring is bounded by bytes, not by rows

`src/evidence_ring.c` (#92) is the one ring whose records are
variable-length, because it retains **whole captured 802.11 frames
including radiotap** rather than a fixed-size decoded struct. The
`min(caplen, 64)` the general packet ring keeps is enough to show a
frame in a view and not nearly enough to reconstruct one, and a
wireless alert — evil twin, deauth flood, KARMA — has no IP for the
per-alert pcap exporter to match on, so without this it ships with no
supporting frames at all.

So the shape differs in four ways:

- **Two bounds, both enforced on every push.** A heap arena used as a
  circular *byte* buffer, plus a FIFO ring of fixed-size metadata slots.
  Payloads are variable-length, so the arena bounds bytes and the slot
  ring bounds record count; a ring watching only one is unbounded in the
  other direction. Tiny frames (an ACK is 14 bytes) exhaust slots long
  before the arena, and one 4 KiB jumbo does the reverse.
- **Sized from system RAM at startup, not by a `MAX_*` constant.** ~1 %
  of `MemTotal` from `/proc/meminfo`, clamped to `[2 MiB, 32 MiB]`
  (owner ruling, 2026-09-30). Zero-config, no flag; an unreadable or
  malformed `/proc/meminfo` — including every non-Linux build — falls
  back to the floor, so a sensor that cannot size itself keeps less
  evidence rather than none.
- **Addressed by event ID, not by recency.** `evidence_ring_get()` takes
  a `uint64_t` event ID and nothing else — no address, no port, no
  window. IDs are issued only once arena space is secured, so live IDs
  form a contiguous range and the lookup is O(1) rather than a scan. The
  index that follows from that invariant is still verified against the
  slot's own ID before the record is returned: if the invariant ever
  breaks, an evidence lookup must miss, never hand back a different
  frame under the requested ID.
- **Eviction is counted.** Dropping the oldest record bumps
  `SH_EVICT_EVIDENCE_FRAME`, surfaced as `evict_evidence_frame` in
  `sensor_health` ([[jsonl-schema]]). An evicted record is a lost
  observation; on a busy channel the ring evicts steadily by design, so
  a rising count is a depth figure, not a fault.

Per-record fidelity is the other half of why it exists, and the contract
is in `src/evidence_ring.h`: the frame's own capture timestamp (never
`time(NULL)`), both the reported original length and the stored captured
length, and a `truncated` flag that deliberately does **not** claim
*which* truncation occurred — a kernel snaplen and the ring's own
`EVIDENCE_FRAME_MAX` cannot be told apart from the record alone.

Memory-only by construction: nothing in the module opens, names or
writes a file. That is what keeps it clear of the `--collect-handshakes`
gate ([[pcap-export]]), since full frames include EAPOL/PMKID material
and a ring that cannot write cannot move that material to disk.

### The wired packet ring is a snapshot, not a shared buffer (#111)

`s->packets[MAX_PACKETS]` / `pkt_head` / `pkt_count` / `pkt_total` on
`sloth_state_t` look like the pattern above and, until #111, were not
an instance of it. `on_packet()` in `src/capture/capture.c` wrote them
*directly* on the capture thread under the module's private `g_mu`,
and the readers on main — `views/packets.c`, `bandwidth.c`,
`pcap_write.c`, `ip_color.c`, `alerts.c`, `jsonl.c`, `alert_pcap.c` —
never took that lock, because a static in another file is not
something they could take. The lock protected the writer from the
writer.

Since #111 the ring is private to `capture.c` (`g_ring`, `g_ring_head`,
`g_ring_count`, `g_ring_total`) and main gets a copy once per poll:

```c
void capture_ring_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    memcpy(s->packets, g_ring, g_ring_count * sizeof(g_ring[0]));
    s->pkt_head  = g_ring_head;
    s->pkt_count = g_ring_count;
    s->pkt_total = g_ring_total;
    pthread_mutex_unlock(&g_mu);
}
```

`poll_data()` calls it **first**, before `bw_update()` walks the ring
from `pkt_bw_cursor` and before the JSONL emitters compare
`pkt_total` against `pkt_jsonl_emitted`. Head, count and total keep
their meanings exactly, so no reader changed; this is the same copy
`mon_frame_snapshot()` has made for the 802.11 stream since #21. The
one difference from the `*_log_snapshot` shape above is that the slots
are copied positionally (`[0, count)`) rather than re-ordered newest
first, because every reader already does its own modulo walk from
`pkt_head`.

The test seam `capture_test_dispatch()` seeds the private ring from
the caller's state before dispatching and snapshots back into it
after, so a test's `sloth_state_t` remains the whole premise and the
whole result, as it was when `on_packet()` wrote it directly.

The same review found `src/fragattack.c` — fed by the probe thread,
read by `frag_snapshot()` and `rule_fragattack()` on main — with no
mutex at all, the one capture-fed module in that state; #111 gave it
one. Both fixes are proved by the ThreadSanitizer CI job, not by the
concurrent tests that accompany them: a single writer against a
reader cannot lose an update, so those tests pass with the lock
deleted, and TSan is what turns the deletion red
(`tests/test_fragattack.c :: test_frag_observe_concurrent_with_snapshot`,
`tests/test_capture_path.c :: test_ring_snapshot_is_stable_under_writer`).

### Specialised event logs deviate further

`src/eapol_log.c` adds a per-(BSSID, STA) pending-handshake state
table alongside the ring. `src/deauth_snoop.c` keys by
(target MAC, BSSID) instead of treating each frame as independent.
`src/scan.c` uses a TTL-decay rather than a strict ring (entries
age out instead of being overwritten). These files are *related*
to the ring pattern but not strict instances; they document their
own state on the file's `## Storage` comment block.

## Mutation testing

The pattern's boundary mutations are documented equivalents and
ignored by `make mutate` via
`.github/scripts/mutate-equivalents.txt`:

- **LZT — saturating-add bound**: `if (g_count < MAX) g_count++;`
  mutated to `<=` is observationally identical, because once
  `g_count == MAX`, further increments would have no observable
  effect (the value stays bounded and indexes past the ring
  wrap correctly either way).
- **LZT — snapshot clamp**: `g_count < MAX ? g_count : MAX`
  mutated to `<=`. Same reasoning — the clamp is only meaningful
  when `g_count == MAX`, and at that boundary both comparisons
  pick the same branch.
- **LZT — snapshot loop bound**: `for (int i = 0; i < n; i++)`
  mutated to `<=`. The extra iteration reads `g_log[<<oldest>>
  - 1 mod MAX]` which is zero-initialised at startup and
  overwritten by every subsequent fill; no observable behaviour
  change for any seeded test state.
- **SBL — stack buffer sizing literal**: declarations like
  `char ja3_str[512]` or `char host[64]` mutated ±1. The
  `snprintf` calls truncate at either size; the test fixtures
  never reach the truncation threshold, so the observable output
  is identical.

These four classes account for the bulk of the equivalents in the
file under each `*_log.c` header. The
`tests/test_<proto>_log.c::test_snapshot_clamps_sel_at_boundary_and_empty`
tests do *not* fall under any equivalence — they exercise the
real semantic invariant on `*_log_sel` and would catch a mutation
that turned `n > 0 ? n - 1 : 0` into `n - 1` (the empty case
overflow).

## Related pages

- [[architecture]] — where this pattern fits in the broader
  source map.
- [[mutation-testing]] — the harness that consumes the
  equivalence file built around this pattern.
- [[jsonl-schema]] — the wire format the `*_log_record` emit
  hook feeds into.
- [[ja3-fingerprinting]] — the TLS log's JA3 builder uses one of
  the SBL-bounded scratch buffers documented here
  (`ja3_str[512]`).
