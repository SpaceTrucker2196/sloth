#ifndef SLOTH_EVIDENCE_RING_H
#define SLOTH_EVIDENCE_RING_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* ── Bounded raw 802.11 evidence ring (#92) ───────────────────────
 *
 * The problem this exists for: a wireless detection usually has no IP
 * to match on. `alert_pcap_dump()` selects supporting packets by
 * `match_ip`, so an evil-twin, deauth-flood or KARMA alert — the
 * detections that are most of sloth's unique value — ships with zero
 * frames behind it. The general packet ring cannot stand in: it stores
 * `min(caplen, 64)` bytes, which on a radiotap capture is often the
 * radiotap header and little else.
 *
 * So this ring keeps the **whole captured frame, radiotap included**,
 * and is addressed by a monotonic event ID rather than by a flow. An
 * alert records the IDs of the frames that triggered it; an exporter
 * (a later slice of #92) pulls those IDs back out.
 *
 * Memory-only, by construction: **nothing here writes a file, and no
 * frame byte ever reaches one.** That matters beyond tidiness. Full
 * frames include EAPOL/PMKID material, and #87 gates *writing*
 * crackable material to disk behind `--collect-handshakes`. A ring that
 * cannot write cannot move that material past the gate, which is why
 * the ring can land while the question of what the on-disk exporter may
 * do is still open on #92.
 *
 * Stated that way rather than as "nothing here opens a file", which the
 * module contradicts: evidence_budget_from_meminfo() opens
 * /proc/meminfo to size the arena. That is a read of kernel-reported
 * memory, never a path to frame data, so the security property is
 * untouched — but a claim whose whole job is to justify landing before
 * the gate question is settled has to be exact, and the earlier wording
 * was refutable by a grep for fopen in this file.
 * `eapol_log.c` already buffers whole EAPOL frames in memory on the
 * same reasoning.
 *
 * ── Fidelity contract ──
 *
 * Each record carries what an analyst needs in order to distrust it
 * correctly:
 *   - `event_id`  unique and monotonic for the process lifetime;
 *   - `ts_sec`/`ts_usec`  the frame's OWN capture timestamp, passed in
 *     from the pcap record header. Never `time(NULL)` — see the clock
 *     note in `src/capture/probe.c`;
 *   - `orig_len`  the length the capture reports for the frame
 *     (`pcap_pkthdr.len`). As in the #92 EAPOL slice, this is what the
 *     capture *claims*, not an independently verified on-air length;
 *   - `cap_len`   bytes actually held in this record;
 *   - `truncated` set when `cap_len` is short of either the bytes
 *     libpcap handed over or `orig_len`. It deliberately does NOT say
 *     which of the two truncations happened — a kernel snaplen and this
 *     ring's own `EVIDENCE_FRAME_MAX` are indistinguishable from the
 *     record alone, and claiming otherwise would be the same
 *     over-reporting #92 is about;
 *   - `freq_mhz`/`signal_dbm`  decoded from radiotap as a convenience.
 *     The authoritative copy is the retained radiotap header itself,
 *     which is inside the stored bytes.
 *
 * ── Boundedness ──
 *
 * One heap arena of `budget` bytes used as a circular byte buffer, plus
 * a metadata ring sized from the same budget. Total footprint is fixed
 * at init and never grows: an attacker spraying frames cannot make
 * sloth allocate. When either the arena or the metadata ring is full the
 * oldest record is dropped and counted as `SH_EVICT_EVIDENCE_FRAME`,
 * because an evicted record is a lost observation and #91's rule is that
 * a bounded table either reports its losses or is not measured.
 *
 * Thread safety: `evidence_ring_note()` runs on the monitor capture
 * thread, everything else on the poll loop, so all of it takes a mutex.
 */

/* Largest number of bytes retained for one frame. A radiotap header plus
 * a full 802.11 MTU fits well inside this; the cap is what stops one
 * aggregated A-MSDU jumbo from evicting the rest of the ring. */
#define EVIDENCE_FRAME_MAX 4096

/* Smallest workable budget: enough arena for one maximum-size record
 * plus a usable number of metadata slots. init() refuses less rather
 * than silently running with a ring that cannot hold a frame. */
#define EVIDENCE_MIN_BUDGET 8192u

/* Budget clamp, per the owner's 2026-09-30 ruling on #92: ~1 % of
 * MemTotal, held between these bounds. Zero-config — no flag. */
#define EVIDENCE_BUDGET_FLOOR (2u  * 1024u * 1024u)
#define EVIDENCE_BUDGET_CEIL  (32u * 1024u * 1024u)

/* Metadata for one retained frame. The bytes live separately; pull them
 * with evidence_ring_get(). */
typedef struct {
    uint64_t event_id;    /* unique, monotonic; never reused */
    time_t   ts_sec;      /* frame's own capture clock */
    long     ts_usec;
    uint32_t orig_len;    /* length the capture reports for the frame */
    uint32_t cap_len;     /* bytes held in this record */
    uint16_t freq_mhz;    /* radiotap channel frequency, 0 if absent */
    int8_t   signal_dbm;  /* radiotap antenna signal */
    uint8_t  truncated;   /* 1 = cap_len is short of the whole frame */
} evidence_rec_t;

/* ~1 % of `mem_total_kb`, clamped to [FLOOR, CEIL]. A zero or absurd
 * input yields the floor — a sensor that cannot size itself keeps
 * evidence, it does not stop keeping it. */
size_t evidence_budget_from_mem_kb(uint64_t mem_total_kb);

/* Same, reading MemTotal from a /proc/meminfo-shaped file. Unreadable or
 * malformed yields the floor; `path` is a parameter so the clamp arms are
 * testable without a particular host's RAM. */
size_t evidence_budget_from_meminfo(const char *path);

/* Where the budget is read from on a live run. A parameter everywhere
 * else so the clamp arms are testable. */
#define EVIDENCE_MEMINFO_PATH "/proc/meminfo"

/* Allocate the ring. Returns 0 on success, -1 on a budget below
 * EVIDENCE_MIN_BUDGET or on allocation failure. Re-initialising frees
 * the previous ring first. */
int evidence_ring_init(size_t budget_bytes);

/* Bring the ring up at the RAM-derived budget if it is not up already,
 * and return 0 if it is usable afterwards.
 *
 * Idempotent on purpose. There are two moments a monitor radio can
 * appear — startup discovery, and an interactive [m] retarget — and the
 * ring has to exist for both or it silently stores nothing for the rest
 * of the session. A second call must leave an existing ring alone,
 * records and all: retargeting the radio is not a reason to discard the
 * evidence already collected. */
int evidence_ring_init_default(void);

/* Free the ring. Safe to call when it was never initialised. */
void evidence_ring_shutdown(void);

/* Retain one captured frame — `frame` is the full capture buffer, from
 * the first radiotap byte. `cap_len` is what libpcap handed over,
 * `orig_len` what it reports the frame's length to be.
 *
 * Returns the event ID assigned, or 0 when nothing was stored (ring not
 * initialised, or a NULL/empty frame). 0 is never a valid event ID. */
uint64_t evidence_ring_note(const uint8_t *frame,
                            uint32_t cap_len, uint32_t orig_len,
                            time_t ts_sec, long ts_usec,
                            uint16_t freq_mhz, int8_t signal_dbm);

/* Look a record up by event ID — no IP match, no flow, no time window.
 * This is the retrieval path the alert engine is meant to use.
 *
 * On a hit, `*out` is filled and up to `max` bytes are copied to `buf`
 * (`buf` may be NULL with `max` 0 for a metadata-only lookup); the
 * return value is the number of bytes copied, so a caller detects a
 * short buffer by comparing it against `out->cap_len`.
 *
 * Returns -1 when the ID was never issued or has been evicted. An
 * evicted record reads as absent, never as a different frame. */
int evidence_ring_get(uint64_t event_id, evidence_rec_t *out,
                      uint8_t *buf, size_t max);

/* Records currently retained, and the highest event ID issued. */
int      evidence_ring_count(void);
uint64_t evidence_ring_last_id(void);

/* Arena bytes in use, arena bytes available, and the whole allocation
 * (arena + metadata) — the figure that must stay inside the budget. */
size_t evidence_ring_bytes_used(void);
size_t evidence_ring_capacity(void);
size_t evidence_ring_footprint(void);

/* Drop every retained record, keeping the allocation. Event IDs continue
 * from where they were: an ID must not come to mean a second frame. */
void evidence_ring_reset(void);

#endif /* SLOTH_EVIDENCE_RING_H */
