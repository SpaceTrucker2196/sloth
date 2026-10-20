---
name: compiler-coverage
description: Which compilers and architectures sloth is actually built and tested on, and the alignment, endianness and integer-width assumptions its parsers and platform code make.
type: reference
---

# Compiler and architecture coverage

**Summary**: sloth is built, tested and sanitised on exactly one target:
gcc on x86-64 Linux, on GitHub's `ubuntu-24.04` runner. Everything else
is unverified. The packet parsers are written so that host alignment and
byte order do not matter — every multi-octet wire field is assembled
from single bytes — but the netlink platform code and a few `long`
timestamps do make x86-64 / LP64 assumptions, listed below.

**Sources**: `.github/workflows/ci.yml`, `Makefile`, `src/bytes.h`,
`src/radiotap.c`, `src/capture/capture.c`, `src/dns_snoop.c`,
`src/platform/linux_wifi.c`, `src/platform/linux_tcpdiag.c`,
`src/wifi_snapshot.c`, `src/posture.c`, `src/stab.h`.

**Last updated**: 2026-10-19 (#95)

---

## What CI builds on

| Job | Compiler | Arch / OS | Flags of note |
|---|---|---|---|
| six configs, `make test` | gcc (the runner's default, gcc 13 on Ubuntu 24.04) | x86-64, `ubuntu-24.04` | `-std=c99 -Wall -Wextra -Werror`, `-O2`, `_FORTIFY_SOURCE=3`, PIE |
| sanitize | same gcc | same | `-Werror -fsanitize=address,undefined -fno-sanitize-recover=all`; suite, capture path, link check of `sloth` and `embedded`, replay |
| tsan | same gcc | same | `-Werror -fsanitize=thread`; `make test` and `make test-capture-path` |
| cppcheck | cppcheck (Ubuntu 24.04 package), not a compiler | same | `make cppcheck`, default `-D` set only |
| replay | same gcc | same | the shipped `sloth`, run on generated savefiles |
| fuzz | clang (runner default) with libFuzzer | same | `-fsanitize=fuzzer,address,undefined` |
| harden | same gcc | same | `readelf` checks on the linked binary |

There is no second architecture, no 32-bit build, no big-endian build,
no musl build and no macOS / BSD job. `src/platform/bsd.c`, `win32.c`
and `stub.c` exist and the Makefile selects them by `uname`, but no job
compiles them, so they should be read as unbuilt.

Local development has used newer gcc than CI (gcc 15 on Debian/Kali for
#95's close-out). A diagnostic that one gcc version emits and another
does not is normal — #95's three ASan-only warnings were reproduced on
gcc 15 and gcc 14 and cleared on both, not on gcc 13 itself — so CI's
result on gcc 13 is the one that counts.

## Parsers: byte reads, not casts

Wire data is never read through a struct overlay or a cast to a wider
integer pointer. Every multi-octet field goes through `src/bytes.h`:

- `be16` / `be32` / `le16` / `le32` / `le48` assemble the value from
  individual `uint8_t` loads and shifts, so they are correct at any
  address and on either host byte order;
- the bounded cursor (`rd_t`, `rd_be16()` …) and the TLV iterator
  (`tlv_next()`) are built on the same loads and add the length check.

Fixed-size blobs that the kernel or libc wants as a struct are copied
out with `memcpy`, never cast in place — for example the A / AAAA
RDATA into `struct in_addr` / `struct in6_addr` in `src/dns_snoop.c`,
and the 6-octet MAC addresses in every 802.11 observer. This matters
because none of sloth's input is aligned: a radiotap header puts the
802.11 header at whatever offset `it_len` says, an Ethernet header
leaves the IP header at offset 14, and an attacker controls every
length in between.

Radiotap is the one format with alignment *in the format*: each field is
naturally aligned relative to the start of the radiotap header
(`RT_PAD()` in `src/radiotap.c`). That is padding to skip, not an
alignment the host relies on — the fields themselves are still read a
byte at a time.

Consequence: the parsers' results do not depend on host alignment or
endianness. That is a property of how the code is written, checked by
reading it; it is not tested on a second architecture, because CI has
none.

## Where the code does assume the host

These are the places that would need attention for a port. None is a
bug on the CI target.

- **Netlink attribute reads cast in place.** `src/platform/linux_wifi.c`
  reads nl80211 attributes as `*(const uint32_t *)NA_DATA(...)` and, for
  the byte counters, `*(const uint64_t *)`; `src/platform/linux_tcpdiag.c`
  casts its receive buffer to `struct nlmsghdr`. Netlink is host-endian by
  definition, so byte order is fine, but attributes are only 4-octet
  aligned (`NLA_ALIGNTO`) and the receive buffers are `uint8_t` / `char`
  arrays with no alignment of their own. On x86-64 and arm64 an unaligned
  load works; on a strict-alignment CPU the 64-bit reads could trap.
  UBSan's alignment check would report it, but no test feeds a live
  netlink reply through this path — it runs against the kernel only.
- **`long` for some timestamps.** `wifi_snapshot_write()` takes the time
  as `long`, and `posture.c` prints durations through `(long)` casts.
  On LP64 (x86-64, arm64) `long` is 64-bit; on an ILP32 target with a
  64-bit `time_t` these would truncate after 2038.
- **`time_t` width is not asserted.** `stab.h` checks a row's
  last-seen field has `sizeof(time_t)`, which keeps the eviction maths
  consistent, but nothing asserts `time_t` is 64-bit.
- **`int` for lengths and offsets.** Parsers carry lengths as `int`.
  The capture snaplen is 65535 and DNS / TLV lengths are 16-bit, so
  `off + len` stays far inside a 32-bit `int`; nothing relies on `int`
  being wider than 32 bits.
- **`char` signedness is not audited.** Packet bytes are `uint8_t`
  throughout the binary parsers; the text protocols (HTTP, SMTP, IMAP,
  POP3, FTP) scan `char` buffers. x86-64 `char` is signed and arm64
  `char` is unsigned, and no audit has checked that a byte ≥ 0x80 is
  classified the same on both.

## Why this is enough for now

The charter target is a Linux sensor, and the CI target is the one the
owner runs. A second architecture would be a new CI job and a ruling,
not a code change. What this page is for is making the assumptions
visible so a port starts from the list above rather than discovering it.

## Related pages

- [[architecture]]
- [[platform-vtable]]
- [[release-checklist]]
- [[threat-model]]
