---
title: Shared parsers ship as libsloth-wire; no cross-repo source includes
date: 2026-11-05
status: Accepted
authority: issue #184 §2 (decision 4) and C3, §6 ("Dash and sensor disagreeing about a frame"); owner ruling on #184 §5 item 4 of 2026-11-04 (the contract artifact lives on sloth's GitHub releases)
---

# ADR 0004 — Shared parsers ship as `libsloth-wire`; no cross-repo source includes

## Context

slothweb links sloth's leaf parsers from source. `WEB_CORE_SRCS`
(`Makefile:717–718`) compiles `src/dot11_frame.c`, `src/radiotap.c`,
`src/wifi_freq.c`, `src/dns_wire.c`, `src/dot11_ie.c` and
`src/netstr.c` straight into the `slothweb` binary, and the alert page's
packet capture (`web/src/web_pcap.c`) reads a radiotap header, a MAC
header, its elements and a DNS name with sloth's own code.

The reason is in the `Makefile`'s own comment (626–629): **the page and
the sensor cannot disagree about a frame.** That guarantee is the thing
to keep. The mechanism — compiling another directory's `.c` files, with
`-iquote src` so the headers resolve as bare names — is the thing that
cannot survive a repository split.

## Decision

`sloth` exports the shared parsers as **`libsloth-wire`** (#184 §2,
decision 4; C3):

- a static archive (`libsloth-wire.a`), its headers, and a
  `sloth-wire.pc` pkg-config file, with a `make install-dev` target;
- built from the same source set that `WEB_CORE_SRCS` names today,
  compiled from `CORE_SRCS` objects, with **no `include/sloth.h`
  dependency** — a wire parser must not need the sensor's state struct;
- `sloth-dash` builds against it at a **pinned version**, named in a
  `contract.lock` file;
- **no cross-repository `#include`.** Not of a header, and not of a
  `.c`.

The archive and its headers travel in the contract artifact, which the
owner ruled on 2026-11-04 lives on `sloth`'s GitHub releases (#184 §5
item 4).

The guarantee survives by pinning rather than by sharing: a bump of
`libsloth-wire` is a commit in `sloth-dash` that says why (#184 §6).

`OPEN — needs owner ruling`: **what the archive contains.** #184 C3
describes `WEB_CORE_SRCS` and names `rsn_ie.c` as one of its members. It
is not: `rsn_ie.c` reaches `web/` only through `WEB_TEST_SRCS`
(`Makefile:727–729`), together with `db_schema.c`, `ip_color.c`,
`tui_palette.c`, `tui.c` and `view_labels.c`. So the test link line
shares six `src/` files that the binary link line does not, and
`libsloth-wire` as C3 describes it covers none of them. Either the
archive is wider than C3 says — wide enough to include `tui.c`, which is
the TUI — or `sloth-dash`'s tests need another answer for those six.
`src/db_schema.c` already has one (C2 ships `schema.sql`) and
`src/tui_palette.c` and `src/tui.c` partly have one (C5 ships
`palette.json`); `rsn_ie.c`, `ip_color.c` and `view_labels.c` do not.
See [architecture-split.md](../architecture-split.md) §5 item 2.

## Consequences

Accepted:

- The page and the sensor can now disagree about a frame for exactly as
  long as `sloth-dash`'s pin is behind `sloth`. The pin makes the window
  visible and bounded; it does not close it.
- `sloth` gains a published API surface it did not have: the headers in
  the archive become an external contract, so renaming one of their
  functions is a stop-and-ask under `agents/dark-factory.md` §4.3 rather
  than a refactor.
- `libsloth-wire` has to build without `include/sloth.h`. That is close
  to true today — the `Makefile` comment at 626 says each file under
  `WEB_CORE_SRCS` includes only its own header and the leaf headers
  beside it, with one call out answered by `web/src/web_sh_stub.c` for
  `dot11_ie.c`'s `sh_parse_fault_note()`. That stub is the seam the
  archive has to define rather than borrow.
- `make contract` becomes a release step with a test behind it: a
  ten-line program, compiled against the unpacked archive in a temporary
  directory, decodes one radiotap header (#185 item 4).

Paid for by:

- One more artifact to publish per `sloth` release, and a pin to move in
  `sloth-dash` per bump.

## Related pages

- [ADR index](README.md)
- [ADR 0001 — three repos](0001-three-repos.md)
- [ADR 0007 — versioning](0007-versioning.md) — how the pin is named.
- [Architecture split inventory](../architecture-split.md) — the measured parser coupling.
- [slothweb](../slothweb.md)
