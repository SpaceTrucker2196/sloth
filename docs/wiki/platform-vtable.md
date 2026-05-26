---
name: platform-vtable
description: The platform_ops_t vtable — the kernel seam that keeps views portable and testable
type: reference
---

# Platform vtable

**Summary**: `platform_ops_t` in `include/sloth.h` is the seam between kernel-facing code and the rest of sloth. Views never call platform ops directly; they read `sloth_state_t`. The test suite swaps the vtable for `tests/fake_platform.c`.

**Sources**: `CLAUDE.md`, `docs/views/connections.md`, `docs/views/interfaces.md` (referenced).

**Last updated**: 2026-05-25.

---

## Why the seam matters

- Lets the test suite drive views with deterministic kernel-state
  fixtures (no rtnetlink chatter, no `/proc` reads).
- Keeps Linux-specific code (`rtnetlink`, `nl80211`, `INET_DIAG`,
  `/proc/net/*`) confined to `src/platform/linux*.c`.
- Makes per-view code portable: a view that only touches
  `sloth_state_t` doesn't care whether the data came from netlink or
  a fake.

## What lives behind it

- rtnetlink — interface enumeration, MAC, MTU, link state.
- nl80211 — WiFi station info, RSSI, channel.
- `/proc/net/{tcp,tcp6,udp,udp6}` — socket table.
- `/proc/<pid>/fd/*` — inode → PID mapping (so [[connections]] can show
  process names).
- `INET_DIAG` netlink — per-socket RTT and retransmits.
- sysfs — interface counters used by the bandwidth smoother.

## Discipline

- **Views never call platform ops directly.** They read
  `sloth_state_t`.
- **No mocks of real-data interfaces.** The fake platform in
  `tests/fake_platform.c` lives there so the seam stays narrow.
- Errors at boundaries only (user input, syscalls, parsing). Trust
  internal code beyond the platform layer.

## Related pages

- [[architecture]]
- [[sloth]]
- [[views-catalog]]
