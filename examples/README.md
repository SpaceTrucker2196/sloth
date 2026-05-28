# sloth examples

Self-contained reference programs that exercise sloth's external
contracts. Each subdirectory is independent — no shared build, no
shared dependencies.

| Path                                              | What it shows |
|---------------------------------------------------|---------------|
| [`consumer/`](consumer/) (Python 3, stdlib only)  | Reading sloth's read-only JSONL data socket (`--data-socket SPEC`). Connect, parse, filter, reconnect. The textbook consumer loop. |

These are *out-of-product*: they don't link to or modify sloth itself,
and they don't ship with the binary. They live here so the schema and
socket contract have a concrete, runnable companion that the next
agent (or the next external integrator) can read as the worked
example.

If you add an example: keep it stdlib-only where possible (consumers
should not need a build environment to follow sloth), include a
self-contained README, and link it from this table.
