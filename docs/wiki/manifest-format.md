---
name: manifest-format
description: JSON schema for the version-checkin manifest consumed by sloth --check-manifest
type: reference
---

# Version manifest format

**Summary**: The tiny JSON file that `--check-manifest FILE` reads to
decide whether to display "update available" in the help view. Small
on purpose — the whole point of the manifest split is that sloth
never fetches from the network, so someone else has to produce this
file.

**Sources**: `src/updater.c`, `examples/updater/check-latest.sh`.

---

## Schema

```json
{
  "latest": "1.5.0",
  "url":    "https://github.com/SpaceTrucker2196/sloth/releases/tag/v1.5.0",
  "checked_at": "2026-07-02T15:00:00Z"
}
```

| Field        | Required | Meaning |
|--------------|----------|---------|
| `latest`     | yes      | Semver string, with or without a leading `v`. Compared to `SLOTH_VERSION`. Malformed → `err="latest not semver"`. |
| `url`        | no       | Displayed under the "update available" indicator so the operator can click through. |
| `checked_at` | no       | ISO-8601 UTC timestamp of when the fetcher pulled the release info. Cosmetic — sloth also stamps its own read time. |

Extra fields are ignored — future writers can add signature blocks,
tarball checksums, changelog excerpts, etc., without breaking older
sloth binaries.

## Reader behaviour

- File missing → `err=1`, `err_msg="manifest missing"`, last-good
  `latest`/`url` preserved so a transient missing-file doesn't
  clobber the display.
- Malformed JSON → `err=1` with a short reason.
- Unparseable `latest` → `err=1`, `err_msg="latest not semver"`.
- `latest` <= `SLOTH_VERSION` → up-to-date (no highlight).
- `latest` > `SLOTH_VERSION` → "update available" in the help view.

The reader re-reads the file only when its mtime changes (checked
every 60 s at most), so leaving the fetcher on a systemd timer
firing every 6 h costs sloth nothing at runtime.

## Producer expectations

The producer writes atomically (write to a sibling temp file, then
`rename(2)` into place) so sloth never observes a partial file. The
reference `examples/updater/check-latest.sh` uses this pattern; any
substitute should follow suit.

## Trust posture

sloth trusts the local file as far as the operator trusts the process
that wrote it. The reference script uses HTTPS to `api.github.com`,
which authenticates the server via TLS but doesn't sign the release
metadata itself. If your policy requires stronger integrity:

- have the producer verify the release tarball's SHA-256 against a
  signed manifest published alongside it, and refuse to write the
  file on mismatch
- or maintain a private mirror with signed metadata and point the
  producer there

sloth's job is to trust the file and report the result. Publishing
integrity is left to the producer so different operators can plug in
different trust stories without recompiling sloth.

## Related pages

- [[version-checkin]] — the design doc for the whole check-in system
- [[jsonl-schema]] — the streaming forensic log (adjacent contract)
