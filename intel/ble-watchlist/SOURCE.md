# ble-watchlist: BLE advertisement categories

`ble_watchlist.csv` carries the schema of sloth's BLE watchlist rows
(`ble_wl_row_t` in sloth's
[`src/ble_watchlist.h`](https://github.com/SpaceTrucker2196/sloth/blob/fa366881644ad32160f5ca8e586af0fdedac00c4/src/ble_watchlist.h) at `fa366881`) and
**no rows**, because sloth ships none: `g_rows` is a NULL pointer and
the count zero by construction (`src/ble_watchlist.c`). A consumer
reads zero rows as "no claim", which is what `ble_watchlist_match()`
already returns. An empty file is not "nothing to find": it is
"nothing sourced yet".

Columns: `category` (at most 15 characters), `match` (`mfr`,
`svc_data` or `uuid16`), `id` (company ID or 16-bit UUID, hex),
`subtype`, `min_len`, `max_len` (-1 for any), `source` (required:
a row with no source is refused, as `ble_watchlist_set_table()`
refuses it).

"A row lands with the primary source that documents the payload shape,
one per commit (owner standard, sloth #145: no row without a primary
source)." The candidate categories and what each still needs are in
sloth's
[`research/bluetooth/ble-watchlist-categories.md`](https://github.com/SpaceTrucker2196/sloth/blob/fa366881644ad32160f5ca8e586af0fdedac00c4/research/bluetooth/ble-watchlist-categories.md).
Category, never identity: a match says "an advertiser of this kind is
in range", never "this tag" and never "this person".

**Licence.** The schema and its notes were written by the owner of sloth
and sloth-comint. sloth carries them under its own licence; sloth-comint
publishes them under PolyForm Noncommercial 1.0.0.