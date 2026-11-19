# oui-builtin: sloth's own short OUI table

`oui_builtin.csv` is the 118-row MA-L table sloth compiles into
`oui_lookup()` (`g_oui` in sloth's `src/oui.c`), and the table
slothweb's vendor generator falls back to when no IEEE registry CSV is
present (`/api/health` then says `"vendor_table":"sloth"`). Columns:
`oui` (six upper-case hex digits, the 24-bit assignment) and
`vendor` (the short display name sloth prints, not the registry's
legal name). Rows are in the source's order, which is ascending by
`oui`: sloth binary-searches the table, and a consumer's generator
refuses a file that is not sorted.

**Where the rows came from.** Moved unchanged from
[`src/oui.c`](https://github.com/SpaceTrucker2196/sloth/blob/fa366881644ad32160f5ca8e586af0fdedac00c4/src/oui.c)
at sloth `fa366881`, and held byte for byte to that source by
sloth-comint's parity check. The source carries no per-row citation:
each row is an IEEE MA-L assignment
(<https://standards-oui.ieee.org/oui/oui.csv>) under a short brand name.
sloth's documentation says 117 rows (`docs/wiki/architecture-split.md`
§3.1, #184 §1); the table has 118, counted from the source and from the
compiled array.

**Licence.** The assignments are the IEEE Registration Authority's
public listing. The short names and the selection were written in sloth
(SLOTH SOURCE-AVAILABLE LICENSE 1.0) by the owner of both repositories.
sloth carries them under its own licence; sloth-comint publishes them
under PolyForm Noncommercial 1.0.0.