# web/data/gnss: the IGS satellite metadata

slothweb's GPS Sat tab names the satellite behind each signal it lists
(`web/src/web_gnssmeta.h`): a PRN is a signal assignment that moves from
one vehicle to another as satellites are retired, so the vehicle is
looked up at the time of the record. The table is the International
GNSS Service's satellite metadata file, kept here as published and
compiled into slothweb at build time by `web/tools/gnssmeta_gen.c` (into
`build/web/web_gnssmeta_table.c`, build output, never committed), as
`web/data/btsig/` is (the ab5fcb2 ruling: nothing is fetched at build or
run time).

| File | What | Published at |
|---|---|---|
| `igs_satellite_metadata.snx` | IGS satellite metadata, SINEX 2.02, release 2441 | https://files.igs.org/pub/station/general/igs_satellite_metadata.snx |

Three blocks are read: `SATELLITE/IDENTIFIER` (SVN, COSPAR
international designator, satellite catalogue / NORAD number, block,
and the comment's launch date and name), `SATELLITE/PRN` (which SVN
transmitted which PRN, with validity times) and `SATELLITE/PLANE`
(orbital plane and slot, with validity times). GPS, GLONASS, Galileo,
BeiDou, QZSS and NavIC; SBAS is not in the file, so an SBAS row shows
its identifier alone.

**Format.** Steigenberger P, Montenbruck O (2024) IGS Satellite
Metadata File Description, Version 1.10, September 30, 2024,
doi:10.57677/metadata-sinex,
https://files.igs.org/pub/resource/working_groups/multi_gnss/Metadata_SINEX_1.10.pdf.

**Licence.** IGS products are freely available to all users (IGS
data and products policy); the file is reproduced unmodified and its
authorship (DLR, the IGS Multi-GNSS Working Group) is the file's own
header.

**This copy.** Fetched once, during development on 2026-11-05, from the
URL above: 277829 bytes, SHA-256
`ac93d053eac7d8b08ce129b6af98667e1867296e1685417d38c081cd046558ae`
(`web/tests/test_gnss.c :: test_gnss_meta_source` holds the file to
it). 295 vehicles, 403 PRN assignments, 259 plane rows.

**Refreshing.** By hand: download the file from the URL above into
this directory, replace the hash, release and counts here, run
`make web-test` (the generator fails the build naming any line it
cannot read; `test_gnss_ident` pins a few assignments that a new
release must still agree with, or be updated against the file), and
commit the result. Satellites launched after the release, and PRN
changes after it, are named only from the next one.
