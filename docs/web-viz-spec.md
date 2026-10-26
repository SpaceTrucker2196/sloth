# sloth web UI: visual system specification

**Working name:** the sloth glyph set
**Applies to:** `web/ui/` (slothweb), with parity notes for the TUI
**Status:** draft for the owner to read, 2026-10-26
**Companion:** `docs/web-ui-spec.md` (the UI spec; its rulings table wins where the two disagree)

---

## 0. What this document is

This is a review of the slothweb page and a specification for a small
set of graphics that the page should use. The graphics follow the
rules Edward Tufte sets out in *The Visual Display of Quantitative
Information*, *Envisioning Information* and *Beautiful Evidence*, and
the later work that tested those rules (Cleveland on aspect ratio,
Heer on horizon graphs, Few on bullet graphs). The review is written
from two seats: a security researcher who watches a local network, and
an intelligence analyst who must keep situational awareness of the
local RF environment.

The review covers everything except the theme. Colour tokens, the
Spacetrucker chrome and the light theme are settled by the 2026-10-23
ruling and are not reopened here. Where a graphic needs a colour, it
uses a token that already exists.

**How the page was reviewed.** The live page at the Tailscale address
was not reachable from the session that wrote this, so the review used
the M6 demo screenshots in `docs/assets/slothweb/` and the source in
`web/ui/app.js`, `web/ui/index.html`, `web/ui/page.css`, together with
the server headers that say what data exists. Section 11 lists the
things to confirm on the live page.

---

## 1. The operator's four questions, restated for RF

`docs/web-ui-spec.md` §1 gives four questions. For an analyst who
watches the air as well as the wire, they read:

1. **Is anything on fire now?** An attack, a flood, a new emitter.
2. **Is this normal?** For this hour of this weekday, for this device,
   for this channel.
3. **Which thing is the outlier?** Which device, host, BSSID or channel.
4. **Who or what is it, and how near is it?** Identity, vendor, and the
   physical proximity that RSSI implies.

The fourth question has a half that the current page does not answer:
*how near is it, and is it getting nearer.* Every other question has a
graphic today. That one has a number (`DBM -47`) with no history.

Endsley's model of situation awareness gives the same three levels in
different words: **perception** (what is there), **comprehension**
(what it means, compared to normal), **projection** (what happens
next). A display supports an analyst only if it serves all three. The
current page serves the first well, the second in part, and the third
not at all. Section 6 maps every proposed graphic to one of the three.

---

## 2. Findings: the page as it stands

Each finding names the view, what the screenshot or the code shows,
why it matters to the analyst, and the fix. The fix refers to a glyph
in section 5 where one applies. Findings are ordered by how much they
cost the operator, not by view.

### F1. The KPI tiles show a number with nothing to compare it to

*Overview.* `DEVICES 23`, `OPEN ALERTS 0 2 0`, `OPEN ANOMALIES 0`,
`RECORDS/S 111.8`. Only throughput has a sparkline. The code says why:
"devices, alerts and anomalies are counts with no stored series behind
them". Tufte's first question of any number is *compared to what?* A
device count of 23 means one thing at 14:00 on a Tuesday when the
baseline is 24, and another at 03:00 when the baseline is 6.

**Fix.** Store a series for each tile (`live.devices`,
`live.alerts_open`, `live.anomalies_open`, `live.records_rate`; §7).
Every tile gets glyph G1 (band sparkline) and the delta words that
G1 prescribes: the value, the band for this hour, and the direction
since the last bucket. The tile's explanatory sentence moves to a
hover note.

### F2. The throughput sparkline is one spike in an empty box

*Overview, Activity.* After one minute of running, the 24 h window
puts every sample in the last 1 to 2 pixels. The "now vs normal" chart
is a vertical line at the right edge, and both axis labels read
`10:25:00`. The analyst learns nothing, and the page looks broken
during the first hours of every deployment, which is when the analyst
is most likely to be watching it.

**Fix.** A chart whose data covers less than a tenth of its window
must either shrink the window to the data span and say so
("`6 min of 24 h`"), or draw the empty span as a labelled gap. The
axis must carry at least three time labels, and a "now" mark at the
right edge. This is rule R4 (§8).

### F3. The hour-of-week heatmap hatches 168 cells

*Overview.* With no baseline, every cell is grey with a diagonal
hatch. Tufte names hatching as the first source of moiré vibration,
"the unintended optical noise of the design", and the screenshot shows
it: the grid flickers and the one outlined cell (now) is hard to find.
Hatching also fails the smallest-effective-difference test: a warming
cell needs to differ from a cold cell, and a lighter grey does that.

**Fix.** A warming cell is `--rule` with no hatch. The panel caption
says `warming: 168 of 168 cells`. The now cell keeps its outline. When
the grid is entirely warming, draw the outline and the caption only.
Glyph G4 (§5).

### F4. Explanatory prose lives inside the data tiles

*Overview.* The anomalies tile carries three lines on rule A4 and the
vendor table. The throughput tile carries "rx, 24 h, band = mean ± k
sd". Tufte asks for documentation, but as a layer under the data, not
in the data's place. A tile is read in a second; a sentence is not.

**Fix.** Every panel keeps one caption line in `--muted` under the
graphic, in the form `source, window, tier, n` (rule R9). Longer
explanation goes behind the `?` key or a hover note. The A4 reason
belongs in the status strip's `DB` pill.

### F5. Sensor facts and server facts share one strip

*All views.* The strip reads `SENSOR connected | DEVS 23 | ALERTS 2 |
ANOMALIES 0 | REC/S 111.8 | TICK 61 | UP 1m1s | CLIENTS 2`. Tick,
uptime and client count describe slothweb. Devices, alerts and
anomalies describe the network. The footer repeats `SOCK | DB | STORE`.
Tufte's layering principle: separate what is about the subject from
what is about the instrument.

**Fix.** The top strip holds only network facts, each with a G1 glyph
40 px wide. The footer holds every slothweb fact (`SOCK DB STORE TICK
UP CLIENTS`). One row each, never mixed.

### F6. Small multiples do not share a scale, and do not say so

*Activity.* Each cell in "every key, last hour" is drawn against its
own maximum. The `eth0` cell at 312.8 kB/s and the `wlan0mon` cell at
29.4 kB/s show the same height of line. Tufte's small multiples work
because "the design is constant and only the data varies"; a reader
who understands one cell must be able to read every other one at a
glance. A silently varying y-scale breaks that contract. The spec
(§8.5) also asks for a sort by `abs(z)`; the code sorts by current
value.

**Fix.** A shared y-scale by default, with the maximum printed once
in the panel caption. A `scale: shared | own` toggle for the case
where one key dwarfs the rest, and when `own` is selected every cell
prints its own maximum in `--faint` at its top left. Sort by `|z|`
when a baseline exists, by value otherwise, and name the sort in the
caption. Glyph G1 in its stacked form.

### F7. The sparkline carries its value twice

*Overview, Activity, Anomalies.* `draw()` with `spark: true` colours
each segment by level (dim, normal, heat mid, heat high, peak) exactly
as the TUI does. Height already encodes the value; the colour encodes
it a second time. Tufte: "erase redundant data-ink". It also spends
the heat ramp, which the page otherwise reserves for *out of band*, on
*high but normal*. A reader who has learned that red means anomalous
on the band chart sees red on a sparkline that is merely busy.

**Fix.** On the web, a sparkline is one ink (`--tui-normal`). Colour
appears only where the value leaves its band (the heat ramp, as the
band chart already does) or where there is no band and the point is
the maximum of the window (one dot). The TUI keeps its graded glyphs
for parity with its own history; this is an owner decision and is
listed in §11.

### F8. The channel waterfall normalises to its busiest cell

*WiFi.* `waterfall()` colours every cell against the maximum in view.
With one sample the screenshot shows six saturated yellow blocks and
one red one, for channel 6 at a demo load that is not unusual. When the
window changes, every colour changes. Tufte again: compared to what?
Channel occupancy has a natural scale (0 to a known busy level), and
AP count has a natural scale (0 to the most ever seen on that
channel). A colour that means "busiest in the last hour" means nothing
when the whole hour was quiet.

**Fix.** An absolute scale per metric: `ap_count` against the
channel's own 30 d maximum; `ctrl_total` against its hour-of-week
baseline as a z-score. The caption prints the scale. The waterfall
becomes glyph G3 (horizon strip), one row per channel, which also
solves the empty-area problem in the screenshot (seven rows, 96
columns, one column filled).

### F9. RSSI is a number in a column

*Devices, WiFi, Lookup.* `DBM -47`, `-38`, `-55`. The AP table has
`DBM -41`. The beacon record carries `rssi_min_60s` and
`rssi_max_60s`, and `twin_episode` carries `rssi_swing_dbm`, so the
sensor already measures the spread. None of it is drawn. For an
analyst, RSSI over time is the only passive proxy for *physical
distance and motion*: a BSSID whose signal climbs from -80 to -45 over
ten minutes is a radio walking toward the building. A number cannot
show that; a 24-point sparkline can.

**Fix.** A per-BSSID and per-client RSSI series (`ap.rssi`,
`sta.rssi`, §7) and glyph G2 (range sparkline: the line, the 60 s
min to max whisker, the last value). It goes in the DBM column of
every table that has one, 72 px wide, and in the device drawer at full
width.

### F10. Presence strips have no time axis

*Devices, History.* The 144-cell strip is the best Tufte object on
the page: a binary sparkline, like his win-loss example. But it has no
tick for midnight or for "now", so the reader cannot tell 03:00 from
15:00 without counting cells. The column header reads `24 H PRESENCE`
and nothing else.

**Fix.** One `--faint` tick above the strip at each local midnight
and one `--signal` tick at now, drawn once in the column header rather
than per row, so the rows stay clean. Glyph G5.

### F11. The flows chord diagram asks the reader to trace crossing arcs

*Flows.* The chord is drawn well, and the spec is honest that it is
"the one place a relationship drawing earns its space". Still, in the
screenshot six lines cross the centre, two labels sit on arcs, the
protocol needs a legend, and the width-by-log rule makes a 64-count
pair look like a 9-count pair. Tufte has no objection to a network
drawing, but he does object to a drawing whose primary reading needs a
legend and a steady hand.

**Fix.** Keep the chord as the second mode. The first mode is a
source by destination matrix: rows are sources, columns destinations,
both in address order with subnets grouped, each cell a G6 count
glyph (a bar with the number). Protocol becomes a small letter in the
cell, not a hue. The matrix answers "who talks to whom" in one scan
and needs no legend.

### F12. The 30 d history strip draws every day as the same tick

*History.* Every device first-seen is a teal tick of one height; every
alert is an orange tick of one height. A day with one new device looks
like a day with thirty. Tufte would draw the count.

**Fix.** Glyph G7 (event rug with height): the tick height is the
count in that column, on a shared scale, and the caption prints the
maximum. Survey sessions keep their white line.

### F13. The anomaly card draws its score bar but not its evidence

*Anomalies.* The card has a score bar (orange on grey) and the
sentence. The sparkline of the metric that fired is drawn only when
the series fetch succeeds and is blank in the screenshot. An analyst
deciding whether A8's "9 of 27 NXDOMAIN in 10 min" is worth an hour of
work needs the shape: was it one burst or a steady drip?

**Fix.** Every card carries G1 with the episode window shaded in
`--signal` at 12 percent and the band behind it. If the fetch fails,
the card says `series unavailable` in the glyph's place, never a
blank.

### F14. No graphic shows the attack chain

*All views.* sloth's own rules know that a deauth flood, then an
evil twin, then a client association to the twin is one event in
three parts (`twin_episode.attack_in_progress`). The page shows the
three in three places: the deauth timeline, the AP table, the alerts
list. Tufte's causality principle: show the mechanism, not three
descriptions. Endsley's projection level: the analyst needs to see
where in the chain the event is, to know what comes next.

**Fix.** Glyph G8 (chain timeline) on the WiFi view and in the
drawer: one horizontal time axis, one lane per stage, each event a
mark, the lanes joined where sloth linked them. Section 6.3.

### F15. New things look like old things

*Devices, WiFi.* The History view computes "new since the previous
session" well. The Devices table and the AP table do not mark a row
that is new today. The analyst's most valuable signal in a stable
environment is *the thing that changed*. The devices query language
has `first:<7d`, but a filter is not a cue.

**Fix.** A `new` mark (a filled `--signal` dot before the swatch) on
any row whose `first_seen` is within the current window, and a count
in the panel caption (`24 shown, 3 new today`). Glyph G5 also gains a
first-seen tick.

### F16. The deauth timeline and probe-client chart are empty boxes

*WiFi.* Both panels reserve a quarter of the page and draw nothing in
the demo. The probe-client line is a step with no band.

**Fix.** Panels collapse to their caption when empty (`0 deauth in
the window`). The probe-client chart gets its band from the baseline
that `wifi.probe_clients` already has.

### F17. Every table column is text, including the ones that are a quantity

*Devices, WiFi, Flows.* `RISK 2`, `ANOM 0`, `karma 82`, `banner 64`,
`TOTAL 9`. Few's bullet graph and Tufte's sparkline exist for exactly
these cells: a quantity with a qualitative range, inside a table.

**Fix.** Glyph G6 (bullet) for bounded scores (`risk`, `karma`,
`confidence`). Glyph G6 in its bar form for counts in a column, so the
column reads as a bar chart without leaving the table.

### F18. The band is drawn, but its width is not stated

*Activity, Overview.* The band is `mean ± k sd` at the slider's `k`.
The slider sits on the Overview only. On the Activity view the reader
sees a band and does not know whether it is 1.5 or 4 sd.

**Fix.** The caption prints `band ±2.0 sd` on every band chart, and
the slider is in the footer on every view.

### F19. Nothing says how much data is behind a graphic

*All views.* A sparkline from three buckets looks like a sparkline
from 8,640. Tufte's documentation principle: state the n.

**Fix.** Rule R9: every caption ends with `n=…` buckets, and a glyph
with fewer than 5 points draws dots, not a line.

### F20. The Lookup card is text only

*Lookup.* The card answers "who is it" and stops. The device's
presence strip and RSSI sparkline exist on other views.

**Fix.** The Lookup card ends with the same G5 and G2 glyphs the
drawer shows, so the analyst does not leave the view to see when the
device is usually present and how near it usually is.

---

## 3. The principles this spec holds every graphic to

Each principle is stated as a rule, with its source. The rules in §8
are the operational form.

**P1. Compared to what.** Every quantity is shown against a
reference: the band for this hour of the week, the device's own
history, or the channel's own maximum. A bare number is a defect.
(Tufte, *Beautiful Evidence*, the six principles: comparisons.)

**P2. Word-sized.** The default graphic is a sparkline: "small,
intense, simple, word-sized graphics with the resolution of
typography". It sits where a word or number sits: in a table cell, in
a tile, in a sentence. (Tufte, *Beautiful Evidence*, pp. 46-63.)

**P3. The data is the ink.** No frame, no grid, no axis where a label
will do. Non-data ink is erased first; then redundant data ink.
(Tufte, *The Visual Display of Quantitative Information*, the
data-ink ratio.)

**P4. Small multiples share a design and a scale.** A stack of
sparklines uses one y-scale unless the caption says otherwise. "Once
viewers understand the design of one slice, they have immediate access
to the data in all the other slices." (Tufte, *Envisioning
Information*.)

**P5. Smallest effective difference.** Marks differ by the least that
still reads. Grey before colour, thin before thick, one hue before
two. Hatching never. (Tufte, *Visual Explanations*; *Envisioning
Information*, layering and separation.)

**P6. One accent, spent once.** `--signal` marks one thing per panel:
now, the selected row, or the live alert. The heat ramp marks *out of
band* and nothing else. (The existing §8.12 ruling, "if two things are
orange, one is wrong", applied to every glyph.)

**P7. Lumpy, not spiky.** A sparkline's height is chosen so the
typical slope is near 45 degrees; a tall thin spike reads worse than a
gentle hill of the same data. (Cleveland 1988, banking to 45; adopted
by Tufte for sparklines. Later work shows the exact angle matters less
than avoiding the extremes.)

**P8. Micro and macro.** A panel reads at arm's length as a shape, and
up close as data. The horizon strip and the matrix are chosen because
they survive both readings. (Tufte, *Envisioning Information*,
micro/macro readings.)

**P9. Show the mechanism.** When sloth knows that A caused B (a deauth
then a twin, a probe then an association), the graphic draws the link.
(Tufte, the six principles: causality.)

**P10. Document on the graphic.** Source, window, tier, scale and n
are on the panel, in one line, every time. (Tufte, the six principles:
documentation.)

**P11. Integrate words and pictures.** The number sits beside its
sparkline, the label beside its line. No legends where a direct label
fits. (Tufte, the six principles: integration.)

**P12. Say when there is nothing.** Empty, warming, and gap are three
different states and must look different. An empty box is never an
answer. (Tufte on the Challenger charts: the data that was missing
from the display was the data that mattered.)

---

## 4. The analyst's questions, by Endsley level

| Level | Question | Graphic (§5) | Where (§6) |
|---|---|---|---|
| 1 Perception | What is on the air now? Which channels, how many emitters, how loud? | G3 channel horizon, G2 RSSI | WiFi: the air picture |
| 1 Perception | What is on the wire now? | G1 in the strip and tiles | Overview |
| 1 Perception | What arrived in the last hour that was not here before? | G5 with first-seen tick, the `new` mark | Devices, WiFi, History |
| 2 Comprehension | Is this level normal for now? | G1 band, G4 heatmap | Overview, Activity |
| 2 Comprehension | Is this device where and when it usually is? | G4 per device, G5 | Drawer, Devices |
| 2 Comprehension | Who is it? | the card (text), G6 confidence | Lookup, drawer |
| 2 Comprehension | How near is it? | G2 RSSI with whisker | Devices, WiFi, drawer |
| 2 Comprehension | What does it talk to? | the matrix, G6 | Flows |
| 3 Projection | Is it getting nearer? | G2 slope and last-value mark | Devices, WiFi |
| 3 Projection | Where in the attack chain are we? | G8 chain timeline | WiFi, drawer |
| 3 Projection | Will this hour's load leave the band? | G1 with the band drawn ahead of now | Activity |
| 3 Projection | Is the sensor still able to see? | G1 on `sensor_health` drops, the footer | Footer |

---

## 5. The glyph set

Eight glyphs. Each is one function in `app.js` (a `glyph.*` namespace
beside `draw()`), drawn on canvas at device pixel ratio, sized by its
container, and with the same states: **empty**, **warming**, **gap**,
**single point**, **normal**, **out of band**. Every glyph has a TUI
form so the two surfaces keep one grammar.

Sizes are in CSS pixels. The text line is 13 px on the body and 12 px
in tables (§8.2 of the UI spec), so a word-sized glyph is **14 px
tall** in a table and **18 px** in a tile.

### G1. Band sparkline

*Answers:* what is the value now, and is it normal.

```
                 ·        ← max dot, --faint, only when no band
   ░░░░░░░░░░░░░░░░░░░░   ← band: mean ± k sd for each bucket's hour, --data at 12 %
   ─────╮  ╭──╮  ╭────●  ← line: one ink; out-of-band segments in the heat ramp
        ╰──╯  ╰──╯       ← last value: a 2.5 px dot, --ink; heat colour if out of band
   459.7k B/s  band 280k to 610k  ↑   ← the words beside it, same line
```

- **Size:** 60 to 120 px wide, 14 or 18 px tall. The height is fixed;
  the y-range is the band's range widened to include the data, so the
  typical slope stays shallow (P7). Never autoscale to the last spike
  alone.
- **Marks:** the line (1 px), the band, the last-value dot. A max dot
  and a min dot (`--faint`) only when there is no band, because then
  the range is the only reference.
- **Words:** value, `band lo to hi`, and one of `↑ ↓ →` for the
  direction since the previous bucket. On a tile, the value is the
  hero number and the words sit under the glyph.
- **States:** empty draws a `--faint` dash and `no data`; warming
  draws the line with no band and `warming` in the caption; a gap of
  more than 2.5 steps breaks the line; fewer than 5 points draw dots.
- **Colour:** one ink. Heat only out of band. No level grading (F7).
- **TUI form:** the existing `▁▂▃▄▅▆▇█` sparkline in `CP_NORMAL`, with
  the last cell in `CP_HEAT_*` when out of band. The band is the
  `±` number after it.

### G2. Range sparkline (RSSI)

*Answers:* how near is this emitter, and is it moving.

```
   -40 ┤          ╭─●  -45   ← last value and the number, bold if climbing 10 dB in 10 min
       │      ╭───╯ ┃         ← whisker: rssi_min_60s to rssi_max_60s at the last sample
   -90 ┤──────╯     ┃
```

- **Data:** `ap.rssi` keyed by BSSID, `sta.rssi` keyed by MAC
  (§7), gauge, fine tier. The whisker from `rssi_min_60s` and
  `rssi_max_60s` on `beacon`, or `rssi_swing_dbm` on `twin_episode`.
- **Scale:** fixed, -95 to -20 dBm, the same on every glyph (P4). A
  fixed scale is what makes "near" readable across rows: a line near
  the top is near, everywhere on the page.
- **Marks:** the line, the whisker at the last sample, the last-value
  dot. A short `--faint` rule at -67 dBm, the usual "good coverage"
  line, so the reader has one reference without an axis.
- **Words:** the last value in dBm. The number is bold when the
  10-minute slope exceeds +1 dB/min (approaching), and the caption of
  the panel says `3 approaching` so the reader finds them.
- **Size:** 72 px wide in a table cell; full panel width in the
  drawer, where the x-axis gets its three time labels.
- **States:** as G1. A device with one sample draws the dot and the
  number only.
- **TUI form:** the same `▁▂▃▄▅▆▇█` glyphs on the fixed scale, with the
  dBm number; the Devices view's `Enter` signal-trail detail already
  draws a trail and should adopt the fixed scale.

### G3. Horizon strip (channel occupancy)

*Answers:* which channels are busy, how busy, and when.

A horizon graph folds a time series into a short strip: the value is
drawn as a filled area, cut into bands of equal height that are laid
over one another, with the higher band darker. Heer, Kong and Agrawala
(CHI 2009) measured that a mirrored two-band horizon strip keeps
estimation accuracy at heights under 24 px, which is the height a
channel row has in the waterfall. It replaces the heat-coloured cell
grid (F8).

```
   ch 6   ▄▄▆█▇▄▂▁▁▂▄▆▆▄▂▁▁▁▂▂▄▄▆▇█▇    ← 2 bands: band 1 in --data at 35 %, band 2 at 70 %
   ch 11  ▁▁▁▂▂▁▁▁▁▁▂▁▁▁▁▁▁▁▁▁▁▁▂▂▁▁
   ───────────────────────────────────  ← rule between 2.4 and 5 GHz (kept)
   ch 36  ▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂
```

- **Data:** `wifi.ctrl_total` (measured occupancy) or `wifi.ap_count`
  per channel, the existing `/api/wifi/channels` grid.
- **Scale:** absolute (F8). For `ap_count`, 0 to the channel's 30 d
  maximum. For `ctrl_total`, the z-score against the hour-of-week
  baseline, so the strip is flat when the channel is normal and rises
  only when it is unusually busy; the second band then begins at the
  slider's `k`, which makes the horizon strip and the band sparkline
  agree on what "out of band" means.
- **Rows:** every channel seen in the last 30 days, not only those in
  the window, so a channel that went quiet keeps its row and its
  silence is visible.
- **Size:** 18 px per row; a caption line under the block.
- **Colour:** two tints of `--data`. Out-of-band columns (band 2
  above `k`) take `--heat-2`. Nothing else.
- **TUI form:** the Channel view's histogram is already a bar form of
  this; a two-level glyph (`▄` and `█` in `CP_NORMAL` and
  `CP_HEAT_MID`) gives the same reading in one row per channel.

### G4. Hour-of-week heat glyph

*Answers:* when is this thing usually here, and is now usual.

The existing 7 by 24 grid, with three changes (F3):

- Warming cells are `--rule`, no hatch. The caption says
  `warming: n of 168`.
- The colour ramp is the TUI's `tui_heat` ramp but applied to the
  cell's mean against the *series'* maximum, as now, and the maximum
  is printed in the caption.
- A second form at 56 by 28 px for a table cell or a drawer row: the
  same grid at 2 px per cell with no labels, so a device's weekly
  rhythm reads at a glance ("only weeknights", "only 03:00").

**TUI form:** the Devices `Enter` detail can draw the 7 by 24 grid in
`▪` at four heat levels.

### G5. Binary strip (presence)

*Answers:* when was it here.

The existing 144-cell strip, with a header ruler (F10) and two marks
(F15):

```
   24 H PRESENCE   |·······|·······|·······▲        ← ruler once, in the header: midnight ticks, ▲ now
   ▮▮▮▮▮▮▮▮      ▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮    ← present cells in --tui-normal
   ◆▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮                                 ← ◆ first seen inside the window, --signal
```

- **Marks:** present cells; a `◆` at the first-seen cell when it is
  inside the window; an anomaly episode as a 1 px `--heat-2` underline
  across its cells. The ruler is drawn once per table, not per row.
- **Size:** unchanged (the column width), 12 px tall.
- **TUI form:** the Devices view can print 24 cells (one per hour)
  as `▮` and `·`.

### G6. Bullet and count bar

*Answers:* how big is this score or count, against its range.

Few's bullet graph, reduced to what a 14 px table cell can hold:

```
   risk   ▐███▌░░░░░  2 of 3      ← qualitative bands in --rule and --faint, the measure in --ink
   karma  ▐██████▌░░  82          ← one comparative tick (the threshold the rule fires at) in --signal
   count  ▐██▌        64          ← bar form: the number drawn as a bar, shared scale per column
```

- **Bounded scores** (`risk`, `karma`, `confidence`, the anomaly
  score): the measure bar, two or three background bands for the
  qualitative ranges the rule defines, and one tick at the threshold.
  Severity colour on the bar only when the score crosses the
  threshold, so the column is grey when all is well.
- **Counts in a column** (`total`, `banner`, `anom`): a bar on a
  scale shared by the column, with the column maximum in the header.
  The number stays; the bar sits behind it in `--rule`.
- **Size:** the cell. Never wider than 48 px plus the number.
- **TUI form:** `▐████▌░░░` in `CP_NORMAL`, eight cells.

### G7. Event rug

*Answers:* when did things happen, and how many.

Ticks under a time axis, height by count (F12):

```
   devices first seen  ▁   ▃     ▁▁  ▇        ▁ ▂       ← height = count in the column, shared scale
   alerts begun            ▂        ▁▁    ▅             ← one lane per class, --sev-* on the alert lane
   sessions            │           │                    ← survey sessions, --ink, full height
```

- **Data:** `/api/history/overview` columns, as now, plus the counts.
- **Marks:** one lane per class, 8 px tall; the tallest column reaches
  the lane height and the caption prints its count. A column with zero
  draws nothing (P3).
- **Size:** full width; the drag range picker stays.
- **TUI form:** the same `▁▂▃▄▅▆▇█` row per lane.

### G8. Chain timeline

*Answers:* which stage of an attack is in progress, and what came
before it.

```
   deauth    ──────▌▌▌▌▌────────────────────────────    ← DEAUTH_FLOOD frames, G7 rug
   twin      ─────────────●━━━━━━━━━━━━━━━━●──────────  ← EVIL_TWIN episode, open to close
   assoc     ────────────────────●──────────────────    ← a client associated to the twin BSSID
   karma     ──────────────────────────●━━━━━━━━━━━━━   ← KARMA_AP on the same BSSID
             │  tainted ↑ 5 s     │  attributed ↑       ← the links sloth made, named
   10:04        10:06        10:08        10:10
```

- **Data:** the `alert.*` lifecycle records (`incident_id`,
  `first_detected`, `last_observed`, `reason`) joined by `key` and
  `bssid`; `twin_episode.attack_in_progress`, `attributed`,
  `confidence`. All of it already crosses the socket.
- **Marks:** one lane per stage, in the order the chain runs. An
  incident is a bar from first to last observation. A link that sloth
  established (the deauth taint within 5 s, an operator attribution) is
  a `--faint` connector with its reason in words beside it (P9, P11).
  Severity colour on the bar at the moment it escalated, nowhere else.
- **Size:** 18 px per lane, full width, one G8 per BSSID that has
  more than one stage. A BSSID with one stage gets a G7 rug, not a G8.
- **Words:** the lane name, the link reason, `confidence 70 %` on the
  twin bar.
- **TUI form:** the Twins view's episode table can carry one 24-cell
  lane per stage, `━` and `●` in the alert's severity colour.

---

## 6. Where each glyph goes

### 6.1 Overview

- **Strip:** `DEVS 23 ▁▂▃▃▂▃` with a 40 px G1 after every network
  fact. Server facts move to the footer (F5).
- **Tiles:** six tiles, each a G1 at 18 px with the hero number, the
  band words and the arrow (F1). The tile's prose becomes a hover
  note (F4). Tile order by urgency: open alerts, open anomalies,
  sensor health, throughput, devices, records.
- **Now vs normal:** rule R4 for the window (F2); three time labels
  and a now mark; `band ±2.0 sd, n=1,440` in the caption (F18, F19).
- **Hour of week:** G4 (F3).
- **Top anomalies:** G1 on each card (F13).
- **Latest alerts:** unchanged; the severity word stays a word.
- **Records:** a 40 px G1 of records per second per type in the
  panel header, so a burst in one type (`deauth`) is visible before
  it scrolls past.

### 6.2 Activity

- Main chart: as the Overview's, plus a `ratio to baseline` toggle the
  UI spec already asks for (§8.5), which puts every key on one axis.
- Multiples: G1 stacked, shared scale by default, `scale` toggle, sort
  by `|z|` then value, both named in the caption (F6).

### 6.3 WiFi: the air picture

This view changes most, because it is where the RF questions live.
Four panels, top to bottom:

1. **Channels.** G3 horizon strips, one per channel seen in 30 d,
   bands grouped with the existing rule (F8). The metric toggle
   stays. Caption: `ctrl_total as z against hour-of-week; band 2
   above 2.0 sd; 7 channels, 40 s cells, n=90`.
2. **Emitters.** The AP table, re-sorted by RSSI by default (near
   first), with a G2 in the DBM column (F9), a G6 bullet for KARMA,
   the `new` mark (F15), and SSID count as a row of small `▪` after
   the SSID rather than `+3 ssids` in words. Caption counts
   `6 shown, 3 approaching, 1 new today`.
3. **Chains.** One G8 per BSSID with more than one stage in the
   window; else one G7 rug for deauth and one for probe floods. The
   empty state is one caption line, not a box (F16).
4. **Clients.** Probe clients over time as G1 with its band (F16),
   and under it the clients seen in the window as rows with G2 and
   G5, so a probing client that is near and new is found by eye.

### 6.4 Devices

- A G2 in the DBM column, a G6 bullet in RISK, a G6 bar in ANOM, a
  `new` dot before the swatch (F9, F15, F17).
- The G5 ruler in the header (F10).
- The Z column: the z-score as a G1 at 40 px when the device has a
  presence baseline, else `-` as now.

### 6.5 Anomalies

- G1 on every card with the episode shaded (F13).
- The score bar becomes G6 with the rule's threshold tick, so a score
  of 60 reads against the 50 that fires it.

### 6.6 Flows

- The matrix as the first mode, the chord as the second (F11). Each
  cell a G6 bar with the count; the protocol as a letter in the
  cell's corner; SMB1 cells keep the critical colour.
- The table's `COUNTS` and `TOTAL` columns as G6 bars (F17).

### 6.7 History

- G7 with height on the 30 d strip (F12).
- "Who was here" rows carry the G5 ruler and marks.

### 6.8 Lookup and the drawer

- The card ends with G5 (24 h), G4 (the 56 by 28 form, when a
  baseline exists), and G2 at full width (F20).
- The drawer adds G8 when the device is a BSSID with more than one
  stage.

### 6.9 Footer

- `SOCK DB STORE TICK UP CLIENTS` and the sensitivity slider (F5,
  F18). A 40 px G1 of `sensor_health` capture drops per tick, because
  a sensor that is dropping frames is the one fact that invalidates
  every other panel (P12).

---

## 7. Data the server must add

Everything in §5 and §6 is drawn from records that already cross the
socket. The server needs five new series and two route changes.

| Series | Key | Kind | Source record and field | Tier | Used by |
|---|---|---|---|---|---|
| `ap.rssi` | bssid | gauge | `beacon.signal_dbm`; `rssi_min_60s`, `rssi_max_60s` kept as the bucket's min and max | fine, minute | G2 on WiFi, drawer |
| `sta.rssi` | mac | gauge | `probe_client.signal_dbm`, `assoc.signal_dbm`, `wifi_sta.signal_dbm` | fine, minute | G2 on Devices, Lookup |
| `live.devices` | (global) | gauge | the device count of sloth's latest pass, as `/api/live` computes it | fine, minute, hour | G1 on the strip and tile |
| `live.alerts_open` | (global) | gauge | open incidents by severity, three keys `low`, `warn`, `crit` | fine, minute, hour | G1 on the strip and tile |
| `live.anomalies_open` | (global) | gauge | open episodes | fine, minute, hour | G1 on the strip and tile |
| `records.rate` | type | counter | records per second by type, the `types[]` counts `/api/live` already keeps | fine | G1 in the Records header |
| `sensor.drops` | (global) | counter | `sensor_health` per-tick libpcap and NIC drop deltas | fine, minute | G1 in the footer |

Rules for the new series:

- They enter the existing cardinality caps (`--web-max-keys`); `ap.rssi`
  and `sta.rssi` are keyed metrics in the device class.
- `ap.rssi` and `sta.rssi` get hour-of-week baselines like any gauge,
  so "nearer than usual for this hour" is a z-score and A1 can fire on
  it without a new rule.
- The three `live.*` gauges are global, so they are always kept and
  never evicted.
- Nothing new is stored about a record's content; RSSI, counts and
  types are what the ingest already parses. The secret-column
  guardrail test stays as it is.

Route changes:

- `/api/wifi/channels` gains `scale: {kind: "absolute"|"z", max}`
  per row so G3 can draw the absolute scale and print it.
- `/api/history/overview` returns the count per column, not only
  presence, so G7 can size its ticks.
- `/api/flows/graph` gains a `matrix` form: the same nodes and edges,
  no folding by rank, with the subnet grouping computed server-side
  so the page draws what it is given.
- `/api/device/{mac}` and `/api/wifi/aps` rows carry `first_seen`
  already; the page derives `new` from it against the window.

---

## 8. Rules of the system

These are the operational rules every glyph and panel follows. A
review of a slothweb change checks the change against this list.

- **R1. One ink.** A line is `--tui-normal`. The band is `--data` at
  12 percent. Grey (`--rule`, `--faint`, `--muted`) carries structure.
  Colour carries only *out of band* (the heat ramp), *severity* (the
  `--sev-*` tokens, on alerts and chain bars only), *identity* (the
  hash hues on addresses and SSIDs, as ruled), and *the one accent*
  (`--signal`, once per panel).
- **R2. Fixed heights, data-driven widths.** A glyph's height is set
  by the text line it sits in (14 px in a table, 18 px in a tile).
  Its width follows the container. Never the other way round.
- **R3. Shared scales inside a set.** Small multiples share a y-scale
  by default and say so. `own` scale is a toggle and prints each
  cell's maximum. RSSI is always on the fixed -95 to -20 dBm scale.
- **R4. Honest windows.** When data covers less than a tenth of the
  window, the glyph shrinks the window to the data and the caption
  says `6 min of 24 h`. A band chart carries at least three time
  labels and a now mark.
- **R5. Three empty states.** `no data` (a `--faint` dash), `warming`
  (the line without the band, the word in the caption), and a gap (a
  break in the line). They never look alike. An empty panel collapses
  to its caption.
- **R6. Fewer than five points draw dots.** A line through three
  buckets claims a shape the data does not have.
- **R7. The last value is marked and written.** A dot on the line and
  the number beside it, always. Min and max dots only where there is
  no band.
- **R8. No hatching, no gradients, no shadows, no rounded bars.** The
  chrome's radius applies to panels, not to data.
- **R9. The caption line.** Every panel ends with one `--muted` line:
  `source, window, tier, scale, n`. Example: `ap.rssi
  02:de:00:00:00:a1, 1 h, fine, -95 to -20 dBm, n=360`.
- **R10. Greyscale must still read.** Every colour meaning is also a
  position, a shape or a word (the existing §8.12 rule, restated so
  the glyphs inherit it). A heat-coloured segment is also above the
  band; a severity bar also carries its word.
- **R11. Scales do not jump.** A glyph that refreshes every tick keeps
  its scale until the data leaves it, and then grows it; it never
  shrinks on refresh. A reader must be able to look away and back.
- **R12. The TUI form exists.** A glyph that has no character-cell
  form is not added. Parity is the test that keeps the web honest.

---

## 9. Tests and acceptance

Tests live in `web/tests/` beside the existing ones. The page's canvas
code is not unit-tested today; this spec adds a thin layer that is.

- **Glyph geometry is pure.** Each glyph is split into a pure
  function that maps data and size to a list of marks (`[kind, x, y,
  w, h, colour-token]`) and a painter that draws the list. The pure
  half is tested in C through the same embed path as `palette.js`,
  or in a small JS harness run by `make web-test` under the system
  `node` if present and skipped with a notice if not. Owner decision,
  §11.
- **Every glyph, every state.** For each of G1 to G8: empty, warming,
  one point, four points (dots), a gap, in band, out of band, and the
  TUI form. The out-of-band test must be seen to fail when the band
  is widened (the repo's "seen to fail" rule).
- **Scale rules.** A shared-scale stack has one maximum; an RSSI glyph
  with a -10 dBm sample clamps and reports it; a refresh never
  shrinks a scale (R11).
- **Window rule.** Six minutes of data in a 24 h window yields the
  shrunk window and the caption text (R4).
- **Captions.** Every panel's caption matches the `source, window,
  tier, scale, n` grammar; a test walks the DOM of the demo and fails
  on a panel without one (R9).
- **Greyscale.** A test renders each glyph with every colour token set
  to the same grey and asserts the mark list still distinguishes
  band, line, last value and severity by kind and position (R10).
- **Series.** The seven new series: derivation from a hand-built
  record, cardinality cap, baseline feed, and the guardrail test
  unchanged.
- **Screenshots.** `docs/assets/slothweb/*.png` regenerated from the
  demo for every view this spec changes, in both themes.

Acceptance, in the demo: an analyst opens the WiFi view and, without
scrolling or hovering, can say which channel is busiest against its
norm, which emitter is nearest and whether it is approaching, which
BSSID is in an attack chain and at which stage, and what arrived today.
Each of those is one glyph.

---

## 10. Delivery slices

One child issue per slice, in the dark-factory style, each green on
its own.

| Slice | Content | Depends on |
|---|---|---|
| V0 | The glyph layer: G1, G5, G6 as pure mark-list functions plus painters; rules R1 to R12 in `web/README.md`; the caption grammar; the strip and footer split (F5); the three empty states (R5); the window rule (R4). No new data. | nothing |
| V1 | The `live.*`, `records.rate` and `sensor.drops` series; G1 on every tile and strip fact (F1); G1 on anomaly cards (F13); the heatmap without hatch (F3); shared-scale multiples (F6); one-ink sparklines (F7). | V0 |
| V2 | `ap.rssi` and `sta.rssi`; G2 on Devices, WiFi, Lookup and the drawer (F9, F20); the `new` mark (F15); G6 on risk, karma, anomaly score and counts (F17). | V0 |
| V3 | G3 horizon strips with absolute scales on the WiFi view (F8); G7 on History (F12); the WiFi view's four-panel layout (§6.3). | V1, V2 |
| V4 | G8 chain timeline from the lifecycle records (F14); the flows matrix (F11). | V3 |

V0 and V1 are the MVP of this spec: after them every number on the
Overview has its comparison. V2 is the RF half. V3 and V4 are the
analyst's projection layer.

---

## 11. Decisions for the owner, and things to confirm on the live page

Decisions:

1. **One-ink sparklines on the web (F7).** The TUI grades its
   sparklines by level and the web copies that for parity. This spec
   says the web should not. Keep parity, or let the web follow the
   data-ink rule and document the difference?
2. **The glyph test harness (§9).** A C-side test of the mark lists
   through the embed path, or a `node` harness that skips when `node`
   is absent? The first keeps `make web-test` dependency-free; the
   second is simpler to write.
3. **The -67 dBm reference line on G2.** It is a common field rule of
   thumb, not a standard. Keep it, choose another, or draw none.
4. **The matrix as the first Flows mode (F11).** The chord is the
   most-liked drawing on the page. The matrix reads faster; the chord
   looks better. Which is first?
5. **The order of the six Overview tiles (§6.1).** Urgency first
   (alerts, anomalies, sensor) or the current order (throughput
   first)?

To confirm on the live page, which this session could not reach:

- Whether "now vs normal" still shows the same time at both ends of
  the axis after a full day (F2 may be a first-hour effect only).
- How the waterfall looks after an hour of real channel data (F8 was
  judged from one sample column).
- Whether the hatch on the heatmap is visible at the operator's
  usual zoom, or only in the screenshot (F3).
- The actual RSSI spread per BSSID over an hour, to set G2's default
  whisker rendering (min to max, or an interquartile range if the
  spread is noisy).
- How many channels the sensor has seen in 30 days, which sets the
  height of the G3 block.

---

## 12. Sources

Books and papers:

- Edward Tufte, *Beautiful Evidence* (2006), "Sparklines: intense,
  simple, word-sized graphics" (pp. 46-63) and "The fundamental
  principles of analytical design" (pp. 122-139).
- Edward Tufte, *The Visual Display of Quantitative Information*
  (1983, 2nd ed. 2001): data-ink, chartjunk, small multiples.
- Edward Tufte, *Envisioning Information* (1990): layering and
  separation, micro/macro readings, the smallest effective
  difference, escaping flatland.
- Edward Tufte, *Visual Explanations* (1997): the Challenger
  decision, "the smallest effective difference".
- William S. Cleveland, Marylyn E. McGill and Robert McGill, "The
  shape parameter of a two-variable graph", *JASA* 83 (1988): banking
  to 45 degrees.
- Jeffrey Heer, Nicholas Kong and Maneesh Agrawala, "Sizing the
  horizon: the effects of chart size and layering on the graphical
  perception of time series visualizations", *CHI* 2009.
- Stephen Few, "Bullet graph design specification", Perceptual Edge
  (2013 revision).
- Mica R. Endsley, "Toward a theory of situation awareness in dynamic
  systems", *Human Factors* 37(1) (1995); Endsley, Bolte and Jones,
  *Designing for Situation Awareness* (2003).

Web, read 2026-10-26:

- Tufte's own course page and sparkline notebook:
  https://www.edwardtufte.com/online-course/ and
  https://www.edwardtufte.com/notebook/sparkline-theory-and-practice-edward-tufte/
- A reader's summary of the sparkline chapter:
  https://www.peterme.com/2006/07/20/tuftes-beautiful-evidence-chapter-2/
- Course notes on Tufte's principles:
  https://websites.umich.edu/~mmmc/516/notes/TuftePrinciples.pdf
- Banking to 45 degrees, and its later tests:
  https://eagereyes.org/basics/banking-45-degrees and
  https://idl.uw.edu/papers/banking
- The horizon graph paper: https://idl.uw.edu/papers/horizon
- Bullet graphs: https://www.visualizing.org/bullet-chart
- Situation awareness in cyber operations:
  https://www.perceptualedge.com/blog/?p=45 and
  https://cylab.be/publications/68/download/2024-evaluation-of-cyber-situation-awareness-theory-techniques-and-applications.pdf

In-tree:

- `docs/web-ui-spec.md` §1, §5.1, §6, §8.4 to §8.12.
- `web/ui/app.js`: `draw()`, `heatmap()`, `drawStrip()`,
  `waterfall()`, `deauthChart()`, `multiples()`, `chord()`,
  `drawOverview()`, `sparkLevel()`, `sparkColor()`.
- `web/src/web_rollup.h` (the metric catalogue), `web_anomaly.h`
  (rules A1 to A10), `web_series.h`, `web_wifi.h`.
- `src/views/dashboard_primitives.c :: draw_sparkline_at()` (the TUI
  sparkline the web copies).
- `docs/wiki/jsonl-schema.md`: `beacon` (`signal_dbm`,
  `rssi_min_60s`, `rssi_max_60s`, `tbtt_jitter_us`), `probe_client`,
  `assoc`, `wifi_sta`, `channel_summary` (`ctrl_total`),
  `twin_episode` (`rssi_swing_dbm`, `attack_in_progress`,
  `attributed`, `confidence`), the `alert.*` lifecycle family,
  `sensor_health`.
- `docs/assets/slothweb/*.png` (the M6 demo screenshots).
