/* The TUI forms of the slothweb glyph set (#195; docs/web-visual-spec.md
 * §5, rule R12: "a glyph that has no character-cell form is not added").
 *
 * Pure: every function here maps numbers to character cells and a tone,
 * and draws nothing, so the views share one reading of each glyph and
 * the suite can pin it without a screen. A view turns a tone into a
 * colour with tg_tone_apply() (src/tui.c's tui_* calls), which is the
 * one place a glyph touches the palette.
 *
 * The web's functions are the reference (web/ui/glyph.js); a constant
 * that both sides carry says which one it copies. */
#ifndef SLOTH_TUI_GLYPH_H
#define SLOTH_TUI_GLYPH_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* What colour a cell takes. NONE draws in the current colour. */
typedef enum {
    TG_NONE = 0,
    TG_DIM,          /* CP_DIM: structure, an unlit segment, a zero */
    TG_NORMAL,       /* CP_NORMAL: the one ink */
    TG_HEAT_MID,     /* CP_HEAT_MID: G3's second band */
    TG_HEAT_HI,      /* CP_HEAT_HI: past S9, G4's third level */
    TG_HEAT_LO,      /* CP_HEAT_LO: G4's first level */
    TG_HEAT_PEAK,    /* CP_HEAT_PEAK: G4's fourth level */
    TG_SEV_LOW,      /* the alert severities, on alert lanes only (R1) */
    TG_SEV_WARN,
    TG_SEV_CRIT
} tg_tone_t;

typedef struct {
    const char *glyph;   /* UTF-8, one terminal cell wide */
    uint8_t     tone;    /* tg_tone_t */
} tg_cell_t;

/* Sets the colour for `tone`; a no-op for TG_NONE. */
void tg_tone_apply(int tone);
/* The tone for an alert_sev_t (0 LOW, 1 WARN, 2 CRIT). */
int  tg_sev_tone(int sev);

/* ── G2, the S-meter ───────────────────────────────────────────
 * glyph.js smDbm(): nine segments S1..S9, TG_SM_DB apart, then segments
 * TG_SM_OVER_DB apart up to TG_SM_TOP dB over S9; S9 by the band the
 * reading was heard on (2.4 GHz and BLE -47 dBm, 5 GHz -54, 6 GHz -56;
 * a band not known reads on the 2.4 GHz row and says so). */
#define TG_SM_DB       6
#define TG_SM_UNITS    9
#define TG_SM_OVER_DB 10
#define TG_SM_TOP     27
#define TG_SM_SEGS    11   /* 9 + the two over S9 */
#define TG_SM_CELLS   12   /* the segments plus the gap at S9 */

/* S9 in dBm for an rf_radio_t (src/rf_distance.h). *known is 0 for a
 * radio with no band (RF_RADIO_NONE), which reads on the 2.4 GHz row. */
int  tg_sm_s9(int radio, int *known);
/* The band's name for an rf_radio_t, "" for none. */
const char *tg_sm_band(int radio);
/* Segments lit by `dbm`, 0..TG_SM_SEGS, clamped at both ends as
 * smLevel() is. A dBm of 0 is sloth's "unseen" and lights nothing. */
int  tg_sm_level(int dbm, int s9);
/* 1 when `dbm` is outside the face (drawn at the end, counted). */
int  tg_sm_clamped(int dbm, int s9);
/* The reading in words, stepped as the face is: "S7", "S9+10"; "-"
 * with no reading. */
void tg_sm_word(int dbm, int s9, char *out, size_t n);
/* The face as TG_SM_CELLS cells: a full block a lit segment, `▁` an
 * unlit one, a space at S9 (the emitter report's `███████▁▁ ▁▁`).
 * Returns 0 and fills nothing with no reading. */
int  tg_sm_cells(int dbm, int s9, tg_cell_t out[TG_SM_CELLS]);

/* ── G3, the horizon strip ─────────────────────────────────────
 * Two bands folded into one row: a value up to half the scale is the
 * first band (`▄`, the one ink), above it the second (`█`, heat). A
 * zero is `_` dim; a cell before the history began is a space, so
 * "nothing counted" and "not watched yet" do not look alike (R5). */
#define TG_HZ_UNSEEN UINT32_MAX
int  tg_hz_level(uint32_t v, uint32_t max);   /* 0 zero, 1, 2; -1 unseen */
tg_cell_t tg_hz_cell(uint32_t v, uint32_t max);

/* ── G4, the hour-of-week grid ─────────────────────────────────
 * `▪` at four heat levels by the cell's share against the grid's
 * maximum; `·` dim for an hour watched with the device absent; a space
 * for an hour not yet watched. */
int  tg_how_level(double share, double max);  /* 0 absent, 1..4 */
tg_cell_t tg_how_cell(int watched, double share, double max);

/* ── G7, the event rug ─────────────────────────────────────────
 * `▁`..`█` by the column's count on a scale the lane shares; a zero
 * draws nothing (a space, P3). */
int  tg_rug_level(int count, int max);        /* 0..8 */
tg_cell_t tg_rug_cell(int count, int max, int tone);
/* Bins `n` event times into `cells` columns over [from, to); counts
 * out[] and returns the largest. Times outside the window are skipped. */
int  tg_rug_bin(const time_t *t, int n, time_t from, time_t to,
                int *out, int cells);

/* ── G8, the chain lane ────────────────────────────────────────
 * One lane per stage on one time axis: `─` dim where nothing is, an
 * incident `━` from its first to its last observation with `●` at each
 * end, a frame or association `▌` / `●`, all in the severity it
 * reached (R1: severity colour on chain bars only). */
typedef struct {
    tg_cell_t cell[64];
    int       n;
} tg_lane_t;
void tg_lane_init(tg_lane_t *l, int cells);
/* Column of `t` in [from, to) across l->n cells, or -1 outside. */
int  tg_lane_col(const tg_lane_t *l, time_t t, time_t from, time_t to);
/* An incident from `a` to `b` (clipped to the window). */
void tg_lane_bar(tg_lane_t *l, time_t a, time_t b, time_t from, time_t to,
                 int tone);
/* One event at `t` drawn as `glyph`. */
void tg_lane_mark(tg_lane_t *l, time_t t, time_t from, time_t to,
                  const char *glyph, int tone);

#endif /* SLOTH_TUI_GLYPH_H */
