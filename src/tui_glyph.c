#include <stdio.h>
#include <string.h>
#include "tui_glyph.h"
#include "tui.h"
#include "rf_distance.h"

#define BLOCK_FULL  "\xe2\x96\x88"   /* █ */
#define BLOCK_LOW1  "\xe2\x96\x81"   /* ▁ */
#define BLOCK_HALF  "\xe2\x96\x84"   /* ▄ */
#define SQUARE_SM   "\xe2\x96\xaa"   /* ▪ */
#define MIDDOT      "\xc2\xb7"       /* · */
#define LINE_LIGHT  "\xe2\x94\x80"   /* ─ */
#define LINE_HEAVY  "\xe2\x94\x81"   /* ━ */
#define DOT_BLACK   "\xe2\x97\x8f"   /* ● */

/* The Alerts view's reading of a severity on the heat ramp, so a lane
 * and the alert row it came from are one colour. */
void tg_tone_apply(int tone) {
    switch (tone) {
    case TG_DIM:       tui_dim();       break;
    case TG_NORMAL:    tui_normal();    break;
    case TG_HEAT_LO:   tui_heat(0.0);   break;
    case TG_HEAT_MID:  tui_heat(0.3);   break;
    case TG_HEAT_HI:   tui_heat(0.5);   break;
    case TG_HEAT_PEAK: tui_heat(0.9);   break;
    case TG_SEV_LOW:   tui_heat(0.3);   break;
    case TG_SEV_WARN:  tui_heat(0.5);   break;
    case TG_SEV_CRIT:  tui_heat(1.0);   break;
    default: break;
    }
}

int tg_sev_tone(int sev) {
    return sev >= 2 ? TG_SEV_CRIT : sev == 1 ? TG_SEV_WARN : TG_SEV_LOW;
}

/* ── G2 ─────────────────────────────────────────────────────── */

int tg_sm_s9(int radio, int *known) {
    int k = 1, s9;
    switch (radio) {
    case RF_RADIO_WIFI_5G: s9 = -54; break;
    case RF_RADIO_WIFI_6G: s9 = -56; break;
    case RF_RADIO_WIFI_2G:
    case RF_RADIO_BLE:     s9 = -47; break;
    default:               s9 = -47; k = 0; break;
    }
    if (known) *known = k;
    return s9;
}

const char *tg_sm_band(int radio) {
    switch (radio) {
    case RF_RADIO_WIFI_2G: return "2.4 GHz";
    case RF_RADIO_WIFI_5G: return "5 GHz";
    case RF_RADIO_WIFI_6G: return "6 GHz";
    case RF_RADIO_BLE:     return "BLE";
    default:               return "";
    }
}

/* The segment edges, as smScale() builds them: S1 at s9 - 8 units,
 * then every TG_SM_DB to S9, then every TG_SM_OVER_DB while under the
 * top. */
static int sm_edge(int i, int s9) {
    int lo = s9 - (TG_SM_UNITS - 1) * TG_SM_DB;
    return i < TG_SM_UNITS ? lo + i * TG_SM_DB
                           : s9 + (i - TG_SM_UNITS + 1) * TG_SM_OVER_DB;
}

int tg_sm_level(int dbm, int s9) {
    if (dbm == 0) return 0;
    int lo = sm_edge(0, s9), hi = s9 + TG_SM_TOP;
    int c = dbm < lo ? lo : dbm > hi ? hi : dbm, n = 0;
    for (int i = 0; i < TG_SM_SEGS; i++)
        if (c >= sm_edge(i, s9)) n++;
    return n;
}

int tg_sm_clamped(int dbm, int s9) {
    return dbm != 0 && (dbm < sm_edge(0, s9) || dbm > s9 + TG_SM_TOP);
}

void tg_sm_word(int dbm, int s9, char *out, size_t n) {
    int lv = tg_sm_level(dbm, s9);
    if (!lv)                    snprintf(out, n, "-");
    else if (lv <= TG_SM_UNITS) snprintf(out, n, "S%d", lv);
    else snprintf(out, n, "S9+%d", (lv - TG_SM_UNITS) * TG_SM_OVER_DB);
}

int tg_sm_cells(int dbm, int s9, tg_cell_t out[TG_SM_CELLS]) {
    int lv = tg_sm_level(dbm, s9), k = 0;
    if (!lv) return 0;
    for (int i = 0; i < TG_SM_SEGS; i++) {
        if (i == TG_SM_UNITS) { out[k].glyph = " "; out[k++].tone = TG_NONE; }
        out[k].glyph = i < lv ? BLOCK_FULL : BLOCK_LOW1;
        out[k++].tone = (uint8_t)(i >= lv ? TG_DIM
                                 : i < TG_SM_UNITS ? TG_NORMAL : TG_HEAT_HI);
    }
    return k;
}

/* ── G3 ─────────────────────────────────────────────────────── */

int tg_hz_level(uint32_t v, uint32_t max) {
    if (v == TG_HZ_UNSEEN) return -1;
    if (v == 0) return 0;
    /* v > max / 2 without the rounding of an odd max: 2v > max. */
    return max > 0 && (uint64_t)v * 2u > (uint64_t)max ? 2 : 1;
}

tg_cell_t tg_hz_cell(uint32_t v, uint32_t max) {
    tg_cell_t c;
    switch (tg_hz_level(v, max)) {
    case -1: c.glyph = " ";        c.tone = TG_NONE;     break;
    case 0:  c.glyph = "_";        c.tone = TG_DIM;      break;
    case 1:  c.glyph = BLOCK_HALF; c.tone = TG_NORMAL;   break;
    default: c.glyph = BLOCK_FULL; c.tone = TG_HEAT_MID; break;
    }
    return c;
}

/* ── G4 ─────────────────────────────────────────────────────── */

int tg_how_level(double share, double max) {
    if (!(share > 0.0) || !(max > 0.0)) return 0;
    double f = share / max;
    if (f > 1.0) f = 1.0;
    int lv = (int)(f * 4.0 + 0.999999);   /* ceil: any presence is >= 1 */
    return lv < 1 ? 1 : lv > 4 ? 4 : lv;
}

tg_cell_t tg_how_cell(int watched, double share, double max) {
    static const uint8_t tone[5] = { TG_DIM, TG_HEAT_LO, TG_HEAT_MID,
                                     TG_HEAT_HI, TG_HEAT_PEAK };
    tg_cell_t c;
    if (!watched) { c.glyph = " "; c.tone = TG_NONE; return c; }
    int lv = tg_how_level(share, max);
    c.glyph = lv ? SQUARE_SM : MIDDOT;
    c.tone  = tone[lv];
    return c;
}

/* ── G7 ─────────────────────────────────────────────────────── */

int tg_rug_level(int count, int max) {
    if (count <= 0 || max <= 0) return 0;
    int lv = (int)(((double)count / (double)max) * 8.0 + 0.5);
    return lv < 1 ? 1 : lv > 8 ? 8 : lv;
}

tg_cell_t tg_rug_cell(int count, int max, int tone) {
    static const char *const g[9] = {
        " ",
        "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83", "\xe2\x96\x84",
        "\xe2\x96\x85", "\xe2\x96\x86", "\xe2\x96\x87", "\xe2\x96\x88",
    };
    tg_cell_t c;
    int lv = tg_rug_level(count, max);
    c.glyph = g[lv];
    c.tone  = (uint8_t)(lv ? tone : TG_NONE);
    return c;
}

int tg_rug_bin(const time_t *t, int n, time_t from, time_t to,
               int *out, int cells) {
    int max = 0;
    for (int i = 0; i < cells; i++) out[i] = 0;
    if (cells <= 0 || to <= from) return 0;
    for (int i = 0; i < n; i++) {
        if (t[i] < from || t[i] >= to) continue;
        int c = (int)(((double)(t[i] - from) * cells) / (double)(to - from));
        if (c >= cells) c = cells - 1;
        if (++out[c] > max) max = out[c];
    }
    return max;
}

/* ── G8 ─────────────────────────────────────────────────────── */

void tg_lane_init(tg_lane_t *l, int cells) {
    int max = (int)(sizeof(l->cell) / sizeof(l->cell[0]));
    l->n = cells < 1 ? 1 : cells > max ? max : cells;
    for (int i = 0; i < l->n; i++) {
        l->cell[i].glyph = LINE_LIGHT;
        l->cell[i].tone  = TG_DIM;
    }
}

int tg_lane_col(const tg_lane_t *l, time_t t, time_t from, time_t to) {
    if (to <= from || t < from || t > to) return -1;
    int c = (int)(((double)(t - from) * l->n) / (double)(to - from));
    return c >= l->n ? l->n - 1 : c;
}

void tg_lane_bar(tg_lane_t *l, time_t a, time_t b, time_t from, time_t to,
                 int tone) {
    if (to <= from || b < from || a > to) return;
    int lo_in = a >= from, hi_in = b <= to;
    if (a < from) a = from;
    if (b > to)   b = to;
    int ca = tg_lane_col(l, a, from, to), cb = tg_lane_col(l, b, from, to);
    if (ca < 0 || cb < 0) return;
    for (int i = ca; i <= cb; i++) {
        l->cell[i].glyph = LINE_HEAVY;
        l->cell[i].tone  = (uint8_t)tone;
    }
    /* An end the window cut off is not an observation, so it is no dot. */
    if (lo_in) l->cell[ca].glyph = DOT_BLACK;
    if (hi_in) l->cell[cb].glyph = DOT_BLACK;
}

void tg_lane_mark(tg_lane_t *l, time_t t, time_t from, time_t to,
                  const char *glyph, int tone) {
    int c = tg_lane_col(l, t, from, to);
    if (c < 0) return;
    l->cell[c].glyph = glyph;
    l->cell[c].tone  = (uint8_t)tone;
}
