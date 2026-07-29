/* Shared colour palette for the two tui.c render backends.
 *
 * tui.c has an ncurses implementation and an ANSI fallback
 * (WITH_NCURSES=0, used by `make embedded` and headless appliance
 * builds). Both need the same colours; before issue #48 the ncurses
 * branch owned them as function-local tables and the fallback had no
 * colour helpers at all — it didn't compile. Keeping the palette here
 * means the fallback can't drift from the real UI.
 *
 * Values are xterm-256 indices. The ncurses backend feeds them to
 * init_pair(); the ANSI backend emits them as SGR 38;5;N. */

#ifndef TUI_PALETTE_H
#define TUI_PALETTE_H

/* Scalar pairs — nuclear teal-green phosphor + heat gradient. */
#define TUI_C_BRIGHT      49   /* #00ffaf */
#define TUI_C_NORMAL      43   /* #00d7af */
#define TUI_C_DIM         29   /* #00875f */
#define TUI_C_HEAT_LO    241   /* rgb(98,98,98)  */
#define TUI_C_HEAT_MID   178   /* rgb(215,175,0) */
#define TUI_C_HEAT_HI    208   /* rgb(255,135,0) */
#define TUI_C_HEAT_PEAK  196   /* rgb(255,0,0)   */
#define TUI_C_BORDER      29   /* same hue family as CP_DIM */
#define TUI_C_HL_FG      255   /* white on ... */
#define TUI_C_HL_BG       22   /* #005f00 dim phosphor */
#define TUI_C_HOT_LOW    220   /* #ffd700 amber-yellow */
#define TUI_C_HOT_WARN   208   /* #ff8700 orange       */
#define TUI_C_HOT_CRIT   196   /* #ff0000 red          */

/* Table-driven pairs. Indices are the low 3 (or 4) bits of the
 * hash-derived colour index — see tui.h for the pair-number layout. */
extern const short tui_ip_fg[8];       /* Fallout phosphor IP palette   */
extern const short tui_brand_fg[16];   /* brand / corporate identity    */
extern const short tui_info_fg[8];     /* earth tones, packets info col */

/* ── colour policy (#50) ──────────────────────────────────
 *
 * Lives here rather than in tui.c because it is a property of the
 * palette, not of either renderer — and because tui.c is swapped out
 * for a stub in the test build, which would leave this untestable.
 *
 * Disabling colour suppresses SGR emission in the ANSI backend and
 * skips colour-pair init under ncurses. It does NOT stop drawing: that
 * is what --headless is for. The two are separate because "I am reading
 * this over a serial console" and "nothing is reading this" are
 * different situations. */
void tui_set_color(int enabled);
int  tui_color_enabled(void);

/* Resolve a colour-pair number to its xterm-256 foreground and
 * background. Writes *fg and *bg and returns 1 for a known pair;
 * returns 0 and leaves both untouched for anything unmapped (the
 * retired CP_PKT_* row-background range, or a number out of range).
 *
 * *bg is -1 for "leave the terminal background alone" — which is every
 * pair but CP_HIGHLIGHT, per the UI convention that rows render on the
 * terminal default. Callers that need a concrete colour substitute 0.
 *
 * Pure integer mapping, so it is unit-testable without a terminal. */
int tui_pair_colors(int pair, short *fg, short *bg);

#endif /* TUI_PALETTE_H */
