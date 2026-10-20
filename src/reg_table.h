#ifndef SLOTH_REG_TABLE_H
#define SLOTH_REG_TABLE_H

#include <stdint.h>

/* Compiled-in 5 GHz channel table (#101 slice A).
 *
 * A claim about law, compiled into a binary, goes stale the day the
 * rule it encodes is amended. So the table is three things at once and
 * says so everywhere it surfaces:
 *
 *   cited     every row names the clause it was read from — 47 CFR
 *             15.407 for the FCC rows, ETSI EN 301 893 for the ETSI
 *             rows — and a row with no primary source is not added;
 *   dated     REG_TABLE_AS_OF is the day the rows were last checked
 *             against those sources, printed in alert detail and in
 *             docs/wiki/regulatory-table.md;
 *   heuristic what it answers is "does this source list the channel,
 *             and does it require radar detection there", never "is
 *             this transmitter lawful where it stands". National
 *             tables, licences, indoor-only conditions and power
 *             limits are all outside it.
 *
 * Only two jurisdictions, because only two sources were read. The issue
 * names JP / CN / IN / GB / CA / AU too; each is one more table with
 * its own primary source, and a row added without one is exactly what
 * the owner ruling on #145 forbids.
 *
 * Rows are 20 MHz channels identified by channel number in the 5 GHz
 * band (802.11-2020 Annex E, global operating classes 115-125). 6 GHz
 * numbers overlap these and are deliberately not looked up here: a
 * caller must have decided the band first (ap_band_label()). */

#define REG_TABLE_AS_OF "2026-10-20"

typedef enum {
    REG_JUR_NONE = 0,   /* country unknown, absent, or not mapped   */
    REG_JUR_FCC,        /* 47 CFR Part 15 Subpart E (U-NII)         */
    REG_JUR_ETSI,       /* ETSI EN 301 893 (EU member states)       */
    REG_JUR_COUNT
} reg_jurisdiction_t;

/* Per-row flags. */
#define REG_CH_DFS      0x01  /* radar detection required on this channel */
#define REG_CH_WEATHER  0x02  /* 5600-5650 MHz: ETSI extended (600 s) CAC  */

typedef struct {
    uint8_t     channel;     /* 20 MHz channel number                  */
    uint16_t    centre_mhz;  /* 5000 + 5 * channel                     */
    uint8_t     flags;       /* REG_CH_*                               */
    uint16_t    cac_s;       /* channel availability check, 0 = none   */
    const char *clause;      /* where in the source the row comes from */
} reg_chan_row_t;

typedef struct {
    reg_jurisdiction_t    jur;
    const char           *name;    /* "FCC" / "ETSI"                    */
    const char           *source;  /* the primary document, with edition */
    const reg_chan_row_t *rows;
    int                   n_rows;
} reg_table_t;

/* The table for one jurisdiction; NULL for REG_JUR_NONE or out of
 * range. */
const reg_table_t *reg_table_get(reg_jurisdiction_t j);

/* Which table a Country element's two-letter code selects. "US" is the
 * FCC table; the 27 EU member states are the ETSI table. Anything else
 * — including "", NULL, "XX" and every country this table has no
 * source for — is REG_JUR_NONE. Case-sensitive: §9.4.2.8 carries
 * ISO 3166-1 alpha-2, which is upper case, and an AP that sends "us" has
 * not named a country this table knows. */
reg_jurisdiction_t reg_jurisdiction_for_country(const char *cc);

/* The row for `channel` in jurisdiction `j`, or NULL when that source
 * does not list it. NULL is "not in this source", not "unlawful": EN
 * 301 893 does not cover 5725-5850 MHz at all, and other ETSI documents
 * do. */
const reg_chan_row_t *reg_table_lookup(reg_jurisdiction_t j, int channel);

/* Is `channel` (already known to be a 5 GHz channel number) one on
 * which radar detection is required?
 *
 * With a mapped `cc`, that jurisdiction's table answers. With none —
 * absent, unmapped, or a country this table has no source for — the
 * answer is the union over every table: DFS if ANY source here requires
 * it. That is the conservative reading for a passive monitor, and in
 * practice the tables agree everywhere except channel 144, which only
 * the FCC table lists.
 *
 * `*which` (optional) is set to the jurisdiction that answered, or
 * REG_JUR_NONE for the union. `*cac_s` (optional) to the longest CAC any
 * answering row requires, 0 when not DFS. */
int reg_channel_is_dfs(const char *cc, int channel,
                       reg_jurisdiction_t *which, int *cac_s);

#endif /* SLOTH_REG_TABLE_H */
