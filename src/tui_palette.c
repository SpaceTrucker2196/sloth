/* Colour-pair → xterm-256 mapping shared by both tui.c backends.
 * See tui_palette.h for why this lives outside tui.c. */

#include "tui.h"
#include "tui_palette.h"

/* Fallout-inspired phosphor palette: teal phosphor (CP_NORMAL = 43) is
 * the anchor, these eight orbit it with hues a CRT might glow at. */
const short tui_ip_fg[8] = {
    50,    /* #00ffd7  bright phosphor teal   */
    80,    /* #5fd7d7  aged dim phosphor cyan */
    121,   /* #87ffaf  rad-green              */
    156,   /* #afff87  mutated lime           */
    178,   /* #d7af00  amber CRT dial         */
    215,   /* #ffaf5f  hazmat orange          */
    174,   /* #d78787  faded crimson (Nuka)   */
    110,   /* #87afd7  Vault-Tec blue         */
};

/* Slots 0..7 mirror the original layout; 8..15 are the
 * corporate-identity additions. Index meanings are the BR_* defines. */
const short tui_brand_fg[16] = {
     33,   /* Google blue     #0087ff */
    167,   /* Google red      #d75f5f */
    220,   /* Google yellow   #ffd700 */
     35,   /* Google green    #00af5f */
    208,   /* Firefox orange  #ff8700 */
    196,   /* Cloudflare red  #ff0000 */
    244,   /* example grey    #808080 */
     99,   /* Discord blurple #875fff */
     27,   /* Facebook blue   #005fff */
     41,   /* Spotify green   #00d75f */
    135,   /* Twitch purple   #af5fff */
    214,   /* Amazon orange   #ffaf00 */
     31,   /* LinkedIn blue   #0087af */
    124,   /* Netflix red     #af0000 */
    202,   /* Reddit orange   #ff5f00 */
    169,   /* Instagram pink  #d75faf */
};

const short tui_info_fg[8] = {
    95,    /* mauve      #875f5f */
    101,   /* olive      #87875f */
    137,   /* tan        #af875f */
    144,   /* sage       #afaf87 */
    173,   /* terracotta #d7875f */
    179,   /* wheat      #d7af87 */
    138,   /* dusty rose #af8787 */
    102,   /* stone grey #878787 */
};

/* Colour is on unless the operator says otherwise — NO_COLOR or
 * --no-color. */
static int g_color = 1;

void tui_set_color(int enabled) { g_color = enabled ? 1 : 0; }
int  tui_color_enabled(void)    { return g_color; }

/* Returns 1 and fills the fg / bg outputs for a mapped pair, 0 otherwise.
 * The band tests are ordered by pair number so the ranges stay
 * readable against the CP_* layout in tui.h. */
int tui_pair_colors(int pair, short *fg, short *bg) {
    short f, b = -1;

    switch (pair) {
    case CP_BRIGHT:         f = TUI_C_BRIGHT;    break;
    case CP_NORMAL:         f = TUI_C_NORMAL;    break;
    case CP_DIM:            f = TUI_C_DIM;       break;
    case CP_HEAT_LO:        f = TUI_C_HEAT_LO;   break;
    case CP_HEAT_MID:       f = TUI_C_HEAT_MID;  break;
    case CP_HEAT_HI:        f = TUI_C_HEAT_HI;   break;
    case CP_HEAT_PEAK:      f = TUI_C_HEAT_PEAK; break;
    case CP_BORDER:         f = TUI_C_BORDER;    break;
    case CP_ALERT_HOT_LOW:  f = TUI_C_HOT_LOW;   break;
    case CP_ALERT_HOT_WARN: f = TUI_C_HOT_WARN;  break;
    case CP_ALERT_HOT_CRIT: f = TUI_C_HOT_CRIT;  break;
    case CP_HIGHLIGHT:      f = TUI_C_HL_FG; b = TUI_C_HL_BG; break;
    default:
        /* Banded ranges: every row-category variant of a given index
         * resolves to the same foreground, because row backgrounds were
         * retired — the category only ever selected the (now identical)
         * bg half of the pair. */
        if      (pair >= CP_IP_BASE_OTHER && pair < CP_IP_BASE_OTHER + 8)
            f = tui_ip_fg[pair - CP_IP_BASE_OTHER];
        else if (pair >= CP_IP_BASE_TCP   && pair < CP_IP_BASE_TCP   + 8)
            f = tui_ip_fg[pair - CP_IP_BASE_TCP];
        else if (pair >= CP_IP_BASE_UDP   && pair < CP_IP_BASE_UDP   + 8)
            f = tui_ip_fg[pair - CP_IP_BASE_UDP];
        else if (pair >= CP_IP_BASE_DNS   && pair < CP_IP_BASE_DNS   + 8)
            f = tui_ip_fg[pair - CP_IP_BASE_DNS];
        else if (pair >= CP_IP_BASE_ICMP  && pair < CP_IP_BASE_ICMP  + 8)
            f = tui_ip_fg[pair - CP_IP_BASE_ICMP];
        else if (pair >= CP_IP_BASE_HTTP  && pair < CP_IP_BASE_HTTP  + 8)
            f = tui_ip_fg[pair - CP_IP_BASE_HTTP];
        else if (pair >= CP_IP_BASE_TLS   && pair < CP_IP_BASE_TLS   + 8)
            f = tui_ip_fg[pair - CP_IP_BASE_TLS];
        else if (pair >= CP_BR_BASE_OTHER && pair < CP_BR_BASE_OTHER + 8)
            f = tui_brand_fg[pair - CP_BR_BASE_OTHER];
        else if (pair >= CP_BR_BASE_TCP   && pair < CP_BR_BASE_TCP   + 8)
            f = tui_brand_fg[pair - CP_BR_BASE_TCP];
        else if (pair >= CP_BR_BASE_UDP   && pair < CP_BR_BASE_UDP   + 8)
            f = tui_brand_fg[pair - CP_BR_BASE_UDP];
        else if (pair >= CP_BR_BASE_DNS   && pair < CP_BR_BASE_DNS   + 8)
            f = tui_brand_fg[pair - CP_BR_BASE_DNS];
        else if (pair >= CP_BR_BASE_ICMP  && pair < CP_BR_BASE_ICMP  + 8)
            f = tui_brand_fg[pair - CP_BR_BASE_ICMP];
        else if (pair >= CP_BR_BASE_HTTP  && pair < CP_BR_BASE_HTTP  + 8)
            f = tui_brand_fg[pair - CP_BR_BASE_HTTP];
        else if (pair >= CP_BR_BASE_TLS   && pair < CP_BR_BASE_TLS   + 8)
            f = tui_brand_fg[pair - CP_BR_BASE_TLS];
        else if (pair >= CP_BR_EXTRA_BASE && pair < CP_BR_EXTRA_BASE + 8)
            f = tui_brand_fg[8 + (pair - CP_BR_EXTRA_BASE)];
        else if (pair >= CP_INFO_BASE     && pair < CP_INFO_BASE     + 8)
            f = tui_info_fg[pair - CP_INFO_BASE];
        else
            return 0;      /* retired CP_PKT_* band, or out of range */
        break;
    }

    if (fg) *fg = f;
    if (bg) *bg = b;
    return 1;
}
