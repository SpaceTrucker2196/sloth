/* The 802.11 band plan — the single frequency ↔ channel converter (#167).
 *
 * Before this module the mapping existed four times over and the copies
 * had drifted: src/radiotap.c accepted 5160..5895 as 5 GHz, the static
 * freq_to_channel() in src/platform/linux_wifi.c accepted 5180..5900,
 * src/radiotap.c's band classifier repeated the first range a third
 * time, and the forward direction was split between chanhop_freq()
 * (1-13, 14, 36-177, no 6 GHz at all) and reg_obs_freq_mhz() (32-177,
 * with 6 GHz). A monitor capture and a managed-mode nl80211 scan
 * therefore disagreed about which frequencies were channels at all,
 * while a test comment in tests/test_radiotap.c claimed they were
 * shared. Everything here is one table and one range check per band.
 *
 * Reference: IEEE 802.11-2020 Annex E Table E-4 (2.4 / 5 GHz) and
 * 802.11ax-2021 §27.3.23.2 with Annex E Table E-4's 6 GHz rows.
 *
 * This is a NUMBERING converter, not a regulatory validator: it answers
 * "what is this frequency called", never "may this radio sit here".
 * Which channels an adapter is permitted to use is the regulatory
 * layer's question (src/reg_table.c), and a passive receiver must be
 * able to name a transmission it heard regardless of the answer.
 *
 * Pure arithmetic — no hardware, no netlink, no regulatory database —
 * so it compiles into every build variant and is tested from
 * hand-computed values rather than from a capture. */

#ifndef SLOTH_WIFI_FREQ_H
#define SLOTH_WIFI_FREQ_H

/* Which band a frequency sits in.
 *
 * A channel NUMBER alone cannot say this: 6 GHz channels run 1..233,
 * so every 2.4 GHz number and every 5 GHz number has a 6 GHz twin (ch 1
 * is 2412 *and* 5955; ch 36 is 5180 *and* 6130). The radio frequency
 * never is ambiguous, which is why the band travels with the channel
 * through this API (#149). */
typedef enum {
    WIFI_BAND_UNKNOWN = 0,
    WIFI_BAND_2GHZ    = 1,
    WIFI_BAND_5GHZ    = 2,
    WIFI_BAND_6GHZ    = 3,
} wifi_band_t;

/* The band `mhz` lies in, or WIFI_BAND_UNKNOWN. Spans the band's
 * assignable channels, so it answers for a frequency inside the band
 * that is not itself a channel centre. */
wifi_band_t wifi_freq_band(int mhz);

/* Channel number for `mhz`, 0 when the frequency names no channel.
 * `band_out` (may be NULL) receives the band — the only thing that
 * tells 2412's channel 1 from 5955's.
 *
 * A 0 return with a known band means "in this band, but not a channel
 * centre": the two are separate questions and are answered separately. */
int wifi_freq_channel(int mhz, wifi_band_t *band_out);

/* Centre frequency in MHz of a band-qualified channel, 0 when the pair
 * names no channel. The inverse of wifi_freq_channel() wherever that
 * returns non-zero. */
int wifi_freq_mhz(wifi_band_t band, int channel);

/* The band a BARE channel number has to mean when its source carried no
 * band of its own — a --hop channel list, a DS Parameter Set IE.
 *
 * Never answers 6 GHz: those numbers collide with both other bands, so
 * inferring it would be a guess dressed as a fact. A caller that knows
 * the band (a 6 GHz Operation Info element, a radiotap frequency) must
 * pass it rather than come through here. */
wifi_band_t wifi_freq_infer_band(int channel);

#endif /* SLOTH_WIFI_FREQ_H */
