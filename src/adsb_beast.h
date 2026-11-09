#ifndef SLOTH_ADSB_BEAST_H
#define SLOTH_ADSB_BEAST_H

#include <stddef.h>
#include <stdint.h>
#include "sloth.h"

/* ── --adsb beast:// (#186, 2026-11-09) ──────────────────────────────
 *
 * The decoder's Beast binary output (readsb --net-bo-port, default
 * 30005), read by the same loopback-only, never-writing TCP client as
 * sbs:// (src/capture/adsb_reader.c), framed and decoded here, and fed
 * into the same table (src/adsb.c). This file is pure: no I/O, no lock;
 * the framer/decoder state is the reader worker's alone.
 *
 * Framing - readsb net_io.c, read at bf8f8fd: modesSendBeastOutput()
 * (what the output writes), netTimestamp(), readBeast() and
 * decodeBinMessage() (what readsb itself accepts as input):
 *
 *   0x1A TYPE TIMESTAMP(6, big-endian 12 MHz receiver clock) SIGNAL(1)
 *   PAYLOAD, where TYPE '1' Mode A/C (2 payload bytes), '2' Mode S
 *   short (7), '3' Mode S long (14). Every 0x1A after TYPE (timestamp,
 *   signal, payload) is sent doubled.
 *   0x1A 0xE3 RECEIVER-ID(8, escaped) - only when --net-receiver-id is
 *   on; skipped.
 *   0x1A '5' + 21 bytes - a Radarcape receiver position (input-side
 *   in readsb); skipped.
 *   Any other TYPE is counted as a parse error and the framer hunts for
 *   the next 0x1A. A 0x1A followed by anything but 0x1A inside a frame
 *   is a frame cut short: one parse error, and that 0x1A starts the next
 *   frame (readBeast() does the same).
 *   readsb has no TYPE '4' on this path; it is an unknown type here.
 *   The output's heartbeat (net_io.c beast_heartbeat_msg) is a '1'
 *   frame of zeros, sent every --net-heartbeat seconds (60 by default,
 *   readsb.h MODES_NET_HEARTBEAT_INTERVAL) to an idle client and five
 *   times at connect (sendFiveHeartbeats()). Mode A/C frames are
 *   counted and otherwise ignored; any frame keeps the source live, so
 *   the stale window is the SBS one (ADSB_SBS_STALE_S, 130 s).
 *
 * SIGNAL: readsb writes round(sqrt(power) * 255) and reads it back as
 * power = (b / 255)^2 (decodeBinMessage); aircraft.json's rssi is
 * 10 log10(mean power over the last 8 messages + 1.125e-5)
 * (track.h getSignal()). Here: the same, over the last up to 8 frames
 * with b > 0 (readsb reports the floor until it has 4; this does not).
 * The 6-byte timestamp is the receiver's clock, not wall time, and is
 * never used as a time: seen is the read time. The one value read from
 * it is readsb's MAGIC_MLAT_TIMESTAMP (readsb.h), which marks an MLAT
 * result (forwarded only with --forward-mlat): such a row is "mlat".
 *
 * Decoding scope (mode_s.c decodeModesMessage(), decodeExtendedSquitter()
 * and the decodeES*() functions; J. Sun, "The 1090 Megahertz Riddle",
 * 2nd ed., mode-s.org: ADS-B identification, airborne position,
 * airborne velocity, error control, and Mode S surveillance chapters):
 *
 *   CRC-24, generator 0x1FFF409: the remainder over the whole frame is
 *   0 for an intact DF11/17/18 and the sender's address for the
 *   address/parity formats (DF4/5/20/21). No bit is ever corrected.
 *   DF11's remainder carries the interrogator code in its low 7 bits:
 *   above them it is an error, II != 0 a reply to some radar (ignored).
 *   DF17 (and DF18) are taken only with remainder 0. DF4/5/20/21 are
 *   taken only for an address a clean DF17, or DF11 with remainder 0
 *   (II = 0), confirmed in the last ADSB_BEAST_CONFIRM_MS: any corrupted
 *   reply otherwise yields a plausible "address" that never existed.
 *   This is readsb's icaoFilterAdd() rule, which also excludes DF18
 *   ("a DF18 transmitter doesn't necessarily have a Mode S transponder")
 *   and keeps an address 60-120 s (MODES_ICAO_FILTER_TTL, two tables).
 *   DF11 itself makes no row; DF0/16 (ACAS) and Comm-D are not decoded.
 *   DF17/18 type codes: 1-4 identification (callsign, category); 5-8
 *   surface position: only on_ground is taken (movement and the surface
 *   CPR are not decoded); 9-18 airborne position with barometric
 *   altitude, 20-22 with GNSS altitude (alt_geom; the 12-bit field is
 *   decoded as readsb does, AC12 with Q); 19 velocity subtypes 1/2
 *   (ground speed, track) and the vertical rate of all four subtypes;
 *   28 subtype 1 emergency/priority status (the emergency word, readsb's
 *   emergency_t order, which is ADSB_EMERG_*; and the Mode A code).
 *   DF18 by its CF as readsb's decodeExtendedSquitter(): 0 ICAO
 *   (adsb_icao_nt), 1 non-ICAO (adsb_other), 2 TIS-B fine (tisb_icao,
 *   IMF set: tisb_trackfile, non-ICAO), 5 TIS-B non-ICAO (tisb_other),
 *   6 ADS-R (adsr_icao, IMF: adsr_other); 3, 4, 7 are not decoded.
 *   DF4/20 altitude: the 13-bit AC field with Q = 1 (25 ft) only; Q = 0
 *   (Gillham, 100 ft) and M = 1 (metres) leave it absent. DF5/21 the
 *   13-bit identity, Gillham-ordered C1 A1 C2 A2 C4 A4 X B1 D1 B2 D2 B4
 *   D4 (readsb decodeID13Field()), an all-zero field left absent.
 *
 * CPR (airborne only): a global decode from an even and an odd message
 * of one address read within ADSB_BEAST_CPR_PAIR_MS (10 s; readsb
 * widens this by ground speed up to 30 s, cpr_global_airborne_max_
 * elapsed()), refused when the two latitudes fall in different NL
 * zones; otherwise a local decode against the aircraft's own last
 * position if that is at most ADSB_BEAST_REF_MS old. Every result,
 * global or local, is refused when it lies farther from that last
 * position than ADSB_BEAST_MAX_KMS per second elapsed plus
 * ADSB_BEAST_SLACK_KM. The sensor's own position (--gps / --location)
 * is NOT used as a reference: a receiver hears aircraft past the
 * 180 NM half-zone a receiver-relative decode is unambiguous within,
 * so an aircraft's first position always comes from a pair. */

#define ADSB_BEAST_DEFAULT_PORT 30005
#define ADSB_BEAST_TRACKS       1024     /* addresses remembered (confirmation, CPR) */
#define ADSB_BEAST_CONFIRM_MS   60000    /* a clean DF17/DF11 vouches this long */
#define ADSB_BEAST_CPR_PAIR_MS  10000
#define ADSB_BEAST_REF_MS       60000    /* a last position this young is a local reference */
#define ADSB_BEAST_MAX_KMS      0.6      /* km/s, about 1170 kt */
#define ADSB_BEAST_SLACK_KM     5.0
#define ADSB_BEAST_MLAT_TS      0xFF004D4C4154ULL   /* readsb.h MAGIC_MLAT_TIMESTAMP */

/* ── Mode S primitives (pure, exposed for the known-answer tests) ── */

/* Remainder of the CRC-24 division over the whole frame of `bits` (56
 * or 112): 0 for an intact DF11 (II 0) / DF17 / DF18, the address for
 * an address/parity frame. */
uint32_t adsb_modes_crc(const uint8_t *msg, int bits);

/* The 13-bit AC field (DF4/20): 0 with feet when M = 0 and Q = 1, -1
 * otherwise (Gillham, metres, all zero). */
int adsb_modes_ac13(unsigned ac13, int *alt_ft);
/* The 12-bit ES altitude: 0 with feet when Q = 1, -1 otherwise. */
int adsb_modes_ac12(unsigned ac12, int *alt_ft);
/* The 13-bit identity (DF5/21, TC28) as four octal digits in out[5];
 * -1 for an all-zero field. */
int adsb_modes_id13(unsigned id13, char out[5]);

/* NL(lat) from the closed form ("The 1090 Megahertz Riddle", airborne
 * position): 59 at the equator, 2 at +-87, 1 beyond. */
int adsb_cpr_nl(double lat);
/* Global airborne decode of an even/odd pair (17-bit values), the
 * newer one's parity in `odd_newest`. 0 with the position; -1 when the
 * latitudes lie in different NL zones or out of range. */
int adsb_cpr_global(int lat_e, int lon_e, int lat_o, int lon_o, int odd_newest,
                    double *lat, double *lon);
/* Local airborne decode of one message against a reference: 0 with the
 * position, -1 when the result is not within half a zone of it. */
int adsb_cpr_local(double ref_lat, double ref_lon, int cpr_lat, int cpr_lon,
                   int odd, double *lat, double *lon);

/* ── The decoder ───────────────────────────────────────────────── */

typedef struct {
    uint32_t addr;
    uint8_t  used, non_icao, had_adsb;
    uint8_t  cpr_valid[2];
    int      cpr_lat[2], cpr_lon[2];
    uint64_t cpr_mono[2];
    uint8_t  has_ref;
    double   ref_lat, ref_lon;
    uint64_t ref_mono;
    uint64_t confirmed_mono;     /* last clean DF17 / DF11; 0 never */
    uint64_t last_mono;          /* eviction order */
    double   sig[8];             /* power, the last up to 8 frames with b > 0 */
    uint8_t  sig_n, sig_next;
} adsb_beast_track_t;

/* What one frame came to. */
enum {
    ADSB_BEAST_ROW = 1,         /* out carries fields for the table */
    ADSB_BEAST_CONFIRM,         /* DF11/DF17 that vouched for an address, nothing to keep */
    ADSB_BEAST_MODEAC,          /* Mode A/C, heartbeat included: ignored */
    ADSB_BEAST_GHOST,           /* DF4/5/20/21 from an unconfirmed address */
    ADSB_BEAST_CRC,             /* DF11/17/18 whose remainder is not 0 */
    ADSB_BEAST_CPR_REJECT,      /* a row, but its position was refused */
    ADSB_BEAST_IGNORED          /* a DF / type code / CF not decoded */
};

typedef struct {
    /* framer */
    int      st;                /* hunt, type, body, escape */
    uint8_t  type;
    uint8_t  body[21];
    int      need, got;
    int      garbage_run;
    /* decoder */
    adsb_beast_track_t trk[ADSB_BEAST_TRACKS];
    /* tallies (tests, the fuzz harness) */
    uint64_t frames, modeac, ghosts, crc_bad, cpr_rejected, ignored, skipped;
    uint64_t parse_errors;
    adsb_aircraft_t out;        /* the last ROW, worker scratch */
} adsb_beast_t;

void adsb_beast_init(adsb_beast_t *b);

/* Decode one unescaped Mode S frame (7 or 14 bytes) with its signal
 * byte and receiver timestamp, read at `mono_ms`. Returns ADSB_BEAST_*;
 * on ROW / CPR_REJECT, `out` holds the fields the frame carried (has_*
 * flags as aircraft.json's parser sets them, emergency ABSENT unless a
 * TC 28 frame gave it, rssi from the track's recent frames). */
int  adsb_beast_decode(adsb_beast_t *b, const uint8_t *msg, int len,
                       uint8_t signal, uint64_t ts, uint64_t mono_ms,
                       adsb_aircraft_t *out);

/* The framer: bytes as read from the socket, any split. Each whole
 * frame is decoded and its ROW fed to the table (adsb_feed_beast) at
 * `wall_ms` / `mono_ms`; any frame (heartbeat included) marks the
 * source alive; garbage and cut frames are parse errors in the table's
 * health. Bounded: never holds more than one frame body. */
void adsb_beast_feed(adsb_beast_t *b, const uint8_t *data, size_t n,
                     int64_t wall_ms, uint64_t mono_ms);

#endif /* SLOTH_ADSB_BEAST_H */
