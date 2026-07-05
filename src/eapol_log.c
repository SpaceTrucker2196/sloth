#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include "eapol_log.h"
#include "eap_track.h"
#include "beacon_snoop.h"
#include "assoc_track.h"
#include "alerts.h"

/* ── Storage ─────────────────────────────────────────────── */

static eapol_event_t   g_events[MAX_EAPOL_EVENTS];
static int             g_head  = 0;
static int             g_count = 0;
static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* Per-(BSSID, STA) pending handshake state. M1 lands first with ANonce
 * (and optionally PMKID); M2 lands with SNonce + MIC. When both are
 * present we emit a combined complete-handshake event.
 *
 * m_frames[0..3] = M1..M4 raw 802.11 bytes (frame body, no radiotap).
 * Stored as captured so the pcap export reproduces them byte-for-byte
 * for use with aircrack-ng / hcxpcapngtool / Wireshark. */
#define MAX_PENDING 64
#define EAPOL_FRAME_MAX 512
typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta[6];
    int      m1_seen;
    int      m2_seen;
    int      has_pmkid;
    uint8_t  pmkid[16];
    uint8_t  anonce[32];
    uint8_t  snonce[32];
    uint8_t  mic[16];
    time_t   m1_ts;
    time_t   m2_ts;
    int8_t   signal_dbm;
    int      channel;
    uint8_t  m_frames[4][EAPOL_FRAME_MAX];
    int      m_frame_lens[4];
    time_t   m_frame_ts[4];
} pending_t;
static pending_t g_pending[MAX_PENDING];
static int       g_pending_n = 0;

static char g_out_dir[256];

/* ── Helpers ─────────────────────────────────────────────── */

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

static pending_t *pending_find_or_alloc(const uint8_t bssid[6],
                                         const uint8_t sta[6]) {
    for (int i = 0; i < g_pending_n; i++) {
        if (mac_eq(g_pending[i].bssid, bssid) && mac_eq(g_pending[i].sta, sta))
            return &g_pending[i];
    }
    int slot;
    if (g_pending_n < MAX_PENDING) {
        slot = g_pending_n++;
    } else {
        /* Evict oldest M1. */
        slot = 0;
        time_t oldest = g_pending[0].m1_ts;
        for (int i = 1; i < g_pending_n; i++) {
            if (g_pending[i].m1_ts < oldest) { oldest = g_pending[i].m1_ts; slot = i; }
        }
    }
    memset(&g_pending[slot], 0, sizeof(g_pending[slot]));
    memcpy(g_pending[slot].bssid, bssid, 6);
    memcpy(g_pending[slot].sta,   sta,   6);
    return &g_pending[slot];
}

static void push_event(const eapol_event_t *e) {
    g_events[g_head] = *e;
    g_head = (g_head + 1) % MAX_EAPOL_EVENTS;
    if (g_count < MAX_EAPOL_EVENTS) g_count++;
}

/* hashcat 22000 hex helpers. */
static void hex_bytes(const uint8_t *b, int n, char *out) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i*2]   = hexd[(b[i] >> 4) & 0xf];
        out[i*2+1] = hexd[b[i] & 0xf];
    }
    out[n*2] = '\0';
}

static void hex_str(const char *s, char *out) {
    static const char hexd[] = "0123456789abcdef";
    int i;
    for (i = 0; s[i]; i++) {
        out[i*2]   = hexd[((unsigned char)s[i] >> 4) & 0xf];
        out[i*2+1] = hexd[(unsigned char)s[i] & 0xf];
    }
    out[i*2] = '\0';
}

/* Append a hashcat-22000 line. If the BSSID was marked tainted by
 * rule_evil_twin_attack_chain, prepend a comment line ('#' is ignored
 * by hashcat's parser) carrying the provenance + BSSID so a forensic
 * reviewer can trace the capture back to the chain alert. */
static void append_22000_line_for_bssid(const char *line,
                                        const uint8_t bssid[6]) {
    if (!g_out_dir[0]) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/eapol.22000", g_out_dir);
    FILE *f = fopen(path, "a");
    if (!f) return;
    if (evil_twin_bssid_is_tainted(bssid)) {
        fprintf(f, "# provenance=tainted-evil-twin "
                   "bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
                bssid[0], bssid[1], bssid[2],
                bssid[3], bssid[4], bssid[5]);
    }
    fputs(line, f);
    fputc('\n', f);
    fclose(f);
}

/* ── Per-handshake pcap writer ───────────────────────────── */

#define PCAP_MAGIC          0xa1b2c3d4u
#define DLT_IEEE802_11      105   /* raw 802.11 without radiotap */

static void w_u32le(FILE *f, uint32_t v) {
    uint8_t b[4] = { v & 0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff };
    fwrite(b, 1, 4, f);
}
static void w_u16le(FILE *f, uint16_t v) {
    uint8_t b[2] = { v & 0xff, (v>>8)&0xff };
    fwrite(b, 1, 2, f);
}

/* Write a per-handshake .pcap to <eapol_dir>/<bssid>_<sta>.pcap.
 * Frames are stored as raw IEEE 802.11 (DLT 105). Aircrack-ng + tshark
 * read this fine; pass -e <SSID> to aircrack if no beacon was bundled.
 *
 * Re-writes overwrite — a fresher capture supersedes the older one. */
static void write_handshake_pcap(const pending_t *p) {
    if (!g_out_dir[0]) return;
    char path[640];
    snprintf(path, sizeof(path),
             "%s/%02x%02x%02x%02x%02x%02x_%02x%02x%02x%02x%02x%02x.pcap",
             g_out_dir,
             p->bssid[0], p->bssid[1], p->bssid[2],
             p->bssid[3], p->bssid[4], p->bssid[5],
             p->sta[0],   p->sta[1],   p->sta[2],
             p->sta[3],   p->sta[4],   p->sta[5]);
    FILE *f = fopen(path, "wb");
    if (!f) return;

    /* Global header */
    w_u32le(f, PCAP_MAGIC);
    w_u16le(f, 2);            /* major */
    w_u16le(f, 4);            /* minor */
    w_u32le(f, 0);            /* thiszone */
    w_u32le(f, 0);            /* sigfigs */
    w_u32le(f, 65535);        /* snaplen */
    w_u32le(f, DLT_IEEE802_11);

    /* Walk M1..M4 in order. Skip empty slots. */
    for (int i = 0; i < 4; i++) {
        if (p->m_frame_lens[i] == 0) continue;
        time_t   ts  = p->m_frame_ts[i];
        uint16_t cap = (uint16_t)p->m_frame_lens[i];
        w_u32le(f, (uint32_t)ts);
        w_u32le(f, 0);                /* usec — second-level resolution */
        w_u32le(f, cap);
        w_u32le(f, cap);
        fwrite(p->m_frames[i], 1, cap, f);
    }
    fclose(f);
}

/* ── EAPOL-Key parser ────────────────────────────────────── */

/* Recognise an EAPOL-Key frame and decide which message number it is.
 * Returns 0 if not an EAPOL-Key frame; 1..4 for valid messages.
 * Outputs ANonce/SNonce/MIC/PMKID as appropriate.
 *
 * keydata points at the start of the EAPOL frame (version byte). */
static int parse_eapol_key(const uint8_t *p, int len,
                            uint8_t out_nonce[32], uint8_t out_mic[16],
                            int *out_has_pmkid, uint8_t out_pmkid[16])
{
    *out_has_pmkid = 0;
    if (len < 95) return 0;       /* EAPOL hdr 4 + key body up through MIC */
    /* EAPOL header. */
    /* p[0] version, p[1] type. type 3 = EAPOL-Key. */
    if (p[1] != 3) return 0;
    /* p[4] Descriptor Type: 2 = RSN (802.11), 254 = WPA. */
    uint8_t desc = p[4];
    if (desc != 2 && desc != 254) return 0;
    /* p[5..6] Key Information, big-endian. */
    uint16_t ki = (uint16_t)((p[5] << 8) | p[6]);
    int key_type    = (ki >> 3) & 1;
    int install     = (ki >> 6) & 1;
    int key_ack     = (ki >> 7) & 1;
    int key_mic     = (ki >> 8) & 1;
    int secure      = (ki >> 9) & 1;
    int encrypted_d = (ki >> 12) & 1;
    if (!key_type) return 0;       /* group key, not interesting */

    /* Nonce: bytes 17..48. */
    memcpy(out_nonce, p + 17, 32);
    /* MIC: bytes 81..96. */
    memcpy(out_mic, p + 81, 16);

    /* Key Data Length: bytes 97..98 (big-endian). */
    int kdl = (p[97] << 8) | p[98];
    if (kdl < 0 || 99 + kdl > len) kdl = 0;

    /* Classify (RFC 8.5.3 / 802.11-2016 §12.7.6): *
     *   M1: KeyACK=1, MIC=0, Install=0, Secure=0
     *   M2: KeyACK=0, MIC=1, Install=0, Secure=0
     *   M3: KeyACK=1, MIC=1, Install=1
     *   M4: KeyACK=0, MIC=1, Install=0, Secure=1                       */
    int msg = 0;
    if (key_ack && !key_mic && !install && !secure)        msg = 1;
    else if (!key_ack && key_mic && !install && !secure)   msg = 2;
    else if (key_ack && key_mic && install)                msg = 3;
    else if (!key_ack && key_mic && !install && secure)    msg = 4;
    else                                                    return 0;

    /* PMKID KDE in M1's Key Data. Walk KDEs:
     *   Type (1B) = 0xDD, Length (1B), then OUI(3B)+DataType(1B)+Data.
     *   PMKID KDE: OUI 00:0F:AC, DataType 0x04, 16-byte PMKID. */
    if (msg == 1 && kdl >= 6 && !encrypted_d) {
        const uint8_t *kd = p + 99;
        int rem = kdl;
        while (rem >= 2) {
            uint8_t t = kd[0];
            uint8_t l = kd[1];
            if (2 + l > rem) break;
            if (t == 0xDD && l == 20 &&
                kd[2] == 0x00 && kd[3] == 0x0f && kd[4] == 0xac &&
                kd[5] == 0x04) {
                memcpy(out_pmkid, kd + 6, 16);
                *out_has_pmkid = 1;
                break;
            }
            kd  += 2 + l;
            rem -= 2 + l;
        }
    }
    return msg;
}

/* ── 802.11 frame walker ─────────────────────────────────── */

int eapol_observe_dot11(const uint8_t *d, int len,
                         int8_t signal, int channel)
{
    if (len < 32) return 0;
    uint8_t fc0   = d[0];
    uint8_t fc1   = d[1];
    uint8_t type  = (fc0 >> 2) & 0x03;
    uint8_t sub   = (fc0 >> 4) & 0x0f;
    if (type != 2) return 0;   /* data frame */
    int to_ds   = (fc1 >> 0) & 1;
    int from_ds = (fc1 >> 1) & 1;

    /* Frame header layout: FC(2)+Dur(2) + Addr1(6)+Addr2(6)+Addr3(6) +
     * SeqCtl(2). With 4-address (WDS) ToDS=FromDS=1 adds Addr4(6).
     * QoS data subtype (sub & 0x08) adds QoSCtl(2). */
    int hdr = 24;
    if (to_ds && from_ds) hdr += 6;
    if (sub & 0x08)       hdr += 2;
    /* Optional Order bit means +HT Control (4 bytes) — uncommon. */
    if ((fc1 >> 7) & 1)   hdr += 4;
    if (len < hdr + 8 + 4) return 0;   /* LLC(8) + at-least EAPOL hdr */

    /* LLC SNAP: AA AA 03 00 00 00 + ethertype */
    const uint8_t *llc = d + hdr;
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return 0;
    if (llc[3] || llc[4] || llc[5]) return 0;
    uint16_t et = (uint16_t)((llc[6] << 8) | llc[7]);
    if (et != 0x888E) return 0;        /* not EAPOL */

    /* Direction → derive BSSID + STA MAC. M1/M3 are AP→STA, so the
     * source (Addr2) is the BSSID; M2/M4 are STA→AP, source is STA. */
    const uint8_t *addr1 = d + 4;
    const uint8_t *addr2 = d + 10;
    uint8_t bssid[6], sta[6];
    if (to_ds && !from_ds) {           /* STA → AP */
        memcpy(bssid, addr1, 6);
        memcpy(sta,   addr2, 6);
    } else if (!to_ds && from_ds) {    /* AP → STA */
        memcpy(sta,   addr1, 6);
        memcpy(bssid, addr2, 6);
    } else {
        return 0;                       /* WDS or ad-hoc — skip */
    }

    /* EAPOL frame: version(1) type(1) length(2) then payload. Type 0 is
     * an EAP-Packet (the 802.1X inner conversation); type 3 is EAPOL-Key
     * (the 4-way handshake handled below). Feed EAP-Packets to the EAP
     * method tracker for the ROGUE_RADIUS detector (#31). */
    const uint8_t *eapol = d + hdr + 8;
    int            elen  = len - hdr - 8;
    if (elen >= 4 && eapol[1] == 0x00) {
        eap_track_observe(bssid, eapol + 4, elen - 4, time(NULL));
        return 1;
    }
    uint8_t nonce[32], mic[16], pmkid[16];
    int has_pmkid = 0;
    int msg = parse_eapol_key(eapol, elen, nonce, mic,
                              &has_pmkid, pmkid);
    if (msg == 0) return 0;

    /* ── Update state machine + log ────────────────────── */
    pthread_mutex_lock(&g_mu);
    time_t now = time(NULL);
    pending_t *p = pending_find_or_alloc(bssid, sta);

    /* Buffer the raw 802.11 frame body into the M-slot, capped at the
     * frame size limit. The per-handshake pcap writer replays these
     * frames verbatim — keeping them exact is what lets aircrack-ng /
     * Wireshark read the file. */
    if (msg >= 1 && msg <= 4) {
        int copy = len < EAPOL_FRAME_MAX ? len : EAPOL_FRAME_MAX;
        memcpy(p->m_frames[msg - 1], d, (size_t)copy);
        p->m_frame_lens[msg - 1] = copy;
        p->m_frame_ts[msg - 1]   = now;
    }

    eapol_event_t ev;
    memset(&ev, 0, sizeof(ev));
    memcpy(ev.bssid,   bssid, 6);
    memcpy(ev.sta_mac, sta,   6);
    ev.ts          = now;
    ev.msg_num     = msg;
    ev.signal_dbm  = signal;
    ev.channel     = channel;
    /* Best-effort SSID lookup against the beacon table. The two
     * modules use independent mutexes, so this is safe — but if the
     * beacon hasn't been seen yet (silent AP, association before
     * beacon observed), ev.ssid stays empty and hashcat tolerates an
     * empty ESSID field. */
    beacon_find_ssid(bssid, ev.ssid);

    if (msg == 1) {
        memcpy(p->anonce, nonce, 32);
        p->m1_seen = 1;
        p->m1_ts   = now;
        p->signal_dbm = signal;
        p->channel    = channel;
        if (has_pmkid) {
            p->has_pmkid = 1;
            memcpy(p->pmkid, pmkid, 16);
            ev.has_pmkid = 1;
            memcpy(ev.pmkid, pmkid, 16);
        }
        memcpy(ev.anonce, nonce, 32);
        push_event(&ev);

        /* PMKID is single-frame — emit a hashcat-22000 PMKID line
         * immediately if we have a known ESSID for this BSSID.
         * We don't currently feed the SSID through here; the writer
         * uses an empty ESSID, which hashcat tolerates. */
        if (ev.has_pmkid && g_out_dir[0]) {
            char pmkid_hex[33], bssid_hex[13], sta_hex[13], essid_hex[67];
            hex_bytes(ev.pmkid,   16, pmkid_hex);
            hex_bytes(ev.bssid,    6, bssid_hex);
            hex_bytes(ev.sta_mac,  6, sta_hex);
            hex_str(ev.ssid, essid_hex);
            char line[256];
            snprintf(line, sizeof(line),
                     "WPA*01*%s*%s*%s*%s***",
                     pmkid_hex, bssid_hex, sta_hex, essid_hex);
            append_22000_line_for_bssid(line, ev.bssid);
            /* Also dump per-(BSSID, STA) pcap with the buffered M1. */
            write_handshake_pcap(p);
        }
    } else if (msg == 2) {
        memcpy(p->snonce, nonce, 32);
        memcpy(p->mic,    mic,   16);
        p->m2_seen = 1;
        p->m2_ts   = now;
        memcpy(ev.snonce, nonce, 32);
        memcpy(ev.mic,    mic,   16);
        if (p->m1_seen) {
            ev.handshake_complete = 1;
            memcpy(ev.anonce, p->anonce, 32);
            if (p->has_pmkid) {
                ev.has_pmkid = 1;
                memcpy(ev.pmkid, p->pmkid, 16);
            }
            /* Completed 4-way == STA is associated to this BSSID.
             * Strongest evidence we have. */
            assoc_observe(ev.bssid, ev.sta_mac,
                          ev.ssid[0] ? ev.ssid : NULL,
                          ASSOC_SRC_EAPOL, signal, channel);
        }
        push_event(&ev);

        /* Full handshake: emit MP=02 line if we have both M1 + M2. */
        if (ev.handshake_complete && g_out_dir[0]) {
            char mic_hex[33], bssid_hex[13], sta_hex[13], essid_hex[67];
            char anonce_hex[65], eapol_hex[1024];
            hex_bytes(ev.mic,     16, mic_hex);
            hex_bytes(ev.bssid,    6, bssid_hex);
            hex_bytes(ev.sta_mac,  6, sta_hex);
            hex_str(ev.ssid, essid_hex);
            hex_bytes(ev.anonce,  32, anonce_hex);
            /* EAPOL field: the M2 frame with MIC zeroed. We only have
             * the EAPOL portion here; copy + zero MIC bytes (81..96
             * from EAPOL start) before hex. */
            int eapol_room = elen;
            if (eapol_room > (int)sizeof(eapol_hex)/2 - 1)
                eapol_room = (int)sizeof(eapol_hex)/2 - 1;
            uint8_t scratch[512];
            if (eapol_room > (int)sizeof(scratch)) eapol_room = (int)sizeof(scratch);
            memcpy(scratch, eapol, eapol_room);
            if (eapol_room >= 97) memset(scratch + 81, 0, 16);
            hex_bytes(scratch, eapol_room, eapol_hex);
            char line[2048];
            snprintf(line, sizeof(line),
                     "WPA*02*%s*%s*%s*%s*%s*%s*02",
                     mic_hex, bssid_hex, sta_hex, essid_hex,
                     anonce_hex, eapol_hex);
            append_22000_line_for_bssid(line, ev.bssid);
            /* Per-handshake pcap with M1+M2 (and any later M3/M4). */
            write_handshake_pcap(p);
        }
    } else if (msg == 3) {
        memcpy(ev.anonce, nonce, 32);
        memcpy(ev.mic,    mic,   16);
        push_event(&ev);
    } else if (msg == 4) {
        memcpy(ev.mic, mic, 16);
        push_event(&ev);
    }
    pthread_mutex_unlock(&g_mu);
    return 1;
}

/* ── Snapshot / utility ──────────────────────────────────── */

void eapol_snapshot(sloth_state_t *s)
{
    pthread_mutex_lock(&g_mu);
    int n = g_count < MAX_EAPOL_EVENTS ? g_count : MAX_EAPOL_EVENTS;
    for (int i = 0; i < n; i++) {
        int idx = ((g_head - 1 - i) % MAX_EAPOL_EVENTS + MAX_EAPOL_EVENTS)
                  % MAX_EAPOL_EVENTS;
        s->eapol_events[i] = g_events[idx];
    }
    s->eapol_count = n;
    if (s->eapol_sel >= n && n > 0) s->eapol_sel = n - 1;
    pthread_mutex_unlock(&g_mu);
}

void eapol_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_head = g_count = 0;
    g_pending_n = 0;
    pthread_mutex_unlock(&g_mu);
}

void eapol_set_output_dir(const char *dir) {
    if (!dir || !dir[0]) { g_out_dir[0] = '\0'; return; }
    snprintf(g_out_dir, sizeof(g_out_dir), "%s", dir);
    /* Try to create the directory. Quietly ignore failures — if it
     * doesn't exist when we go to write, fopen() will fail and we
     * just skip that line. */
    mkdir(g_out_dir, 0755);
}

int eapol_event_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_count;
    pthread_mutex_unlock(&g_mu);
    return n;
}
