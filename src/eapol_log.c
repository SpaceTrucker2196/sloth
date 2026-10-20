#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include "eapol_log.h"
#include "pcap_format.h"
#include "secure_file.h"
#include "eap_track.h"
#include "wps_track.h"
#include "beacon_snoop.h"
#include "assoc_track.h"
#include "alerts.h"
#include "stab.h"
#include "sensor_health.h"
#include "dot11_frame.h"
#include "bytes.h"
#include "sensor_health.h"
#include "tune.h"

/* ── Storage ─────────────────────────────────────────────── */

static eapol_event_t   g_events[MAX_EAPOL_EVENTS];
static int             g_head  = 0;
static int             g_count = 0;
static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* Per-(BSSID, STA) handshake state.
 *
 * The record is a *pair*; inside it sits at most one live *attempt*.
 * That split is the fix for #97 / T12: the old record had a single
 * m1_seen / m2_seen flag pair with no replay counter and no age bound,
 * so an M1 cached at boot paired with an M2 from an entirely different
 * association minutes later, and a new M1 left the previous attempt's
 * M2 and PMKID sitting underneath it.
 *
 * Attempt fields are wiped by attempt_reset() whenever a new M1 arrives
 * or the pairing window closes. Pair fields below the marker survive
 * that: the PTK generation counter is per-pair history that the
 * FragAttacks mixed-key detector reads *across* rekeys, and a rekey is
 * exactly a new M1.
 *
 * m_frames[0..3] = M1..M4 raw 802.11 bytes (frame body, no radiotap).
 * Stored as captured so the pcap export reproduces them byte-for-byte
 * for use with aircrack-ng / hcxpcapngtool / Wireshark. They belong to
 * the attempt — a pcap must never splice two attempts together.
 *
 * m_frame_lens is what was stored (capped at EAPOL_FRAME_MAX);
 * m_frame_origlens is the full 802.11 frame length as captured --
 * radiotap removed, but still libpcap's caplen, not hdr->len (see
 * on_probe_frame() in src/capture/probe.c). The radio opens at a
 * 65535 snaplen so the two coincide for any real 802.11 frame, but
 * this is not the wire length by construction. Both are kept because a pcap
 * record header carries both (#92): writing the truncated length as the
 * original too would claim every frame was exactly as short as sloth's
 * copy, and an analyst could no longer tell a genuinely short frame
 * from a truncated one. */
#define MAX_PENDING 64
#define EAPOL_FRAME_MAX 512
typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta[6];
    time_t   last_seen;          /* any EAPOL-Key for this pair; evicts LRU */

    /* ── Current attempt ─────────────────────────────────── */
    int      progress;           /* observed_handshake_progress, 0..4 */
    int      has_m1;
    int      has_m2;
    int      has_m3;
    uint8_t  m1_rc[8];           /* Key Replay Counter, big-endian */
    uint8_t  m2_rc[8];
    uint8_t  m3_rc[8];
    int      has_pmkid;
    uint8_t  pmkid[16];
    uint8_t  anonce[32];
    uint8_t  snonce[32];
    uint8_t  mic[16];
    time_t   m1_ts;
    time_t   m2_ts;
    int      paired;             /* candidate_message_pair established */
    int      rc_checked;         /* that pairing was a real byte compare */
    int      exported;           /* this attempt's pair already written */
    uint8_t  m_frames[4][EAPOL_FRAME_MAX];
    int      m_frame_lens[4];
    int      m_frame_origlens[4];
    time_t   m_frame_ts[4];
    uint32_t m_frame_usec[4];

    /* ── Pair-level, survives attempt_reset() ────────────── */
    /* PTK generation (#75 slice 4, CVE-2020-24587). Bumped when an M3
     * carries an ANonce that differs from the one last installed — see
     * the comment at the msg==3 handler for why ANonce, not merely
     * "another M3 arrived". installed_anonce starts zeroed and
     * has_installed distinguishes that from a legitimately all-zero
     * nonce. */
    int      generation;
    uint8_t  installed_anonce[32];
    int      has_installed;
} pending_t;
typedef struct { const uint8_t *bssid, *sta; } pending_key_t;

static int pending_key_eq(const void *row, const void *key) {
    const pending_t *p = row; const pending_key_t *k = key;
    return memcmp(p->bssid, k->bssid, 6) == 0 &&
           memcmp(p->sta, k->sta, 6) == 0;
}

/* Evicts the pair heard from least recently — not the oldest M1, which
 * reads as "never saw one" for every record that has only ever shown
 * M3/M4. STAB_OLDEST since #110, and an eviction is counted
 * (evict_eapol_pending): it drops a handshake in flight, so a capture
 * that never pairs is distinguishable from one that was crowded out. */
STAB_DECL(g_pending, pending_t, MAX_PENDING, last_seen, STAB_OLDEST,
          SH_EVICT_EAPOL_PENDING, NULL, pending_key_eq);

/* Export target (#87). g_out_fd pins the directory validated by
 * eapol_set_output_dir(): every file is opened relative to it, so a
 * later rename or symlink swap of the path cannot redirect crackable
 * material. g_out_dir is kept for messages and as the enabled flag. */
static char         g_out_dir[256];
static int          g_out_fd = -1;
static sfile_fail_t g_fail;

/* The crackable-material gate and its retention window (#87, owner
 * decision 2026-09-30). g_collect is the --collect-handshakes opt-in and
 * starts closed: an operator who said nothing about handshakes gets no
 * crackable material on disk. g_last_sweep == 0 means "never swept",
 * which is what makes the first eapol_maintain() call the startup
 * sweep. */
static int          g_collect        = 0;
/* The retention window is the handshake.retention_days row of the --tune
 * registry (#120): --handshake-retention is an alias, and a moved window
 * reaches sensor_health's `tuned`. Written only at startup, before the
 * sweep can run, so it needs no share of g_mu. */
static time_t       g_last_sweep     = 0;

#define EAPOL_SECS_PER_DAY 86400

/* ── Helpers ─────────────────────────────────────────────── */

/* Read-only lookup — never allocates. Used by eapol_key_generation() so
 * a mere query cannot evict a live pending handshake. */
static const pending_t *pending_find(const uint8_t bssid[6],
                                      const uint8_t sta[6]) {
    pending_key_t key = { bssid, sta };
    return stab_find(&g_pending, &key);
}

static pending_t *pending_get(const uint8_t bssid[6], const uint8_t sta[6],
                              time_t now) {
    pending_key_t key = { bssid, sta };
    int created;
    pending_t *p = stab_get(&g_pending, &key, now, &created);
    if (created) {
        memcpy(p->bssid, bssid, 6);
        memcpy(p->sta,   sta,   6);
    }
    return p;
}

/* ── Handshake attempt bookkeeping (#97 / T12) ───────────── */

/* The Key Replay Counter (IEEE 802.11-2020 §12.7.2) is an 8-byte
 * big-endian integer chosen by the authenticator: M2 echoes M1's value
 * verbatim, M3 uses M1's + 1, and M4 echoes M3's. Comparing it is what
 * tells one attempt from the next for the same (BSSID, STA) pair. */
static int rc_eq(const uint8_t a[8], const uint8_t b[8]) {
    return memcmp(a, b, 8) == 0;
}

static int rc_is_successor(const uint8_t prev[8], const uint8_t next[8]) {
    uint8_t want[8];
    memcpy(want, prev, 8);
    for (int i = 7; i >= 0; i--) { if (++want[i] != 0) break; }
    return memcmp(want, next, 8) == 0;
}

/* Discard everything that depended on the attempt's M1: the M2 that
 * answered it, the PMKID that M1 advertised, the buffered frames, the
 * export flag. Called when a new M1 supersedes the old one and when the
 * pairing window closes — after either, nothing from the previous
 * attempt can be paired, exported or counted as progress. Pair-level
 * history (generation / installed_anonce) is deliberately untouched. */
static void attempt_reset(pending_t *p) {
    p->progress = 0;
    p->has_m1 = p->has_m2 = p->has_m3 = 0;
    p->paired = p->rc_checked = p->exported = 0;
    p->has_pmkid = 0;
    p->m1_ts = p->m2_ts = 0;
    memset(p->m1_rc,  0, sizeof(p->m1_rc));
    memset(p->m2_rc,  0, sizeof(p->m2_rc));
    memset(p->m3_rc,  0, sizeof(p->m3_rc));
    memset(p->pmkid,  0, sizeof(p->pmkid));
    memset(p->anonce, 0, sizeof(p->anonce));
    memset(p->snonce, 0, sizeof(p->snonce));
    memset(p->mic,    0, sizeof(p->mic));
    memset(p->m_frames,     0, sizeof(p->m_frames));
    memset(p->m_frame_lens, 0, sizeof(p->m_frame_lens));
    /* Zeroed with its siblings for consistency; no read path depends
     * on it today, since observe rewrites len and origlen together. */
    memset(p->m_frame_origlens, 0, sizeof(p->m_frame_origlens));
    memset(p->m_frame_ts,   0, sizeof(p->m_frame_ts));
    memset(p->m_frame_usec, 0, sizeof(p->m_frame_usec));
}

/* Bounded lifetime: an M1 older than EAPOL_PAIR_WINDOW_S can no longer
 * be answered by anything. A clock stepping backwards makes the
 * difference negative, which is not an expiry. */
static void attempt_expire(pending_t *p, time_t now) {
    if (p->has_m1 && now > p->m1_ts &&
        now - p->m1_ts > EAPOL_PAIR_WINDOW_S)
        attempt_reset(p);
}

uint8_t eapol_message_pair(eapol_msg_pair_t kind, int replaycount_checked) {
    uint8_t b = (uint8_t)kind & 0x07;
    if (!replaycount_checked) b |= EAPOL_MP_NOT_REPLAYCOUNT_CHECKED;
    return b;
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

static int write_all(int fd, const char *buf, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, buf, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        buf += w;
        n   -= (size_t)w;
    }
    return 0;
}

/* Append a hashcat-22000 line. If the BSSID was marked tainted by
 * rule_evil_twin_attack_chain, prepend a comment line ('#' is ignored
 * by hashcat's parser) carrying the provenance + BSSID so a forensic
 * reviewer can trace the capture back to the chain alert.
 *
 * Append, not replace: eapol.22000 is the run-spanning file hashcat
 * reads whole, and every earlier line is still a valid target. A
 * failed write is rolled back to the previous length so a full disk
 * leaves no half line, and is reported. */
static void append_22000_line_for_bssid(const char *line,
                                        const uint8_t bssid[6]) {
    /* The gate is re-checked here, not only at eapol_set_output_dir():
     * this is the last statement before crackable material becomes a
     * file, and that is where the cheapest possible check belongs. */
    if (!g_collect || g_out_fd < 0) return;
    char err[SFILE_ERR_MAX];
    int fd = sfile_open(g_out_fd, "eapol.22000", SFILE_APPEND,
                        err, sizeof(err));
    if (fd < 0) { sfile_fail(&g_fail, "eapol", err); return; }
    struct stat st;
    off_t before = fstat(fd, &st) == 0 ? st.st_size : -1;

    char note[96];
    int  nn = 0;
    if (evil_twin_bssid_is_tainted(bssid)) {
        nn = snprintf(note, sizeof(note), "# provenance=tainted-evil-twin "
                      "bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
                      bssid[0], bssid[1], bssid[2],
                      bssid[3], bssid[4], bssid[5]);
    }
    int bad = (nn > 0 && write_all(fd, note, (size_t)nn) != 0) ||
              write_all(fd, line, strlen(line)) != 0 ||
              write_all(fd, "\n", 1) != 0;
    if (bad) {
        snprintf(err, sizeof(err), "eapol.22000: write failed: %s",
                 strerror(errno));
        /* Best effort: the write failure is what gets reported; a
         * rollback that also fails cannot be made any more visible. */
        if (before >= 0 && ftruncate(fd, before) != 0) { }
        sfile_fail(&g_fail, "eapol", err);
    }
    if (close(fd) != 0 && !bad) {
        snprintf(err, sizeof(err), "eapol.22000: write failed: %s",
                 strerror(errno));
        sfile_fail(&g_fail, "eapol", err);
    }
}

/* ── Per-handshake pcap writer ───────────────────────────── */

/* Write a per-handshake .pcap to <eapol_dir>/<bssid>_<sta>.pcap.
 * Frames are stored as raw IEEE 802.11 (DLT 105). Aircrack-ng + tshark
 * read this fine; pass -e <SSID> to aircrack if no beacon was bundled.
 *
 * Atomic replace: a fresher capture supersedes the older one, so the
 * file is rewritten — but into an exclusive temp file in the same
 * private dir, renamed over the old name only once completely written.
 * A failed write (full disk) leaves the previous capture intact, and
 * rename() replaces whatever sits at the name — a planted symlink
 * included — rather than writing through it. */
static void write_handshake_pcap(const pending_t *p) {
    /* Same gate as the 22000 append: a replayable handshake pcap is the
     * same crackable material in another container. */
    if (!g_collect || g_out_fd < 0) return;
    char name[64], tmp[80], err[SFILE_ERR_MAX];
    snprintf(name, sizeof(name),
             "%02x%02x%02x%02x%02x%02x_%02x%02x%02x%02x%02x%02x.pcap",
             p->bssid[0], p->bssid[1], p->bssid[2],
             p->bssid[3], p->bssid[4], p->bssid[5],
             p->sta[0],   p->sta[1],   p->sta[2],
             p->sta[3],   p->sta[4],   p->sta[5]);
    snprintf(tmp, sizeof(tmp), ".%s.tmp", name);
    /* Only sloth writes this private dir; a temp file here is our own,
     * left by a crash mid-write. */
    unlinkat(g_out_fd, tmp, 0);
    FILE *f = sfile_fopen(g_out_fd, tmp, SFILE_EXCL, err, sizeof(err));
    if (!f) { sfile_fail(&g_fail, "eapol", err); return; }

    pcap_fmt_put_file_hdr(f, PCAP_DLT_IEEE802_11, PCAP_SNAPLEN_FRAME);

    /* Walk M1..M4 in order. Skip empty slots. */
    for (int i = 0; i < 4; i++) {
        if (p->m_frame_lens[i] == 0) continue;
        /* The frame's own capture time (#92), not when it was written.
         * caplen <= origlen holds by construction here — both come from
         * the same observed length at the single buffering site, one
         * min()-ed — and pcap_fmt_put_rec() clamps anyway. */
        pcap_fmt_put_rec(f, (uint32_t)p->m_frame_ts[i], p->m_frame_usec[i],
                         p->m_frames[i], (uint32_t)p->m_frame_lens[i],
                         (uint32_t)p->m_frame_origlens[i]);
    }
    if (sfile_fclose(f, name, err, sizeof(err)) != 0) {
        unlinkat(g_out_fd, tmp, 0);
        sfile_fail(&g_fail, "eapol", err);
        return;
    }
    if (renameat(g_out_fd, tmp, g_out_fd, name) != 0) {
        snprintf(err, sizeof(err), "%s: rename failed: %s",
                 name, strerror(errno));
        unlinkat(g_out_fd, tmp, 0);
        sfile_fail(&g_fail, "eapol", err);
    }
}

/* ── EAPOL-Key parser ────────────────────────────────────── */

/* EAPOL header (version, type, body length) is 4 bytes; the RSN/WPA
 * key descriptor is 95 bytes up to and including Key Data Length. */
#define EAPOL_HDR_LEN        4
#define EAPOL_KEY_FIXED_LEN 99

/* Parser rejects, as negative returns. -(1 + eapol_reject_t). */
#define PARSE_TRUNCATED (-1 - EAPOL_REJECT_TRUNCATED)
#define PARSE_MALFORMED (-1 - EAPOL_REJECT_MALFORMED)

static int g_rejects[EAPOL_REJECT_COUNT];

/* Recognise an EAPOL-Key frame and decide which message number it is.
 * Returns 0 if not an EAPOL-Key frame we handle; 1..4 for valid
 * messages; PARSE_TRUNCATED / PARSE_MALFORMED for an EAPOL-Key frame
 * whose lengths don't hold together (#83). A rejected frame has no
 * outputs worth reading.
 * Outputs ANonce/SNonce/MIC/PMKID and the Key Replay Counter as
 * appropriate, and *out_span = the EAPOL frame length the frame itself
 * declares (4 + body length) — the only bytes that are EAPOL. Capture
 * padding / FCS past it are not.
 *
 * p points at the start of the EAPOL frame (version byte); len is the
 * number of captured bytes from there. */
static int parse_eapol_key(const uint8_t *p, size_t len, size_t *out_span,
                            uint8_t out_nonce[32], uint8_t out_mic[16],
                            uint8_t out_rc[8],
                            int *out_has_pmkid, uint8_t out_pmkid[16])
{
    *out_has_pmkid = 0;
    *out_span = 0;
    if (len < EAPOL_HDR_LEN) return 0;
    /* EAPOL header. */
    /* p[0] version, p[1] type. type 3 = EAPOL-Key. */
    if (p[1] != 3) return 0;
    /* p[2..3] body length, big-endian. Everything below is bounded by
     * the declared span, and the declared span by the capture. */
    size_t span = EAPOL_HDR_LEN + (size_t)((p[2] << 8) | p[3]);
    if (span > len) return PARSE_TRUNCATED;
    if (span <= EAPOL_HDR_LEN) return PARSE_MALFORMED;   /* no descriptor */
    /* p[4] Descriptor Type: 2 = RSN (802.11), 254 = WPA. */
    uint8_t desc = p[4];
    if (desc != 2 && desc != 254) return 0;
    if (span < EAPOL_KEY_FIXED_LEN) return PARSE_MALFORMED;
    /* p[5..6] Key Information, big-endian. */
    uint16_t ki = (uint16_t)((p[5] << 8) | p[6]);
    int key_type    = (ki >> 3) & 1;
    int install     = (ki >> 6) & 1;
    int key_ack     = (ki >> 7) & 1;
    int key_mic     = (ki >> 8) & 1;
    int secure      = (ki >> 9) & 1;
    int encrypted_d = (ki >> 12) & 1;
    if (!key_type) return 0;       /* group key, not interesting */

    /* Key Replay Counter: bytes 9..16, big-endian (§12.7.2). */
    memcpy(out_rc, p + 9, 8);
    /* Nonce: bytes 17..48. */
    memcpy(out_nonce, p + 17, 32);
    /* MIC: bytes 81..96. */
    memcpy(out_mic, p + 81, 16);

    /* Key Data Length: bytes 97..98 (big-endian). Key Data must fit in
     * what the declared body leaves after the fixed descriptor; a
     * longer claim is a malformed frame, not "no key data". A shorter
     * one leaves unparsed bytes inside the frame's own span —
     * tolerated, and never walked as KDEs. */
    size_t kdl = (size_t)((p[97] << 8) | p[98]);
    if (kdl > span - EAPOL_KEY_FIXED_LEN) return PARSE_MALFORMED;

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
     *   PMKID KDE: OUI 00:0F:AC, DataType 0x04, 16-byte PMKID.
     * KDEs share element framing, so this is the shared iterator
     * (#126). The 0xDD-then-zeros padding of §12.7.2 applies only to
     * an encrypted Key Data field, which is never walked here, so a
     * short tail in what is walked is a real fault, not padding. */
    if (msg == 1 && kdl >= 6 && !encrypted_d) {
        tlv_it_t it;
        uint16_t t; int l; const uint8_t *kb;
        tlv_init(&it, p + EAPOL_KEY_FIXED_LEN, (int)kdl);
        while (tlv_next(&it, &t, &l, &kb) == TLV_OK) {
            if (t == 0xDD && l == 20 &&
                kb[0] == 0x00 && kb[1] == 0x0f && kb[2] == 0xac &&
                kb[3] == 0x04) {
                memcpy(out_pmkid, kb + 4, 16);
                *out_has_pmkid = 1;
                break;
            }
        }
        if (it.status == TLV_OVERRUN) sh_parse_fault_note(SH_PF_IE_OVERRUN);
    }
    *out_span = span;
    return msg;
}

/* ── 802.11 frame walker ─────────────────────────────────── */

/* The byte entry point stays for the tests and fuzz harnesses written
 * against it (#130); it decodes once and hands the view on. */
int eapol_observe_dot11(const uint8_t *d, int len,
                         int8_t signal, int channel,
                         time_t now, long ts_usec)
{
    dot11_frame_t f;
    dot11_frame_decode(d, len, NULL, &f);
    return eapol_observe_frame(&f, signal, channel, now, ts_usec);
}

int eapol_observe_frame(const dot11_frame_t *f,
                        int8_t signal, int channel,
                        time_t now, long ts_usec)
{
    /* The timestamp is caller input and ends up in an exported pcap
     * record header, where ts_usec must be below 1000000; anything
     * else is not a timestamp, so it is not written through. */
    uint32_t usec = (ts_usec >= 0 && ts_usec <= 999999)
                  ? (uint32_t)ts_usec : 0;
    if (!f || !f->p) return 0;
    /* The frame as it was on the air: the bytes below are buffered
     * verbatim into the handshake pcap, so a caller holding a datapad
     * capture removes the pad first (dot11_frame_depad()), and the body
     * is read where the MAC header ends. */
    const uint8_t *d   = f->p;
    const int      len = f->len;
    if (len < 32) return 0;
    if (f->type != 2) return 0;                 /* data frame */
    int to_ds   = f->to_ds;
    int from_ds = f->from_ds;

    /* The header length comes from the shared view (#122), not from a
     * private formula. The copy that lived here added HT Control for
     * EVERY data frame with the Order bit set — the non-QoS
     * StrictlyOrdered misread fixed in dot11_data.c on 2026-10-14 was
     * still live in this seventh implementation, so a non-QoS EAPOL
     * frame carrying that one bit had its LLC header read four bytes
     * late and the handshake was silently missed. In bounds throughout,
     * so no sanitiser or fuzz target could see it. */
    int hdr = f->hdr_len;
    if (hdr < 0 || len < hdr + 8 + 4) return 0;   /* LLC(8) + at-least EAPOL hdr */

    /* LLC SNAP: AA AA 03 00 00 00 + ethertype */
    const uint8_t *llc = d + hdr;
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return 0;
    if (llc[3] || llc[4] || llc[5]) return 0;
    uint16_t et = (uint16_t)((llc[6] << 8) | llc[7]);
    if (et != 0x888E) return 0;        /* not EAPOL */

    /* Direction -> BSSID + STA, from the Table 9-26 roles the view
     * owns. M1/M3 are AP->STA, so the station is the DA; M2/M4 are
     * STA->AP, so the station is the SA. WDS (no single BSSID) and
     * IBSS (no AP) are skipped as before. */
    uint8_t bssid[6], sta[6];
    if (to_ds == from_ds) return 0;                  /* WDS or ad-hoc */
    if (!f->bssid || !f->sa || !f->da) return 0;
    memcpy(bssid, f->bssid, 6);
    memcpy(sta, to_ds ? f->sa : f->da, 6);

    /* EAPOL frame: version(1) type(1) length(2) then payload. Type 0 is
     * an EAP-Packet (the 802.1X inner conversation); type 3 is EAPOL-Key
     * (the 4-way handshake handled below). Feed EAP-Packets to the EAP
     * method tracker for the ROGUE_RADIUS detector (#31). */
    const uint8_t *eapol = d + hdr + 8;
    int            elen  = len - hdr - 8;
    if (elen >= 4 && eapol[1] == 0x00) {
        /* from_ds means the AP transmitted it — the direction the
         * CVE-2023-52160 rule needs to know a server identity was
         * actually presented rather than merely present in the flow. */
        eap_track_observe(bssid, sta, from_ds ? 1 : 0,
                          eapol + 4, elen - 4, now);
        /* Same inner EAP packet, WSC lens (#82): sequences M1..M8 /
         * NACK into per-(BSSID,STA) sessions. Ignores non-WSC frames. */
        wps_track_observe(bssid, sta, eapol + 4, elen - 4, now);
        return 1;
    }
    uint8_t nonce[32], mic[16], pmkid[16], rc[8];
    int has_pmkid = 0;
    size_t span = 0;
    int msg = parse_eapol_key(eapol, (size_t)elen, &span, nonce, mic, rc,
                              &has_pmkid, pmkid);
    if (msg < 0) {
        /* Truncated / inconsistent EAPOL-Key: counted, nothing else. */
        pthread_mutex_lock(&g_mu);
        g_rejects[-1 - msg]++;
        pthread_mutex_unlock(&g_mu);
        return 0;
    }
    if (msg == 0) return 0;

    /* ── Update state machine + log ────────────────────── */
    pthread_mutex_lock(&g_mu);

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

    /* Direction is part of the message's identity, not decoration: M1
     * and M3 are the authenticator's, M2 and M4 the supplicant's. A
     * frame whose Key Information claims a role the frame didn't travel
     * in — an "M3" transmitted by a station, an "M2" by the AP — is
     * recorded as seen and goes no further. It updates no attempt,
     * pairs nothing, exports nothing and is not association evidence,
     * because it is not the exchange it claims to be. */
    int want_from_ds = (msg == 1 || msg == 3);
    if (want_from_ds != (from_ds ? 1 : 0)) {
        push_event(&ev);
        pthread_mutex_unlock(&g_mu);
        return 1;
    }

    pending_t *p = pending_get(bssid, sta, now);
    p->last_seen = now;
    attempt_expire(p, now);

    /* A new M1 starts a new attempt. Only a verbatim retransmission —
     * same replay counter AND same ANonce, which is what an AP resends
     * when M2 is lost — continues the one in flight. Anything else is
     * the AP starting over, and everything cached under the old ANonce
     * (M2, PMKID, frames, the export flag) has to go: pairing across
     * that boundary is exactly the T12 defect. */
    if (msg == 1) {
        int retransmit = p->has_m1 && rc_eq(p->m1_rc, rc) &&
                         memcmp(p->anonce, nonce, 32) == 0;
        if (!retransmit) attempt_reset(p);
    }

    /* Buffer the raw 802.11 frame body into the M-slot, capped at the
     * frame size limit. The per-handshake pcap writer replays these
     * frames verbatim — keeping them exact is what lets aircrack-ng /
     * Wireshark read the file. Done after the reset above so a new
     * attempt's pcap can never carry the previous attempt's frames. */
    {
        int copy = len < EAPOL_FRAME_MAX ? len : EAPOL_FRAME_MAX;
        memcpy(p->m_frames[msg - 1], d, (size_t)copy);
        p->m_frame_lens[msg - 1] = copy;
        /* The observed frame length, kept whether or not the copy was
         * capped: it is the pcap record's origlen, and the only record
         * left of how long the frame actually was. */
        p->m_frame_origlens[msg - 1] = len;
        p->m_frame_ts[msg - 1]   = now;
        p->m_frame_usec[msg - 1] = usec;
    }

    if (msg == 1) {
        memcpy(p->anonce, nonce, 32);
        memcpy(p->m1_rc,  rc,    8);
        p->has_m1   = 1;
        /* The window runs from the most recent M1, retransmission
         * included: a retry is the AP re-offering the same ANonce under
         * the same counter, so an M2 answering the retry answers a live
         * offer. Nothing about the attempt changed, so this cannot mix
         * material — it only avoids dropping a genuine handshake. */
        p->m1_ts    = now;
        /* Monotonic within an attempt: attempt_reset() zeroed it if this
         * M1 started a new one, so a retry cannot walk progress back. */
        if (p->progress < 1) p->progress = 1;
        if (has_pmkid) {
            p->has_pmkid = 1;
            memcpy(p->pmkid, pmkid, 16);
            ev.has_pmkid = 1;
            memcpy(ev.pmkid, pmkid, 16);
        }
        memcpy(ev.anonce, nonce, 32);
    } else if (msg == 2) {
        memcpy(p->snonce, nonce, 32);
        memcpy(p->mic,    mic,   16);
        memcpy(p->m2_rc,  rc,    8);
        p->has_m2 = 1;
        p->m2_ts  = now;
        memcpy(ev.snonce, nonce, 32);
        memcpy(ev.mic,    mic,   16);

        /* candidate_message_pair. Both halves must belong to the same
         * attempt: a live M1 (attempt_expire ran above, so a stale one
         * is already gone) carrying the very replay counter this M2
         * echoes. A pair built any other way yields a 22000 record whose
         * MIC was computed over a different exchange — it can never
         * crack, and it was never evidence of anything. */
        if (p->has_m1 && rc_eq(p->m1_rc, rc)) {
            p->paired     = 1;
            p->rc_checked = 1;
            if (p->progress < 2) p->progress = 2;
            ev.handshake_complete = 1;
            ev.replay_counter_ok  = 1;
            memcpy(ev.anonce, p->anonce, 32);
            if (p->has_pmkid) {
                ev.has_pmkid = 1;
                memcpy(ev.pmkid, p->pmkid, 16);
            }
        }
    } else if (msg == 3) {
        memcpy(ev.anonce, nonce, 32);
        memcpy(ev.mic,    mic,   16);
        memcpy(p->m3_rc,  rc,    8);
        p->has_m3 = 1;
        ev.replay_counter_ok = p->rc_checked;
        /* M3 continues this attempt only when it carries M1's replay
         * counter + 1 (§12.7.2). An M3 that can't be tied to a tracked
         * M1+M2 is still association evidence below — it just doesn't
         * advance an attempt whose start was never seen. */
        if (p->paired && rc_is_successor(p->m1_rc, rc)) p->progress = 3;

        /* PTK generation bump — #75 slice 4, CVE-2020-24587. M3 is the
         * AP telling the station to install a key (Install=1 is part of
         * msg 3's own classification above), so it is the moment a
         * fragment reassembly detector needs to know "the key changed
         * under this pair", not M4 (which only confirms the station
         * complied and may never arrive on a hopping radio).
         *
         * Gated on the ANonce changing rather than "an M3 arrived": an
         * AP retries M3 verbatim — same ANonce — when M4 is lost, and
         * every one of those retries would otherwise look like a fresh
         * rekey. A genuine rekey (periodic PTK refresh, or a second
         * association) draws a new ANonce, so comparing it is exact
         * where counting messages is not. */
        if (!p->has_installed || memcmp(p->installed_anonce, nonce, 32) != 0) {
            p->generation++;
            memcpy(p->installed_anonce, nonce, 32);
            p->has_installed = 1;
        }

        /* association_evidence. The AP is installing a pairwise key for
         * this STA, which it only does having accepted the STA's M2 —
         * the first point in the exchange where the *authenticator*
         * commits to this client. M1+M2 never showed that: an M1 goes
         * to whoever asks and an M2 can be replayed by anyone who heard
         * one, so promoting that pair (as sloth used to) called a
         * half-exchange an association. Still observed progression,
         * not cryptographic proof — sloth does not verify the MIC. */
        ev.assoc_evidence = 1;
    } else if (msg == 4) {
        memcpy(ev.mic, mic, 16);
        ev.replay_counter_ok = p->rc_checked;
        /* M4 confirms the station installed the key. It advances the
         * attempt but promotes nothing on its own: it is supplicant-sent
         * and therefore exactly as replayable as the M2 that no longer
         * promotes either. The M3 it answers already did the promoting. */
        if (p->progress == 3 && p->has_m3 && rc_eq(p->m3_rc, rc))
            p->progress = 4;
    }

    /* replay_counter_ok is per event, not per attempt: an M2 that failed
     * the comparison must report 0 even when an earlier M2 of the same
     * record passed it. The M1/M3/M4 branches set it above where it has
     * a meaning; on an M1 nothing has been compared yet. */
    ev.handshake_progress = p->progress;
    push_event(&ev);

    if (ev.assoc_evidence)
        assoc_observe(ev.bssid, ev.sta_mac,
                      ev.ssid[0] ? ev.ssid : NULL,
                      ASSOC_SRC_EAPOL, signal, channel);

    /* PMKID is single-frame — emit a hashcat-22000 PMKID line
     * immediately if we have a known ESSID for this BSSID.
     * We don't currently feed the SSID through here; the writer
     * uses an empty ESSID, which hashcat tolerates. */
    if (msg == 1 && ev.has_pmkid && g_out_dir[0]) {
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

    /* One 22000 record per attempt: a retransmitted M2 carries the same
     * SNonce and MIC over the same ANonce, so a second line would be a
     * duplicate target, not a second one. */
    if (msg == 2 && ev.handshake_complete && !p->exported && g_out_dir[0]) {
        char mic_hex[33], bssid_hex[13], sta_hex[13], essid_hex[67];
        char anonce_hex[65], eapol_hex[1024];
        hex_bytes(ev.mic,     16, mic_hex);
        hex_bytes(ev.bssid,    6, bssid_hex);
        hex_bytes(ev.sta_mac,  6, sta_hex);
        hex_str(ev.ssid, essid_hex);
        hex_bytes(ev.anonce,  32, anonce_hex);
        /* EAPOL field: the M2 frame with MIC zeroed. We only have
         * the EAPOL portion here; copy + zero MIC bytes (81..96
         * from EAPOL start) before hex. The declared span, not
         * the captured length — trailing FCS / padding isn't
         * EAPOL, and hashcat would recompute the MIC over it. */
        int eapol_room = (int)span;
        if (eapol_room > (int)sizeof(eapol_hex)/2 - 1)
            eapol_room = (int)sizeof(eapol_hex)/2 - 1;
        uint8_t scratch[512];
        if (eapol_room > (int)sizeof(scratch)) eapol_room = (int)sizeof(scratch);
        memcpy(scratch, eapol, eapol_room);
        if (eapol_room >= 97) memset(scratch + 81, 0, 16);
        hex_bytes(scratch, eapol_room, eapol_hex);
        /* The message-pair byte states what this record IS and what was
         * verified building it — ANonce from M1, EAPOL blob from M2,
         * replay counters compared. Writing a literal here is how the
         * old export came to label a challenge pair as M2+M3 (T13). */
        uint8_t mp = eapol_message_pair(EAPOL_MP_M1M2_E2, p->rc_checked);
        char line[2048];
        snprintf(line, sizeof(line),
                 "WPA*02*%s*%s*%s*%s*%s*%s*%02x",
                 mic_hex, bssid_hex, sta_hex, essid_hex,
                 anonce_hex, eapol_hex, mp);
        append_22000_line_for_bssid(line, ev.bssid);
        p->exported = 1;
        /* Per-handshake pcap with M1+M2 (and any later M3/M4). */
        write_handshake_pcap(p);
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
    s->eapol_export_failures = g_fail.failures;
    /* The view line is width-bound anyway; keep the head of the reason. */
    size_t el = g_fail.failures ? strlen(g_fail.last) : 0;
    if (el > sizeof(s->eapol_export_err) - 1)
        el = sizeof(s->eapol_export_err) - 1;
    memcpy(s->eapol_export_err, g_fail.last, el);
    s->eapol_export_err[el] = '\0';
    pthread_mutex_unlock(&g_mu);
}

void eapol_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_head = g_count = 0;
    stab_clear(&g_pending);
    memset(g_rejects, 0, sizeof(g_rejects));
    pthread_mutex_unlock(&g_mu);
}

int eapol_set_output_dir(const char *dir) {
    pthread_mutex_lock(&g_mu);
    if (g_out_fd >= 0) { close(g_out_fd); g_out_fd = -1; }
    g_out_dir[0] = '\0';
    sfile_fail_reset(&g_fail);
    g_last_sweep = 0;                 /* a new target gets a startup sweep */
    int rc = 0;
    if (dir && dir[0]) {
        if (!g_collect) {
            /* Refused before mkdir: a run without the opt-in must not
             * even leave an export directory behind, since its existence
             * reads as "handshakes are being collected here". */
            snprintf(g_fail.last, sizeof(g_fail.last),
                     "%s: refusing to export crackable material without "
                     "--collect-handshakes (PMKIDs and 4-way handshakes "
                     "support offline password guessing; detection and the "
                     "[e] view do not need the opt-in)", dir);
            rc = -1;
        } else {
            /* A refusal leaves export disabled; the caller reports it.
             * The reason is kept where eapol_export_error() finds it. */
            int fd = sfile_private_dir(dir, g_fail.last, sizeof(g_fail.last));
            if (fd < 0) {
                rc = -1;
            } else {
                g_out_fd = fd;
                snprintf(g_out_dir, sizeof(g_out_dir), "%s", dir);
            }
        }
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

/* ── Gated export-directory access for other modules (#92) ─────────── */

/* Create a file in the --collect-handshakes export directory, through
 * the same pinned descriptor every artifact here uses.
 *
 * Exists so the #92 evidence exporter can write raw 802.11 frames —
 * which carry the EAPOL 4-way and PMKID, the same crackable material
 * this module exports — without a second gate, a second directory or a
 * second retention policy. Owner ruling 2026-10-08 chose exactly that:
 * the exporter writes only when this gate is open, and its files expire
 * on eapol_sweep()'s window because the sweep walks every regular file
 * in this directory by mtime.
 *
 * The descriptor itself does NOT escape. A caller gets an fd for one
 * named file or a refusal, so it cannot enumerate, unlink or re-point
 * the directory — and it cannot hold a path and race it, which is the
 * whole reason this module pins a dirfd rather than keeping a string.
 *
 * Re-checks the gate under the lock at the last moment before creating
 * anything, the same way append_22000_line_for_bssid() and
 * write_handshake_pcap() do, so a caller that opened the gate, had it
 * closed under it, and then called here is refused.
 *
 * Returns the fd (caller closes), or -1 with a reason in err. */
int eapol_export_create(const char *name, char *err, size_t errsz) {
    if (!name || !*name) {
        if (err && errsz) snprintf(err, errsz, "no name");
        return -1;
    }
    pthread_mutex_lock(&g_mu);
    int gate = g_collect, dirfd = g_out_fd;
    pthread_mutex_unlock(&g_mu);
    if (!gate) {
        if (err && errsz)
            snprintf(err, errsz, "--collect-handshakes is not set");
        return -1;
    }
    if (dirfd < 0) {
        if (err && errsz)
            snprintf(err, errsz, "no export directory (--eapol-dir)");
        return -1;
    }
    return sfile_open(dirfd, name, SFILE_EXCL, err, errsz);
}

/* Bare-name rule for the helpers below. sfile_open() applies it to
 * create; renameat/unlinkat do not, so it is repeated here rather than
 * trusted to the caller (CWE-22, #134). */
static int bare_name(const char *n) {
    return n && n[0] && strcmp(n, ".") != 0 && strcmp(n, "..") != 0 &&
           strchr(n, '/') == NULL;
}

int eapol_export_commit(const char *tmp, const char *name,
                        char *err, size_t errsz) {
    if (!bare_name(tmp) || !bare_name(name)) {
        if (err && errsz) snprintf(err, errsz, "not a bare file name");
        return -1;
    }
    pthread_mutex_lock(&g_mu);
    int rc = -1;
    struct stat st;
    if (!g_collect || g_out_fd < 0) {
        if (err && errsz)
            snprintf(err, errsz, "--collect-handshakes closed before commit");
    } else if (fstatat(g_out_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (err && errsz)
            snprintf(err, errsz, "%s: already exists", name);
    } else if (errno != ENOENT) {
        if (err && errsz)
            snprintf(err, errsz, "%s: cannot check the name is free: %s",
                     name, strerror(errno));
    } else if (renameat(g_out_fd, tmp, g_out_fd, name) != 0) {
        if (err && errsz)
            snprintf(err, errsz, "%s: rename failed: %s", name, strerror(errno));
    } else {
        if (fsync(g_out_fd) != 0) { /* best effort; see the header */ }
        rc = 0;
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

void eapol_export_discard(const char *tmp) {
    if (!bare_name(tmp)) return;
    pthread_mutex_lock(&g_mu);
    if (g_out_fd >= 0) (void)unlinkat(g_out_fd, tmp, 0);
    pthread_mutex_unlock(&g_mu);
}

void eapol_export_note_failure(const char *who, const char *msg) {
    pthread_mutex_lock(&g_mu);
    sfile_fail(&g_fail, who ? who : "eapol", msg);
    pthread_mutex_unlock(&g_mu);
}

int eapol_export_ready(void) {
    pthread_mutex_lock(&g_mu);
    int ok = g_collect && g_out_fd >= 0;
    pthread_mutex_unlock(&g_mu);
    return ok;
}

int eapol_export_path(const char *name, char *out, size_t outsz) {
    if (!out || !outsz) return -1;
    out[0] = '\0';
    if (!bare_name(name)) return -1;
    pthread_mutex_lock(&g_mu);
    int rc = -1;
    if (g_collect && g_out_fd >= 0 && g_out_dir[0]) {
        int n = snprintf(out, outsz, "%s/%s", g_out_dir, name);
        if (n > 0 && (size_t)n < outsz) rc = 0;
        else out[0] = '\0';
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

/* ── The crackable-material gate and its retention sweep (#87) ─────── */

void eapol_set_collect_enabled(int on) {
    pthread_mutex_lock(&g_mu);
    g_collect = on ? 1 : 0;
    /* Closing the gate mid-run drops the pinned directory too, so the
     * descriptor cannot outlive the permission to write through it. */
    if (!g_collect && g_out_fd >= 0) {
        close(g_out_fd);
        g_out_fd = -1;
        g_out_dir[0] = '\0';
    }
    pthread_mutex_unlock(&g_mu);
}

int eapol_collect_enabled(void) {
    pthread_mutex_lock(&g_mu);
    int on = g_collect;
    pthread_mutex_unlock(&g_mu);
    return on;
}

int eapol_set_retention_days(int days) {
    if (days < 0 || days > EAPOL_MAX_RETENTION_DAYS) return -1;
    return tune_set_id(TUNE_HANDSHAKE_RETENTION_DAYS, days) ? 0 : -1;
}

int eapol_retention_days(void) {
    return (int)tune_val(TUNE_HANDSHAKE_RETENTION_DAYS);
}

/* Names this module writes, and only those. An operator file sharing the
 * directory is out of scope — the sweep deletes sloth's artifacts, not
 * the directory's contents. "." and ".." cannot match: both are shorter
 * than the ".tmp" suffix the dotted branch requires. */
static int is_export_artifact(const char *name) {
    size_t n = strlen(name);
    if (strcmp(name, "eapol.22000") == 0) return 1;
    if (n > 5 && strcmp(name + n - 5, ".pcap") == 0) return 1;
    if (name[0] == '.' && n > 5 && strcmp(name + n - 4, ".tmp") == 0) return 1;
    return 0;
}

/* Caller holds g_mu. */
static int sweep_locked(time_t now) {
    const int retention_days = eapol_retention_days();
    if (g_out_fd < 0 || retention_days <= 0) return 0;

    time_t window = (time_t)retention_days * EAPOL_SECS_PER_DAY;
    if (now <= window) return 0;      /* nothing can predate the epoch+window */
    time_t cutoff = now - window;

    char err[SFILE_ERR_MAX];
    /* A duplicate, because closedir() closes the descriptor it was given
     * and g_out_fd has to survive the sweep. F_DUPFD_CLOEXEC rather than
     * dup() so the copy is not inherited across an exec either. */
    int dfd = fcntl(g_out_fd, F_DUPFD_CLOEXEC, 0);
    DIR *d  = dfd >= 0 ? fdopendir(dfd) : NULL;
    if (!d) {
        if (dfd >= 0) close(dfd);
        snprintf(err, sizeof(err),
                 "%.200s: cannot read the export directory for the "
                 "retention sweep: %s", g_out_dir, strerror(errno));
        sfile_fail(&g_fail, "eapol", err);
        return -1;
    }
    /* The duplicate shares its offset with g_out_fd; rewind so a second
     * sweep starts at the first entry rather than wherever the last one
     * stopped. */
    rewinddir(d);

    int removed = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!is_export_artifact(e->d_name)) continue;
        struct stat st;
        if (fstatat(g_out_fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) continue;      /* raced away; fine */
            snprintf(err, sizeof(err),
                     "%.100s: cannot stat for the retention sweep: %s",
                     e->d_name, strerror(errno));
            sfile_fail(&g_fail, "eapol", err);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            /* A symlink, directory or FIFO at an artifact name is not
             * something sloth wrote. It is left exactly as it is — the
             * sweep never follows, so it can never delete through a link
             * — and reported rather than skipped silently: in a directory
             * only sloth writes, it is either operator error or someone
             * steering the export, and both deserve a line. Reported
             * whatever its age: the anomaly is the entry, not its mtime,
             * and an mtime read off a planted symlink proves nothing. */
            snprintf(err, sizeof(err),
                     "%.100s: not a regular file — left in place by the "
                     "retention sweep, nothing was followed", e->d_name);
            sfile_fail(&g_fail, "eapol", err);
            continue;
        }
        if (st.st_mtime >= cutoff) continue;
        if (unlinkat(g_out_fd, e->d_name, 0) != 0) {
            snprintf(err, sizeof(err),
                     "%.100s: could not delete past the %d-day handshake "
                     "retention window: %s",
                     e->d_name, retention_days, strerror(errno));
            sfile_fail(&g_fail, "eapol", err);
            continue;
        }
        removed++;
    }
    closedir(d);
    return removed;
}

int eapol_sweep(time_t now) {
    pthread_mutex_lock(&g_mu);
    int n = sweep_locked(now);
    /* Set after the sweep, failures included: a directory that cannot be
     * read is retried on the next window, not on every poll. */
    g_last_sweep = now;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void eapol_maintain(time_t now) {
    pthread_mutex_lock(&g_mu);
    /* A clock that stepped backwards past the last sweep would otherwise
     * wait a whole day; treat it as due instead. */
    int due = (g_last_sweep == 0) ||
              (now < g_last_sweep) ||
              (now - g_last_sweep >= EAPOL_SWEEP_INTERVAL_S);
    if (due) {
        sweep_locked(now);
        g_last_sweep = now;
    }
    pthread_mutex_unlock(&g_mu);
}

int eapol_export_failures(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_fail.failures;
    pthread_mutex_unlock(&g_mu);
    return n;
}

/* Returned pointer is stable storage; tests and main read it on the
 * thread that drove the export, so no copy is taken. */
const char *eapol_export_error(void) {
    return g_fail.last;
}

int eapol_event_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_count;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int eapol_reject_count(eapol_reject_t why) {
    if ((int)why < 0 || why >= EAPOL_REJECT_COUNT) return 0;
    pthread_mutex_lock(&g_mu);
    int n = g_rejects[why];
    pthread_mutex_unlock(&g_mu);
    return n;
}

int eapol_key_generation(const uint8_t bssid[6], const uint8_t sta[6]) {
    pthread_mutex_lock(&g_mu);
    const pending_t *p = pending_find(bssid, sta);
    int gen = p ? p->generation : 0;
    pthread_mutex_unlock(&g_mu);
    return gen;
}
