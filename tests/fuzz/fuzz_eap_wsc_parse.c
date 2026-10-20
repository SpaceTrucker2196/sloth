#include <stdint.h>
#include <stddef.h>
#include <time.h>

#include "eap_parse.h"
#include "wps_track.h"

/* libFuzzer smoke target for eap_wsc_parse() (#82).
 *
 * EAP-WSC is attacker-authored end to end: the enrollee or registrar
 * on the far side of a WPS run writes the EAP Length, the Expanded-Type
 * vendor header, the Flags octet that decides whether a 2-byte Message
 * Length follows, and then a chain of 2+2 TLVs whose lengths it also
 * chose (RFC 3748 §5.7, WSC 2.0 §7.7 and §12). Three nested length
 * claims, every one hostile.
 *
 * The input is the EAP packet from its Code byte, which is what
 * eap_wsc_parse() takes and what src/eapol_log.c hands it. The same
 * bytes then go through wps_track_observe(), so the session state
 * machine, the per-attempt Pixie-Dust fields and the opcode ring are
 * driven by whatever the parser accepted; the pure readers are called
 * on the result so their ring indexing is exercised too. The table is
 * global and bounded (LRU over MAX_WPS_SESSIONS), so it is not reset
 * between inputs — accumulated state is a harder test, not a leak. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 4096) return 0;   /* EAPOL bodies are far shorter in practice */
    eap_wsc_info_t w;
    eap_wsc_parse(data, (int)size, &w);

    static const uint8_t bssid[6] = { 0x02, 0, 0, 0, 0, 0x01 };
    uint8_t sta[6] = { 0x02, 0, 0, 0, 0, 0x02 };
    /* Spread inputs over a few stations so session creation and the
     * per-pair attempt state both see traffic. */
    if (size > 0) sta[5] = data[0] & 0x07;
    static time_t t = 1700000000;
    t += (size > 1) ? (data[1] & 0x7f) : 1;
    wps_track_observe(bssid, sta, data, (int)size, t);

    wps_session_t s;
    if (wps_track_session(bssid, sta, &s)) {
        wps_evt_t ev[WPS_EVT_RING];
        time_t m3; int quiet;
        (void)wps_track_events(&s, ev, WPS_EVT_RING);
        (void)wps_track_m3_abandon(&s, t, &m3, &quiet);
        (void)wps_track_cycles_since(&s, t, 60);
    }
    return 0;
}
