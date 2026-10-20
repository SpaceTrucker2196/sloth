#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sloth.h"
#include "ssdp_snoop.h"
#include "camera_vendor.h"

/* libFuzzer target for the SSDP header walk (#106 slice A).
 *
 * ssdp_snoop() reads every header a NOTIFY carries — now SERVER as
 * well — out of a datagram whose every byte the announcer chose, and
 * the camera rule then token-walks that SERVER value. Both are driven
 * here: the parser on the raw input, and cam_vendor_server() on each
 * stored server string, so a missing terminator faults at the read.
 *
 * Table state persists across runs on purpose: the eviction path and
 * the sticky-SERVER update are reached only once rows exist. src_ip is
 * an RFC 5737 documentation address. */
static sloth_state_t g_s;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65507) return 0;      /* largest UDP payload over IPv4 */
    char info[64];
    ssdp_snoop("192.0.2.7", data, (int)size, info, (int)sizeof(info));
    if (strnlen(info, sizeof(info)) >= sizeof(info)) abort();

    ssdp_snapshot(&g_s);
    size_t n = 0;
    for (int i = 0; i < g_s.ssdp_count; i++) {
        const ssdp_device_t *d = &g_s.ssdp_devices[i];
        if (strnlen(d->server, sizeof(d->server)) >= sizeof(d->server))
            abort();
        const char *v = NULL;
        if (cam_vendor_server(d->server, &v) && !v) abort();
        n += strnlen(d->type, sizeof(d->type));
    }
    return (int)(n & 0);
}
