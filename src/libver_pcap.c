/* The loaded libpcap's version (#142), apart from src/libver.c since
 * #213 so that only a binary that captures references libpcap for it. */

#include "libver.h"

#ifdef WITH_PCAP
#include <pcap.h>
#endif

const char *libver_pcap(void) {
#ifdef WITH_PCAP
    const char *v = pcap_lib_version();
    return v ? v : "unknown";
#else
    return "none";
#endif
}

int libver_format(char *buf, size_t n) {
    return libver_format_libs(buf, n, libver_pcap());
}
