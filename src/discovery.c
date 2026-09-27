#include "discovery.h"
#include "observe.h"
#include "data_socket.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define DISCOVERY_DEFAULT_PATH "/etc/avahi/services/sloth.service"

/* Path we actually wrote, so unpublish can remove exactly that file.
 * Empty = nothing published. */
static char g_published_path[512];

/* XML-escape the instance name into out (bounded). The service name is
 * operator-controlled (the hostname), but escaping keeps the XML
 * well-formed regardless of what gethostname() returns. */
static void xml_escape(const char *in, char *out, size_t sz) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 6 < sz; i++) {
        char c = in[i];
        const char *rep = NULL;
        switch (c) {
        case '&':  rep = "&amp;";  break;
        case '<':  rep = "&lt;";   break;
        case '>':  rep = "&gt;";   break;
        case '"':  rep = "&quot;"; break;
        case '\'': rep = "&apos;"; break;
        default: break;
        }
        if (rep) { size_t l = strlen(rep); memcpy(out + o, rep, l); o += l; }
        else out[o++] = c;
    }
    out[o] = '\0';
}

int discovery_service_xml(char *buf, size_t sz, const char *instance, int port) {
    if (!buf || !instance || port <= 0 || port > 65535) return -1;
    char esc[128];
    xml_escape(instance, esc, sizeof(esc));
    int n = snprintf(buf, sz,
        "<?xml version=\"1.0\" standalone='no'?>\n"
        "<!DOCTYPE service-group SYSTEM \"avahi-service.dtd\">\n"
        "<!-- Written by sloth (issue #29). Advertises the read-only\n"
        "     data socket so the sloth-ios client can discover it. -->\n"
        "<service-group>\n"
        "  <name>%s</name>\n"
        "  <service>\n"
        "    <type>_sloth._tcp</type>\n"
        "    <port>%d</port>\n"
        "  </service>\n"
        "</service-group>\n",
        esc, port);
    if (n < 0 || (size_t)n >= sz) return -1;
    return n;
}

/* Delegates both decisions to data_socket.c rather than re-deriving
 * them. A private copy here had drifted: it named only 127.0.0.1 as
 * loopback, so 127.0.0.2 (unreachable off-host, and bound without
 * --data-socket-allow-remote) was advertised over mDNS, and it read the
 * port with atoi, so "8765x" advertised 8765. One classifier means the
 * advertisement can only ever describe what the exposure guard allowed. */
int discovery_routable_tcp_port(const char *spec) {
    if (data_socket_spec_is_remote(spec) != 1) return -1;
    return data_socket_spec_tcp_port(spec);
}

int discovery_publish(const char *spec, const char *path) {
    int port = discovery_routable_tcp_port(spec);
    if (port < 0) return -1;

    /* --strict suppresses the carve-out (#84). sloth still transmits
     * nothing itself, but avahi-daemon announcing on its behalf is the
     * host's presence on the wire, and an operator who locked strict
     * observation for the run asked for none of it. Enforced here rather
     * than at the call site so the gate sits on the function that writes
     * the file, not on whoever remembers to check first. */
    if (!observe_discovery_allowed()) {
        fprintf(stderr, "sloth: --strict: not advertising _sloth._tcp "
                        "(discovery suppressed for this run)\n");
        return -1;
    }

    const char *out = path ? path : DISCOVERY_DEFAULT_PATH;

    char host[256];
    if (gethostname(host, sizeof(host)) != 0 || host[0] == '\0')
        snprintf(host, sizeof(host), "sloth");

    char xml[1024];
    if (discovery_service_xml(xml, sizeof(xml), host, port) < 0) return -1;

    FILE *f = fopen(out, "w");
    if (!f) {
        fprintf(stderr,
                "sloth: discovery: could not write %s (%s); "
                "not advertising. Use --no-discovery to silence this.\n",
                out, strerror(errno));
        return -1;
    }
    fputs(xml, f);
    fclose(f);
    snprintf(g_published_path, sizeof(g_published_path), "%s", out);
    fprintf(stderr, "sloth: advertising _sloth._tcp on port %d via %s\n",
            port, out);
    return 0;
}

void discovery_unpublish(void) {
    if (g_published_path[0]) {
        unlink(g_published_path);
        g_published_path[0] = '\0';
    }
}
