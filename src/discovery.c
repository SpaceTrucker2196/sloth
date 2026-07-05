#include "discovery.h"
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

/* Case-insensitive exact match. */
static int ieq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return *a == *b;
}

static int is_loopback_host(const char *host) {
    return ieq(host, "127.0.0.1") || ieq(host, "localhost") ||
           ieq(host, "::1") || ieq(host, "[::1]") || host[0] == '\0';
}

int discovery_routable_tcp_port(const char *spec) {
    if (!spec) return -1;
    if (strncmp(spec, "tcp:", 4) != 0) return -1;   /* unix / other */
    const char *rest = spec + 4;
    /* Port is after the LAST colon; the host is everything before it.
     * (Bare IPv6 literals without brackets are ambiguous here and treated
     * as non-routable-if-loopback via the ::1 check; the documented spec
     * form is tcp:HOST:PORT with a plain host.) */
    const char *colon = strrchr(rest, ':');
    if (!colon || colon == rest) return -1;
    char host[128];
    size_t hlen = (size_t)(colon - rest);
    if (hlen >= sizeof(host)) return -1;
    memcpy(host, rest, hlen);
    host[hlen] = '\0';
    if (is_loopback_host(host)) return -1;
    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) return -1;
    return port;
}

int discovery_publish(const char *spec, const char *path) {
    int port = discovery_routable_tcp_port(spec);
    if (port < 0) return -1;

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
