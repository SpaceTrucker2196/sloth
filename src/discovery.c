#include "discovery.h"
#include "observe.h"
#include "data_socket.h"
#include "secure_file.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#define DISCOVERY_DEFAULT_PATH "/etc/avahi/services/sloth.service"

/* What we actually wrote, so unpublish can remove exactly that file:
 * the directory descriptor pinned at publish time plus the bare name
 * inside it. Unlinking through the held descriptor means a swap of
 * /etc/avahi/services itself between publish and exit cannot redirect
 * the removal (#134). g_dfd < 0 = nothing published. */
static int  g_dfd = -1;
static char g_name[256];

/* write(2) until done; a short write on a regular file is not an
 * error. */
static int write_all(int fd, const char *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

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
    int xml_len = discovery_service_xml(xml, sizeof(xml), host, port);
    if (xml_len < 0) return -1;

    /* This file is written as root into a directory sloth does not own,
     * so it goes through secure_file like every other write (#134):
     * a plain fopen(out, "w") followed a symlink planted at the name
     * and truncated whatever it pointed at (CWE-59, CWE-367). The
     * directory is pinned first, the content lands in an O_EXCL temp
     * inside it, and the final name is taken over by rename — which
     * replaces a planted link rather than following it. */
    char dir[512], name[256], tmp[264], err[SFILE_ERR_MAX];
    const char *slash = strrchr(out, '/');
    const char *base  = slash ? slash + 1 : out;
    size_t dl = slash ? (size_t)(slash - out) : 0;
    /* Refused, never clamped: a truncated directory path would pin
     * some other directory and write there with every check passing. */
    if (!base[0] || strlen(base) >= sizeof(name) || dl >= sizeof(dir)) {
        fprintf(stderr, "sloth: discovery: %s: bad path; "
                        "not advertising.\n", out);
        return -1;
    }
    if (!slash) {
        snprintf(dir, sizeof(dir), ".");
    } else if (slash == out) {
        snprintf(dir, sizeof(dir), "/");
    } else {
        memcpy(dir, out, dl);
        dir[dl] = '\0';
    }
    snprintf(name, sizeof(name), "%s", base);
    snprintf(tmp, sizeof(tmp), ".%s.tmp", name);

    int dfd = sfile_system_dir(dir, err, sizeof(err));
    if (dfd < 0) {
        fprintf(stderr, "sloth: discovery: %s; not advertising. "
                        "Use --no-discovery to silence this.\n", err);
        return -1;
    }
    /* A temp of this name is ours, left by a crash mid-write (the same
     * reasoning as the handshake pcap writer). unlinkat removes the
     * name without following it, so a planted link here is removed,
     * not written through. */
    unlinkat(dfd, tmp, 0);
    int fd = sfile_open(dfd, tmp, SFILE_EXCL, err, sizeof(err));
    if (fd < 0) {
        fprintf(stderr, "sloth: discovery: %s; not advertising. "
                        "Use --no-discovery to silence this.\n", err);
        close(dfd);
        return -1;
    }
    /* fchmod 0644 is deliberate and is the one place sloth loosens a
     * mode: avahi-daemon runs as the `avahi` user and has to read the
     * file, and the content is the hostname and a port — the very
     * things the mDNS announcement is about to broadcast. It is by
     * descriptor on a file this call created a moment ago, never a
     * chmod of an operator path. */
    const char *fail = NULL;
    if (write_all(fd, xml, (size_t)xml_len) != 0) fail = "write";
    else if (fsync(fd) != 0)                     fail = "fsync";
    else if (fchmod(fd, 0644) != 0)              fail = "chmod";
    int e = errno;
    close(fd);
    if (!fail && renameat(dfd, tmp, dfd, name) != 0) {
        fail = "rename";
        e = errno;
    }
    if (fail) {
        unlinkat(dfd, tmp, 0);
        fprintf(stderr, "sloth: discovery: %s: %s failed: %s; "
                        "not advertising.\n", out, fail, strerror(e));
        close(dfd);
        return -1;
    }
    if (g_dfd >= 0) close(g_dfd);   /* re-publish: drop the older pin */
    g_dfd = dfd;
    snprintf(g_name, sizeof(g_name), "%s", name);
    fprintf(stderr, "sloth: advertising _sloth._tcp on port %d via %s\n",
            port, out);
    return 0;
}

void discovery_unpublish(void) {
    if (g_dfd >= 0) {
        unlinkat(g_dfd, g_name, 0);
        close(g_dfd);
        g_dfd = -1;
    }
    g_name[0] = '\0';
}
