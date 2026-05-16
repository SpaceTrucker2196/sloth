#include "services.h"
#include <stddef.h>
#include <stdio.h>

/* Sorted by port number (ascending) for binary search. */
static const struct { uint16_t port; const char *name; } g_svc[] = {
    {     7, "echo"       },
    {    13, "daytime"    },
    {    19, "chargen"    },
    {    20, "ftp-data"   },
    {    21, "ftp"        },
    {    22, "ssh"        },
    {    23, "telnet"     },
    {    25, "smtp"       },
    {    37, "time"       },
    {    43, "whois"      },
    {    53, "dns"        },
    {    67, "dhcp"       },
    {    68, "dhcp-client"},
    {    69, "tftp"       },
    {    79, "finger"     },
    {    80, "http"       },
    {    88, "kerberos"   },
    {   110, "pop3"       },
    {   111, "rpcbind"    },
    {   113, "ident"      },
    {   119, "nntp"       },
    {   123, "ntp"        },
    {   135, "msrpc"      },
    {   137, "netbios-ns" },
    {   138, "netbios-dg" },
    {   139, "netbios"    },
    {   143, "imap"       },
    {   161, "snmp"       },
    {   162, "snmptrap"   },
    {   179, "bgp"        },
    {   194, "irc"        },
    {   389, "ldap"       },
    {   443, "https"      },
    {   445, "smb"        },
    {   465, "smtps"      },
    {   500, "isakmp"     },
    {   514, "syslog"     },
    {   515, "lpd"        },
    {   587, "submission" },
    {   631, "ipp"        },
    {   636, "ldaps"      },
    {   853, "dns-tls"    },
    {   993, "imaps"      },
    {   995, "pop3s"      },
    {  1080, "socks"      },
    {  1194, "openvpn"    },
    {  1433, "mssql"      },
    {  1521, "oracle"     },
    {  1701, "l2tp"       },
    {  1723, "pptp"       },
    {  1883, "mqtt"       },
    {  2049, "nfs"        },
    {  2222, "alt-ssh"    },
    {  2379, "etcd"       },
    {  2380, "etcd-peer"  },
    {  3000, "dev-http"   },
    {  3306, "mysql"      },
    {  3389, "rdp"        },
    {  4443, "alt-https"  },
    {  4444, "shell"      },
    {  5000, "upnp"       },
    {  5060, "sip"        },
    {  5061, "sips"       },
    {  5222, "xmpp"       },
    {  5353, "mdns"       },
    {  5432, "postgres"   },
    {  5555, "adb"        },
    {  5672, "amqp"       },
    {  5900, "vnc"        },
    {  6379, "redis"      },
    {  6443, "k8s-api"    },
    {  6881, "bittorrent" },
    {  8000, "dev-http"   },
    {  8008, "alt-http"   },
    {  8080, "alt-http"   },
    {  8443, "alt-https"  },
    {  8883, "mqtt-tls"   },
    {  8888, "jupyter"    },
    {  9000, "php-fpm"    },
    {  9090, "prometheus" },
    {  9092, "kafka"      },
    {  9200, "elastic"    },
    {  9300, "elastic-xp" },
    {  9418, "git"        },
    { 10000, "webmin"     },
    { 11211, "memcached"  },
    { 27017, "mongodb"    },
    { 50051, "grpc"       },
    { 51820, "wireguard"  },
};

#define SVC_COUNT ((int)(sizeof g_svc / sizeof g_svc[0]))

const char *svc_name(uint16_t port) {
    int lo = 0, hi = SVC_COUNT - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if      (g_svc[mid].port < port) lo = mid + 1;
        else if (g_svc[mid].port > port) hi = mid - 1;
        else                             return g_svc[mid].name;
    }
    return NULL;
}

void svc_fmt_addr(char *buf, int sz, const char *addr, uint16_t port) {
    const char *name = svc_name(port);
    if (name)
        snprintf(buf, sz, "%s:%s", addr, name);
    else
        snprintf(buf, sz, "%s:%u", addr, (unsigned)port);
}
