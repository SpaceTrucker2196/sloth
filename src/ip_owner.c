#include <stdio.h>
#include <string.h>
#include "ip_owner.h"

/* Helper macros to express CIDRs at compile time. */
#define IP4(a,b,c,d)      (((uint32_t)(a)<<24)|((uint32_t)(b)<<16)| \
                           ((uint32_t)(c)<< 8)| (uint32_t)(d))
#define CIDR(a,b,c,d,n)   IP4(a,b,c,d), (IP4(a,b,c,d) + ((n) == 0 ? 0xFFFFFFFFu \
                                          : ((1u << (32 - (n))) - 1u)))

typedef struct {
    uint32_t    start;
    uint32_t    end;
    const char *owner;
} ip_owner_range_t;

/* Curated set of well-known public ranges. Order matters: more-specific
 * prefixes are listed before broader ones so the linear scan returns the
 * tighter match first. */
static const ip_owner_range_t g_owners[] = {
    /* Public resolvers */
    { CIDR(1,   1,   1,   0, 24), "Cloudflare DNS"  },
    { CIDR(1,   0,   0,   0, 24), "Cloudflare DNS"  },
    { CIDR(8,   8,   4,   0, 24), "Google DNS"      },
    { CIDR(8,   8,   8,   0, 24), "Google DNS"      },
    { CIDR(9,   9,   9,   0, 24), "Quad9"           },
    { CIDR(149,112,112,   0, 24), "Quad9"           },
    { CIDR(208, 67,222,   0, 24), "OpenDNS"         },
    { CIDR(208, 67,220,   0, 24), "OpenDNS"         },
    { CIDR(185,228,168,   0, 24), "CleanBrowsing"   },
    { CIDR( 76, 76,  2,   0, 24), "ControlD"        },

    /* Cloudflare proxy */
    { CIDR(104, 16,  0,   0, 12), "Cloudflare"      },
    { CIDR(172, 64,  0,   0, 13), "Cloudflare"      },
    { CIDR(173,245, 48,   0, 20), "Cloudflare"      },
    { CIDR(188,114, 96,   0, 20), "Cloudflare"      },
    { CIDR(190, 93,240,   0, 20), "Cloudflare"      },
    { CIDR(198, 41,128,   0, 17), "Cloudflare"      },
    { CIDR(162,159,  0,   0, 16), "Cloudflare"      },

    /* Google */
    { CIDR( 35,190,  0,   0, 17), "Google"          },
    { CIDR( 64,233,160,   0, 19), "Google"          },
    { CIDR( 66,249, 64,   0, 19), "Google (crawl)"  },
    { CIDR(142,250,  0,   0, 15), "Google"          },
    { CIDR(172,217,  0,   0, 16), "Google"          },
    { CIDR(209, 85,128,   0, 17), "Google"          },
    { CIDR(216, 58,192,   0, 19), "Google"          },

    /* AWS — coarse blocks, accept the false-positives for clarity */
    { CIDR( 13, 32,  0,   0, 15), "AWS CloudFront"  },
    { CIDR( 52,  0,  0,   0,  8), "AWS"             },
    { CIDR( 54,  0,  0,   0,  8), "AWS"             },
    { CIDR( 99, 83, 64,   0, 19), "AWS Global Acc"  },

    /* Microsoft Azure / 365 */
    { CIDR( 13, 64,  0,   0, 11), "Microsoft Azure" },
    { CIDR( 20,  0,  0,   0,  8), "Microsoft Azure" },
    { CIDR( 40, 64,  0,   0, 10), "Microsoft Azure" },
    { CIDR( 52,108,  0,   0, 14), "Microsoft 365"   },

    /* Apple */
    { CIDR( 17,  0,  0,   0,  8), "Apple"           },

    /* Meta (Facebook) */
    { CIDR( 31, 13,  0,   0, 16), "Meta"            },
    { CIDR( 66,220,144,   0, 20), "Meta"            },
    { CIDR( 69,171,224,   0, 19), "Meta"            },
    { CIDR(157,240,  0,   0, 16), "Meta"            },
    { CIDR(173,252, 64,   0, 18), "Meta"            },
    { CIDR(179, 60,192,   0, 22), "Meta"            },
    { CIDR(185, 60,216,   0, 22), "Meta"            },
    { CIDR(204, 15, 20,   0, 22), "Meta"            },

    /* GitHub */
    { CIDR(140, 82,112,   0, 20), "GitHub"          },
    { CIDR(192, 30,252,   0, 22), "GitHub"          },
    { CIDR(185,199,108,   0, 22), "GitHub Pages"    },

    /* Akamai */
    { CIDR( 23,  0,  0,   0, 12), "Akamai"          },
    { CIDR(104, 64,  0,   0, 10), "Akamai"          },
    { CIDR(184, 24,  0,   0, 13), "Akamai"          },

    /* Fastly */
    { CIDR(151,101,  0,   0, 16), "Fastly"          },
    { CIDR(199,232,  0,   0, 16), "Fastly"          },
    { CIDR( 23,235, 32,   0, 20), "Fastly"          },

    /* Twitch / other notables */
    { CIDR(185, 31, 16,   0, 22), "Twitch"          },
};

#define NRANGES (int)(sizeof(g_owners) / sizeof(g_owners[0]))

const char *ip_owner_lookup(uint32_t ip) {
    for (int i = 0; i < NRANGES; i++) {
        if (ip >= g_owners[i].start && ip <= g_owners[i].end)
            return g_owners[i].owner;
    }
    return NULL;
}

const char *ip_owner_lookup_str(const char *ip) {
    if (!ip || !*ip || strchr(ip, ':')) return NULL;
    unsigned a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return NULL;
    if (a > 255 || b > 255 || c > 255 || d > 255)       return NULL;
    uint32_t host = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                    ((uint32_t)c <<  8) |  (uint32_t)d;
    return ip_owner_lookup(host);
}
