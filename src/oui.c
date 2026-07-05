#include "oui.h"
#include <stddef.h>
#include <stdio.h>

/* Sorted by OUI value (ascending) for binary search. */
static const struct { uint32_t oui; const char *vendor; } g_oui[] = {
    { 0x000347, "Intel"        },
    { 0x00037F, "Atheros"      },
    { 0x000393, "Apple"        },
    { 0x000423, "Intel"        },
    { 0x0007E9, "Intel"        },
    { 0x000A27, "Apple"        },
    { 0x000A95, "Apple"        },
    { 0x000AF7, "Broadcom"     },
    { 0x000CF1, "Intel"        },
    { 0x001018, "Broadcom"     },
    { 0x001111, "Intel"        },
    { 0x001124, "Apple"        },
    { 0x001195, "D-Link"       },
    { 0x001247, "Samsung"      },
    { 0x001302, "Intel"        },
    { 0x001320, "Intel"        },
    { 0x001329, "TP-Link"      },
    { 0x001451, "Apple"        },
    { 0x00156D, "Ubiquiti"     },
    { 0x001599, "Samsung"      },
    { 0x0016CB, "Apple"        },
    { 0x001731, "Atheros"      },
    { 0x0017C9, "Samsung"      },
    { 0x0017F2, "Apple"        },
    { 0x001A2B, "Broadcom"     },
    { 0x001A8A, "Samsung"      },
    { 0x001AEF, "Qualcomm"     },
    { 0x001B21, "Intel"        },
    { 0x001B63, "Apple"        },
    { 0x001CA0, "Netgear"      },
    { 0x001CB3, "Apple"        },
    { 0x001CF0, "D-Link"       },
    { 0x001D25, "Samsung"      },
    { 0x001D4F, "Apple"        },
    { 0x001E52, "Apple"        },
    { 0x001EE5, "Broadcom"     },
    { 0x001F5B, "Apple"        },
    { 0x001FF3, "Apple"        },
    { 0x0021E9, "Apple"        },
    { 0x002214, "Qualcomm"     },
    { 0x002241, "Apple"        },
    { 0x002312, "Apple"        },
    { 0x002332, "Apple"        },
    { 0x00236C, "Apple"        },
    { 0x0023DF, "Apple"        },
    { 0x002436, "Apple"        },
    { 0x002500, "Apple"        },
    { 0x00254B, "Apple"        },
    { 0x0025BC, "Apple"        },
    { 0x002608, "Apple"        },
    { 0x00264A, "Apple"        },
    { 0x0026B9, "Apple"        },
    { 0x0026BB, "Apple"        },
    { 0x002722, "Ubiquiti"     },
    { 0x003065, "Apple"        },
    { 0x009049, "Netgear"      },
    { 0x00904C, "Broadcom"     },
    { 0x040CCE, "Apple"        },
    { 0x041552, "Apple"        },
    { 0x0418D6, "Ubiquiti"     },
    { 0x042665, "Apple"        },
    { 0x0452F3, "Apple"        },
    { 0x107B44, "ASUS"         },
    { 0x10BF48, "ASUS"         },
    { 0x18E829, "Ubiquiti"     },
    { 0x18FE34, "Espressif"    },
    { 0x246F28, "Espressif"    },
    { 0x24A43C, "Ubiquiti"     },
    { 0x28107B, "D-Link"       },
    { 0x2C4D54, "ASUS"         },
    { 0x305A3A, "ASUS"         },
    { 0x30AEA4, "Espressif"    },
    { 0x3C5AB4, "Google"       },
    { 0x3C6105, "Espressif"    },
    { 0x40167E, "ASUS"         },
    { 0x44650D, "Amazon"       },
    { 0x44D9E7, "Ubiquiti"     },
    { 0x50465D, "ASUS"         },
    { 0x543204, "Espressif"    },
    { 0x54607E, "Google"       },
    { 0x5CCF7F, "Espressif"    },
    { 0x600194, "Espressif"    },
    { 0x70039F, "Espressif"    },
    { 0x74C246, "Amazon"       },
    { 0x7C9EBD, "Espressif"    },
    { 0x802AA8, "Ubiquiti"     },
    { 0x840D8E, "Espressif"    },
    { 0x84F3EB, "Espressif"    },
    { 0x8CECB4, "Intel"        },
    { 0x904CE5, "Netgear"      },
    { 0x9097D5, "Espressif"    },
    { 0xA020A6, "Espressif"    },
    { 0xA4CF12, "Espressif"    },
    { 0xAC67B2, "Espressif"    },
    { 0xB4E62D, "Espressif"    },
    { 0xB4FBE4, "Ubiquiti"     },
    { 0xB827EB, "Raspberry Pi" },
    { 0xBCDDC2, "Espressif"    },
    { 0xC44F33, "Espressif"    },
    { 0xC4C604, "Huawei"       },
    { 0xC8C9A3, "Espressif"    },
    { 0xCC50E3, "Espressif"    },
    { 0xD0AD45, "TP-Link"      },
    { 0xD8A01D, "Espressif"    },
    { 0xDC9FDB, "Ubiquiti"     },
    { 0xDCA632, "Raspberry Pi" },
    { 0xE063DA, "Ubiquiti"     },
    { 0xE0D55E, "TP-Link"      },
    { 0xE45F01, "Raspberry Pi" },
    { 0xE8DB84, "Espressif"    },
    { 0xEC6260, "Espressif"    },
    { 0xF008D1, "Espressif"    },
    { 0xF09FC2, "Ubiquiti"     },
    { 0xF4CFA2, "Espressif"    },
    { 0xF4F5D8, "Google"       },
    { 0xF88FCA, "Google"       },
    { 0xFCF5C4, "Espressif"    },
};

#define OUI_COUNT ((int)(sizeof g_oui / sizeof g_oui[0]))

const char *oui_lookup(const uint8_t *mac) {
    if (mac[0] & 0x02) return "Randomized";
    if (mac[0] & 0x01) return "Multicast";

    uint32_t key = ((uint32_t)mac[0] << 16) |
                   ((uint32_t)mac[1] <<  8) |
                    (uint32_t)mac[2];

    int lo = 0, hi = OUI_COUNT - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if      (g_oui[mid].oui < key) lo = mid + 1;
        else if (g_oui[mid].oui > key) hi = mid - 1;
        else                           return g_oui[mid].vendor;
    }
    return NULL;
}

const char *oui_vendor_label(const uint8_t *mac, int *is_random) {
    if (is_random) *is_random = (mac[0] & 0x02) != 0;
    const char *v = oui_lookup(mac);
    return (v && v[0]) ? v : "?";
}

const char *oui_lookup_str(const char *bssid_str) {
    unsigned b0, b1, b2, b3, b4, b5;
    if (sscanf(bssid_str, "%x:%x:%x:%x:%x:%x",
               &b0, &b1, &b2, &b3, &b4, &b5) != 6)
        return NULL;
    uint8_t mac[6] = { (uint8_t)b0, (uint8_t)b1, (uint8_t)b2,
                       (uint8_t)b3, (uint8_t)b4, (uint8_t)b5 };
    return oui_lookup(mac);
}
