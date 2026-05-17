#ifndef LINUX_DHCP_H
#define LINUX_DHCP_H

#include "ntop.h"

int linux_get_dhcp(dhcp_lease_t *out, int max);

#endif /* LINUX_DHCP_H */
