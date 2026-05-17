#ifndef SCENARIOS_H
#define SCENARIOS_H

#include "fake_platform.h"

/* Static scenarios — populate g_fake_net with a fixed network state */
void scenario_empty(void);         /* no interfaces, no connections */
void scenario_idle(void);          /* 2 ifaces, light traffic, 5 conns */
void scenario_busy(void);          /* 1Gbps saturated link, 200 conns */
void scenario_many_conns(void);    /* 500 mixed TCP/UDP connections */
void scenario_wifi_crowded(void);  /* 20 APs, varying signal/channel/enc */
void scenario_no_wifi(void);       /* ifaces + conns but 0 APs */
void scenario_monitor_env(void);   /* wlan0 assoc + wlan1mon with diverse probe clients */

/* Simulation — call repeatedly to evolve the network state over time.
   Modifies rx_rate/tx_rate on existing ifaces using a sin/cos wave.
   Increments g_fake_net.tick each call. */
void scenario_simulate_step(void);

#endif /* SCENARIOS_H */
