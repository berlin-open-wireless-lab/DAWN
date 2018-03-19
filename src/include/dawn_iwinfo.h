#ifndef DAWN_RSSI_H
#define DAWN_RSSI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int get_rssi_iwinfo(__uint8_t *client_addr);

int get_expected_throughput_iwinfo(uint8_t *client_addr);

int get_bandwidth_iwinfo(__uint8_t *client_addr, float *rx_rate, float *tx_rate);

int compare_essid_iwinfo(__uint8_t *bssid_addr, __uint8_t *bssid_addr_to_compare);

int get_expected_throughput(const char *ifname, uint8_t *client_addr);

#endif //DAWN_RSSI_H
