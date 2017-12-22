#ifndef DAWN_RSSI_H
#define DAWN_RSSI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int get_rssi_iwinfo(__uint8_t *client_addr);

int get_bandwidth_iwinfo(__uint8_t *client_addr, float *rx_rate, float *tx_rate);

#endif //DAWN_RSSI_H
