#ifndef DAWN_RSSI_H
#define DAWN_RSSI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int get_rssi_from_iwinfo(__uint8_t *client_addr);

int get_rssi_iwinfo();

#endif //DAWN_RSSI_H
