#ifndef DAWN_RSSI_H
#define DAWN_RSSI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/**
 * Get RSSI using the mac adress of the client.
 * Function uses libiwinfo and searches through all interfaces that are existing.
 * @param client_addr - mac adress of the client
 * @return The RSSI of the client if successful. INT_MIN if client was not found.
 */
int get_rssi_iwinfo(__uint8_t *client_addr);

/**
 * Get expected throughut using the mac adress of the client.
 * Function uses libiwinfo and searches through all interfaces that are existing.
 * @param client_addr - mac adress of the client
 * @return
 * + The expected throughput of the client if successful.
 * + INT_MIN if client was not found.
 * + 0 if the client is not supporting this feature.
 */
int get_expected_throughput_iwinfo(uint8_t *client_addr);

/**
 * Get rx and tx bandwidth using the mac of the client.
 * Function uses libiwinfo and searches through all interfaces that are existing.
 * @param client_addr - mac adress of the client
 * @param rx_rate - float pointer for returning the rx rate
 * @param tx_rate - float pointer for returning the tx rate
 * @return 0 if successful 1 otherwise.
 */
int get_bandwidth_iwinfo(__uint8_t *client_addr, float *rx_rate, float *tx_rate);

/**
 * Function checks if two bssid adresses have the same essid.
 * Function uses libiwinfo and searches through all interfaces that are existing.
 * @param bssid_addr
 * @param bssid_addr_to_compares
 * @return 1 if the bssid adresses have the same essid.
 */
int compare_essid_iwinfo(__uint8_t *bssid_addr, __uint8_t *bssid_addr_to_compare);

/**
 * Function returns the expected throughput using the interface and the client address.
 * @param ifname
 * @param client_addr
 * @return
 * + The expected throughput of the client if successful.
 * + INT_MIN if client was not found.
 * + 0 if the client is not supporting this feature.
 */
int get_expected_throughput(const char *ifname, uint8_t *client_addr);

int get_bssid(const char *ifname, uint8_t *bssid_addr);

#endif //DAWN_RSSI_H
