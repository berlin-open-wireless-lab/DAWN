#ifndef DAWN_IEEE80211_UTILS_H
#define DAWN_IEEE80211_UTILS_H

#include <stdint.h>

/**
 * Calculate bitrate using the supported rates values.
 * @param supp_rate_val
 * @return the bitrate.
 */
double iee80211_calculate_bitrate(uint8_t supp_rate_val);

/**
 * Calculate expected throughput in Mbit/sec.
 * @param exp_thr
 * @return
 */
double iee80211_calculate_expected_throughput_mbit(int exp_thr);

/**
 * Convert 802.11k RCPI value to RSSI dB
 * @param rcpi
 * @return
 */
int rcpi_to_rssi(int rcpi);

#endif //DAWN_IEEE80211_UTILS_H
