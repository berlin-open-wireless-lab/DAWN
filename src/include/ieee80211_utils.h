#ifndef DAWN_IEEE80211_UTILS_H
#define DAWN_IEEE80211_UTILS_H

#include <stdint.h>

/**
 * Calculate bitrate using the supported rates values.
 * @param supp_rate_val
 * @return the bitrate.
 */
double iee80211_calculate_bitrate(uint8_t supp_rate_val);

#endif //DAWN_IEEE80211_UTILS_H
