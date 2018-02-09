#include "ieee80211_utils.h"

#include <stdint.h>

double iee80211_calculate_bitrate(uint8_t supp_rate_val)
{
    return ((double) supp_rate_val) / 2;
}