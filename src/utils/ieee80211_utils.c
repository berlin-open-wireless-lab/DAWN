#include "ieee80211_utils.h"

double iee80211_calculate_bitrate(uint8_t supp_rate_val) {
    return ((double) supp_rate_val) / 2;
}

double iee80211_calculate_expected_throughput_mbit(int exp_thr) {
    return (((double) exp_thr) / 1000);
}

int rcpi_to_rssi(int rcpi)
{
    return rcpi / 2 - 110;
}
