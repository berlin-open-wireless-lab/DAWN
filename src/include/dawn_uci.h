#ifndef DAWN_UCI_H
#define DAWN_UCI_H

struct probe_metric_s uci_get_dawn_metric();

struct time_config_s uci_get_time_config();

struct network_config_s uci_get_dawn_network();

const char* uci_get_dawn_hostapd_dir();

const char* uci_get_dawn_sort_order();

int uci_init();

int uci_clear();

#endif //DAWN_UCI_H_H
