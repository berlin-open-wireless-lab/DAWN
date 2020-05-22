#include <limits.h>
#include <stdbool.h>

#include "dawn_iwinfo.h"
#include "utils.h"
#include "ieee80211_utils.h"

#include "datastorage.h"
#include "uface.h"

void ap_array_insert(ap entry);

ap ap_array_delete(ap entry);

int main()
{
ap ap0;
union __attribute__((__packed__)){
struct {
uint8_t the_mac[6];
uint8_t packing[2];
}mac;
uint64_t u64;
} mac_mangler;


    print_ap_array();
    for (int m = 0; m < 1000; m++)
    {
        mac_mangler.u64 = m;
        memcpy(ap0.bssid_addr, mac_mangler.mac.the_mac, sizeof(ap0.bssid_addr));
        ap_array_insert(ap0);
    }
    print_ap_array();
    for (int m = 0; m < 1000; m++)
    {
        mac_mangler.u64 = m;
        memcpy(ap0.bssid_addr, mac_mangler.mac.the_mac, sizeof(ap0.bssid_addr));
        ap_array_delete(ap0);
    }
    print_ap_array();
}

void send_beacon_report(uint8_t client[], int id)
{
    printf("send_beacon_report() was called...\n");
}

int send_set_probe(uint8_t client_addr[])
{
    printf("send_set_probe() was called...\n");
    return 0;
}

void wnm_disassoc_imminent(uint32_t id, const uint8_t *client_addr, char* dest_ap, uint32_t duration)
{
    printf("wnm_disassoc_imminent() was called...\n");
}

void add_client_update_timer(time_t time)
{
    printf("add_client_update_timer() was called...\n");
}

void del_client_interface(uint32_t id, const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time)
{
    printf("del_client_interface() was called...\n");
}

int send_probe_via_network(struct probe_entry_s probe_entry)
{
    printf("send_probe_via_network() was called...\n");
    return 0;
}

int get_rssi_iwinfo(uint8_t *client_addr)
{
    printf("get_rssi_iwinfo() was called...\n");
    return 0;
}

int get_expected_throughput_iwinfo(uint8_t *client_addr)
{
    printf("get_expected_throughput_iwinfo() was called...\n");
    return 0;
}

int get_bandwidth_iwinfo(uint8_t *client_addr, float *rx_rate, float *tx_rate)
{
    printf("get_bandwidth_iwinfo() was called...\n");
    return 0;
}

