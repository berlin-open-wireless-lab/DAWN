#ifndef __DAWN_DATASTORAGE_H
#define __DAWN_DATASTORAGE_H

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libubox/blobmsg_json.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/* Mac */

// ---------------- Defines -------------------
#define MAC_LIST_LENGTH 100

// ---------------- Structs ----------------
uint8_t mac_list[MAC_LIST_LENGTH][ETH_ALEN];

// ---------------- Functions ----------
void insert_macs_from_file();

int insert_to_maclist(uint8_t mac[]);

int mac_in_maclist(uint8_t mac[]);


/* Metric */

struct probe_metric_s dawn_metric;

// ---------------- Structs ----------------
struct probe_metric_s {
    int ap_weight;
    int ht_support;
    int vht_support;
    int no_ht_support;
    int no_vht_support;
    int rssi;
    int low_rssi;
    int freq;
    int chan_util;
    int max_chan_util;
    int rssi_val;
    int low_rssi_val;
    int chan_util_val;
    int max_chan_util_val;
    int min_probe_count;
    int bandwidth_threshold;
    int use_station_count;
    int max_station_diff;
    int eval_probe_req;
    int eval_auth_req;
    int eval_assoc_req;
    int deny_auth_reason;
    int deny_assoc_reason;
    int use_driver_recog;
    int min_kick_count;
    int chan_util_avg_period;
    int kicking;
    int op_class;
    int duration;
    int mode;
    int scan_channel;
};

struct time_config_s {
    time_t update_client;
    time_t remove_client;
    time_t remove_probe;
    time_t remove_ap;
    time_t update_hostapd;
    time_t update_tcp_con;
    time_t denied_req_threshold;
    time_t update_chan_util;
    time_t update_beacon_reports;
};

struct network_config_s {
    const char *broadcast_ip;
    int broadcast_port;
    int tcp_port;
    int network_option;
    const char *multicast;
    const char *shared_key;
    const char *iv;
    int bool_multicast;
    int use_symm_enc;
    int collision_domain;
    int bandwidth;
};

struct network_config_s network_config;
struct time_config_s timeout_config;

// ---------------- Global variables ----------------
struct probe_metric_s dawn_metric;


/* Probe, Auth, Assoc */

// ---------------- Structs ----------------
typedef struct probe_entry_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
    uint8_t target_addr[ETH_ALEN];
    uint32_t signal;
    uint32_t freq;
    uint8_t ht_capabilities;
    uint8_t vht_capabilities;
    time_t time;
    int counter;
    int deny_counter;
    uint8_t max_supp_datarate;
    uint8_t min_supp_datarate;
    uint32_t rcpi;
    uint32_t rsni;
} probe_entry;

typedef struct auth_entry_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
    uint8_t target_addr[ETH_ALEN];
    uint32_t signal;
    uint32_t freq;
    time_t time;
    int counter;
} auth_entry;

typedef struct hostapd_notify_entry_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
} hostapd_notify_entry;

typedef struct auth_entry_s assoc_entry;

#define DENY_REQ_ARRAY_LEN 100
struct auth_entry_s denied_req_array[DENY_REQ_ARRAY_LEN];
pthread_mutex_t denied_array_mutex;

auth_entry insert_to_denied_req_array(auth_entry entry, int inc_counter);

// ---------------- Defines ----------------
#define PROBE_ARRAY_LEN 1000

#define SSID_MAX_LEN 32
#define NEIGHBOR_REPORT_LEN 200

// ---------------- Global variables ----------------
struct probe_entry_s probe_array[PROBE_ARRAY_LEN];
pthread_mutex_t probe_array_mutex;

// ---------------- Functions ----------------
probe_entry insert_to_array(probe_entry entry, int inc_counter, int save_80211k);

void probe_array_insert(probe_entry entry);

probe_entry probe_array_delete(probe_entry entry);

probe_entry probe_array_get_entry(uint8_t bssid_addr[], uint8_t client_addr[]);

void print_probe_array();

void print_probe_entry(probe_entry entry);

void print_auth_entry(auth_entry entry);

void uloop_add_data_cbs();

/* AP, Client */

// blobmsg_alloc_string_buffer(&b, "signature", 1024);
#define SIGNATURE_LEN 1024

// ---------------- Structs ----------------
typedef struct client_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
    char signature[SIGNATURE_LEN];
    uint8_t ht_supported;
    uint8_t vht_supported;
    uint32_t freq;
    uint8_t auth;
    uint8_t assoc;
    uint8_t authorized;
    uint8_t preauth;
    uint8_t wds;
    uint8_t wmm;
    uint8_t ht;
    uint8_t vht;
    uint8_t wps;
    uint8_t mfp;
    time_t time;
    uint32_t aid;
    uint32_t kick_count;
} client;

typedef struct ap_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint32_t freq;
    uint8_t ht_support;
    uint8_t vht_support;
    uint32_t channel_utilization;
    time_t time;
    uint32_t station_count;
    uint8_t ssid[SSID_MAX_LEN];
    char neighbor_report[NEIGHBOR_REPORT_LEN];
    uint32_t collision_domain;
    uint32_t bandwidth;
    uint32_t ap_weight;
} ap;

// ---------------- Defines ----------------
#define ARRAY_AP_LEN 50
#define TIME_THRESHOLD_AP 30
#define ARRAY_CLIENT_LEN 1000
#define TIME_THRESHOLD_CLIENT 30
#define TIME_THRESHOLD_CLIENT_UPDATE 10
#define TIME_THRESHOLD_CLIENT_KICK 60

// ---------------- Global variables ----------------
struct client_s client_array[ARRAY_CLIENT_LEN];
pthread_mutex_t client_array_mutex;
struct ap_s ap_array[ARRAY_AP_LEN];
pthread_mutex_t ap_array_mutex;

int mac_is_equal(uint8_t addr1[], uint8_t addr2[]);

int mac_is_greater(uint8_t addr1[], uint8_t addr2[]);

// ---------------- Functions ----------------

int probe_array_update_rssi(uint8_t bssid_addr[], uint8_t client_addr[], uint32_t rssi, int send_network);

int probe_array_update_rcpi_rsni(uint8_t bssid_addr[], uint8_t client_addr[], uint32_t rcpi, uint32_t rsni, int send_network);

void insert_client_to_array(client entry);

void kick_clients(uint8_t bssid[], uint32_t id);

void client_array_insert(client entry);

client client_array_delete(client entry);

void print_client_array();

void print_client_entry(client entry);

ap insert_to_ap_array(ap entry);

void print_ap_array();

ap ap_array_get_ap(uint8_t bssid_addr[]);

int build_hearing_map_sort_client(struct blob_buf *b);

int build_network_overview(struct blob_buf *b);

int probe_array_set_all_probe_count(uint8_t client_addr[], uint32_t probe_count);

int ap_get_collision_count(int col_domain);

void send_beacon_reports(uint8_t bssid[], int id);

/* Utils */

// ---------------- Defines -------------------
#define SORT_NUM 5

// ---------------- Global variables ----------------
char *sort_string;

// ---------------- Functions -------------------
int better_ap_available(uint8_t bssid_addr[], uint8_t client_addr[], char* neighbor_report, int automatic_kick);

#endif