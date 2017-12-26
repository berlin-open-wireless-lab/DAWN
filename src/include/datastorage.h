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


/* Metric */

struct probe_metric_s dawn_metric;

// ---------------- Structs ----------------
struct probe_metric_s {
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
    int bandwith_threshold;
    int use_station_count;
    int eval_probe_req;
};

struct time_config_s {
    time_t update_client;
    time_t remove_client;
    time_t remove_probe;
    time_t remove_ap;
    time_t update_hostapd;
};

struct network_config_s {
    const char* broadcast_ip;
    int broadcast_port;
    const char* multicast;
    const char* shared_key;
    const char* iv;
    int bool_multicast;
};

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
    uint8_t ht_support;
    uint8_t vht_support;
    time_t time;
    int counter;
} probe_entry;

typedef struct auth_entry_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
    uint8_t target_addr[ETH_ALEN];
    uint32_t signal;
    uint32_t freq;
} auth_entry;

typedef struct hostapd_notify_entry_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
} hostapd_notify_entry;

typedef struct auth_entry_s assoc_entry;

// ---------------- Defines ----------------
#define PROBE_ARRAY_LEN 1000

#define SSID_MAX_LEN 32

// ---------------- Global variables ----------------
struct probe_entry_s probe_array[PROBE_ARRAY_LEN];
pthread_mutex_t probe_array_mutex;

// ---------------- Functions ----------------
probe_entry insert_to_array(probe_entry entry, int inc_counter);

void probe_array_insert(probe_entry entry);

probe_entry probe_array_delete(probe_entry entry);

probe_entry probe_array_get_entry(uint8_t bssid_addr[], uint8_t client_addr[]);

void print_probe_array();

void print_probe_entry(probe_entry entry);

void print_auth_entry(auth_entry entry);

void uloop_add_data_cbs();

/* AP, Client */

// ---------------- Structs ----------------
typedef struct client_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
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
} client;

typedef struct ap_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint32_t freq;
    uint8_t ht;
    uint8_t vht;
    uint32_t channel_utilization;
    time_t time;
    uint32_t station_count;
    uint8_t ssid[SSID_MAX_LEN];
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

// ---------------- Functions ----------------
void insert_client_to_array(client entry);

void kick_clients(uint8_t bssid[], uint32_t id);

void client_array_insert(client entry);

client *client_array_delete(client entry);

void print_client_array();

void print_client_entry(client entry);

ap insert_to_ap_array(ap entry);

void print_ap_array();

ap ap_array_get_ap(uint8_t bssid_addr[]);

int build_hearing_map_sort_client(struct blob_buf *b);

int build_network_overview(struct blob_buf *b);

int probe_array_set_all_probe_count(uint8_t client_addr[], uint32_t probe_count);

/* Utils */

// ---------------- Defines -------------------
#define SORT_NUM 5
#define TIME_THRESHOLD 120  // every minute

// ---------------- Global variables ----------------
char* sort_string;

// ---------------- Functions -------------------
int mac_is_equal(uint8_t addr1[], uint8_t addr2[]);

int mac_is_greater(uint8_t addr1[], uint8_t addr2[]);

int better_ap_available(uint8_t bssid_addr[], uint8_t client_addr[], int automatic_kick);


/* List stuff */

typedef struct node {
    probe_entry data;
    struct node *ptr;
} node;

node *insert(node *head, probe_entry entry);

void free_list(node *head);

void print_list();

void insert_to_list(probe_entry entry, int inc_counter);

int mac_first_in_probe_list(uint8_t bssid_addr[], uint8_t client_addr[]);

void *remove_thread(void *arg);

pthread_mutex_t list_mutex;
node *probe_list_head;


#endif