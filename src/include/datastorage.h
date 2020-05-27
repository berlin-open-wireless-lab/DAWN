#ifndef __DAWN_DATASTORAGE_H
#define __DAWN_DATASTORAGE_H

#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <limits.h>

#include "mac_utils.h"
#include "utils.h"

/* Mac */

// ---------------- Defines -------------------
#define MAC_LIST_LENGTH 100

// ---------------- Global variables ----------------
extern uint8_t mac_list[][ETH_ALEN];

// ---------------- Functions ----------
void insert_macs_from_file();

int insert_to_maclist(uint8_t mac[]);

int mac_in_maclist(uint8_t mac[]);


// ---------------- Global variables ----------------
/*** Metrics and configuration data ***/

// ---------------- Structs ----------------
struct probe_metric_s {
    int ap_weight; // TODO: Never evaluated?
    int ht_support; // eval_probe_metric()()
    int vht_support; // eval_probe_metric()()
    int no_ht_support; // eval_probe_metric()()
    int no_vht_support; // eval_probe_metric()()
    int rssi; // eval_probe_metric()()
    int low_rssi; // eval_probe_metric()()
    int freq; // eval_probe_metric()()
    int chan_util; // eval_probe_metric()()
    int max_chan_util; // eval_probe_metric()()
    int rssi_val; // eval_probe_metric()()
    int low_rssi_val; // eval_probe_metric()()
    int chan_util_val; // eval_probe_metric()()
    int max_chan_util_val; // eval_probe_metric()()
    int min_probe_count;
    int bandwidth_threshold; // kick_clients()
    int use_station_count; // better_ap_available()
    int max_station_diff; // compare_station_count() <- better_ap_available()
    int eval_probe_req;
    int eval_auth_req;
    int eval_assoc_req;
    int deny_auth_reason;
    int deny_assoc_reason;
    int use_driver_recog;
    int min_kick_count; // kick_clients()
    int chan_util_avg_period;
    int set_hostapd_nr;
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

#define MAX_IP_LENGTH 46
#define MAX_KEY_LENGTH 65

struct network_config_s {
    char broadcast_ip[MAX_IP_LENGTH];
    int broadcast_port;
    int tcp_port;
    int network_option;
    char shared_key[MAX_KEY_LENGTH];
    char iv[MAX_KEY_LENGTH];
    int use_symm_enc;
    int collision_domain;
    int bandwidth;
};

extern struct network_config_s network_config;
extern struct time_config_s timeout_config;
extern struct probe_metric_s dawn_metric;

/*** Core DAWN data structures for tracking network devices and status ***/
// Define this to remove printing / reporing of fields, and hence observe
// which fields are evaluated in use.
// #define DAWN_NO_OUTPUT

// TODO notes:
//    Never used? = No code reference
//    Never evaluated? = Set and passed in ubus, etc but never evaluated for outcomes

/* Probe, Auth, Assoc */

// ---------------- Structs ----------------
typedef struct probe_entry_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
    uint8_t target_addr[ETH_ALEN]; // TODO: Never evaluated?
    uint32_t signal; // eval_probe_metric()
    uint32_t freq; // eval_probe_metric()
    uint8_t ht_capabilities; // eval_probe_metric()
    uint8_t vht_capabilities; // eval_probe_metric()
    time_t time; // remove_old...entries
    int counter;
#ifndef DAWN_NO_OUTPUT
    int deny_counter; // TODO: Never used?
    uint8_t max_supp_datarate; // TODO: Never used?
    uint8_t min_supp_datarate; // TODO: Never used?
#endif
    uint32_t rcpi;
    uint32_t rsni;
} probe_entry;

typedef struct auth_entry_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
    uint8_t target_addr[ETH_ALEN]; // TODO: Never evaluated?
    uint32_t signal; // TODO: Never evaluated?
    uint32_t freq; // TODO: Never evaluated?
    time_t time; // Never used for removal?
    int counter;
} auth_entry;

typedef struct hostapd_notify_entry_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
} hostapd_notify_entry;

typedef struct auth_entry_s assoc_entry;

// ---------------- Defines ----------------
#define DENY_REQ_ARRAY_LEN 100
#define PROBE_ARRAY_LEN 1000

#define SSID_MAX_LEN 32
#define NEIGHBOR_REPORT_LEN 200

// ---------------- Global variables ----------------
extern struct auth_entry_s denied_req_array[];
extern int denied_req_last;
extern pthread_mutex_t denied_array_mutex;

extern struct probe_entry_s probe_array[];
extern int probe_entry_last;
extern pthread_mutex_t probe_array_mutex;

// ---------------- Functions ----------------
probe_entry insert_to_array(probe_entry entry, int inc_counter, int save_80211k, int is_beacon);

void probe_array_insert(probe_entry entry);

probe_entry probe_array_delete(probe_entry entry);

probe_entry probe_array_get_entry(uint8_t bssid_addr[], uint8_t client_addr[]);

void remove_old_probe_entries(time_t current_time, long long int threshold);

void print_probe_array();

void print_probe_entry(probe_entry entry);

int eval_probe_metric(struct probe_entry_s probe_entry);

void denied_req_array_insert(auth_entry entry);

auth_entry denied_req_array_delete(auth_entry entry);

auth_entry insert_to_denied_req_array(auth_entry entry, int inc_counter);

void print_auth_entry(auth_entry entry);

/* AP, Client */

#define SIGNATURE_LEN 1024
#define MAX_INTERFACE_NAME 64

// ---------------- Structs ----------------
typedef struct client_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint8_t client_addr[ETH_ALEN];
    char signature[SIGNATURE_LEN]; // TODO: Never evaluated?
    uint8_t ht_supported; // TODO: Never evaluated?
    uint8_t vht_supported; // TODO: Never evaluated?
    uint32_t freq; // TODO: Never evaluated?
    uint8_t auth; // TODO: Never evaluated?
    uint8_t assoc; // TODO: Never evaluated?
    uint8_t authorized; // TODO: Never evaluated?
    uint8_t preauth; // TODO: Never evaluated?
    uint8_t wds; // TODO: Never evaluated?
    uint8_t wmm;  // TODO: Never evaluated?
    uint8_t ht; // TODO: Never evaluated?
    uint8_t vht; // TODO: Never evaluated?
    uint8_t wps; // TODO: Never evaluated?
    uint8_t mfp; // TODO: Never evaluated?
    time_t time; // remove_old...entries
    uint32_t aid; // TODO: Never evaluated?
    uint32_t kick_count; // kick_clients()
    uint8_t rrm_enabled_capa; //the first byte is enough
} client;

typedef struct ap_s {
    uint8_t bssid_addr[ETH_ALEN];
    uint32_t freq; // TODO: Never evaluated?
    uint8_t ht_support; // eval_probe_metric()
    uint8_t vht_support; // eval_probe_metric()
    uint32_t channel_utilization; // eval_probe_metric()
    time_t time; // remove_old...entries
    uint32_t station_count; // compare_station_count() <- better_ap_available()
    uint8_t ssid[SSID_MAX_LEN]; // compare_sid() < -better_ap_available()
    char neighbor_report[NEIGHBOR_REPORT_LEN];
    uint32_t collision_domain;  // TODO: ap_get_collision_count() never evaluated?
    uint32_t bandwidth; // TODO: Never evaluated?
    uint32_t ap_weight; // eval_probe_metric()
    char iface[MAX_INTERFACE_NAME];
    char hostname[HOST_NAME_MAX];
} ap;

// ---------------- Defines ----------------
#define ARRAY_AP_LEN 50
#define TIME_THRESHOLD_AP 30

#define ARRAY_CLIENT_LEN 1000
#define TIME_THRESHOLD_CLIENT 30
#define TIME_THRESHOLD_CLIENT_UPDATE 10
#define TIME_THRESHOLD_CLIENT_KICK 60

// ---------------- Global variables ----------------
extern struct ap_s ap_array[];
extern int ap_entry_last;
extern pthread_mutex_t ap_array_mutex;

extern struct client_s client_array[];
extern int client_entry_last;
extern pthread_mutex_t client_array_mutex;

// ---------------- Functions ----------------

int probe_array_update_rssi(uint8_t bssid_addr[], uint8_t client_addr[], uint32_t rssi, int send_network);

int probe_array_update_rcpi_rsni(uint8_t bssid_addr[], uint8_t client_addr[], uint32_t rcpi, uint32_t rsni, int send_network);

void remove_old_client_entries(time_t current_time, long long int threshold);

void insert_client_to_array(client entry);

int kick_clients(uint8_t bssid[], uint32_t id);

void update_iw_info(uint8_t bssid[]);

void client_array_insert(client entry);

client client_array_get_client(const uint8_t* client_addr);

client client_array_delete(client entry);

void print_client_array();

void print_client_entry(client entry);

int is_connected_somehwere(uint8_t client_addr[]);

ap insert_to_ap_array(ap entry);

void remove_old_ap_entries(time_t current_time, long long int threshold);

void print_ap_array();

ap ap_array_get_ap(uint8_t bssid_addr[]);

int probe_array_set_all_probe_count(uint8_t client_addr[], uint32_t probe_count);

#ifndef DAWN_NO_OUTPUT
int ap_get_collision_count(int col_domain);
#endif

void send_beacon_reports(uint8_t bssid[], int id);

/* Utils */
#define SORT_LENGTH 5
extern char sort_string[];

// ---------------- Functions -------------------
int better_ap_available(uint8_t bssid_addr[], uint8_t client_addr[], char* neighbor_report, int automatic_kick);

// All users of datastorage should call init_ / destroy_mutex at initialisation and termination respectively
int init_mutex();
void destroy_mutex();
#endif
