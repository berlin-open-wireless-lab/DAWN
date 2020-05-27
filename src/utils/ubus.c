#include <limits.h>


#include <ctype.h>
#include <dirent.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubus.h>
#include <sys/types.h>
#include <stdbool.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define REQ_TYPE_PROBE 0
#define REQ_TYPE_AUTH 1
#define REQ_TYPE_ASSOC 2

#include "networksocket.h"
#include "utils.h"
#include "dawn_uci.h"
#include "dawn_iwinfo.h"
#include "tcpsocket.h"
#include "ieee80211_utils.h"

#include "datastorage.h"
#include "uface.h"
#include "ubus.h"

static struct ubus_context *ctx = NULL;

static struct blob_buf b;
static struct blob_buf b_send_network;
static struct blob_buf network_buf;
static struct blob_buf data_buf;
static struct blob_buf b_probe;
static struct blob_buf b_domain;
static struct blob_buf b_notify;
static struct blob_buf b_clients;
static struct blob_buf b_umdns;
static struct blob_buf b_beacon;
static struct blob_buf b_nr;

void update_clients(struct uloop_timeout *t);

void update_tcp_connections(struct uloop_timeout *t);

void update_channel_utilization(struct uloop_timeout *t);

void run_server_update(struct uloop_timeout *t);

void update_beacon_reports(struct uloop_timeout *t);

struct uloop_timeout client_timer = {
        .cb = update_clients
};
struct uloop_timeout hostapd_timer = {
        .cb = update_hostapd_sockets
};
struct uloop_timeout umdns_timer = {
        .cb = update_tcp_connections
};
struct uloop_timeout channel_utilization_timer = {
        .cb = update_channel_utilization
};

struct uloop_timeout usock_timer = {
        .cb = run_server_update
};

struct uloop_timeout beacon_reports_timer = {
        .cb = update_beacon_reports
};

#define MAX_HOSTAPD_SOCKETS 10
#define MAX_INTERFACE_NAME 64

LIST_HEAD(hostapd_sock_list);

struct hostapd_sock_entry {
    struct list_head list;

    uint32_t id;
    char iface_name[MAX_INTERFACE_NAME];
    uint8_t bssid_addr[ETH_ALEN];
    char ssid[SSID_MAX_LEN];
    uint8_t ht_support;
    uint8_t vht_support;
    uint64_t last_channel_time;
    uint64_t last_channel_time_busy;
    int chan_util_samples_sum;
    int chan_util_num_sample_periods;
    int chan_util_average;

    // add neighbor report string
    /*
    [Elemen ID|1][LENGTH|1][BSSID|6][BSSID INFORMATION|4][Operating Class|1][Channel Number|1][PHY Type|1][Operational Subelements]
    */
    char neighbor_report[NEIGHBOR_REPORT_LEN];

    struct ubus_subscriber subscriber;
    struct ubus_event_handler wait_handler;
    bool subscribed;
};

struct hostapd_sock_entry* hostapd_sock_arr[MAX_HOSTAPD_SOCKETS];
int hostapd_sock_last = -1;

enum {
    NETWORK_METHOD,
    NETWORK_DATA,
    __NETWORK_MAX,
};

static const struct blobmsg_policy network_policy[__NETWORK_MAX] = {
        [NETWORK_METHOD] = {.name = "method", .type = BLOBMSG_TYPE_STRING},
        [NETWORK_DATA] = {.name = "data", .type = BLOBMSG_TYPE_STRING},
};

enum {
    HOSTAPD_NOTIFY_BSSID_ADDR,
    HOSTAPD_NOTIFY_CLIENT_ADDR,
    __HOSTAPD_NOTIFY_MAX,
};

static const struct blobmsg_policy hostapd_notify_policy[__HOSTAPD_NOTIFY_MAX] = {
        [HOSTAPD_NOTIFY_BSSID_ADDR] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
        [HOSTAPD_NOTIFY_CLIENT_ADDR] = {.name = "address", .type = BLOBMSG_TYPE_STRING},
};

enum {
    AUTH_BSSID_ADDR,
    AUTH_CLIENT_ADDR,
    AUTH_TARGET_ADDR,
    AUTH_SIGNAL,
    AUTH_FREQ,
    __AUTH_MAX,
};

static const struct blobmsg_policy auth_policy[__AUTH_MAX] = {
        [AUTH_BSSID_ADDR] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
        [AUTH_CLIENT_ADDR] = {.name = "address", .type = BLOBMSG_TYPE_STRING},
        [AUTH_TARGET_ADDR] = {.name = "target", .type = BLOBMSG_TYPE_STRING},
        [AUTH_SIGNAL] = {.name = "signal", .type = BLOBMSG_TYPE_INT32},
        [AUTH_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
};

enum {
    PROB_BSSID_ADDR,
    PROB_CLIENT_ADDR,
    PROB_TARGET_ADDR,
    PROB_SIGNAL,
    PROB_FREQ,
    PROB_HT_CAPABILITIES,
    PROB_VHT_CAPABILITIES,
    PROB_RCPI,
    PROB_RSNI,
    __PROB_MAX,
};

static const struct blobmsg_policy prob_policy[__PROB_MAX] = {
        [PROB_BSSID_ADDR] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
        [PROB_CLIENT_ADDR] = {.name = "address", .type = BLOBMSG_TYPE_STRING},
        [PROB_TARGET_ADDR] = {.name = "target", .type = BLOBMSG_TYPE_STRING},
        [PROB_SIGNAL] = {.name = "signal", .type = BLOBMSG_TYPE_INT32},
        [PROB_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
        [PROB_HT_CAPABILITIES] = {.name = "ht_capabilities", .type = BLOBMSG_TYPE_TABLE},
        [PROB_VHT_CAPABILITIES] = {.name = "vht_capabilities", .type = BLOBMSG_TYPE_TABLE},
        [PROB_RCPI] = {.name = "rcpi", .type = BLOBMSG_TYPE_INT32},
        [PROB_RSNI] = {.name = "rsni", .type = BLOBMSG_TYPE_INT32},
};

enum {
    BEACON_REP_ADDR,
    BEACON_REP_OP_CLASS,
    BEACON_REP_CHANNEL,
    BEACON_REP_START_TIME,
    BEACON_REP_DURATION,
    BEACON_REP_REPORT_INFO,
    BEACON_REP_RCPI,
    BEACON_REP_RSNI,
    BEACON_REP_BSSID,
    BEACON_REP_ANTENNA_ID,
    BEACON_REP_PARENT_TSF,
    __BEACON_REP_MAX,
};

static const struct blobmsg_policy beacon_rep_policy[__BEACON_REP_MAX] = {
        [BEACON_REP_ADDR] = {.name = "address", .type = BLOBMSG_TYPE_STRING},
        [BEACON_REP_OP_CLASS] = {.name = "op-class", .type = BLOBMSG_TYPE_INT16},
        [BEACON_REP_CHANNEL] = {.name = "channel", .type = BLOBMSG_TYPE_INT64},
        [BEACON_REP_START_TIME] = {.name = "start-time", .type = BLOBMSG_TYPE_INT32},
        [BEACON_REP_DURATION] = {.name = "duration", .type = BLOBMSG_TYPE_INT16},
        [BEACON_REP_REPORT_INFO] = {.name = "report-info", .type = BLOBMSG_TYPE_INT16},
        [BEACON_REP_RCPI] = {.name = "rcpi", .type = BLOBMSG_TYPE_INT16},
        [BEACON_REP_RSNI] = {.name = "rsni", .type = BLOBMSG_TYPE_INT16},
        [BEACON_REP_BSSID] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
        [BEACON_REP_ANTENNA_ID] = {.name = "antenna-id", .type = BLOBMSG_TYPE_INT16},
        [BEACON_REP_PARENT_TSF] = {.name = "parent-tsf", .type = BLOBMSG_TYPE_INT16},
};

enum {
    CLIENT_TABLE,
    CLIENT_TABLE_BSSID,
    CLIENT_TABLE_SSID,
    CLIENT_TABLE_FREQ,
    CLIENT_TABLE_HT,
    CLIENT_TABLE_VHT,
    CLIENT_TABLE_CHAN_UTIL,
    CLIENT_TABLE_NUM_STA,
    CLIENT_TABLE_COL_DOMAIN,
    CLIENT_TABLE_BANDWIDTH,
    CLIENT_TABLE_WEIGHT,
    CLIENT_TABLE_NEIGHBOR,
    CLIENT_TABLE_RRM,
    __CLIENT_TABLE_MAX,
};

static const struct blobmsg_policy client_table_policy[__CLIENT_TABLE_MAX] = {
        [CLIENT_TABLE] = {.name = "clients", .type = BLOBMSG_TYPE_TABLE},
        [CLIENT_TABLE_BSSID] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
        [CLIENT_TABLE_SSID] = {.name = "ssid", .type = BLOBMSG_TYPE_STRING},
        [CLIENT_TABLE_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
        [CLIENT_TABLE_HT] = {.name = "ht_supported", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_TABLE_VHT] = {.name = "vht_supported", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_TABLE_CHAN_UTIL] = {.name = "channel_utilization", .type = BLOBMSG_TYPE_INT32},
        [CLIENT_TABLE_NUM_STA] = {.name = "num_sta", .type = BLOBMSG_TYPE_INT32},
        [CLIENT_TABLE_COL_DOMAIN] = {.name = "collision_domain", .type = BLOBMSG_TYPE_INT32},
        [CLIENT_TABLE_BANDWIDTH] = {.name = "bandwidth", .type = BLOBMSG_TYPE_INT32},
        [CLIENT_TABLE_WEIGHT] = {.name = "ap_weight", .type = BLOBMSG_TYPE_INT32},
        [CLIENT_TABLE_NEIGHBOR] = {.name = "neighbor_report", .type = BLOBMSG_TYPE_STRING},
        [CLIENT_TABLE_RRM] = {.name = "rrm", .type = BLOBMSG_TYPE_ARRAY},
};

enum {
    CLIENT_SIGNATURE,
    CLIENT_AUTH,
    CLIENT_ASSOC,
    CLIENT_AUTHORIZED,
    CLIENT_PREAUTH,
    CLIENT_WDS,
    CLIENT_WMM,
    CLIENT_HT,
    CLIENT_VHT,
    CLIENT_WPS,
    CLIENT_MFP,
    CLIENT_AID,
    __CLIENT_MAX,
};

static const struct blobmsg_policy client_policy[__CLIENT_MAX] = {
        [CLIENT_SIGNATURE] = {.name = "signature", .type = BLOBMSG_TYPE_STRING},
        [CLIENT_AUTH] = {.name = "auth", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_ASSOC] = {.name = "assoc", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_AUTHORIZED] = {.name = "authorized", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_PREAUTH] = {.name = "preauth", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_WDS] = {.name = "wds", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_WMM] = {.name = "wmm", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_HT] = {.name = "ht", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_VHT] = {.name = "vht", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_WPS] = {.name = "wps", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_MFP] = {.name = "mfp", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_AID] = {.name = "aid", .type = BLOBMSG_TYPE_INT32},
};

enum {
    DAWN_UMDNS_TABLE,
    __DAWN_UMDNS_TABLE_MAX,
};

static const struct blobmsg_policy dawn_umdns_table_policy[__DAWN_UMDNS_TABLE_MAX] = {
        [DAWN_UMDNS_TABLE] = {.name = "_dawn._tcp", .type = BLOBMSG_TYPE_TABLE},
};

enum {
    DAWN_UMDNS_IPV4,
    DAWN_UMDNS_PORT,
    __DAWN_UMDNS_MAX,
};

static const struct blobmsg_policy dawn_umdns_policy[__DAWN_UMDNS_MAX] = {
        [DAWN_UMDNS_IPV4] = {.name = "ipv4", .type = BLOBMSG_TYPE_STRING},
        [DAWN_UMDNS_PORT] = {.name = "port", .type = BLOBMSG_TYPE_INT32},
};

enum {
    RRM_ARRAY,
    __RRM_MAX,
};

static const struct blobmsg_policy rrm_array_policy[__RRM_MAX] = {
        [RRM_ARRAY] = {.name = "value", .type = BLOBMSG_TYPE_ARRAY},
};

/* Function Definitions */
static int hostapd_notify(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg);

static int ubus_get_clients();

static int
add_mac(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg);

static int reload_config(struct ubus_context *ctx, struct ubus_object *obj,
                         struct ubus_request_data *req, const char *method,
                         struct blob_attr *msg);

static int get_hearing_map(struct ubus_context *ctx, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg);

static int get_network(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg);

static int handle_set_probe(struct blob_attr *msg);

static int parse_add_mac_to_file(struct blob_attr *msg);

static void ubus_add_oject();

static void respond_to_notify(uint32_t id);

int handle_uci_config(struct blob_attr *msg);

void subscribe_to_new_interfaces(const char *hostapd_sock_path);

bool subscriber_to_interface(const char *ifname);

bool subscribe(struct hostapd_sock_entry *hostapd_entry);

int parse_to_beacon_rep(struct blob_attr *msg, probe_entry *beacon_rep);

void ubus_set_nr();

void add_client_update_timer(time_t time) {
    uloop_timeout_set(&client_timer, time);
}

static inline int
subscription_wait(struct ubus_event_handler *handler) {
    return ubus_register_event_handler(ctx, handler, "ubus.object.add");
}

void blobmsg_add_macaddr(struct blob_buf *buf, const char *name, const uint8_t *addr) {
    char *s;

    s = blobmsg_alloc_string_buffer(buf, name, 20);
    sprintf(s, MACSTR, MAC2STR(addr));
    blobmsg_add_string_buffer(buf);
}

static int decide_function(probe_entry *prob_req, int req_type) {
    if (mac_in_maclist(prob_req->client_addr)) {
        return 1;
    }

    if (prob_req->counter < dawn_metric.min_probe_count) {
        return 0;
    }

    if (req_type == REQ_TYPE_PROBE && dawn_metric.eval_probe_req <= 0) {
        return 1;
    }

    if (req_type == REQ_TYPE_AUTH && dawn_metric.eval_auth_req <= 0) {
        return 1;
    }

    if (req_type == REQ_TYPE_ASSOC && dawn_metric.eval_assoc_req <= 0) {
        return 1;
    }

    if (better_ap_available(prob_req->bssid_addr, prob_req->client_addr, NULL, 0)) {
        return 0;
    }

    return 1;
}

int parse_to_hostapd_notify(struct blob_attr *msg, hostapd_notify_entry *notify_req) {
    struct blob_attr *tb[__HOSTAPD_NOTIFY_MAX];

    blobmsg_parse(hostapd_notify_policy, __HOSTAPD_NOTIFY_MAX, tb, blob_data(msg), blob_len(msg));

    if (hwaddr_aton(blobmsg_data(tb[HOSTAPD_NOTIFY_BSSID_ADDR]), notify_req->bssid_addr))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (hwaddr_aton(blobmsg_data(tb[HOSTAPD_NOTIFY_CLIENT_ADDR]), notify_req->client_addr))
        return UBUS_STATUS_INVALID_ARGUMENT;

    return 0;
}

int parse_to_auth_req(struct blob_attr *msg, auth_entry *auth_req) {
    struct blob_attr *tb[__AUTH_MAX];

    blobmsg_parse(auth_policy, __AUTH_MAX, tb, blob_data(msg), blob_len(msg));

    if (hwaddr_aton(blobmsg_data(tb[AUTH_BSSID_ADDR]), auth_req->bssid_addr))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (hwaddr_aton(blobmsg_data(tb[AUTH_CLIENT_ADDR]), auth_req->client_addr))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (hwaddr_aton(blobmsg_data(tb[AUTH_TARGET_ADDR]), auth_req->target_addr))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (tb[PROB_SIGNAL]) {
        auth_req->signal = blobmsg_get_u32(tb[AUTH_SIGNAL]);
    }

    if (tb[PROB_FREQ]) {
        auth_req->freq = blobmsg_get_u32(tb[AUTH_FREQ]);
    }

    return 0;
}

int parse_to_assoc_req(struct blob_attr *msg, assoc_entry *assoc_req) {
    return (parse_to_auth_req(msg, assoc_req));
}

int parse_to_probe_req(struct blob_attr *msg, probe_entry *prob_req) {
    struct blob_attr *tb[__PROB_MAX];

    blobmsg_parse(prob_policy, __PROB_MAX, tb, blob_data(msg), blob_len(msg));

    if (hwaddr_aton(blobmsg_data(tb[PROB_BSSID_ADDR]), prob_req->bssid_addr))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (hwaddr_aton(blobmsg_data(tb[PROB_CLIENT_ADDR]), prob_req->client_addr))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (hwaddr_aton(blobmsg_data(tb[PROB_TARGET_ADDR]), prob_req->target_addr))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (tb[PROB_SIGNAL]) {
        prob_req->signal = blobmsg_get_u32(tb[PROB_SIGNAL]);
    }

    if (tb[PROB_FREQ]) {
        prob_req->freq = blobmsg_get_u32(tb[PROB_FREQ]);
    }

    if (tb[PROB_RCPI]) {
        prob_req->rcpi = blobmsg_get_u32(tb[PROB_RCPI]);
    } else {
        prob_req->rcpi = -1;
    }

    if (tb[PROB_RSNI]) {
        prob_req->rsni = blobmsg_get_u32(tb[PROB_RSNI]);
    } else {
        prob_req->rsni = -1;
    }

    if (tb[PROB_HT_CAPABILITIES]) {
        prob_req->ht_capabilities = true;
    } else
    {
        prob_req->ht_capabilities = false;
    }

    if (tb[PROB_VHT_CAPABILITIES]) {
        prob_req->vht_capabilities = true;
    } else
    {
        prob_req->vht_capabilities = false;
    }

    return 0;
}

int parse_to_beacon_rep(struct blob_attr *msg, probe_entry *beacon_rep) {
    struct blob_attr *tb[__BEACON_REP_MAX];

    blobmsg_parse(beacon_rep_policy, __BEACON_REP_MAX, tb, blob_data(msg), blob_len(msg));

    if(!tb[BEACON_REP_BSSID] || !tb[BEACON_REP_ADDR])
    {
        return -1;
    }

    if (hwaddr_aton(blobmsg_data(tb[BEACON_REP_BSSID]), beacon_rep->bssid_addr))
        return UBUS_STATUS_INVALID_ARGUMENT;

    ap check_null = {.bssid_addr = {0, 0, 0, 0, 0, 0}};
    if(mac_is_equal(check_null.bssid_addr,beacon_rep->bssid_addr))
    {
        fprintf(stderr, "Received NULL MAC! Client is strange!\n");
        return -1;
    }

    ap ap_entry_rep = ap_array_get_ap(beacon_rep->bssid_addr);

    // no client from network!!
    if (!mac_is_equal(ap_entry_rep.bssid_addr, beacon_rep->bssid_addr)) {
        return -1; //TODO: Check this
    }

    if (hwaddr_aton(blobmsg_data(tb[BEACON_REP_ADDR]), beacon_rep->client_addr))
        return UBUS_STATUS_INVALID_ARGUMENT;

    int rcpi = 0;
    int rsni = 0;
    rcpi = blobmsg_get_u16(tb[BEACON_REP_RCPI]);
    rsni = blobmsg_get_u16(tb[BEACON_REP_RSNI]);


    // HACKY WORKAROUND!
    printf("Try update RCPI and RSNI for beacon report!\n");
    if(!probe_array_update_rcpi_rsni(beacon_rep->bssid_addr, beacon_rep->client_addr, rcpi, rsni, true))
    {
        printf("Beacon: No Probe Entry Existing!\n");
        beacon_rep->counter = dawn_metric.min_probe_count;
        hwaddr_aton(blobmsg_data(tb[PROB_BSSID_ADDR]), beacon_rep->target_addr);
        beacon_rep->signal = 0;
        beacon_rep->freq = ap_entry_rep.freq;
        beacon_rep->rcpi = rcpi;
        beacon_rep->rsni = rsni;

        beacon_rep->ht_capabilities = false; // that is very problematic!!!
        beacon_rep->vht_capabilities = false; // that is very problematic!!!
        printf("Inserting to array!\n");
        insert_to_array(*beacon_rep, false, false, true);
        ubus_send_probe_via_network(*beacon_rep);
    }
    return 0;
}

static int handle_auth_req(struct blob_attr *msg) {

    print_probe_array();
    auth_entry auth_req;
    parse_to_auth_req(msg, &auth_req);

    printf("Auth entry: ");
    print_auth_entry(auth_req);

    if (mac_in_maclist(auth_req.client_addr)) {
        return WLAN_STATUS_SUCCESS;
    }

    probe_entry tmp = probe_array_get_entry(auth_req.bssid_addr, auth_req.client_addr);

    printf("Entry found\n");
    print_probe_entry(tmp);

    // block if entry was not already found in probe database
    if (!(mac_is_equal(tmp.bssid_addr, auth_req.bssid_addr) && mac_is_equal(tmp.client_addr, auth_req.client_addr))) {
        printf("Deny authentication!\n");

        if (dawn_metric.use_driver_recog) {
            insert_to_denied_req_array(auth_req, 1);
        }
        return dawn_metric.deny_auth_reason;
    }

    if (!decide_function(&tmp, REQ_TYPE_AUTH)) {
        printf("Deny authentication\n");
        if (dawn_metric.use_driver_recog) {
            insert_to_denied_req_array(auth_req, 1);
        }
        return dawn_metric.deny_auth_reason;
    }

    // maybe send here that the client is connected?
    printf("Allow authentication!\n");
    return WLAN_STATUS_SUCCESS;
}

static int handle_assoc_req(struct blob_attr *msg) {

    print_probe_array();
    auth_entry auth_req;
    parse_to_assoc_req(msg, &auth_req);
    printf("Association entry: ");
    print_auth_entry(auth_req);

    if (mac_in_maclist(auth_req.client_addr)) {
        return WLAN_STATUS_SUCCESS;
    }

    probe_entry tmp = probe_array_get_entry(auth_req.bssid_addr, auth_req.client_addr);

    printf("Entry found\n");
    print_probe_entry(tmp);

    // block if entry was not already found in probe database
    if (!(mac_is_equal(tmp.bssid_addr, auth_req.bssid_addr) && mac_is_equal(tmp.client_addr, auth_req.client_addr))) {
        printf("Deny associtation!\n");
        if (dawn_metric.use_driver_recog) {
            insert_to_denied_req_array(auth_req, 1);
        }
        return dawn_metric.deny_assoc_reason;
    }

    if (!decide_function(&tmp, REQ_TYPE_ASSOC)) {
        printf("Deny association\n");
        if (dawn_metric.use_driver_recog) {
            insert_to_denied_req_array(auth_req, 1);
        }
        return dawn_metric.deny_assoc_reason;
    }

    printf("Allow association!\n");
    return WLAN_STATUS_SUCCESS;
}

static int handle_probe_req(struct blob_attr *msg) {
    probe_entry prob_req;
    probe_entry tmp_prob_req;

    if (parse_to_probe_req(msg, &prob_req) == 0) {
        tmp_prob_req = insert_to_array(prob_req, 1, true, false);
        ubus_send_probe_via_network(tmp_prob_req);
        //send_blob_attr_via_network(msg, "probe");
    }

    if (!decide_function(&tmp_prob_req, REQ_TYPE_PROBE)) {
        return WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA; // no reason needed...
    }
    return WLAN_STATUS_SUCCESS;
}

static int handle_beacon_rep(struct blob_attr *msg) {
    probe_entry beacon_rep;

    if (parse_to_beacon_rep(msg, &beacon_rep) == 0) {
        printf("Inserting beacon Report!\n");
        // insert_to_array(beacon_rep, 1);
        printf("Sending via network!\n");
        // send_blob_attr_via_network(msg, "beacon-report");
    }
    return 0;
}

static int handle_deauth_req(struct blob_attr *msg) {

    hostapd_notify_entry notify_req;
    parse_to_hostapd_notify(msg, &notify_req);

    client client_entry;
    memcpy(client_entry.bssid_addr, notify_req.bssid_addr, sizeof(uint8_t) * ETH_ALEN);
    memcpy(client_entry.client_addr, notify_req.client_addr, sizeof(uint8_t) * ETH_ALEN);

    pthread_mutex_lock(&client_array_mutex);
    client_array_delete(client_entry);
    pthread_mutex_unlock(&client_array_mutex);

    printf("[WC] Deauth: %s\n", "deauth");

    return 0;
}

static int handle_set_probe(struct blob_attr *msg) {

    hostapd_notify_entry notify_req;
    parse_to_hostapd_notify(msg, &notify_req);

    client client_entry;
    memcpy(client_entry.bssid_addr, notify_req.bssid_addr, sizeof(uint8_t) * ETH_ALEN);
    memcpy(client_entry.client_addr, notify_req.client_addr, sizeof(uint8_t) * ETH_ALEN);

    probe_array_set_all_probe_count(client_entry.client_addr, dawn_metric.min_probe_count);

    return 0;
}

int handle_network_msg(char *msg) {
    struct blob_attr *tb[__NETWORK_MAX];
    char *method;
    char *data;

    blob_buf_init(&network_buf, 0);
    blobmsg_add_json_from_string(&network_buf, msg);

    blobmsg_parse(network_policy, __NETWORK_MAX, tb, blob_data(network_buf.head), blob_len(network_buf.head));

    if (!tb[NETWORK_METHOD] || !tb[NETWORK_DATA]) {
        return -1;
    }

    method = blobmsg_data(tb[NETWORK_METHOD]);
    data = blobmsg_data(tb[NETWORK_DATA]);

    printf("Network Method new: %s : %s\n", method, msg);

    blob_buf_init(&data_buf, 0);
    blobmsg_add_json_from_string(&data_buf, data);

    if (!data_buf.head) {
        return -1;
    }

    if (blob_len(data_buf.head) <= 0) {
        return -1;
    }

    if (strlen(method) < 2) {
        return -1;
    }

    // add inactive death...

// TODO: strncmp() look wrong - should all tests be for n = 5 characters? Shorthand checks?
    if (strncmp(method, "probe", 5) == 0) {
        probe_entry entry;
        if (parse_to_probe_req(data_buf.head, &entry) == 0) {
            insert_to_array(entry, 0, false, false); // use 802.11k values
        }
    } else if (strncmp(method, "clients", 5) == 0) {
        parse_to_clients(data_buf.head, 0, 0);
    } else if (strncmp(method, "deauth", 5) == 0) {
        printf("METHOD DEAUTH\n");
        handle_deauth_req(data_buf.head);
    } else if (strncmp(method, "setprobe", 5) == 0) {
        printf("HANDLING SET PROBE!\n");
        handle_set_probe(data_buf.head);
    } else if (strncmp(method, "addmac", 5) == 0) {
        parse_add_mac_to_file(data_buf.head);
    } else if (strncmp(method, "macfile", 5) == 0) {
        parse_add_mac_to_file(data_buf.head);
    } else if (strncmp(method, "uci", 2) == 0) {
        printf("HANDLING UCI!\n");
        handle_uci_config(data_buf.head);
    } else if (strncmp(method, "beacon-report", 12) == 0) {
        // TODO: Check beacon report stuff

        //printf("HANDLING BEACON REPORT NETWORK!\n");
        //printf("The Method for beacon-report is: %s\n", method);
        // ignore beacon reports send via network!, use probe functions for it
        //probe_entry entry; // for now just stay at probe entry stuff...
        //parse_to_beacon_rep(data_buf.head, &entry, true);
    } else
    {
        printf("No method fonud for: %s\n", method);
    }

    return 0;
}


int send_blob_attr_via_network(struct blob_attr *msg, char *method) {

    if (!msg) {
        return -1;
    }

    char *data_str;
    char *str;
    data_str = blobmsg_format_json(msg, true);
    blob_buf_init(&b_send_network, 0);
    blobmsg_add_string(&b_send_network, "method", method);
    blobmsg_add_string(&b_send_network, "data", data_str);

    str = blobmsg_format_json(b_send_network.head, true);

    if (network_config.network_option == 2) {
        send_tcp(str);
    } else {
        if (network_config.use_symm_enc) {
            send_string_enc(str);
        } else {
            send_string(str);
        }
    }

    free(data_str);
    free(str);

    return 0;
}

static int hostapd_notify(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg) {
    char *str;
    str = blobmsg_format_json(msg, true);
    printf("Method new: %s : %s\n", method, str);
    free(str);

    struct hostapd_sock_entry *entry;
    struct ubus_subscriber *subscriber;

    subscriber = container_of(obj, struct ubus_subscriber, obj);
    entry = container_of(subscriber, struct hostapd_sock_entry, subscriber);

    struct blob_attr *cur; int rem;
    blob_buf_init(&b_notify, 0);
    blobmsg_for_each_attr(cur, msg, rem){
        blobmsg_add_blob(&b_notify, cur);
    }

    blobmsg_add_macaddr(&b_notify, "bssid", entry->bssid_addr);
    blobmsg_add_string(&b_notify, "ssid", entry->ssid);

    if (strncmp(method, "probe", 5) == 0) {
        return handle_probe_req(b_notify.head);
    } else if (strncmp(method, "auth", 4) == 0) {
        return handle_auth_req(b_notify.head);
    } else if (strncmp(method, "assoc", 5) == 0) {
        return handle_assoc_req(b_notify.head);
    } else if (strncmp(method, "deauth", 6) == 0) {
        send_blob_attr_via_network(b_notify.head, "deauth");
        return handle_deauth_req(b_notify.head);
    } else if (strncmp(method, "beacon-report", 12) == 0) {
        return handle_beacon_rep(b_notify.head);
    }
    return 0;
}

int dawn_init_ubus(const char *ubus_socket, const char *hostapd_dir) {
    uloop_init();
    signal(SIGPIPE, SIG_IGN);

    ctx = ubus_connect(ubus_socket);
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return -1;
    } else {
        printf("Connected to ubus\n");
    }

    ubus_add_uloop(ctx);

    // set dawn metric
    dawn_metric = uci_get_dawn_metric();

    uloop_timeout_add(&hostapd_timer);

    // remove probe
    uloop_add_data_cbs();

    // get clients
    uloop_timeout_add(&client_timer);

    uloop_timeout_add(&channel_utilization_timer);

    // request beacon reports
    if(timeout_config.update_beacon_reports) // allow setting timeout to 0
        uloop_timeout_add(&beacon_reports_timer);

    ubus_add_oject();

    if (network_config.network_option == 2)
    {
        start_umdns_update();
        if(run_server(network_config.tcp_port))
            uloop_timeout_set(&usock_timer, 1 * 1000);
    }

    subscribe_to_new_interfaces(hostapd_dir_glob);

    uloop_run();

    close_socket();

    ubus_free(ctx);
    uloop_done();
    return 0;
}

// TOOD: Refactor this!
static void
dump_client(struct blob_attr **tb, uint8_t client_addr[], const char *bssid_addr, uint32_t freq, uint8_t ht_supported,
            uint8_t vht_supported) {
    client client_entry;

    hwaddr_aton(bssid_addr, client_entry.bssid_addr);
    memcpy(client_entry.client_addr, client_addr, ETH_ALEN * sizeof(uint8_t));
    client_entry.freq = freq;
    client_entry.ht_supported = ht_supported;
    client_entry.vht_supported = vht_supported;

    if (tb[CLIENT_AUTH]) {
        client_entry.auth = blobmsg_get_u8(tb[CLIENT_AUTH]);
    }
    if (tb[CLIENT_ASSOC]) {
        client_entry.assoc = blobmsg_get_u8(tb[CLIENT_ASSOC]);
    }
    if (tb[CLIENT_AUTHORIZED]) {
        client_entry.authorized = blobmsg_get_u8(tb[CLIENT_AUTHORIZED]);
    }
    if (tb[CLIENT_PREAUTH]) {
        client_entry.preauth = blobmsg_get_u8(tb[CLIENT_PREAUTH]);
    }
    if (tb[CLIENT_WDS]) {
        client_entry.wds = blobmsg_get_u8(tb[CLIENT_WDS]);
    }
    if (tb[CLIENT_WMM]) {
        client_entry.wmm = blobmsg_get_u8(tb[CLIENT_WMM]);
    }
    if (tb[CLIENT_HT]) {
        client_entry.ht = blobmsg_get_u8(tb[CLIENT_HT]);
    }
    if (tb[CLIENT_VHT]) {
        client_entry.vht = blobmsg_get_u8(tb[CLIENT_VHT]);
    }
    if (tb[CLIENT_WPS]) {
        client_entry.wps = blobmsg_get_u8(tb[CLIENT_WPS]);
    }
    if (tb[CLIENT_MFP]) {
        client_entry.mfp = blobmsg_get_u8(tb[CLIENT_MFP]);
    }
    if (tb[CLIENT_AID]) {
        client_entry.aid = blobmsg_get_u32(tb[CLIENT_AID]);
    }
        /* RRM Caps */
    if (tb[CLIENT_TABLE_RRM]) {
        //ap_entry.ap_weight = blobmsg_get_u32(tb[CLIENT_TABLE_RRM]);
    } else {
        //ap_entry.ap_weight = 0;
    }

    // copy signature
    if (tb[CLIENT_SIGNATURE]) {
        memcpy(client_entry.signature, blobmsg_data(tb[CLIENT_SIGNATURE]), SIGNATURE_LEN * sizeof(char));
    } else
    {
        memset(client_entry.signature, 0, 1024);
    }    

    insert_client_to_array(client_entry);
}

static int
dump_client_table(struct blob_attr *head, int len, const char *bssid_addr, uint32_t freq, uint8_t ht_supported,
                  uint8_t vht_supported) {
    struct blob_attr *attr;
    struct blobmsg_hdr *hdr;
    int station_count = 0;

    __blob_for_each_attr(attr, head, len)
    {
        hdr = blob_data(attr);

        struct blob_attr *tb[__CLIENT_MAX];
        blobmsg_parse(client_policy, __CLIENT_MAX, tb, blobmsg_data(attr), blobmsg_len(attr));
        //char* str = blobmsg_format_json_indent(attr, true, -1);

        int tmp_int_mac[ETH_ALEN];
        uint8_t tmp_mac[ETH_ALEN];
        sscanf((char *) hdr->name, MACSTR, STR2MAC(tmp_int_mac));
        for (int i = 0; i < ETH_ALEN; ++i)
            tmp_mac[i] = (uint8_t) tmp_int_mac[i];

        dump_client(tb, tmp_mac, bssid_addr, freq, ht_supported, vht_supported);
        station_count++;
    }
    return station_count;
}

int parse_to_clients(struct blob_attr *msg, int do_kick, uint32_t id) {
    struct blob_attr *tb[__CLIENT_TABLE_MAX];

    if (!msg) {
        return -1;
    }

    if (!blob_data(msg)) {
        return -1;
    }

    if (blob_len(msg) <= 0) {
        return -1;
    }

    blobmsg_parse(client_table_policy, __CLIENT_TABLE_MAX, tb, blob_data(msg), blob_len(msg));

    if (tb[CLIENT_TABLE] && tb[CLIENT_TABLE_BSSID] && tb[CLIENT_TABLE_FREQ]) {
        int num_stations = 0;
         num_stations = dump_client_table(blobmsg_data(tb[CLIENT_TABLE]), blobmsg_data_len(tb[CLIENT_TABLE]),
                          blobmsg_data(tb[CLIENT_TABLE_BSSID]), blobmsg_get_u32(tb[CLIENT_TABLE_FREQ]),
                          blobmsg_get_u8(tb[CLIENT_TABLE_HT]), blobmsg_get_u8(tb[CLIENT_TABLE_VHT]));
        ap ap_entry;
        hwaddr_aton(blobmsg_data(tb[CLIENT_TABLE_BSSID]), ap_entry.bssid_addr);
        ap_entry.freq = blobmsg_get_u32(tb[CLIENT_TABLE_FREQ]);

        if(tb[CLIENT_TABLE_HT]){
            ap_entry.ht_support = blobmsg_get_u8(tb[CLIENT_TABLE_HT]);
        } else {
            ap_entry.ht_support = false;
        }

        if(tb[CLIENT_TABLE_VHT]){
            ap_entry.vht_support = blobmsg_get_u8(tb[CLIENT_TABLE_VHT]);
        } else
        {
            ap_entry.vht_support = false;
        }

        if(tb[CLIENT_TABLE_CHAN_UTIL]) {
            ap_entry.channel_utilization = blobmsg_get_u32(tb[CLIENT_TABLE_CHAN_UTIL]);
        } else // if this is not existing set to 0?
        {
            ap_entry.channel_utilization = 0;
        }

        if(tb[CLIENT_TABLE_SSID]) {
            strcpy((char *) ap_entry.ssid, blobmsg_get_string(tb[CLIENT_TABLE_SSID]));
        }

        if (tb[CLIENT_TABLE_COL_DOMAIN]) {
            ap_entry.collision_domain = blobmsg_get_u32(tb[CLIENT_TABLE_COL_DOMAIN]);
        } else {
            ap_entry.collision_domain = -1;
        }

        if (tb[CLIENT_TABLE_BANDWIDTH]) {
            ap_entry.bandwidth = blobmsg_get_u32(tb[CLIENT_TABLE_BANDWIDTH]);
        } else {
            ap_entry.bandwidth = -1;
        }

        ap_entry.station_count = num_stations;

        if (tb[CLIENT_TABLE_WEIGHT]) {
            ap_entry.ap_weight = blobmsg_get_u32(tb[CLIENT_TABLE_WEIGHT]);
        } else {
            ap_entry.ap_weight = 0;
        }


        if (tb[CLIENT_TABLE_NEIGHBOR]) {
            strcpy(ap_entry.neighbor_report, blobmsg_get_string(tb[CLIENT_TABLE_NEIGHBOR]));
        }

        insert_to_ap_array(ap_entry);

        if (do_kick && dawn_metric.kicking) {
            kick_clients(ap_entry.bssid_addr, id);
        }
    }
    return 0;
}

static void ubus_get_clients_cb(struct ubus_request *req, int type, struct blob_attr *msg) {
    struct hostapd_sock_entry *sub, *entry = NULL;

    if (!msg)
        return;

    char *data_str = blobmsg_format_json(msg, 1);
    blob_buf_init(&b_domain, 0);
    blobmsg_add_json_from_string(&b_domain, data_str);
    blobmsg_add_u32(&b_domain, "collision_domain", network_config.collision_domain);
    blobmsg_add_u32(&b_domain, "bandwidth", network_config.bandwidth);

    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->id == req->peer) {
            entry = sub;
        }
    }

    if (entry == NULL) {
        fprintf(stderr, "Failed to find interface!\n");
        return;
    }

    if (!entry->subscribed) {
        fprintf(stderr, "Interface %s is not subscribed!\n", entry->iface_name);
        return;
    }

    blobmsg_add_macaddr(&b_domain, "bssid", entry->bssid_addr);
    blobmsg_add_string(&b_domain, "ssid", entry->ssid);
    blobmsg_add_u8(&b_domain, "ht_supported", entry->ht_support);
    blobmsg_add_u8(&b_domain, "vht_supported", entry->vht_support);

    blobmsg_add_u32(&b_domain, "ap_weight", dawn_metric.ap_weight);

    //int channel_util = get_channel_utilization(entry->iface_name, &entry->last_channel_time, &entry->last_channel_time_busy);
    blobmsg_add_u32(&b_domain, "channel_utilization", entry->chan_util_average);

    blobmsg_add_string(&b_domain, "neighbor_report", entry->neighbor_report);

    send_blob_attr_via_network(b_domain.head, "clients");
    parse_to_clients(b_domain.head, 1, req->peer);

    print_client_array();
    print_ap_array();

    free(data_str);
}

static int ubus_get_clients() {
    int timeout = 1;
    struct hostapd_sock_entry *sub;
    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed) {
            blob_buf_init(&b_clients, 0);
            ubus_invoke(ctx, sub->id, "get_clients", b_clients.head, ubus_get_clients_cb, NULL, timeout * 1000);
        }
    }
    return 0;
}

static void ubus_get_rrm_cb(struct ubus_request *req, int type, struct blob_attr *msg) {
    struct hostapd_sock_entry *sub, *entry = NULL;
    struct blob_attr *tb[__RRM_MAX];

    if (!msg)
        return;

    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->id == req->peer) {
            entry = sub;
        }
    }

    blobmsg_parse(rrm_array_policy, __RRM_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[RRM_ARRAY]) {
        return;
    }
    struct blob_attr *attr;
    //struct blobmsg_hdr *hdr;
    int len = blobmsg_data_len(tb[RRM_ARRAY]);
    int i = 0;

     __blob_for_each_attr(attr, blobmsg_data(tb[RRM_ARRAY]), len)
     {
         if(i==2)
         {
            char* neighborreport = blobmsg_get_string(blobmsg_data(attr));
            strcpy(entry->neighbor_report,neighborreport);
            printf("Copied Neighborreport: %s,\n", entry->neighbor_report);
         }
         i++;
     }
}

static int ubus_get_rrm() {
    int timeout = 1;
    struct hostapd_sock_entry *sub;
    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed) {
            blob_buf_init(&b, 0);
            ubus_invoke(ctx, sub->id, "rrm_nr_get_own", b.head, ubus_get_rrm_cb, NULL, timeout * 1000);
        }
    }
    return 0;
}

void update_clients(struct uloop_timeout *t) {
    ubus_get_clients();
    if(dawn_metric.set_hostapd_nr)
        ubus_set_nr();
    // maybe to much?! don't set timer again...
    uloop_timeout_set(&client_timer, timeout_config.update_client * 1000);
}

void run_server_update(struct uloop_timeout *t) {
    if(run_server(network_config.tcp_port))
        uloop_timeout_set(&usock_timer, 1 * 1000);
}

void update_channel_utilization(struct uloop_timeout *t) {
    struct hostapd_sock_entry *sub;

    list_for_each_entry(sub, &hostapd_sock_list, list)
    {

        if (sub->subscribed) {
            sub->chan_util_samples_sum += get_channel_utilization(sub->iface_name, &sub->last_channel_time,
                                                                  &sub->last_channel_time_busy);
            sub->chan_util_num_sample_periods++;

            if (sub->chan_util_num_sample_periods > dawn_metric.chan_util_avg_period) {
                sub->chan_util_average = sub->chan_util_samples_sum / sub->chan_util_num_sample_periods;
                sub->chan_util_samples_sum = 0;
                sub->chan_util_num_sample_periods = 0;
            }
        }
    }
    uloop_timeout_set(&channel_utilization_timer, timeout_config.update_chan_util * 1000);
}

void ubus_send_beacon_report(uint8_t client[], int id)
{
    printf("Crafting Beacon Report\n");
    int timeout = 1;
    blob_buf_init(&b_beacon, 0);
    blobmsg_add_macaddr(&b_beacon, "addr", client);
    blobmsg_add_u32(&b_beacon, "op_class", dawn_metric.op_class);
    blobmsg_add_u32(&b_beacon, "channel", dawn_metric.scan_channel);
    blobmsg_add_u32(&b_beacon, "duration", dawn_metric.duration);
    blobmsg_add_u32(&b_beacon, "mode", dawn_metric.mode);
    printf("Adding string\n");
    blobmsg_add_string(&b_beacon, "ssid", "");

    printf("Invoking beacon report!\n");
    ubus_invoke(ctx, id, "rrm_beacon_req", b_beacon.head, NULL, NULL, timeout * 1000);
}

void update_beacon_reports(struct uloop_timeout *t) {
    if(!timeout_config.update_beacon_reports) // if 0 just return
    {
        return;
    }
    printf("Sending beacon report!\n");
    struct hostapd_sock_entry *sub;
    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed) {
            printf("Sending beacon report Sub!\n");
            send_beacon_reports(sub->bssid_addr, sub->id);
        }
    }
    uloop_timeout_set(&beacon_reports_timer, timeout_config.update_beacon_reports * 1000);
}

void update_tcp_connections(struct uloop_timeout *t) {
    ubus_call_umdns();
    uloop_timeout_set(&umdns_timer, timeout_config.update_tcp_con * 1000);
}

void start_umdns_update() {
    // update connections
    uloop_timeout_add(&umdns_timer);
}

void update_hostapd_sockets(struct uloop_timeout *t) {
    subscribe_to_new_interfaces(hostapd_dir_glob);
    uloop_timeout_set(&hostapd_timer, timeout_config.update_hostapd * 1000);
}

void ubus_set_nr(){
    struct hostapd_sock_entry *sub;


    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed) {
            int timeout = 1;
            blob_buf_init(&b_nr, 0);
            ap_get_nr(&b_nr, sub->bssid_addr);
            ubus_invoke(ctx, sub->id, "rrm_nr_set", b_nr.head, NULL, NULL, timeout * 1000);
        }
    }
}

void del_client_all_interfaces(const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time) {
    struct hostapd_sock_entry *sub;

    blob_buf_init(&b, 0);
    blobmsg_add_macaddr(&b, "addr", client_addr);
    blobmsg_add_u32(&b, "reason", reason);
    blobmsg_add_u8(&b, "deauth", deauth);
    blobmsg_add_u32(&b, "ban_time", ban_time);

    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed) {
            int timeout = 1;
            ubus_invoke(ctx, sub->id, "del_client", b.head, NULL, NULL, timeout * 1000);
        }
    }
}

void del_client_interface(uint32_t id, const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time) {
    struct hostapd_sock_entry *sub;

    blob_buf_init(&b, 0);
    blobmsg_add_macaddr(&b, "addr", client_addr);
    blobmsg_add_u32(&b, "reason", reason);
    blobmsg_add_u8(&b, "deauth", deauth);
    blobmsg_add_u32(&b, "ban_time", ban_time);


    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed) {
            int timeout = 1;
            ubus_invoke(ctx, id, "del_client", b.head, NULL, NULL, timeout * 1000);
        }
    }

}

void wnm_disassoc_imminent(uint32_t id, const uint8_t *client_addr, char* dest_ap, uint32_t duration) {
    struct hostapd_sock_entry *sub;

    blob_buf_init(&b, 0);
    blobmsg_add_macaddr(&b, "addr", client_addr);
    blobmsg_add_u32(&b, "duration", duration);
    blobmsg_add_u8(&b, "abridged", 1); // prefer aps in neighborlist

    // ToDo: maybe exchange to a list of aps
    void* nbs = blobmsg_open_array(&b, "neighbors");
    if(dest_ap!=NULL)
    {
        blobmsg_add_string(&b, NULL, dest_ap);
        printf("BSS TRANSITION TO %s\n", dest_ap);
    }

    blobmsg_close_array(&b, nbs);
    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed) {
            int timeout = 1; //TDO: Maybe ID is wrong?! OR CHECK HERE ID
            ubus_invoke(ctx, id, "wnm_disassoc_imminent", b.head, NULL, NULL, timeout * 1000);
        }
    }
}

static void ubus_umdns_cb(struct ubus_request *req, int type, struct blob_attr *msg) {
    struct blob_attr *tb[__DAWN_UMDNS_TABLE_MAX];

    if (!msg)
        return;

    blobmsg_parse(dawn_umdns_table_policy, __DAWN_UMDNS_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[DAWN_UMDNS_TABLE]) {
        return;
    }

    struct blob_attr *attr;
    struct blobmsg_hdr *hdr;
    int len = blobmsg_data_len(tb[DAWN_UMDNS_TABLE]);

    __blob_for_each_attr(attr, blobmsg_data(tb[DAWN_UMDNS_TABLE]), len)
    {
        hdr = blob_data(attr);

        struct blob_attr *tb_dawn[__DAWN_UMDNS_MAX];
        blobmsg_parse(dawn_umdns_policy, __DAWN_UMDNS_MAX, tb_dawn, blobmsg_data(attr), blobmsg_len(attr));

        printf("Hostname: %s\n", hdr->name);
        if (tb_dawn[DAWN_UMDNS_IPV4] && tb_dawn[DAWN_UMDNS_PORT]) {
            printf("IPV4: %s\n", blobmsg_get_string(tb_dawn[DAWN_UMDNS_IPV4]));
            printf("Port: %d\n", blobmsg_get_u32(tb_dawn[DAWN_UMDNS_PORT]));
        } else {
            return;
        }
        add_tcp_conncection(blobmsg_get_string(tb_dawn[DAWN_UMDNS_IPV4]), blobmsg_get_u32(tb_dawn[DAWN_UMDNS_PORT]));
    }
}

int ubus_call_umdns() {
    u_int32_t id;
    if (ubus_lookup_id(ctx, "umdns", &id)) {
        fprintf(stderr, "Failed to look up test object for %s\n", "umdns");
        return -1;
    }

    int timeout = 1;
    blob_buf_init(&b_umdns, 0);
    ubus_invoke(ctx, id, "update", b_umdns.head, NULL, NULL, timeout * 1000);
    ubus_invoke(ctx, id, "browse", b_umdns.head, ubus_umdns_cb, NULL, timeout * 1000);

    return 0;
}

//TODO: ADD STUFF HERE!!!!
int ubus_send_probe_via_network(struct probe_entry_s probe_entry) {
    blob_buf_init(&b_probe, 0);
    blobmsg_add_macaddr(&b_probe, "bssid", probe_entry.bssid_addr);
    blobmsg_add_macaddr(&b_probe, "address", probe_entry.client_addr);
    blobmsg_add_macaddr(&b_probe, "target", probe_entry.target_addr);
    blobmsg_add_u32(&b_probe, "signal", probe_entry.signal);
    blobmsg_add_u32(&b_probe, "freq", probe_entry.freq);

    blobmsg_add_u32(&b_probe, "rcpi", probe_entry.rcpi);
    blobmsg_add_u32(&b_probe, "rsni", probe_entry.rsni);

    if(probe_entry.ht_capabilities)
    {
        void *ht_cap = blobmsg_open_table(&b, "ht_capabilities");
        blobmsg_close_table(&b, ht_cap);
    }

    if(probe_entry.vht_capabilities) {
        void *vht_cap = blobmsg_open_table(&b, "vht_capabilities");
        blobmsg_close_table(&b, vht_cap);
    }

    send_blob_attr_via_network(b_probe.head, "probe");

    return 0;
}

int send_set_probe(uint8_t client_addr[]) {
    blob_buf_init(&b_probe, 0);
    blobmsg_add_macaddr(&b_probe, "bssid", client_addr);
    blobmsg_add_macaddr(&b_probe, "address", client_addr);

    send_blob_attr_via_network(b_probe.head, "setprobe");

    return 0;
}

enum {
    MAC_ADDR,
    __ADD_DEL_MAC_MAX
};

static const struct blobmsg_policy add_del_policy[__ADD_DEL_MAC_MAX] = {
        [MAC_ADDR] = {"addrs", BLOBMSG_TYPE_ARRAY},
};

static const struct ubus_method dawn_methods[] = {
        UBUS_METHOD("add_mac", add_mac, add_del_policy),
        UBUS_METHOD_NOARG("get_hearing_map", get_hearing_map),
        UBUS_METHOD_NOARG("get_network", get_network),
        UBUS_METHOD_NOARG("reload_config", reload_config)
};

static struct ubus_object_type dawn_object_type =
        UBUS_OBJECT_TYPE("dawn", dawn_methods);

static struct ubus_object dawn_object = {
        .name = "dawn",
        .type = &dawn_object_type,
        .methods = dawn_methods,
        .n_methods = ARRAY_SIZE(dawn_methods),
};

static int parse_add_mac_to_file(struct blob_attr *msg) {
    struct blob_attr *tb[__ADD_DEL_MAC_MAX];
    struct blob_attr *attr;
    
    printf("Parsing MAC!\n");

    blobmsg_parse(add_del_policy, __ADD_DEL_MAC_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[MAC_ADDR])
        return UBUS_STATUS_INVALID_ARGUMENT;

    int len = blobmsg_data_len(tb[MAC_ADDR]);
    printf("Length of array maclist: %d\n", len);

    __blob_for_each_attr(attr, blobmsg_data(tb[MAC_ADDR]), len)
    {
        printf("Iteration through MAC-list\n");
        uint8_t addr[ETH_ALEN];
        hwaddr_aton(blobmsg_data(attr), addr);

        if (insert_to_maclist(addr) == 0) {
// TODO: File can grow arbitarily large.  Resource consumption risk.
// TODO: Consolidate use of file across source: shared resource for name, single point of access?
            write_mac_to_file("/tmp/dawn_mac_list", addr);
        }
    }

    return 0;
}

static int add_mac(struct ubus_context *ctx, struct ubus_object *obj,
                   struct ubus_request_data *req, const char *method,
                   struct blob_attr *msg) {
    parse_add_mac_to_file(msg);

    // here we need to send it via the network!
    send_blob_attr_via_network(msg, "addmac");

    return 0;
}

int send_add_mac(uint8_t *client_addr) {
    blob_buf_init(&b, 0);
    blobmsg_add_macaddr(&b, "addr", client_addr);
    send_blob_attr_via_network(b.head, "addmac");
    return 0;
}

static int reload_config(struct ubus_context *ctx, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg) {
    int ret;
    blob_buf_init(&b, 0);
    uci_reset();
    dawn_metric = uci_get_dawn_metric();
    timeout_config = uci_get_time_config();
    hostapd_dir_glob = uci_get_dawn_hostapd_dir();
    sort_string = (char *) uci_get_dawn_sort_order();

    if(timeout_config.update_beacon_reports) // allow setting timeout to 0
        uloop_timeout_add(&beacon_reports_timer);

    uci_send_via_network();
    ret = ubus_send_reply(ctx, req, b.head);
    if (ret)
        fprintf(stderr, "Failed to send reply: %s\n", ubus_strerror(ret));
    return 0;
}

static int get_hearing_map(struct ubus_context *ctx, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg) {
    int ret;

    build_hearing_map_sort_client(&b);
    ret = ubus_send_reply(ctx, req, b.head);
    if (ret)
        fprintf(stderr, "Failed to send reply: %s\n", ubus_strerror(ret));
    return 0;
}


static int get_network(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg) {
    int ret;

    build_network_overview(&b);
    ret = ubus_send_reply(ctx, req, b.head);
    if (ret)
        fprintf(stderr, "Failed to send reply: %s\n", ubus_strerror(ret));
    return 0;
}

static void ubus_add_oject() {
    int ret;

    ret = ubus_add_object(ctx, &dawn_object);
    if (ret)
        fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
}

static void respond_to_notify(uint32_t id) {
    // This is needed to respond to the ubus notify ...
    // Maybe we need to disable on shutdown...
    // But it is not possible when we disable the notify that other daemons are running that relay on this notify...
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "notify_response", 1);

    int timeout = 1;
    ret = ubus_invoke(ctx, id, "notify_response", b.head, NULL, NULL, timeout * 1000);
    if (ret)
        fprintf(stderr, "Failed to invoke: %s\n", ubus_strerror(ret));
}

static void enable_rrm(uint32_t id) {
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_u8(&b, "neighbor_report", 1);
    blobmsg_add_u8(&b, "beacon_report", 1);
    blobmsg_add_u8(&b, "bss_transition", 1);    

    int timeout = 1;
    ret = ubus_invoke(ctx, id, "bss_mgmt_enable", b.head, NULL, NULL, timeout * 1000);
    if (ret)
        fprintf(stderr, "Failed to invoke: %s\n", ubus_strerror(ret));
}

static void hostapd_handle_remove(struct ubus_context *ctx,
                                  struct ubus_subscriber *s, uint32_t id) {
    fprintf(stdout, "Object %08x went away\n", id);
    struct hostapd_sock_entry *hostapd_sock = container_of(s,
    struct hostapd_sock_entry, subscriber);

    if (hostapd_sock->id != id) {
        printf("ID is not the same!\n");
        return;
    }
    
    hostapd_sock->subscribed = false;
    subscription_wait(&hostapd_sock->wait_handler);

}

bool subscribe(struct hostapd_sock_entry *hostapd_entry) {
    char subscribe_name[sizeof("hostapd.") + MAX_INTERFACE_NAME + 1];

    if (hostapd_entry->subscribed)
        return false;

    sprintf(subscribe_name, "hostapd.%s", hostapd_entry->iface_name);

    if (ubus_lookup_id(ctx, subscribe_name, &hostapd_entry->id)) {
        fprintf(stdout, "Failed to lookup ID!");
        subscription_wait(&hostapd_entry->wait_handler);
        return false;
    }

    if (ubus_subscribe(ctx, &hostapd_entry->subscriber, hostapd_entry->id)) {
        fprintf(stdout, "Failed to register subscriber!");
        subscription_wait(&hostapd_entry->wait_handler);
        return false;
    }

    hostapd_entry->subscribed = true;

    get_bssid(hostapd_entry->iface_name, hostapd_entry->bssid_addr);
    get_ssid(hostapd_entry->iface_name, hostapd_entry->ssid);

    hostapd_entry->ht_support = (uint8_t) support_ht(hostapd_entry->iface_name);
    hostapd_entry->vht_support = (uint8_t) support_vht(hostapd_entry->iface_name);

    respond_to_notify(hostapd_entry->id);
    enable_rrm(hostapd_entry->id);
    ubus_get_rrm();

    printf("Subscribed to: %s\n", hostapd_entry->iface_name);

    return true;
}

static void
wait_cb(struct ubus_context *ctx, struct ubus_event_handler *ev_handler,
        const char *type, struct blob_attr *msg) {
    static const struct blobmsg_policy wait_policy = {
            "path", BLOBMSG_TYPE_STRING
    };

    struct blob_attr *attr;
    const char *path;
    struct hostapd_sock_entry *sub = container_of(ev_handler,
    struct hostapd_sock_entry, wait_handler);

    if (strcmp(type, "ubus.object.add"))
        return;

    blobmsg_parse(&wait_policy, 1, &attr, blob_data(msg), blob_len(msg));
    if (!attr)
        return;

    path = blobmsg_data(attr);

    path = strchr(path, '.');
    if (!path)
        return;

    if (strcmp(sub->iface_name, path + 1))
        return;

    subscribe(sub);
}

bool subscriber_to_interface(const char *ifname) {

    struct hostapd_sock_entry *hostapd_entry;

    hostapd_entry = calloc(1, sizeof(struct hostapd_sock_entry));
    strcpy(hostapd_entry->iface_name, ifname);
    hostapd_entry->subscriber.cb = hostapd_notify;
    hostapd_entry->subscriber.remove_cb = hostapd_handle_remove;
    hostapd_entry->wait_handler.cb = wait_cb;

    hostapd_entry->subscribed = false;

    if (ubus_register_subscriber(ctx, &hostapd_entry->subscriber)) {
        fprintf(stderr, "Failed to register subscriber!");
        return false;
    }

    list_add(&hostapd_entry->list, &hostapd_sock_list);

    return subscribe(hostapd_entry);
}

void subscribe_to_new_interfaces(const char *hostapd_sock_path) {
    DIR *dirp;
    struct dirent *entry;
    struct hostapd_sock_entry *sub = NULL;

    if (ctx == NULL) {
        return;
    }

    dirp = opendir(hostapd_sock_path);  // error handling?
    if (!dirp) {
        fprintf(stderr, "[SUBSCRIBING] No hostapd sockets!\n");
        return;
    }
    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            bool do_subscribe = true;
            if (strcmp(entry->d_name, "global") == 0)
                continue;
            list_for_each_entry(sub, &hostapd_sock_list, list)
            {
                if (strncmp(sub->iface_name, entry->d_name, MAX_INTERFACE_NAME) == 0) {
                    do_subscribe = false;
                    break;
                }
            }
            if (do_subscribe) {
                subscriber_to_interface(entry->d_name);
            }

        }
    }
    closedir(dirp);
    return;
}

int uci_send_via_network()
{
    void *metric, *times;

    blob_buf_init(&b, 0);
    metric = blobmsg_open_table(&b, "metric");
    blobmsg_add_u32(&b, "ht_support", dawn_metric.ht_support);
    blobmsg_add_u32(&b, "vht_support", dawn_metric.vht_support);
    blobmsg_add_u32(&b, "no_ht_support", dawn_metric.no_ht_support);
    blobmsg_add_u32(&b, "no_vht_support", dawn_metric.no_vht_support);
    blobmsg_add_u32(&b, "rssi", dawn_metric.rssi);
    blobmsg_add_u32(&b, "low_rssi", dawn_metric.low_rssi);
    blobmsg_add_u32(&b, "freq", dawn_metric.freq);
    blobmsg_add_u32(&b, "chan_util", dawn_metric.chan_util);


    blobmsg_add_u32(&b, "max_chan_util", dawn_metric.max_chan_util);
    blobmsg_add_u32(&b, "rssi_val", dawn_metric.rssi_val);
    blobmsg_add_u32(&b, "low_rssi_val", dawn_metric.low_rssi_val);
    blobmsg_add_u32(&b, "chan_util_val", dawn_metric.chan_util_val);
    blobmsg_add_u32(&b, "max_chan_util_val", dawn_metric.max_chan_util_val);
    blobmsg_add_u32(&b, "min_probe_count", dawn_metric.min_probe_count);
    blobmsg_add_u32(&b, "bandwidth_threshold", dawn_metric.bandwidth_threshold);
    blobmsg_add_u32(&b, "use_station_count", dawn_metric.use_station_count);
    blobmsg_add_u32(&b, "max_station_diff", dawn_metric.max_station_diff);
    blobmsg_add_u32(&b, "eval_probe_req", dawn_metric.eval_probe_req);
    blobmsg_add_u32(&b, "eval_auth_req", dawn_metric.eval_auth_req);
    blobmsg_add_u32(&b, "eval_assoc_req", dawn_metric.eval_assoc_req);
    blobmsg_add_u32(&b, "kicking", dawn_metric.kicking);
    blobmsg_add_u32(&b, "deny_auth_reason", dawn_metric.deny_auth_reason);
    blobmsg_add_u32(&b, "deny_assoc_reason", dawn_metric.deny_assoc_reason);
    blobmsg_add_u32(&b, "use_driver_recog", dawn_metric.use_driver_recog);
    blobmsg_add_u32(&b, "min_number_to_kick", dawn_metric.min_kick_count);
    blobmsg_add_u32(&b, "chan_util_avg_period", dawn_metric.chan_util_avg_period);
    blobmsg_add_u32(&b, "set_hostapd_nr", dawn_metric.set_hostapd_nr);
    blobmsg_add_u32(&b, "op_class", dawn_metric.op_class);
    blobmsg_add_u32(&b, "duration", dawn_metric.duration);
    blobmsg_add_u32(&b, "mode", dawn_metric.mode);
    blobmsg_add_u32(&b, "scan_channel", dawn_metric.scan_channel);
    blobmsg_close_table(&b, metric);

    times = blobmsg_open_table(&b, "times");
    blobmsg_add_u32(&b, "update_client", timeout_config.update_client);
    blobmsg_add_u32(&b, "denied_req_threshold", timeout_config.denied_req_threshold);
    blobmsg_add_u32(&b, "remove_client", timeout_config.remove_client);
    blobmsg_add_u32(&b, "remove_probe", timeout_config.remove_probe);
    blobmsg_add_u32(&b, "remove_ap", timeout_config.remove_ap);
    blobmsg_add_u32(&b, "update_hostapd", timeout_config.update_hostapd);
    blobmsg_add_u32(&b, "update_tcp_con", timeout_config.update_tcp_con);
    blobmsg_add_u32(&b, "update_chan_util", timeout_config.update_chan_util);
    blobmsg_add_u32(&b, "update_beacon_reports", timeout_config.update_beacon_reports);
    blobmsg_close_table(&b, times);

    send_blob_attr_via_network(b.head, "uci");

    return 0;
}
enum {
    UCI_TABLE_METRIC,
    UCI_TABLE_TIMES,
    __UCI_TABLE_MAX
};

enum {
    UCI_HT_SUPPORT,
    UCI_VHT_SUPPORT,
    UCI_NO_HT_SUPPORT,
    UCI_NO_VHT_SUPPORT,
    UCI_RSSI,
    UCI_LOW_RSSI,
    UCI_FREQ,
    UCI_CHAN_UTIL,
    UCI_MAX_CHAN_UTIL,
    UCI_RSSI_VAL,
    UCI_LOW_RSSI_VAL,
    UCI_CHAN_UTIL_VAL,
    UCI_MAX_CHAN_UTIL_VAL,
    UCI_MIN_PROBE_COUNT,
    UCI_BANDWIDTH_THRESHOLD,
    UCI_USE_STATION_COUNT,
    UCI_MAX_STATION_DIFF,
    UCI_EVAL_PROBE_REQ,
    UCI_EVAL_AUTH_REQ,
    UCI_EVAL_ASSOC_REQ,
    UCI_KICKING,
    UCI_DENY_AUTH_REASON,
    UCI_DENY_ASSOC_REASON,
    UCI_USE_DRIVER_RECOG,
    UCI_MIN_NUMBER_TO_KICK,
    UCI_CHAN_UTIL_AVG_PERIOD,
    UCI_SET_HOSTAPD_NR,
    UCI_OP_CLASS,
    UCI_DURATION,
    UCI_MODE,
    UCI_SCAN_CHANNEL,
    __UCI_METIC_MAX
};

enum {
    UCI_UPDATE_CLIENT,
    UCI_DENIED_REQ_THRESHOLD,
    UCI_REMOVE_CLIENT,
    UCI_REMOVE_PROBE,
    UCI_REMOVE_AP,
    UCI_UPDATE_HOSTAPD,
    UCI_UPDATE_TCP_CON,
    UCI_UPDATE_CHAN_UTIL,
    UCI_UPDATE_BEACON_REPORTS,
    __UCI_TIMES_MAX,
};

static const struct blobmsg_policy uci_table_policy[__UCI_TABLE_MAX] = {
        [UCI_TABLE_METRIC] = {.name = "metric", .type = BLOBMSG_TYPE_TABLE},
        [UCI_TABLE_TIMES] = {.name = "times", .type = BLOBMSG_TYPE_TABLE}
};

static const struct blobmsg_policy uci_metric_policy[__UCI_METIC_MAX] = {
        [UCI_HT_SUPPORT] = {.name = "ht_support", .type = BLOBMSG_TYPE_INT32},
        [UCI_VHT_SUPPORT] = {.name = "vht_support", .type = BLOBMSG_TYPE_INT32},
        [UCI_NO_HT_SUPPORT] = {.name = "no_ht_support", .type = BLOBMSG_TYPE_INT32},
        [UCI_NO_VHT_SUPPORT] = {.name = "no_vht_support", .type = BLOBMSG_TYPE_INT32},
        [UCI_RSSI] = {.name = "rssi", .type = BLOBMSG_TYPE_INT32},
        [UCI_LOW_RSSI] = {.name = "low_rssi", .type = BLOBMSG_TYPE_INT32},
        [UCI_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
        [UCI_CHAN_UTIL] = {.name = "chan_util", .type = BLOBMSG_TYPE_INT32},
        [UCI_MAX_CHAN_UTIL] = {.name = "max_chan_util", .type = BLOBMSG_TYPE_INT32},
        [UCI_RSSI_VAL] = {.name = "rssi_val", .type = BLOBMSG_TYPE_INT32},
        [UCI_LOW_RSSI_VAL] = {.name = "low_rssi_val", .type = BLOBMSG_TYPE_INT32},
        [UCI_CHAN_UTIL_VAL] = {.name = "chan_util_val", .type = BLOBMSG_TYPE_INT32},
        [UCI_MAX_CHAN_UTIL_VAL] = {.name = "max_chan_util_val", .type = BLOBMSG_TYPE_INT32},
        [UCI_MIN_PROBE_COUNT] = {.name = "min_probe_count", .type = BLOBMSG_TYPE_INT32},
        [UCI_BANDWIDTH_THRESHOLD] = {.name = "bandwidth_threshold", .type = BLOBMSG_TYPE_INT32},
        [UCI_USE_STATION_COUNT] = {.name = "use_station_count", .type = BLOBMSG_TYPE_INT32},
        [UCI_MAX_STATION_DIFF] = {.name = "max_station_diff", .type = BLOBMSG_TYPE_INT32},
        [UCI_EVAL_PROBE_REQ] = {.name = "eval_probe_req", .type = BLOBMSG_TYPE_INT32},
        [UCI_EVAL_AUTH_REQ] = {.name = "eval_auth_req", .type = BLOBMSG_TYPE_INT32},
        [UCI_EVAL_ASSOC_REQ] = {.name = "eval_assoc_req", .type = BLOBMSG_TYPE_INT32},
        [UCI_KICKING] = {.name = "kicking", .type = BLOBMSG_TYPE_INT32},
        [UCI_DENY_AUTH_REASON] = {.name = "deny_auth_reason", .type = BLOBMSG_TYPE_INT32},
        [UCI_DENY_ASSOC_REASON] = {.name = "deny_assoc_reason", .type = BLOBMSG_TYPE_INT32},
        [UCI_USE_DRIVER_RECOG] = {.name = "use_driver_recog", .type = BLOBMSG_TYPE_INT32},
        [UCI_MIN_NUMBER_TO_KICK] = {.name = "min_number_to_kick", .type = BLOBMSG_TYPE_INT32},
        [UCI_CHAN_UTIL_AVG_PERIOD] = {.name = "chan_util_avg_period", .type = BLOBMSG_TYPE_INT32},
        [UCI_SET_HOSTAPD_NR] = {.name = "set_hostapd_nr", .type = BLOBMSG_TYPE_INT32},
        [UCI_OP_CLASS] = {.name = "op_class", .type = BLOBMSG_TYPE_INT32},
        [UCI_DURATION] = {.name = "duration", .type = BLOBMSG_TYPE_INT32},
        [UCI_MODE] = {.name = "mode", .type = BLOBMSG_TYPE_INT32},
        [UCI_SCAN_CHANNEL] = {.name = "mode", .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy uci_times_policy[__UCI_TIMES_MAX] = {
        [UCI_UPDATE_CLIENT] = {.name = "update_client", .type = BLOBMSG_TYPE_INT32},
        [UCI_DENIED_REQ_THRESHOLD] = {.name = "denied_req_threshold", .type = BLOBMSG_TYPE_INT32},
        [UCI_REMOVE_CLIENT] = {.name = "remove_client", .type = BLOBMSG_TYPE_INT32},
        [UCI_REMOVE_PROBE] = {.name = "remove_probe", .type = BLOBMSG_TYPE_INT32},
        [UCI_REMOVE_AP] = {.name = "remove_ap", .type = BLOBMSG_TYPE_INT32},
        [UCI_UPDATE_HOSTAPD] = {.name = "update_hostapd", .type = BLOBMSG_TYPE_INT32},
        [UCI_UPDATE_TCP_CON] = {.name = "update_tcp_con", .type = BLOBMSG_TYPE_INT32},
        [UCI_UPDATE_CHAN_UTIL] = {.name = "update_chan_util", .type = BLOBMSG_TYPE_INT32},
        [UCI_UPDATE_BEACON_REPORTS] = {.name = "update_beacon_reports", .type = BLOBMSG_TYPE_INT32},
};

int handle_uci_config(struct blob_attr *msg) {

    struct blob_attr *tb[__UCI_TABLE_MAX];
    blobmsg_parse(uci_table_policy, __UCI_TABLE_MAX, tb, blob_data(msg), blob_len(msg));

    struct blob_attr *tb_metric[__UCI_METIC_MAX];
    blobmsg_parse(uci_metric_policy, __UCI_METIC_MAX, tb_metric, blobmsg_data(tb[UCI_TABLE_METRIC]), blobmsg_len(tb[UCI_TABLE_METRIC]));

    char cmd_buffer[1024];
    sprintf(cmd_buffer, "dawn.@metric[0].ht_support=%d", blobmsg_get_u32(tb_metric[UCI_HT_SUPPORT]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].vht_support=%d", blobmsg_get_u32(tb_metric[UCI_VHT_SUPPORT]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].no_ht_support=%d", blobmsg_get_u32(tb_metric[UCI_NO_HT_SUPPORT]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].no_vht_support=%d", blobmsg_get_u32(tb_metric[UCI_NO_VHT_SUPPORT]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].rssi=%d", blobmsg_get_u32(tb_metric[UCI_RSSI]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].low_rssi=%d", blobmsg_get_u32(tb_metric[UCI_LOW_RSSI]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].freq=%d", blobmsg_get_u32(tb_metric[UCI_FREQ]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].chan_util=%d", blobmsg_get_u32(tb_metric[UCI_CHAN_UTIL]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].rssi_val=%d", blobmsg_get_u32(tb_metric[UCI_RSSI_VAL]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].low_rssi_val=%d", blobmsg_get_u32(tb_metric[UCI_LOW_RSSI_VAL]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].chan_util_val=%d", blobmsg_get_u32(tb_metric[UCI_CHAN_UTIL_VAL]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].max_chan_util=%d", blobmsg_get_u32(tb_metric[UCI_MAX_CHAN_UTIL]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].max_chan_util_val=%d", blobmsg_get_u32(tb_metric[UCI_MAX_CHAN_UTIL_VAL]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].min_probe_count=%d", blobmsg_get_u32(tb_metric[UCI_MIN_PROBE_COUNT]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].bandwidth_threshold=%d", blobmsg_get_u32(tb_metric[UCI_BANDWIDTH_THRESHOLD]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].use_station_count=%d", blobmsg_get_u32(tb_metric[UCI_USE_STATION_COUNT]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].max_station_diff=%d", blobmsg_get_u32(tb_metric[UCI_MAX_STATION_DIFF]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].eval_probe_req=%d", blobmsg_get_u32(tb_metric[UCI_EVAL_PROBE_REQ]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].eval_auth_req=%d", blobmsg_get_u32(tb_metric[UCI_EVAL_AUTH_REQ]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].evalcd_assoc_req=%d", blobmsg_get_u32(tb_metric[UCI_EVAL_ASSOC_REQ]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].kicking=%d", blobmsg_get_u32(tb_metric[UCI_KICKING]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].deny_auth_reason=%d", blobmsg_get_u32(tb_metric[UCI_DENY_AUTH_REASON]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].deny_assoc_reason=%d", blobmsg_get_u32(tb_metric[UCI_DENY_ASSOC_REASON]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].use_driver_recog=%d", blobmsg_get_u32(tb_metric[UCI_USE_DRIVER_RECOG]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].min_number_to_kick=%d", blobmsg_get_u32(tb_metric[UCI_MIN_NUMBER_TO_KICK]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].chan_util_avg_period=%d", blobmsg_get_u32(tb_metric[UCI_CHAN_UTIL_AVG_PERIOD]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].set_hostapd_nr=%d", blobmsg_get_u32(tb_metric[UCI_SET_HOSTAPD_NR]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].op_class=%d", blobmsg_get_u32(tb_metric[UCI_OP_CLASS]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].duration=%d", blobmsg_get_u32(tb_metric[UCI_DURATION]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].mode=%d", blobmsg_get_u32(tb_metric[UCI_MODE]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@metric[0].scan_channel=%d", blobmsg_get_u32(tb_metric[UCI_SCAN_CHANNEL]));
    uci_set_network(cmd_buffer);

    struct blob_attr *tb_times[__UCI_TIMES_MAX];
    blobmsg_parse(uci_times_policy, __UCI_TIMES_MAX, tb_times, blobmsg_data(tb[UCI_TABLE_TIMES]), blobmsg_len(tb[UCI_TABLE_TIMES]));

    sprintf(cmd_buffer, "dawn.@times[0].update_client=%d", blobmsg_get_u32(tb_times[UCI_UPDATE_CLIENT]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@times[0].denied_req_threshold=%d", blobmsg_get_u32(tb_times[UCI_DENIED_REQ_THRESHOLD]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@times[0].remove_client=%d", blobmsg_get_u32(tb_times[UCI_REMOVE_CLIENT]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@times[0].remove_probe=%d", blobmsg_get_u32(tb_times[UCI_REMOVE_PROBE]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@times[0].remove_ap=%d", blobmsg_get_u32(tb_times[UCI_REMOVE_AP]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@times[0].update_hostapd=%d", blobmsg_get_u32(tb_times[UCI_UPDATE_HOSTAPD]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@times[0].update_tcp_con=%d", blobmsg_get_u32(tb_times[UCI_UPDATE_TCP_CON]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@times[0].update_chan_util=%d", blobmsg_get_u32(tb_times[UCI_UPDATE_CHAN_UTIL]));
    uci_set_network(cmd_buffer);

    sprintf(cmd_buffer, "dawn.@times[0].update_beacon_reports=%d", blobmsg_get_u32(tb_times[UCI_UPDATE_BEACON_REPORTS]));
    uci_set_network(cmd_buffer);

    uci_reset();
    dawn_metric = uci_get_dawn_metric();
    timeout_config = uci_get_time_config();

    return 0;
}

int build_hearing_map_sort_client(struct blob_buf *b) {
    print_probe_array();
    pthread_mutex_lock(&probe_array_mutex);

    void *client_list, *ap_list, *ssid_list;
    char ap_mac_buf[20];
    char client_mac_buf[20];

    blob_buf_init(b, 0);
    int m;
    for (m = 0; m <= ap_entry_last; m++) {
        if (m > 0) {
            if (strcmp((char *) ap_array[m].ssid, (char *) ap_array[m - 1].ssid) == 0) {
                continue;
            }
        }
        ssid_list = blobmsg_open_table(b, (char *) ap_array[m].ssid);

        int i;
        for (i = 0; i <= probe_entry_last; i++) {
            /*if(!mac_is_equal(ap_array[m].bssid_addr, probe_array[i].bssid_addr))
            {
                continue;
            }*/

            ap ap_entry_i = ap_array_get_ap(probe_array[i].bssid_addr);

            if (!mac_is_equal(ap_entry_i.bssid_addr, probe_array[i].bssid_addr)) {
                continue;
            }

            if (strcmp((char *) ap_entry_i.ssid, (char *) ap_array[m].ssid) != 0) {
                continue;
            }

            int k;
            sprintf(client_mac_buf, MACSTR, MAC2STR(probe_array[i].client_addr));
            client_list = blobmsg_open_table(b, client_mac_buf);
            for (k = i; k <= probe_entry_last; k++) {
                ap ap_entry = ap_array_get_ap(probe_array[k].bssid_addr);

                if (!mac_is_equal(ap_entry.bssid_addr, probe_array[k].bssid_addr)) {
                    continue;
                }

                if (strcmp((char *) ap_entry.ssid, (char *) ap_array[m].ssid) != 0) {
                    continue;
                }

                if (!mac_is_equal(probe_array[k].client_addr, probe_array[i].client_addr)) {
                    i = k - 1;
                    break;
                } else if (k == probe_entry_last) {
                    i = k;
                }

                sprintf(ap_mac_buf, MACSTR, MAC2STR(probe_array[k].bssid_addr));
                ap_list = blobmsg_open_table(b, ap_mac_buf);
                blobmsg_add_u32(b, "signal", probe_array[k].signal);
                blobmsg_add_u32(b, "rcpi", probe_array[k].rcpi);
                blobmsg_add_u32(b, "rsni", probe_array[k].rsni);
                blobmsg_add_u32(b, "freq", probe_array[k].freq);
                blobmsg_add_u8(b, "ht_capabilities", probe_array[k].ht_capabilities);
                blobmsg_add_u8(b, "vht_capabilities", probe_array[k].vht_capabilities);


                // check if ap entry is available
                blobmsg_add_u32(b, "channel_utilization", ap_entry.channel_utilization);
                blobmsg_add_u32(b, "num_sta", ap_entry.station_count);
                blobmsg_add_u8(b, "ht_support", ap_entry.ht_support);
                blobmsg_add_u8(b, "vht_support", ap_entry.vht_support);

                blobmsg_add_u32(b, "score", eval_probe_metric(probe_array[k]));
                blobmsg_close_table(b, ap_list);
            }
            blobmsg_close_table(b, client_list);
        }
        blobmsg_close_table(b, ssid_list);
    }
    pthread_mutex_unlock(&probe_array_mutex);
    return 0;
}

int build_network_overview(struct blob_buf *b) {
    void *client_list, *ap_list, *ssid_list;
    char ap_mac_buf[20];
    char client_mac_buf[20];

    blob_buf_init(b, 0);
    int m;
    for (m = 0; m <= ap_entry_last; m++) {
        if (m > 0) {
            if (strcmp((char *) ap_array[m].ssid, (char *) ap_array[m - 1].ssid) == 0) {
                continue;
            }
        }

        ssid_list = blobmsg_open_table(b, (char *) ap_array[m].ssid);

        int i;
        for (i = 0; i <= client_entry_last; i++) {
            ap ap_entry_i = ap_array_get_ap(client_array[i].bssid_addr);

            if (strcmp((char *) ap_entry_i.ssid, (char *) ap_array[m].ssid) != 0) {
                continue;
            }
            int k;
            sprintf(ap_mac_buf, MACSTR, MAC2STR(client_array[i].bssid_addr));
            ap_list = blobmsg_open_table(b, ap_mac_buf);

            blobmsg_add_u32(b, "freq", ap_entry_i.freq);
            blobmsg_add_u32(b, "channel_utilization", ap_entry_i.channel_utilization);
            blobmsg_add_u32(b, "num_sta", ap_entry_i.station_count);
            blobmsg_add_u8(b, "ht_support", ap_entry_i.ht_support);
            blobmsg_add_u8(b, "vht_support", ap_entry_i.vht_support);

            char *nr;
            nr = blobmsg_alloc_string_buffer(b, "neighbor_report", NEIGHBOR_REPORT_LEN);
            sprintf(nr, "%s", ap_entry_i.neighbor_report);
            blobmsg_add_string_buffer(b);

            for (k = i; k <= client_entry_last; k++) {
                if (!mac_is_equal(client_array[k].bssid_addr, client_array[i].bssid_addr)) {
                    i = k - 1;
                    break;
                } else if (k == client_entry_last) {
                    i = k;
                }

                sprintf(client_mac_buf, MACSTR, MAC2STR(client_array[k].client_addr));
                client_list = blobmsg_open_table(b, client_mac_buf);
                if(strlen(client_array[k].signature) != 0)
                {
                    char *s;
                    s = blobmsg_alloc_string_buffer(b, "signature", 1024);
                    sprintf(s, "%s", client_array[k].signature);
                    blobmsg_add_string_buffer(b);
                }
                blobmsg_add_u8(b, "ht", client_array[k].ht);
                blobmsg_add_u8(b, "vht", client_array[k].vht);
                blobmsg_add_u32(b, "collision_count", ap_get_collision_count(ap_array[m].collision_domain));

                int n;
                for(n = 0; n <= probe_entry_last; n++)
                {
                    if (mac_is_equal(client_array[k].client_addr, probe_array[n].client_addr) &&
                            mac_is_equal(client_array[k].bssid_addr, probe_array[n].bssid_addr)) {
                        blobmsg_add_u32(b, "signal", probe_array[n].signal);
                        break;
                    }
                }
                blobmsg_close_table(b, client_list);
            }
            blobmsg_close_table(b, ap_list);
        }
        blobmsg_close_table(b, ssid_list);
    }
    return 0;
}

int ap_get_nr(struct blob_buf *b_local, uint8_t own_bssid_addr[]) {

    pthread_mutex_lock(&ap_array_mutex);
    int i;

    void* nbs = blobmsg_open_array(b_local, "list");

    for (i = 0; i <= ap_entry_last; i++) {
        if (mac_is_equal(own_bssid_addr, ap_array[i].bssid_addr)) {
            continue; //TODO: Skip own entry?!
        }

        void* nr_entry = blobmsg_open_array(b_local, NULL);

        char mac_buf[20];
        sprintf(mac_buf, MACSTRLOWER, MAC2STR(ap_array[i].bssid_addr));
        blobmsg_add_string(b_local, NULL, mac_buf);

        blobmsg_add_string(b_local, NULL, (char *) ap_array[i].ssid);
        blobmsg_add_string(b_local, NULL, ap_array[i].neighbor_report);
        blobmsg_close_array(b_local, nr_entry);

    }
    blobmsg_close_array(b_local, nbs);

    pthread_mutex_unlock(&ap_array_mutex);

    return 0;
}
