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

#include "ubus.h"

#include "networksocket.h"
#include "utils.h"
#include "dawn_uci.h"
#include "dawn_iwinfo.h"
#include "datastorage.h"
#include "tcpsocket.h"

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

void update_clients(struct uloop_timeout *t);

void update_tcp_connections(struct uloop_timeout *t);

void update_channel_utilization(struct uloop_timeout *t);

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

    if (req_type == REQ_TYPE_PROBE && !dawn_metric.eval_probe_req) {
        return 1;
    }

    if (req_type == REQ_TYPE_AUTH && !dawn_metric.eval_auth_req) {
        return 1;
    }

    if (req_type == REQ_TYPE_ASSOC && !dawn_metric.eval_assoc_req) {
        return 1;
    }

    if (better_ap_available(prob_req->bssid_addr, prob_req->client_addr, 0)) {
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
        tmp_prob_req = insert_to_array(prob_req, 1);
        send_blob_attr_via_network(msg, "probe");
    }

    if (!decide_function(&tmp_prob_req, REQ_TYPE_PROBE)) {
        return WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA; // no reason needed...
    }
    return WLAN_STATUS_SUCCESS;
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

    if (strncmp(method, "probe", 5) == 0) {
        probe_entry entry;
        if (parse_to_probe_req(data_buf.head, &entry) == 0) {
            insert_to_array(entry, 0);
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

    ubus_call_umdns();

    ubus_add_oject();

    start_umdns_update();

    if (network_config.network_option == 2)
        run_server(network_config.tcp_port);

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

void update_clients(struct uloop_timeout *t) {
    ubus_get_clients();
    // maybe to much?! don't set timer again...
    uloop_timeout_set(&client_timer, timeout_config.update_client * 1000);
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
    blobmsg_add_u32(&b, "bandwith_threshold", dawn_metric.bandwith_threshold);
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
    UCI_BANDWITH_THRESHOLD,
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
        [UCI_BANDWITH_THRESHOLD] = {.name = "bandwith_threshold", .type = BLOBMSG_TYPE_INT32},
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

    sprintf(cmd_buffer, "dawn.@metric[0].bandwith_threshold=%d", blobmsg_get_u32(tb_metric[UCI_BANDWITH_THRESHOLD]));
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

    uci_reset();
    dawn_metric = uci_get_dawn_metric();
    timeout_config = uci_get_time_config();

    return 0;
}