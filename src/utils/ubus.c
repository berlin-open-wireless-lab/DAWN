#include <dirent.h>
#include <libubus.h>

#include "memory_utils.h"
#include "networksocket.h"
#include "tcpsocket.h"
#include "mac_utils.h"
#include "dawn_uci.h"
#include "dawn_iwinfo.h"
#include "datastorage.h"
#include "ubus.h"
#include "msghandler.h"


#define REQ_TYPE_PROBE 0
#define REQ_TYPE_AUTH 1
#define REQ_TYPE_ASSOC 2


static struct ubus_context *ctx = NULL;

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
struct uloop_timeout tcp_con_timer = {
        .cb = update_tcp_connections
};
struct uloop_timeout channel_utilization_timer = {
        .cb = update_channel_utilization
};

void remove_ap_array_cb(struct uloop_timeout* t);

void denied_req_array_cb(struct uloop_timeout* t);

void remove_client_array_cb(struct uloop_timeout* t);

void remove_probe_array_cb(struct uloop_timeout* t);

struct uloop_timeout probe_timeout = {
        .cb = remove_probe_array_cb
};

struct uloop_timeout client_timeout = {
        .cb = remove_client_array_cb
};

struct uloop_timeout ap_timeout = {
        .cb = remove_ap_array_cb
};

struct uloop_timeout denied_req_timeout = {
        .cb = denied_req_array_cb
};

// TODO: Never scheduled?
struct uloop_timeout usock_timer = {
        .cb = run_server_update
};

struct uloop_timeout beacon_reports_timer = {
        .cb = update_beacon_reports
};

#define MAX_HOSTAPD_SOCKETS 10

LIST_HEAD(hostapd_sock_list);

struct hostapd_sock_entry {
    struct list_head list;

    uint32_t id;
    char iface_name[MAX_INTERFACE_NAME];
    char hostname[HOST_NAME_MAX];
    struct dawn_mac bssid_addr;
    char ssid[SSID_MAX_LEN + 1];
    uint8_t ht_support;
    uint8_t vht_support;
    uint64_t last_channel_time;
    uint64_t last_channel_time_busy;
    int chan_util_samples_sum;
    int chan_util_num_sample_periods;
    int chan_util_average; //TODO: Never evaluated?
    int band;

    // add neighbor report string
    /*
    [Elemen ID|1][LENGTH|1][BSSID|6][BSSID INFORMATION|4][Operating Class|1][Channel Number|1][PHY Type|1][Operational Subelements]
    */
    char neighbor_report[NEIGHBOR_REPORT_LEN];

    struct ubus_subscriber subscriber;
    struct ubus_event_handler wait_handler;
    bool subscribed;
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
    BEACON_REP_SSID,
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
        [BEACON_REP_SSID] = {.name = "ssid", .type = BLOBMSG_TYPE_STRING},
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
static int hostapd_notify(struct ubus_context *ctx_local, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg);

static int ubus_get_clients();

static int
add_mac(struct ubus_context *ctx_local, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg);

static int reload_config(struct ubus_context *ctx_local, struct ubus_object *obj,
                         struct ubus_request_data *req, const char *method,
                         struct blob_attr *msg);

static int get_hearing_map(struct ubus_context *ctx_local, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg);

static int get_network(struct ubus_context *ctx_local, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg);

static void ubus_add_oject();

static void respond_to_notify(uint32_t id);

//static int handle_uci_config(struct blob_attr *msg);

void subscribe_to_new_interfaces(const char *hostapd_sock_path);

bool subscriber_to_interface(const char *ifname);

bool subscribe(struct ubus_context *ctx_local, struct hostapd_sock_entry *hostapd_entry);

int parse_to_beacon_rep(struct blob_attr *msg);

void ubus_set_nr();

void add_client_update_timer(time_t time) {
    uloop_timeout_set(&client_timer, time);
}

static inline int
subscription_wait(struct ubus_event_handler *handler) {
    return ubus_register_event_handler(ctx, handler, "ubus.object.add");
}

void blobmsg_add_macaddr(struct blob_buf *buf, const char *name, const struct dawn_mac addr) {
    char *s;

    dawnlog_debug_func("Entering...");

    s = blobmsg_alloc_string_buffer(buf, name, 20);
    sprintf(s, MACSTR, MAC2STR(addr.u8));
    blobmsg_add_string_buffer(buf);
}

int parse_to_auth_req(struct blob_attr *msg, auth_entry *auth_req) {
    struct blob_attr *tb[__AUTH_MAX];

    dawnlog_debug_func("Entering...");

    blobmsg_parse(auth_policy, __AUTH_MAX, tb, blob_data(msg), blob_len(msg));

    if (hwaddr_aton(blobmsg_data(tb[AUTH_BSSID_ADDR]), auth_req->bssid_addr.u8))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (hwaddr_aton(blobmsg_data(tb[AUTH_CLIENT_ADDR]), auth_req->client_addr.u8))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (hwaddr_aton(blobmsg_data(tb[AUTH_TARGET_ADDR]), auth_req->target_addr.u8))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (tb[AUTH_SIGNAL]) {
        auth_req->signal = blobmsg_get_u32(tb[AUTH_SIGNAL]);
    }

    if (tb[AUTH_FREQ]) {
        auth_req->freq = blobmsg_get_u32(tb[AUTH_FREQ]);
    }

    return 0;
}

int parse_to_assoc_req(struct blob_attr *msg, assoc_entry *assoc_req) {
    dawnlog_debug_func("Entering...");

    return (parse_to_auth_req(msg, assoc_req));
}

int parse_to_beacon_rep(struct blob_attr *msg) {
    struct blob_attr *tb[__BEACON_REP_MAX];
    struct dawn_mac msg_bssid;
    struct dawn_mac msg_client;

    dawnlog_debug_func("Entering...");

    blobmsg_parse(beacon_rep_policy, __BEACON_REP_MAX, tb, blob_data(msg), blob_len(msg));

    if(!tb[BEACON_REP_BSSID] || !tb[BEACON_REP_ADDR])
    {
        return -1;
    }

    if (hwaddr_aton(blobmsg_data(tb[BEACON_REP_BSSID]), msg_bssid.u8))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if(mac_is_null(msg_bssid.u8))
    {
        dawnlog_warning("Received NULL MAC! Client is strange!\n");
        return -1;
    }

    const uint8_t *ssid = (const uint8_t*)blobmsg_get_string(tb[BEACON_REP_SSID]);
    ap *ap_entry_rep = ap_array_get_ap(msg_bssid, ssid);

    // no client from network!!
    if (ap_entry_rep == NULL) {
        return -1; //TODO: Check this
    }

    if (hwaddr_aton(blobmsg_data(tb[BEACON_REP_ADDR]), msg_client.u8))
        return UBUS_STATUS_INVALID_ARGUMENT;

    int rcpi = blobmsg_get_u16(tb[BEACON_REP_RCPI]);
    int rsni = blobmsg_get_u16(tb[BEACON_REP_RSNI]);


    // HACKY WORKAROUND!
    dawnlog_debug("Try update RCPI and RSNI for beacon report!\n");
    if(!probe_array_update_rcpi_rsni(msg_bssid, msg_client, rcpi, rsni, true))
    {
        dawnlog_debug("Beacon: No Probe Entry Existing!\n");

        probe_entry* beacon_rep = dawn_malloc(sizeof(probe_entry));
        probe_entry* beacon_rep_updated = NULL;
        if (beacon_rep == NULL)
        {
            dawnlog_error("dawn_malloc of probe_entry failed!\n");
            return -1;
        }

        beacon_rep->next_probe = NULL;
        beacon_rep->bssid_addr = msg_bssid;
        beacon_rep->client_addr = msg_client;
        strncpy((char*)beacon_rep->ssid, (char*)ssid, SSID_MAX_LEN);
        beacon_rep->ssid[SSID_MAX_LEN] = '\0';
        beacon_rep->counter = dawn_metric.min_probe_count;
        hwaddr_aton(blobmsg_data(tb[BEACON_REP_ADDR]), beacon_rep->target_addr.u8);  // TODO: What is this for?
        beacon_rep->signal = 0;
        beacon_rep->freq = ap_entry_rep->freq;
        beacon_rep->rcpi = rcpi;
        beacon_rep->rsni = rsni;

        beacon_rep->ht_capabilities = false; // that is very problematic!!!
        beacon_rep->vht_capabilities = false; // that is very problematic!!!
        dawnlog_debug("Inserting to array!\n");

        // TODO: kept original code order here - send on network first to simplify?
        beacon_rep_updated = insert_to_array(beacon_rep, false, false, true, time(0));
        if (beacon_rep != beacon_rep_updated) // use 802.11k values  // TODO: Change 0 to false?
        {
            // insert found an existing entry, rather than linking in our new one
            ubus_send_probe_via_network(beacon_rep_updated);
            dawn_free(beacon_rep);
            beacon_rep = NULL;
        }
        else
            ubus_send_probe_via_network(beacon_rep_updated);
    }
    return 0;
}

int handle_auth_req(struct blob_attr* msg) {
int ret = WLAN_STATUS_SUCCESS;
bool discard_entry = true;

    dawnlog_debug_func("Entering...");

    auth_entry *auth_req = dawn_malloc(sizeof(struct auth_entry_s));
    if (auth_req == NULL)
    {
        dawnlog_error("Memory allocation of auth req failed!");
        return ret; // Allow if we can't evalute a reason to deny
    }

    parse_to_auth_req(msg, auth_req);

    dawnlog_debug("Auth entry: ");
    print_auth_entry(DAWNLOG_DEBUG, auth_req);

    if (dawn_metric.eval_auth_req <= 0) {
        dawnlog_trace("Allow authentication due to not evaluating requests");
    }
    else if (mac_in_maclist(auth_req->client_addr)) {
        dawnlog_trace("Allow authentication due to mac_in_maclist()");
    }
    else {
        pthread_mutex_lock(&probe_array_mutex);

        if (dawnlog_showing(DAWNLOG_DEBUG))
            print_probe_array();

        probe_entry *tmp = probe_array_get_entry(auth_req->bssid_addr, auth_req->client_addr);

        pthread_mutex_unlock(&probe_array_mutex);

        /*** Deprecated function decide_function() removed here ***/
        int deny_request = 0;
        
        // block if entry was not already found in probe database
        if (tmp == NULL) {
            dawnlog_trace("Deny authentication due to no probe entry");
            deny_request = 1;
        }
#if 0
        // Already know this is false from outer test above
        else if (mac_in_maclist(probe_req_updated->client_addr)) {
            dawnlog_trace("Short cut due to mac_in_maclist()");
        }
#endif
        else if (tmp->counter < dawn_metric.min_probe_count) {
            dawnlog_trace("Deny authentication due to low probe count");
            deny_request = 1;
        }
        else
        {
            // find own probe entry and calculate score
            ap* this_ap = ap_array_get_ap(tmp->bssid_addr, tmp->ssid);
            if (this_ap != NULL && better_ap_available(this_ap, tmp->client_addr, NULL) > 0) {
                dawnlog_trace("Deny authentication due to better AP available");
                deny_request = 1;
            }
            else
                // maybe send here that the client is connected?
                dawnlog_trace("Allow authentication!\n");
        }
        /*** End of decide_function() rework ***/

        if (deny_request) {
            if (dawn_metric.use_driver_recog) {
                if (auth_req == insert_to_denied_req_array(auth_req, 1, time(0)))
                    discard_entry = false;
            }
            ret = dawn_metric.deny_auth_reason;
        }
    }

    if (discard_entry)
    {
        dawn_free(auth_req);
        auth_req = NULL;
    }

    return ret;
}

static int handle_assoc_req(struct blob_attr *msg) {
int ret = WLAN_STATUS_SUCCESS;
int discard_entry = true;

    dawnlog_debug_func("Entering...");

    auth_entry* assoc_req = dawn_malloc(sizeof(struct auth_entry_s));
    if (assoc_req == NULL)
    {
        dawnlog_error("Memory allocation of assoc req failed!");
        return ret; // Allow if we can't evalute a reason to deny
    }

    parse_to_assoc_req(msg, assoc_req);
    dawnlog_debug("Association entry: ");
    print_auth_entry(DAWNLOG_DEBUG, assoc_req);

    if (dawn_metric.eval_assoc_req <= 0) {
        dawnlog_trace("Allow association due to not evaluating requests");
    }
    else if (mac_in_maclist(assoc_req->client_addr)) {
        dawnlog_trace("Allow association due to mac_in_maclist()");
    } else {
        pthread_mutex_lock(&probe_array_mutex);

        if (dawnlog_showing(DAWNLOG_DEBUG))
            print_probe_array();

        probe_entry *tmp = probe_array_get_entry(assoc_req->bssid_addr, assoc_req->client_addr);

        pthread_mutex_unlock(&probe_array_mutex);

        /*** Deprecated function decide_function() removed here ***/
        int deny_request = 0;
        
        // block if entry was not already found in probe database
        if (tmp == NULL) {
            dawnlog_trace("Deny association due to no probe entry found");
            deny_request = 1;
        }
#if 0
        // Already know this is false from outer test above
        else if (mac_in_maclist(tmp->client_addr)) {
            dawnlog_trace("Allow due to mac_in_maclist()");
        }
#endif
        else if (tmp->counter < dawn_metric.min_probe_count) {
            dawnlog_trace("Deny association due to low probe count");
            deny_request = 1;
        }
        else
        {
            // find own probe entry and calculate score
            ap* this_ap = ap_array_get_ap(tmp->bssid_addr, tmp->ssid);
            if (this_ap != NULL && better_ap_available(this_ap, tmp->client_addr, NULL) > 0) {
                dawnlog_trace("Deny association due to better AP available");
                deny_request = 1;
            }
            else
                dawnlog_trace("Allow association!\n");
        }
        /*** End of decide_function() rework ***/

        if (deny_request) {
            if (tmp != NULL)
                print_probe_entry(DAWNLOG_DEBUG, tmp);

            if (dawn_metric.use_driver_recog) {
                if (assoc_req == insert_to_denied_req_array(assoc_req, 1, time(0)))
                    discard_entry = false;
            }
            ret = dawn_metric.deny_assoc_reason;
        }
    }

    if (discard_entry)
    {
        dawn_free(assoc_req);
        assoc_req = NULL;
    }

    return ret;
}

static int handle_probe_req(struct blob_attr* msg) {
    // MUSTDO: Untangle dawn_malloc() and linking of probe_entry
    probe_entry* probe_req = parse_to_probe_req(msg);

    dawnlog_debug_func("Entering...");


    if (probe_req == NULL)
    {
        dawnlog_error("Parse of probe req failed!");
        return WLAN_STATUS_SUCCESS; // Allow if we can't evalute a reason to deny
    }
    else
    {
        probe_entry* probe_req_updated = insert_to_array(probe_req, true, true, false, time(0));
        // If insert finds an existing entry, rather than linking in our new one,
        // send new probe req because we want to stay synced.
        // If not, probe_req and probe_req_updated should be equivalent
        if (probe_req != probe_req_updated)
        {
            dawn_free(probe_req);
            probe_req = NULL;
        }

        ubus_send_probe_via_network(probe_req_updated);

        /*** Deprecated function decide_function() removed here ***/
        int deny_request = 0;

        if (dawn_metric.eval_probe_req <= 0) {
            dawnlog_trace("Allow probe due to not evaluating requests");
        }
        else if (mac_in_maclist(probe_req_updated->client_addr)) {
            dawnlog_trace("Allow probe due to mac_in_maclist()");
        }
        else if (probe_req_updated->counter < dawn_metric.min_probe_count) {
            dawnlog_trace("Deny probe due to low probe count");
            deny_request = 1;
        }
        else
        {
            // find own probe entry and calculate score
            ap* this_ap = ap_array_get_ap(probe_req_updated->bssid_addr, probe_req_updated->ssid);
            if (this_ap != NULL && better_ap_available(this_ap, probe_req_updated->client_addr, NULL) > 0) {
                dawnlog_trace("Deny probe due to better AP available");
                deny_request = 1;
            }
            else
            {
                dawnlog_trace("Allow probe request!");
            }
        }
        /*** End of decide_function() rework ***/

        if (deny_request) {
            return WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA; // no reason needed...
        }
    }

    // TODO: Return for dawn_malloc() failure?
    return WLAN_STATUS_SUCCESS;
}

// FIXME: Seems to do nothing...
static int handle_beacon_rep(struct blob_attr *msg) {
    dawnlog_debug_func("Entering...");

    if (parse_to_beacon_rep(msg) == 0) {
        // dawnlog_debug("Inserting beacon Report!\n");
        // insert_to_array(beacon_rep, 1);
        // dawnlog_debug("Sending via network!\n");
        // send_blob_attr_via_network(msg, "beacon-report");
    }
    return 0;
}


int send_blob_attr_via_network(struct blob_attr* msg, char* method) {

    dawnlog_debug_func("Entering...");

    if (!msg) {
        return -1;
    }

    char *data_str;
    char *str;
    struct blob_buf b = {0};

    data_str = blobmsg_format_json(msg, true);
    dawn_regmem(data_str);

    blob_buf_init(&b, 0);
    dawn_regmem(&b);

    blobmsg_add_string(&b, "method", method);
    blobmsg_add_string(&b, "data", data_str);

    str = blobmsg_format_json(b.head, true);
    dawn_regmem(str);

    if (network_config.network_option == 2
        || network_config.network_option == 3) {
        send_tcp(str);
    } else {
        if (network_config.use_symm_enc) {
            send_string_enc(str);
        } else {
            send_string(str);
        }
    }

    dawn_free(str);
    str = NULL;

    blob_buf_free(&b);
    dawn_unregmem(&b);

    dawn_free(data_str);
    data_str = NULL;

    return 0;
}

static int hostapd_notify(struct ubus_context* ctx_local, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method,
    struct blob_attr* msg) {
    int ret = 0;
    struct blob_buf b = {0};

    dawnlog_debug_func("Entering...");

    if (dawnlog_showing(DAWNLOG_DEBUG))
    {
        char* str = blobmsg_format_json(msg, true);
        dawn_regmem(str);
        dawnlog_debug("Method new: %s : %s\n", method, str);
        dawn_free(str);
        str = NULL;
    }

    struct hostapd_sock_entry *entry;
    struct ubus_subscriber *subscriber;

    subscriber = container_of(obj, struct ubus_subscriber, obj);
    entry = container_of(subscriber, struct hostapd_sock_entry, subscriber);

    struct blob_attr *cur; int rem;
    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    blobmsg_for_each_attr(cur, msg, rem){
        blobmsg_add_blob(&b, cur);
    }

    blobmsg_add_macaddr(&b, "bssid", entry->bssid_addr);
    blobmsg_add_string(&b, "ssid", entry->ssid);

    if (strncmp(method, "probe", 5) == 0) {
        ret = handle_probe_req(b.head);
    } else if (strncmp(method, "auth", 4) == 0) {
        ret = handle_auth_req(b.head);
    } else if (strncmp(method, "assoc", 5) == 0) {
        ret = handle_assoc_req(b.head);
    } else if (strncmp(method, "deauth", 6) == 0) {
        send_blob_attr_via_network(b.head, "deauth");
        ret = handle_deauth_req(b.head);
    } else if (strncmp(method, "beacon-report", 12) == 0) {
        ret = handle_beacon_rep(b.head);
    }

    blob_buf_free(&b);
    dawn_unregmem(&b);

    return ret;
}

int dawn_init_ubus(const char *ubus_socket, const char *hostapd_dir) {
    uloop_init();
    signal(SIGPIPE, SIG_IGN);

    dawnlog_debug_func("Entering...");

    ctx = ubus_connect(ubus_socket);
    if (!ctx) {
        dawnlog_error("Failed to connect to ubus\n");
        return -1;
    } else {
        dawnlog_debug("Connected to ubus\n");
        dawn_regmem(ctx);
    }

    ubus_add_uloop(ctx);

    // set dawn metric
    dawn_metric = uci_get_dawn_metric();

    uloop_timeout_add(&hostapd_timer);  // callback = update_hostapd_sockets

    // set up callbacks to remove aged data
    uloop_add_data_cbs();

    // get clients
    uloop_timeout_add(&client_timer);  // callback = update_clients

    uloop_timeout_add(&channel_utilization_timer);  // callback = update_channel_utilization

    // request beacon reports
    if(timeout_config.update_beacon_reports) // allow setting timeout to 0
        uloop_timeout_add(&beacon_reports_timer); // callback = update_beacon_reports

    ubus_add_oject();

    if (network_config.network_option == 2
        || network_config.network_option == 3)
    {
        start_tcp_con_update();
        if(run_server(network_config.tcp_port))
            uloop_timeout_set(&usock_timer, 1 * 1000);
    }

    subscribe_to_new_interfaces(hostapd_dir_glob);

    uloop_run();

    close_socket();

    ubus_free(ctx);
    dawn_unregmem(ctx);
    ctx = NULL;
    uloop_done();
    return 0;
}

static int get_band_from_bssid(struct dawn_mac bssid) {
    ap *a;
    dawnlog_debug_func("Entering...");

    for (a = ap_set; a; a = a->next_ap) {
        if (mac_is_equal_bb(a->bssid_addr, bssid))
            return get_band(a->freq);
    }
    return -1;
}

static void ubus_get_clients_cb(struct ubus_request *req, int type, struct blob_attr *msg) {
    dawnlog_debug_func("Entering...");

    if (!msg)
        return;

    struct hostapd_sock_entry* entry = NULL;

    struct hostapd_sock_entry* sub = NULL;
    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->id == req->peer) {
            entry = sub;
        }
    }

    sub = NULL;

    if (entry == NULL) {
        dawnlog_error("Failed to find interface!\n");
        return;
    }

    if (!entry->subscribed) {
        dawnlog_error("Interface %s is not subscribed!\n", entry->iface_name);
        return;
    }

    char *data_str = blobmsg_format_json(msg, 1);
    dawn_regmem(data_str);

    struct blob_buf b = {0};
    blob_buf_init(&b, 0);
    dawn_regmem(&b);

    blobmsg_add_json_from_string(&b, data_str);
    blobmsg_add_u32(&b, "collision_domain", network_config.collision_domain);
    blobmsg_add_u32(&b, "bandwidth", network_config.bandwidth);

    blobmsg_add_macaddr(&b, "bssid", entry->bssid_addr);
    blobmsg_add_string(&b, "ssid", entry->ssid);
    blobmsg_add_u8(&b, "ht_supported", entry->ht_support);
    blobmsg_add_u8(&b, "vht_supported", entry->vht_support);

    if (entry->band < 0)
        entry->band = get_band_from_bssid(entry->bssid_addr);
    if (entry->band >= 0)
        blobmsg_add_u32(&b, "ap_weight", dawn_metric.ap_weight[entry->band]);

    //int channel_util = get_channel_utilization(entry->iface_name, &entry->last_channel_time, &entry->last_channel_time_busy);
    blobmsg_add_u32(&b, "channel_utilization", entry->chan_util_average);

    blobmsg_add_string(&b, "neighbor_report", entry->neighbor_report);

    blobmsg_add_string(&b, "iface", entry->iface_name);
    blobmsg_add_string(&b, "hostname", entry->hostname);

    send_blob_attr_via_network(b.head, "clients");
    // TODO: Have we just bit-packed data to send to something locally to unpack it again?  Performance / scalability?
    parse_to_clients(b.head, 1, req->peer);

    print_client_array();
    print_ap_array();

    dawn_free(data_str);
    data_str = NULL;

    blob_buf_free(&b);
    dawn_unregmem(&b);
}

static int ubus_get_clients() {
    int timeout = 1;
    struct hostapd_sock_entry *sub;
    dawnlog_debug_func("Entering...");

    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed) {
            struct blob_buf b = {0};
            blob_buf_init(&b, 0);
            dawn_regmem(&b);
            ubus_invoke(ctx, sub->id, "get_clients", b.head, ubus_get_clients_cb, NULL, timeout * 1000);
            blob_buf_free(&b);
            dawn_unregmem(&b);
        }
    }
    return 0;
}

static void ubus_get_rrm_cb(struct ubus_request *req, int type, struct blob_attr *msg) {
    struct hostapd_sock_entry *sub, *entry = NULL;
    struct blob_attr *tb[__RRM_MAX];

    dawnlog_debug_func("Entering...");

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
            char* neighborreport = blobmsg_get_string(attr);
            strcpy(entry->neighbor_report,neighborreport);
            dawnlog_debug("Copied Neighborreport: %s,\n", entry->neighbor_report);
         }
         i++;
     }
}

static int ubus_get_rrm() {
    int timeout = 1;
    struct hostapd_sock_entry *sub;

    dawnlog_debug_func("Entering...");

    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed) {
            struct blob_buf b = {0};
            blob_buf_init(&b, 0);
            dawn_regmem(&b);
            ubus_invoke(ctx, sub->id, "rrm_nr_get_own", b.head, ubus_get_rrm_cb, NULL, timeout * 1000);
            blob_buf_free(&b);
            dawn_unregmem(&b);
        }
    }
    return 0;
}

void update_clients(struct uloop_timeout *t) {
    dawnlog_debug_func("Entering...");

    ubus_get_clients();
    if(dawn_metric.set_hostapd_nr)
        ubus_set_nr();
    // maybe to much?! don't set timer again...
    uloop_timeout_set(&client_timer, timeout_config.update_client * 1000);
}

void run_server_update(struct uloop_timeout *t) {
    dawnlog_debug_func("Entering...");

    if(run_server(network_config.tcp_port))
        uloop_timeout_set(&usock_timer, 1 * 1000);
}

void update_channel_utilization(struct uloop_timeout *t) {
    struct hostapd_sock_entry *sub;

    dawnlog_debug_func("Entering...");

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

static int get_mode_from_capability(int capability) {
    dawnlog_debug_func("Entering...");

    for (int n = 0; n < __RRM_BEACON_RQST_MODE_MAX; n++) {
        switch (capability & dawn_metric.rrm_mode_order[n]) {
        case WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE:
            return RRM_BEACON_RQST_MODE_PASSIVE;
        case WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE:
            return RRM_BEACON_RQST_MODE_ACTIVE;
        case WLAN_RRM_CAPS_BEACON_REPORT_TABLE:
            return RRM_BEACON_RQST_MODE_BEACON_TABLE;
        }
    }
    return -1;
}

void ubus_send_beacon_report(client *c, ap *a, int id)
{
    struct blob_buf b = {0};
    dawnlog_debug_func("Entering...");

    dawnlog_debug("Crafting Beacon Report\n");
    int timeout = 1;

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    blobmsg_add_macaddr(&b, "addr", c->client_addr);
    blobmsg_add_u32(&b, "op_class", a->op_class);
    blobmsg_add_u32(&b, "channel", a->channel);
    blobmsg_add_u32(&b, "duration", dawn_metric.duration);
    blobmsg_add_u32(&b, "mode", get_mode_from_capability(c->rrm_enabled_capa));
    blobmsg_add_string(&b, "ssid", (char*)a->ssid);

    dawnlog_debug("Invoking beacon report!\n");
    ubus_invoke(ctx, id, "rrm_beacon_req", b.head, NULL, NULL, timeout * 1000);
    blob_buf_free(&b);
    dawn_unregmem(&b);
}

void update_beacon_reports(struct uloop_timeout *t) {
    ap *a;

    dawnlog_debug_func("Entering...");

    if(!timeout_config.update_beacon_reports) // if 0 just return
    {
        return;
    }
    dawnlog_debug("Sending beacon report!\n");
    struct hostapd_sock_entry *sub;
    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed && (a = ap_array_get_ap(sub->bssid_addr, (uint8_t*)sub->ssid))) {
            dawnlog_debug("Sending beacon report Sub!\n");
            send_beacon_reports(a, sub->id);
        }
    }
    uloop_timeout_set(&beacon_reports_timer, timeout_config.update_beacon_reports * 1000);
}

void update_tcp_connections(struct uloop_timeout *t) {
    dawnlog_debug_func("Entering...");

    if (strcmp(network_config.server_ip, ""))
    {
        // nothing happens if tcp connection is already established
        add_tcp_connection(network_config.server_ip, network_config.tcp_port);
    }
    if (network_config.network_option == 2) // mdns enabled?
    {
        ubus_call_umdns();
    }
    uloop_timeout_set(&tcp_con_timer, timeout_config.update_tcp_con * 1000);
}

void start_tcp_con_update() {
    dawnlog_debug_func("Entering...");

    // update connections
    uloop_timeout_add(&tcp_con_timer); // callback = update_tcp_connections
}

void update_hostapd_sockets(struct uloop_timeout *t) {
    dawnlog_debug_func("Entering...");

    subscribe_to_new_interfaces(hostapd_dir_glob);
    uloop_timeout_set(&hostapd_timer, timeout_config.update_hostapd * 1000);
}

void ubus_set_nr(){
    dawnlog_debug_func("Entering...");

    struct hostapd_sock_entry *sub;
    int timeout = 1;

    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed) {
            struct blob_buf b = {0};
            blob_buf_init(&b, 0);
            dawn_regmem(&b);
            ap_get_nr(&b, sub->bssid_addr, sub->ssid);
            ubus_invoke(ctx, sub->id, "rrm_nr_set", b.head, NULL, NULL, timeout * 1000);
            blob_buf_free(&b);
            dawn_unregmem(&b);
        }
    }
}

void del_client_all_interfaces(const struct dawn_mac client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time) {
    struct hostapd_sock_entry *sub;
    struct blob_buf b = {0};

    dawnlog_debug_func("Entering...");

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
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
    blob_buf_free(&b);
    dawn_unregmem(&b);
}

void del_client_interface(uint32_t id, const struct dawn_mac client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time) {
    struct hostapd_sock_entry *sub;
    struct blob_buf b = {0};

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
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
    blob_buf_free(&b);
    dawn_unregmem(&b);
}

int wnm_disassoc_imminent(uint32_t id, const struct dawn_mac client_addr, struct kicking_nr* neighbor_list, uint32_t duration) {
    struct hostapd_sock_entry *sub;
    struct blob_buf b = {0};

    dawnlog_debug_func("Entering...");

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    blobmsg_add_macaddr(&b, "addr", client_addr);
    blobmsg_add_u8(&b, "disassociation_imminent", 1);
    blobmsg_add_u32(&b, "disassociation_timer", duration);
    blobmsg_add_u32(&b, "validity_period", duration);
    blobmsg_add_u8(&b, "abridged", 1); // prefer aps in neighborlist

    void* nbs = blobmsg_open_array(&b, "neighbors");
    while(neighbor_list != NULL) {
        dawnlog_info("BSS TRANSITION NEIGHBOR " NR_MACSTR ", Score=%d\n", NR_MAC2STR(neighbor_list->nr), neighbor_list->score);
        blobmsg_add_string(&b, NULL, neighbor_list->nr);
        neighbor_list = neighbor_list->next;
    }

    blobmsg_close_array(&b, nbs);
    list_for_each_entry(sub, &hostapd_sock_list, list)
    {
        if (sub->subscribed) {
            int timeout = 1; //TDO: Maybe ID is wrong?! OR CHECK HERE ID
            ubus_invoke(ctx, id, "bss_transition_request", b.head, NULL, NULL, timeout * 1000);
        }
    }

    blob_buf_free(&b);
    dawn_unregmem(&b);

    return 0;
}

static void ubus_umdns_cb(struct ubus_request *req, int type, struct blob_attr *msg) {
    struct blob_attr *tb[__DAWN_UMDNS_TABLE_MAX];

    dawnlog_debug_func("Entering...");

    if (!msg)
        return;

    blobmsg_parse(dawn_umdns_table_policy, __DAWN_UMDNS_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[DAWN_UMDNS_TABLE]) {
        return;
    }

    struct blob_attr *attr;
    int len = blobmsg_data_len(tb[DAWN_UMDNS_TABLE]);

    __blob_for_each_attr(attr, blobmsg_data(tb[DAWN_UMDNS_TABLE]), len)
    {
#if DAWNLOG_COMPILING(DAWNLOG_DEBUG)
        struct blobmsg_hdr *hdr = blob_data(attr);
        dawnlog_debug("Hostname: %s\n", hdr->name);
#endif

        struct blob_attr *tb_dawn[__DAWN_UMDNS_MAX];
        blobmsg_parse(dawn_umdns_policy, __DAWN_UMDNS_MAX, tb_dawn, blobmsg_data(attr), blobmsg_len(attr));

        if (tb_dawn[DAWN_UMDNS_IPV4] && tb_dawn[DAWN_UMDNS_PORT]) {
            dawnlog_debug("IPV4: %s\n", blobmsg_get_string(tb_dawn[DAWN_UMDNS_IPV4]));
            dawnlog_debug("Port: %d\n", blobmsg_get_u32(tb_dawn[DAWN_UMDNS_PORT]));
        } else {
            return;
        }
        add_tcp_connection(blobmsg_get_string(tb_dawn[DAWN_UMDNS_IPV4]), blobmsg_get_u32(tb_dawn[DAWN_UMDNS_PORT]));
    }
}

int ubus_call_umdns() {
    u_int32_t id;
    struct blob_buf b = {0};

    dawnlog_debug_func("Entering...");

    if (ubus_lookup_id(ctx, "umdns", &id)) {
        dawnlog_error("Failed to look up test object for %s\n", "umdns");
        return -1;
    }

    int timeout = 1;
    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    ubus_invoke(ctx, id, "update", b.head, NULL, NULL, timeout * 1000);
    ubus_invoke(ctx, id, "browse", b.head, ubus_umdns_cb, NULL, timeout * 1000);
    blob_buf_free(&b);
    dawn_unregmem(&b);

    return 0;
}

//TODO: ADD STUFF HERE!!!!
int ubus_send_probe_via_network(struct probe_entry_s *probe_entry) {  // TODO: probe_entry is also a typedef - fix?
    struct blob_buf b = {0};

    dawnlog_debug_func("Entering...");

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    blobmsg_add_macaddr(&b, "bssid", probe_entry->bssid_addr);
    blobmsg_add_macaddr(&b, "address", probe_entry->client_addr);
    blobmsg_add_macaddr(&b, "target", probe_entry->target_addr);
    blobmsg_add_u32(&b, "signal", probe_entry->signal);
    blobmsg_add_u32(&b, "freq", probe_entry->freq);

    blobmsg_add_u32(&b, "rcpi", probe_entry->rcpi);
    blobmsg_add_u32(&b, "rsni", probe_entry->rsni);

    blobmsg_add_u32(&b, "ht_capabilities", probe_entry->ht_capabilities);
    blobmsg_add_u32(&b, "vht_capabilities", probe_entry->vht_capabilities);

    /*if (probe_entry->ht_capabilities)
    {
        void *ht_cap = blobmsg_open_table(&b, "ht_capabilities");
        blobmsg_close_table(&b, ht_cap);
    }

    if (probe_entry->vht_capabilities) {
        void *vht_cap = blobmsg_open_table(&b, "vht_capabilities");
        blobmsg_close_table(&b, vht_cap);
    }*/

    send_blob_attr_via_network(b.head, "probe");

    blob_buf_free(&b);
    dawn_unregmem(&b);

    return 0;
}

int send_set_probe(struct dawn_mac client_addr) {
    struct blob_buf b = {0};

    dawnlog_debug_func("Entering...");

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    blobmsg_add_macaddr(&b, "bssid", client_addr);
    blobmsg_add_macaddr(&b, "address", client_addr);

    send_blob_attr_via_network(b.head, "setprobe");

    blob_buf_free(&b);
    dawn_unregmem(&b);

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

int parse_add_mac_to_file(struct blob_attr *msg) {
    struct blob_attr *tb[__ADD_DEL_MAC_MAX];
    struct blob_attr *attr;

    dawnlog_debug_func("Entering...");

    dawnlog_debug("Parsing MAC!\n");

    blobmsg_parse(add_del_policy, __ADD_DEL_MAC_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[MAC_ADDR])
        return UBUS_STATUS_INVALID_ARGUMENT;

    int len = blobmsg_data_len(tb[MAC_ADDR]);
    dawnlog_debug("Length of array maclist: %d\n", len);

    __blob_for_each_attr(attr, blobmsg_data(tb[MAC_ADDR]), len)
    {
        dawnlog_debug("Iteration through MAC-list\n");
        struct dawn_mac addr;
        hwaddr_aton(blobmsg_data(attr), addr.u8);

        if (insert_to_maclist(addr) == 0) {
            // TODO: File can grow arbitarily large.  Resource consumption risk.
            // TODO: Consolidate use of file across source: shared resource for name, single point of access?
            write_mac_to_file("/tmp/dawn_mac_list", addr);
        }
    }

    return 0;
}

static int add_mac(struct ubus_context *ctx_local, struct ubus_object *obj,
                   struct ubus_request_data *req, const char *method,
                   struct blob_attr *msg) {
    dawnlog_debug_func("Entering...");

    dawnlog_trace("UBUS invoking add_mac()");

    parse_add_mac_to_file(msg);

    // here we need to send it via the network!
    send_blob_attr_via_network(msg, "addmac");

    return 0;
}

static int reload_config(struct ubus_context *ctx_local, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg) {
    int ret;
    struct blob_buf b = {0};

    dawnlog_debug_func("Entering...");

    dawnlog_trace("UBUS invoking reload_config()");

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    uci_reset();
    dawn_metric = uci_get_dawn_metric();
    timeout_config = uci_get_time_config();
    uci_get_dawn_hostapd_dir();
    uci_get_dawn_sort_order();

    if(timeout_config.update_beacon_reports) // allow setting timeout to 0
        uloop_timeout_add(&beacon_reports_timer); // callback = update_beacon_reports

    uci_send_via_network();
    ret = ubus_send_reply(ctx_local, req, b.head);
    if (ret)
        dawnlog_error("Failed to send reply: %s\n", ubus_strerror(ret));

    blob_buf_free(&b);
    dawn_unregmem(&b);

    return 0;
}

static int get_hearing_map(struct ubus_context *ctx_local, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg) {
    int ret;
    struct blob_buf b = {0};

    dawnlog_debug_func("Entering...");

    dawnlog_trace("UBUS invoking get_hearing_map()");

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    build_hearing_map_sort_client(&b);
    ret = ubus_send_reply(ctx_local, req, b.head);
    if (ret)
        dawnlog_error("Failed to send reply: %s\n", ubus_strerror(ret));
    blob_buf_free(&b);
    dawn_unregmem(&b);

    return 0;
}


static int get_network(struct ubus_context *ctx_local, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg) {
    int ret;
    struct blob_buf b = {0};

    dawnlog_debug_func("Entering...");

    dawnlog_trace("UBUS invoking get_network()");

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    build_network_overview(&b);
    ret = ubus_send_reply(ctx_local, req, b.head);
    if (ret)
        dawnlog_error("Failed to send reply: %s\n", ubus_strerror(ret));
    blob_buf_free(&b);
    dawn_unregmem(&b);

    return 0;
}

static void ubus_add_oject() {
    int ret;

    dawnlog_debug_func("Entering...");

    ret = ubus_add_object(ctx, &dawn_object);
    if (ret)
        dawnlog_error("Failed to add object: %s\n", ubus_strerror(ret));
}

static void respond_to_notify(uint32_t id) {
    // This is needed to respond to the ubus notify ...
    // Maybe we need to disable on shutdown...
    // But it is not possible when we disable the notify that other daemons are running that relay on this notify...
    int ret;
    struct blob_buf b = {0};
    int timeout = 1;

    dawnlog_debug_func("Entering...");

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    blobmsg_add_u32(&b, "notify_response", 1);

    ret = ubus_invoke(ctx, id, "notify_response", b.head, NULL, NULL, timeout * 1000);
    if (ret)
        dawnlog_error("Failed to invoke: %s\n", ubus_strerror(ret));

    blob_buf_free(&b);
    dawn_unregmem(&b);
}

static void enable_rrm(uint32_t id) {
    int ret;
    struct blob_buf b = {0};

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    blobmsg_add_u8(&b, "neighbor_report", 1);
    blobmsg_add_u8(&b, "beacon_report", 1);
    blobmsg_add_u8(&b, "bss_transition", 1);

    int timeout = 1;
    ret = ubus_invoke(ctx, id, "bss_mgmt_enable", b.head, NULL, NULL, timeout * 1000);
    if (ret)
        dawnlog_error("Failed to invoke: %s\n", ubus_strerror(ret));
    
    blob_buf_free(&b);
    dawn_unregmem(&b);
}

static void hostapd_handle_remove(struct ubus_context *ctx_local,
                                  struct ubus_subscriber *s, uint32_t id) {
    dawnlog_debug_func("Entering...");

    dawnlog_debug("Object %08x went away\n", id);
    struct hostapd_sock_entry *hostapd_sock = container_of(s,
    struct hostapd_sock_entry, subscriber);

    if (hostapd_sock->id != id) {
        dawnlog_debug("ID is not the same!\n");
        return;
    }

    hostapd_sock->subscribed = false;
    subscription_wait(&hostapd_sock->wait_handler);

}

bool subscribe(struct ubus_context *ctx_local, struct hostapd_sock_entry *hostapd_entry) {
    dawnlog_debug_func("Entering...");

    char subscribe_name[sizeof("hostapd.") + MAX_INTERFACE_NAME + 1];

    if (hostapd_entry->subscribed)
        return false;

    sprintf(subscribe_name, "hostapd.%s", hostapd_entry->iface_name);

    if (ubus_lookup_id(ctx_local, subscribe_name, &hostapd_entry->id)) {
        dawnlog_warning("Failed to lookup ID!");
        subscription_wait(&hostapd_entry->wait_handler);
        return false;
    }

    if (ubus_subscribe(ctx_local, &hostapd_entry->subscriber, hostapd_entry->id)) {
        dawnlog_warning("Failed to register subscriber!");
        subscription_wait(&hostapd_entry->wait_handler);
        return false;
    }

    hostapd_entry->subscribed = true;

    get_bssid(hostapd_entry->iface_name, hostapd_entry->bssid_addr.u8);
    get_ssid(hostapd_entry->iface_name, hostapd_entry->ssid, (SSID_MAX_LEN) * sizeof(char));
    hostapd_entry->ssid[SSID_MAX_LEN] = '\0';

    hostapd_entry->ht_support = (uint8_t) support_ht(hostapd_entry->iface_name);
    hostapd_entry->vht_support = (uint8_t) support_vht(hostapd_entry->iface_name);
    hostapd_entry->band = -1;

    respond_to_notify(hostapd_entry->id);
    enable_rrm(hostapd_entry->id);
    ubus_get_rrm();

    dawnlog_debug("Subscribed to: %s\n", hostapd_entry->iface_name);

    return true;
}

static void
wait_cb(struct ubus_context *ctx_local, struct ubus_event_handler *ev_handler,
        const char *type, struct blob_attr *msg) {
    static const struct blobmsg_policy wait_policy = {
            "path", BLOBMSG_TYPE_STRING
    };

    dawnlog_debug_func("Entering...");

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

    subscribe(ctx_local, sub);
}

bool subscriber_to_interface(const char *ifname) {

    struct hostapd_sock_entry *hostapd_entry;

    dawnlog_debug_func("Entering...");

    hostapd_entry = dawn_calloc(1, sizeof(struct hostapd_sock_entry));
    strcpy(hostapd_entry->iface_name, ifname);

    // add hostname
    uci_get_hostname(hostapd_entry->hostname);

    hostapd_entry->subscriber.cb = hostapd_notify;
    hostapd_entry->subscriber.remove_cb = hostapd_handle_remove;
    hostapd_entry->wait_handler.cb = wait_cb;

    hostapd_entry->subscribed = false;

    if (ubus_register_subscriber(ctx, &hostapd_entry->subscriber)) {
        dawnlog_error("Failed to register subscriber!");
        return false;
    }

    list_add(&hostapd_entry->list, &hostapd_sock_list);

    return subscribe(ctx, hostapd_entry);
}

void subscribe_to_new_interfaces(const char *hostapd_sock_path) {
    DIR *dirp;
    struct dirent *entry;
    struct hostapd_sock_entry *sub = NULL;

    dawnlog_debug_func("Entering...");

    if (ctx == NULL) {
        return;
    }

    dirp = opendir(hostapd_sock_path);  // error handling?
    if (!dirp) {
        dawnlog_error("[SUBSCRIBING] No hostapd sockets!\n");
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

static char get_rrm_mode_char(int val)
{
    dawnlog_debug_func("Entering...");

    switch (val) {
    case WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE:
        return 'p';
    case WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE:
        return 'a';
    case WLAN_RRM_CAPS_BEACON_REPORT_TABLE:
        return 't';
    }
    return '?';
}

const static char* get_rrm_mode_string(int *rrm_mode_order) {
    static char rrm_mode_string [__RRM_BEACON_RQST_MODE_MAX + 1] = {0};

    dawnlog_debug_func("Entering...");

    for (int n = 0; n < __RRM_BEACON_RQST_MODE_MAX && rrm_mode_order[n]; n++)
        rrm_mode_string[n] = get_rrm_mode_char(rrm_mode_order[n]);
    return rrm_mode_string;
}

int uci_send_via_network()
{
    void *metric, *times, *band_table, *band_entry;
    struct blob_buf b = {0};

    dawnlog_debug_func("Entering...");

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    blobmsg_add_string(&b, "version", DAWN_CONFIG_VERSION);
    metric = blobmsg_open_table(&b, "metric");

    blobmsg_add_u32(&b, "min_probe_count", dawn_metric.min_probe_count);
    blobmsg_add_u32(&b, "bandwidth_threshold", dawn_metric.bandwidth_threshold);
    blobmsg_add_u32(&b, "use_station_count", dawn_metric.use_station_count);
    blobmsg_add_u32(&b, "max_station_diff", dawn_metric.max_station_diff);
    blobmsg_add_u32(&b, "eval_probe_req", dawn_metric.eval_probe_req);
    blobmsg_add_u32(&b, "eval_auth_req", dawn_metric.eval_auth_req);
    blobmsg_add_u32(&b, "eval_assoc_req", dawn_metric.eval_assoc_req);
    blobmsg_add_u32(&b, "kicking", dawn_metric.kicking);
    blobmsg_add_u32(&b, "kicking_threshold", dawn_metric.kicking_threshold);
    blobmsg_add_u32(&b, "deny_auth_reason", dawn_metric.deny_auth_reason);
    blobmsg_add_u32(&b, "deny_assoc_reason", dawn_metric.deny_assoc_reason);
    blobmsg_add_u32(&b, "use_driver_recog", dawn_metric.use_driver_recog);
    blobmsg_add_u32(&b, "min_number_to_kick", dawn_metric.min_number_to_kick);
    blobmsg_add_u32(&b, "chan_util_avg_period", dawn_metric.chan_util_avg_period);
    blobmsg_add_u32(&b, "set_hostapd_nr", dawn_metric.set_hostapd_nr);
    blobmsg_add_u32(&b, "duration", dawn_metric.duration);
    blobmsg_add_string(&b, "rrm_mode", get_rrm_mode_string(dawn_metric.rrm_mode_order));
    band_table = blobmsg_open_table(&b, "band_metrics");

    for (int band=0; band < __DAWN_BAND_MAX; band++) {
        band_entry = blobmsg_open_table(&b, band_config_name[band]);
        blobmsg_add_u32(&b, "initial_score", dawn_metric.initial_score[band]);
        blobmsg_add_u32(&b, "ap_weight", dawn_metric.ap_weight[band]);
        blobmsg_add_u32(&b, "ht_support", dawn_metric.ht_support[band]);
        blobmsg_add_u32(&b, "vht_support", dawn_metric.vht_support[band]);
        blobmsg_add_u32(&b, "no_ht_support", dawn_metric.no_ht_support[band]);
        blobmsg_add_u32(&b, "no_vht_support", dawn_metric.no_vht_support[band]);
        blobmsg_add_u32(&b, "rssi", dawn_metric.rssi[band]);
        blobmsg_add_u32(&b, "rssi_val", dawn_metric.rssi_val[band]);
        blobmsg_add_u32(&b, "low_rssi", dawn_metric.low_rssi[band]);
        blobmsg_add_u32(&b, "low_rssi_val", dawn_metric.low_rssi_val[band]);
        blobmsg_add_u32(&b, "chan_util", dawn_metric.chan_util[band]);
        blobmsg_add_u32(&b, "max_chan_util", dawn_metric.max_chan_util[band]);
        blobmsg_add_u32(&b, "chan_util_val", dawn_metric.chan_util_val[band]);
        blobmsg_add_u32(&b, "max_chan_util_val", dawn_metric.max_chan_util_val[band]);
        blobmsg_add_u32(&b, "rssi_weight", dawn_metric.rssi_weight[band]);
        blobmsg_add_u32(&b, "rssi_center", dawn_metric.rssi_center[band]);
        blobmsg_close_table(&b, band_entry);
    }
    blobmsg_close_table(&b, band_table);

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

    blob_buf_free(&b);
    dawn_unregmem(&b);

    return 0;
}

int build_hearing_map_sort_client(struct blob_buf *b) {
    dawnlog_debug_func("Entering...");

    if (dawnlog_showing(DAWNLOG_DEBUG))
        print_probe_array();

    pthread_mutex_lock(&probe_array_mutex);

    void *client_list, *ap_list, *ssid_list;
    char ap_mac_buf[20];
    char client_mac_buf[20];
    bool same_ssid = false;

    for (ap* m = ap_set; m != NULL; m = m->next_ap) {
        // MUSTDO: Ensure SSID / BSSID ordering.  Lost when switched to linked list!
        // Scan AP list to find first of each SSID
        if (!same_ssid) {
            ssid_list = blobmsg_open_table(b, (char*)m->ssid);
            probe_entry* i = probe_set;
            while (i != NULL) {
                ap *ap_entry_i = ap_array_get_ap(i->bssid_addr, m->ssid);

                if (ap_entry_i == NULL) {
                    i = i->next_probe;
                    continue;
                }

                if (strcmp((char*)ap_entry_i->ssid, (char*)m->ssid) != 0) {
                    i = i->next_probe;
                    continue;
                }

                sprintf(client_mac_buf, MACSTR, MAC2STR(i->client_addr.u8));
                client_list = blobmsg_open_table(b, client_mac_buf);
                probe_entry *k;
                for (k = i;
                k != NULL && mac_is_equal_bb(k->client_addr, i->client_addr);
                k = k->next_probe) {

                    ap *ap_k = ap_array_get_ap(k->bssid_addr, m->ssid);

                    if (ap_k == NULL || strcmp((char*)ap_k->ssid, (char*)m->ssid) != 0) {
                        continue;
                    }

                    sprintf(ap_mac_buf, MACSTR, MAC2STR(k->bssid_addr.u8));
                    ap_list = blobmsg_open_table(b, ap_mac_buf);
                    blobmsg_add_u32(b, "signal", k->signal);
                    blobmsg_add_u32(b, "rcpi", k->rcpi);
                    blobmsg_add_u32(b, "rsni", k->rsni);
                    blobmsg_add_u32(b, "freq", k->freq);
                    blobmsg_add_u8(b, "ht_capabilities", k->ht_capabilities);
                    blobmsg_add_u8(b, "vht_capabilities", k->vht_capabilities);


                    // check if ap entry is available
                    blobmsg_add_u32(b, "channel_utilization", ap_k->channel_utilization);
                    blobmsg_add_u32(b, "num_sta", ap_k->station_count);
                    blobmsg_add_u8(b, "ht_support", ap_k->ht_support);
                    blobmsg_add_u8(b, "vht_support", ap_k->vht_support);

                    blobmsg_add_u32(b, "score", eval_probe_metric(k, ap_k));
                    blobmsg_close_table(b, ap_list);
                }

                blobmsg_close_table(b, client_list);

                // TODO: Change this so that i and k are single loop?
                i = k;
            }
        }

        if ((m->next_ap == NULL) || strcmp((char*)m->ssid, (char*)((m->next_ap)->ssid)) != 0)
        {
            blobmsg_close_table(b, ssid_list);
            same_ssid = false;
        }
        else
            same_ssid = true;
    }

    pthread_mutex_unlock(&probe_array_mutex);
    return 0;
}

int build_network_overview(struct blob_buf *b) {
    void *client_list, *ap_list, *ssid_list;
    char ap_mac_buf[20];
    char client_mac_buf[20];
    struct hostapd_sock_entry *sub;

    dawnlog_debug_func("Entering...");

    bool add_ssid = true;
    for (ap* m = ap_set; m != NULL; m = m->next_ap) {
        if(add_ssid)
        {
            ssid_list = blobmsg_open_table(b, (char *) m->ssid);
            add_ssid = false;
        }
        sprintf(ap_mac_buf, MACSTR, MAC2STR(m->bssid_addr.u8));
        ap_list = blobmsg_open_table(b, ap_mac_buf);

        blobmsg_add_u32(b, "freq", m->freq);
        blobmsg_add_u32(b, "channel_utilization", m->channel_utilization);
        blobmsg_add_u32(b, "num_sta", m->station_count);
        blobmsg_add_u8(b, "ht_support", m->ht_support);
        blobmsg_add_u8(b, "vht_support", m->vht_support);

        bool local_ap = false;
        list_for_each_entry(sub, &hostapd_sock_list, list)
        {
            if (mac_is_equal_bb(m->bssid_addr, sub->bssid_addr)) {
                local_ap = true;
            }
        }
        blobmsg_add_u8(b, "local", local_ap);

        char *nr;
        nr = blobmsg_alloc_string_buffer(b, "neighbor_report", NEIGHBOR_REPORT_LEN);
        sprintf(nr, "%s", m->neighbor_report); // TODO: Why not strcpy()
        blobmsg_add_string_buffer(b);

        char *iface;
        iface = blobmsg_alloc_string_buffer(b, "iface", MAX_INTERFACE_NAME);
        sprintf(iface, "%s", m->iface);
        blobmsg_add_string_buffer(b);

        char *hostname;
        hostname = blobmsg_alloc_string_buffer(b, "hostname", HOST_NAME_MAX);
        sprintf(hostname, "%s", m->hostname);
        blobmsg_add_string_buffer(b);

        // TODO: Could optimise this by exporting search func, but not a core process
        client *k = client_set_bc;
        while (k != NULL) {

            if (mac_is_equal_bb(m->bssid_addr, k->bssid_addr)) {
                sprintf(client_mac_buf, MACSTR, MAC2STR(k->client_addr.u8));
                client_list = blobmsg_open_table(b, client_mac_buf);

                if(strlen(k->signature) != 0)
                {
                    char *s;
                    s = blobmsg_alloc_string_buffer(b, "signature", 1024);
                    sprintf(s, "%s", k->signature);
                    blobmsg_add_string_buffer(b);
                }
                blobmsg_add_u8(b, "ht", k->ht);
                blobmsg_add_u8(b, "vht", k->vht);
                blobmsg_add_u32(b, "collision_count", ap_get_collision_count(m->collision_domain));

                pthread_mutex_lock(&probe_array_mutex);

                probe_entry* n = probe_array_get_entry(k->bssid_addr, k->client_addr);
                pthread_mutex_unlock(&probe_array_mutex);

                if (n != NULL) {
                    blobmsg_add_u32(b, "signal", n->signal);
                }
                blobmsg_close_table(b, client_list);
            }
            k = k->next_entry_bc;
        }
        blobmsg_close_table(b, ap_list);

        // Rely on short-circuit of OR to protect NULL reference in 2nd clause
        if ((m->next_ap == NULL) || strcmp((char*)m->ssid, (char*)(m->next_ap)->ssid) != 0) {
            blobmsg_close_table(b, ssid_list);
        }

        if ((m->next_ap != NULL) && strcmp((char*)m->ssid, (char*)(m->next_ap)->ssid) != 0) {
            add_ssid = true;
        }
    }

    return 0;
}


static void blobmsg_add_nr(struct blob_buf *b_local, ap *i) {
    void* nr_entry = blobmsg_open_array(b_local, NULL);
    char mac_buf[20];

    dawnlog_debug_func("Entering...");

    sprintf(mac_buf, MACSTRLOWER, MAC2STR(i->bssid_addr.u8));
    blobmsg_add_string(b_local, NULL, mac_buf);

    blobmsg_add_string(b_local, NULL, (char *) i->ssid);
    blobmsg_add_string(b_local, NULL, i->neighbor_report);
    blobmsg_close_array(b_local, nr_entry);
}

static int mac_is_in_entry_list(const struct dawn_mac mac, const struct mac_entry_s *list) {
    dawnlog_debug_func("Entering...");

    for (const struct mac_entry_s *i = list; i; i = i->next_mac)
        if (mac_is_equal_bb(i->mac, mac))
            return 1;
    return 0;
}

// TODO: Does all APs constitute neighbor report?  How about using list of AP connected
// clients can also see (from probe_set) to give more (physically) local set?
// Here, we let the user configure a list of preferred APs that clients can see, and then
// add the rest of all APs.  hostapd inserts this list backwards, so we must start with
// the regular APs, then add the preferred ones, which are already ordered backwards.
int ap_get_nr(struct blob_buf *b_local, struct dawn_mac own_bssid_addr, const char *ssid) {

    ap *i, *own_ap;
    struct mac_entry_s *preferred_list, *n;

    dawnlog_debug_func("Entering...");

    void* nbs = blobmsg_open_array(b_local, "list");

    own_ap = ap_array_get_ap(own_bssid_addr, (uint8_t*)ssid);
    if (!own_ap)
        return -1;
    for (int band = 0; band < __DAWN_BAND_MAX; band++) {
        preferred_list = dawn_metric.neighbors[band];
        if (own_ap->freq <= max_band_freq[band])
           break;
    }
    pthread_mutex_lock(&ap_array_mutex);
    for (i = ap_set; i != NULL; i = i->next_ap) {
        if (i != own_ap && !strncmp((char *)i->ssid, ssid, SSID_MAX_LEN) &&
            !mac_is_in_entry_list(i->bssid_addr, preferred_list))
        {
            blobmsg_add_nr(b_local, i);
        }
    }
    pthread_mutex_unlock(&ap_array_mutex);

    for (n = preferred_list; n; n = n->next_mac) {
        if ((i = ap_array_get_ap(n->mac, (uint8_t*)ssid)))
            blobmsg_add_nr(b_local, i);
    }
    blobmsg_close_array(b_local, nbs);

    return 0;
}

void uloop_add_data_cbs() {
    dawnlog_debug_func("Entering...");

    uloop_timeout_add(&probe_timeout);  //  callback = remove_probe_array_cb
    uloop_timeout_add(&client_timeout);  //  callback = remove_client_array_cb
    uloop_timeout_add(&ap_timeout);  //  callback = remove_ap_array_cb

    if (dawn_metric.use_driver_recog) {
        uloop_timeout_add(&denied_req_timeout);  //  callback = denied_req_array_cb
    }
}

// TODO: Move mutex handling to remove_??? function to make test harness simpler?
// Or not needed as test harness not threaded?
void remove_probe_array_cb(struct uloop_timeout* t) {
    dawnlog_debug_func("Entering...");

    pthread_mutex_lock(&probe_array_mutex);
    dawnlog_debug("[Thread] : Removing old probe entries!\n");
    remove_old_probe_entries(time(0), timeout_config.remove_probe);
    dawnlog_debug("[Thread] : Removing old entries finished!\n");
    pthread_mutex_unlock(&probe_array_mutex);
    uloop_timeout_set(&probe_timeout, timeout_config.remove_probe * 1000);
}

// TODO: Move mutex handling to remove_??? function to make test harness simpler?
// Or not needed as test harness not threaded?
void remove_client_array_cb(struct uloop_timeout* t) {
    dawnlog_debug_func("Entering...");

    pthread_mutex_lock(&client_array_mutex);
    dawnlog_debug("[Thread] : Removing old client entries!\n");
    remove_old_client_entries(time(0), timeout_config.update_client);
    pthread_mutex_unlock(&client_array_mutex);
    uloop_timeout_set(&client_timeout, timeout_config.update_client * 1000);
}

// TODO: Move mutex handling to remove_??? function to make test harness simpler?
// Or not needed as test harness not threaded?
void remove_ap_array_cb(struct uloop_timeout* t) {
    dawnlog_debug_func("Entering...");

    pthread_mutex_lock(&ap_array_mutex);
    dawnlog_debug("[ULOOP] : Removing old ap entries!\n");
    remove_old_ap_entries(time(0), timeout_config.remove_ap);
    pthread_mutex_unlock(&ap_array_mutex);
    uloop_timeout_set(&ap_timeout, timeout_config.remove_ap * 1000);
}

// TODO: Move mutex handling to (new) remove_??? function to make test harness simpler?
// Or not needed as test harness not threaded?
void denied_req_array_cb(struct uloop_timeout* t) {
    dawnlog_debug_func("Entering...");

    pthread_mutex_lock(&denied_array_mutex);
    dawnlog_debug("[ULOOP] : Processing denied authentication!\n");

    remove_old_denied_req_entries(time(0), timeout_config.denied_req_threshold, true);

    pthread_mutex_unlock(&denied_array_mutex);
    uloop_timeout_set(&denied_req_timeout, timeout_config.denied_req_threshold * 1000);
}

int send_add_mac(struct dawn_mac client_addr) {
    struct blob_buf b = {0};

    dawnlog_debug_func("Entering...");

    blob_buf_init(&b, 0);
    dawn_regmem(&b);
    blobmsg_add_macaddr(&b, "addr", client_addr);
    send_blob_attr_via_network(b.head, "addmac");
    blob_buf_free(&b);
    dawn_unregmem(&b);

    return 0;
}
