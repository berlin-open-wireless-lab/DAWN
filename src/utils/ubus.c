#include <ctype.h>
#include <dirent.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubus.h>
#include <sys/types.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#include "ubus.h"

#include "networksocket.h"
#include "utils.h"
#include "dawn_uci.h"
#include "datastorage.h"

static struct ubus_context *ctx = NULL;
static struct ubus_context *ctx_clients; /* own ubus conext otherwise strange behavior... */

static struct ubus_subscriber hostapd_event;
static struct blob_buf b;
static struct blob_buf b_send_network;
static struct blob_buf network_buf;
static struct blob_buf data_buf;
static struct blob_buf b_probe;




void update_clients(struct uloop_timeout *t);

struct uloop_timeout client_timer = {
        .cb = update_clients
};
struct uloop_timeout hostapd_timer = {
        .cb = update_hostapd_sockets
};

#define MAX_HOSTAPD_SOCKETS 10
uint32_t hostapd_sock_arr[MAX_HOSTAPD_SOCKETS];
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
    PROB_HT_SUPPORT,
    PROB_VHT_SUPPORT,
    __PROB_MAX,
};

static const struct blobmsg_policy prob_policy[__PROB_MAX] = {
        [PROB_BSSID_ADDR] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
        [PROB_CLIENT_ADDR] = {.name = "address", .type = BLOBMSG_TYPE_STRING},
        [PROB_TARGET_ADDR] = {.name = "target", .type = BLOBMSG_TYPE_STRING},
        [PROB_SIGNAL] = {.name = "signal", .type = BLOBMSG_TYPE_INT32},
        [PROB_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
        [PROB_HT_SUPPORT] = {.name = "ht_support", .type = BLOBMSG_TYPE_INT8},
        [PROB_VHT_SUPPORT] = {.name = "vht_support", .type = BLOBMSG_TYPE_INT8},
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
};

enum {
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

/* Function Definitions */
static void hostapd_handle_remove(struct ubus_context *ctx,
                                  struct ubus_subscriber *s, uint32_t id);

static int hostapd_notify(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg);

static int add_subscriber(char *name);

static int subscribe_to_hostapd_interfaces(const char *hostapd_dir);

static int ubus_get_clients();

static int
add_mac(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg);

static int get_hearing_map(struct ubus_context *ctx, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg);

static int get_network(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg);

static int handle_set_probe(struct blob_attr *msg);

int hostapd_array_check_id(uint32_t id);

void hostapd_array_insert(uint32_t id);

void hostapd_array_delete(uint32_t id);
static void ubus_add_oject();

void add_client_update_timer(time_t time) {
    uloop_timeout_set(&client_timer, time);
}

int hostapd_array_check_id(uint32_t id) {
    for (int i = 0; i <= hostapd_sock_last; i++) {
        if (hostapd_sock_arr[i] == id) {
            return 1;
        }
    }
    return 0;
}


void hostapd_array_insert(uint32_t id) {
    if (hostapd_sock_last < MAX_HOSTAPD_SOCKETS) {
        hostapd_sock_last++;
        hostapd_sock_arr[hostapd_sock_last] = id;
    }

    for (int i = 0; i <= hostapd_sock_last; i++) {
        printf("%d: %d\n", i, hostapd_sock_arr[i]);
    }
}

void hostapd_array_delete(uint32_t id) {
    int i = 0;
    int found_in_array = 0;

    if (hostapd_sock_last == -1) {
        return;
    }

    for (i = 0; i <= hostapd_sock_last; i++) {
        if (hostapd_sock_arr[i] == id) {
            found_in_array = 1;
            break;
        }
    }

    for (int j = i; j <= hostapd_sock_last; j++) {
        hostapd_sock_arr[j] = hostapd_sock_arr[j + 1];
    }

    if (hostapd_sock_last > -1 && found_in_array) {
        hostapd_sock_last--;
    }

}

void blobmsg_add_macaddr(struct blob_buf *buf, const char *name, const uint8_t *addr) {
    char *s;

    s = blobmsg_alloc_string_buffer(buf, name, 20);
    sprintf(s, MACSTR, MAC2STR(addr));
    blobmsg_add_string_buffer(buf);
}


static int decide_function(probe_entry *prob_req) {
    printf("COUNTER: %d\n", prob_req->counter);

    if (prob_req->counter < dawn_metric.min_probe_count) {
        return 0;
    }

    if(!dawn_metric.eval_probe_req)
    {
        return 1;
    }

    if (better_ap_available(prob_req->bssid_addr, prob_req->client_addr, 0)) {
        return 0;
    }

    return 1;
}


static void hostapd_handle_remove(struct ubus_context *ctx,
                                  struct ubus_subscriber *s, uint32_t id) {
    fprintf(stderr, "Object %08x went away\n", id);
    ubus_unsubscribe(ctx, s, id);
    hostapd_array_delete(id);
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

    if (tb[PROB_HT_SUPPORT]) {
        prob_req->ht_support = blobmsg_get_u8(tb[PROB_HT_SUPPORT]);
    }

    if (tb[PROB_VHT_SUPPORT]) {
        prob_req->vht_support = blobmsg_get_u8(tb[PROB_VHT_SUPPORT]);
    }

    return 0;
}

static int handle_auth_req(struct blob_attr *msg) {

    print_probe_array();
    auth_entry auth_req;
    parse_to_auth_req(msg, &auth_req);
    printf("AUTH Entry: ");
    print_auth_entry(auth_req);

    probe_entry tmp = probe_array_get_entry(auth_req.bssid_addr, auth_req.client_addr);

    printf("Entry found\n");
    print_probe_entry(tmp);

    // block if entry was not already found in probe database
    if (!(mac_is_equal(tmp.bssid_addr, auth_req.bssid_addr) && mac_is_equal(tmp.client_addr, auth_req.client_addr))) {
        printf("DENY AUTH!\n");
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

    if (!decide_function(&tmp)) {
        printf("DENY AUTH\n");
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

    // maybe add here if a client is already connected...
    // delay problems...

    printf("ALLOW AUTH!\n");
    return 0;
}

static int handle_assoc_req(struct blob_attr *msg) {
    //assoc_entry assoc_req;
    //parse_to_auth_req(msg, &assoc_req);

    return handle_auth_req(msg);
}

static int handle_probe_req(struct blob_attr *msg) {
    //printf("[WC] Parse Probe Request\n");
    probe_entry prob_req;
    probe_entry tmp_prob_req;
    if(parse_to_probe_req(msg, &prob_req) == 0)
    {
        tmp_prob_req = insert_to_array(prob_req, 1);
        //print_probe_array();
        send_blob_attr_via_network(msg, "probe");
    }

    if (!decide_function(&tmp_prob_req)) {
        //printf("MAC WILL BE DECLINED!!!\n");
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    //printf("MAC WILL BE ACCEPDTED!!!\n");
    return 0;
}

static int handle_deauth_req(struct blob_attr *msg) {

    hostapd_notify_entry notify_req;
    parse_to_hostapd_notify(msg, &notify_req);

    client client_entry;
    memcpy(client_entry.bssid_addr, client_entry.bssid_addr, sizeof(uint8_t) * ETH_ALEN );
    memcpy(client_entry.client_addr, client_entry.client_addr, sizeof(uint8_t) * ETH_ALEN );

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
    memcpy(client_entry.bssid_addr, client_entry.bssid_addr, sizeof(uint8_t) * ETH_ALEN );
    memcpy(client_entry.client_addr, client_entry.client_addr, sizeof(uint8_t) * ETH_ALEN );

    probe_array_set_all_probe_count(client_entry.client_addr, dawn_metric.min_probe_count);

    return 0;
}

int handle_network_msg(char* msg)
{
    //printf("HANDLING NETWORK MSG: %s\n", msg);
    struct blob_attr *tb[__NETWORK_MAX];
    char *method;
    char *data;

    blob_buf_init(&network_buf, 0);
    blobmsg_add_json_from_string(&network_buf, msg);

    blobmsg_parse(network_policy, __NETWORK_MAX, tb, blob_data(network_buf.head), blob_len(network_buf.head));

    if(!tb[NETWORK_METHOD] ||!tb[NETWORK_DATA] )
    {
        return -1;
    }
    //method = blobmsg_get_string(tb[NETWORK_METHOD]);
    //data = blobmsg_get_string(tb[NETWORK_DATA]);

    method = blobmsg_data(tb[NETWORK_METHOD]);
    data = blobmsg_data(tb[NETWORK_DATA]);

    blob_buf_init(&data_buf, 0);
    blobmsg_add_json_from_string(&data_buf, data);


    //printf("DO STRINGCOMPARE: %s : %s!\n", method, data);
    if(!data_buf.head)
    {
        //printf("NULL?!\n");
        return -1;
    }

    if(blob_len(data_buf.head) <= 0)
    {
        //printf("NULL?!\n");
        return -1;
    }

    if(strlen(method) < 5)
    {
        //printf("STRING IS LESS THAN 5!\n");
        return -1;
    }

    if (strncmp(method, "probe", 5) == 0) {
        //printf("METHOD PROBE\n");
        probe_entry entry;
        if(parse_to_probe_req(data_buf.head, &entry) == 0)
        {
            insert_to_array(entry, 0);
            //print_probe_array();
        }
    } else if (strncmp(method, "clients", 5) == 0) {
        //printf("METHOD CLIENTS\n");
        //printf("PARSING CLIENTS NETWORK MSG!\n");
        parse_to_clients(data_buf.head, 0, 0);
    } else if (strncmp(method, "deauth", 5) == 0) {
        printf("METHOD DEAUTH\n");
        handle_deauth_req(data_buf.head);
    } else if (strncmp(method, "setprobe", 5) == 0) {
        printf("SET PROBE!\n");
        handle_set_probe(data_buf.head);
    }


        /*
        hostapd_notify_entry entry;
        parse_to_hostapd_notify(data_buf.head, &entry);

        client client_entry;
        memcpy(client_entry.bssid_addr, client_entry.bssid_addr, sizeof(uint8_t) * ETH_ALEN );
        memcpy(client_entry.client_addr, client_entry.client_addr, sizeof(uint8_t) * ETH_ALEN );

        pthread_mutex_lock(&client_array_mutex);
        client_array_delete(client_entry);
        pthread_mutex_unlock(&client_array_mutex);*/
    //}
    //free(method);
    //free(data);
    //printf("HANDLING FINISHED NETWORK MSG!\n");
    return 0;
}


int send_blob_attr_via_network(struct blob_attr *msg, char* method)
{
    if(!msg)
    {
        return -1;
    }

    char *data_str;
    char *str;
    data_str = blobmsg_format_json(msg, true);
    blob_buf_init(&b_send_network, 0);
    blobmsg_add_string(&b_send_network, "method", method);
    blobmsg_add_string(&b_send_network, "data", data_str);


    //blobmsg_add_blob(&b, msg);
    str = blobmsg_format_json(b_send_network.head, true);
    send_string_enc(str);
    //free(str);
    //free(data_str);
    return 0;
}

static int hostapd_notify(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg) {
    char *str;
    str = blobmsg_format_json(msg, true);
    printf("METHOD new: %s : %s\n", method, str);

    //TODO CHECK IF FREE IS CORREECT!
    free(str);


    // TODO: Only handle probe request and NOT assoc, ...

    if (strncmp(method, "probe", 5) == 0) {
        return handle_probe_req(msg);
    } else if (strncmp(method, "auth", 4) == 0) {
        return handle_auth_req(msg);
    } else if (strncmp(method, "assoc", 5) == 0) {
        return handle_assoc_req(msg);
    } else if (strncmp(method, "deauth", 6) == 0) {
        send_blob_attr_via_network(msg, "deauth");
        return handle_deauth_req(msg);
    }
    return 0;
}

static int add_subscriber(char *name) {
    uint32_t id = 0;

    if (ubus_lookup_id(ctx, name, &id)) {
        fprintf(stderr, "Failed to look up test object for %s\n", name);
        return -1;
    }

    if (hostapd_array_check_id(id)) {
        return 0;
    }

    int ret = ubus_subscribe(ctx, &hostapd_event, id);
    hostapd_array_insert(id);
    fprintf(stderr, "Watching object %08x: %s\n", id, ubus_strerror(ret));

    return 0;
}

static int subscribe_to_hostapd_interfaces(const char *hostapd_dir) {
    DIR *dirp;
    struct dirent *entry;

    if (ctx == NULL) {
        return 0;
    }

    dirp = opendir(hostapd_dir);  // error handling?
    if (!dirp) {
        fprintf(stderr, "No hostapd sockets!\n");
        return -1;
    }
    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            char subscribe_name[256];
            sprintf(subscribe_name, "hostapd.%s", entry->d_name);
            add_subscriber(subscribe_name);
        }
    }
    closedir(dirp);
    return 0;
}

static int subscribe_to_hostapd(const char *hostapd_dir) {

    if (ctx == NULL) {
        return 0;
    }

    printf("Registering ubus event subscriber!\n");
    int ret = ubus_register_subscriber(ctx, &hostapd_event);
    if (ret) {
        fprintf(stderr, "Failed to add watch handler: %s\n", ubus_strerror(ret));
        return -1;
    }

    // add callbacks
    hostapd_event.remove_cb = hostapd_handle_remove;
    hostapd_event.cb = hostapd_notify;

    subscribe_to_hostapd_interfaces(hostapd_dir);


    // free(hostapd_dir); // free string
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

    subscribe_to_hostapd(hostapd_dir);

    // update hostapd
    uloop_timeout_add(&hostapd_timer);

    // remove probe
    uloop_add_data_cbs();

    // get clients
    const char *ubus_socket_clients = NULL;
    ctx_clients = ubus_connect(ubus_socket_clients);
    uloop_timeout_add(&client_timer);


    //ubus_call_umdns();

    ubus_add_oject();

    uloop_run();


    close_socket();

    ubus_free(ctx);
    uloop_done();
    return 0;
}

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

    insert_client_to_array(client_entry);
}

static void
dump_client_table(struct blob_attr *head, int len, const char *bssid_addr, uint32_t freq, uint8_t ht_supported,
                  uint8_t vht_supported) {
    struct blob_attr *attr;
    struct blobmsg_hdr *hdr;

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
    }
}

int parse_to_clients(struct blob_attr *msg, int do_kick, uint32_t id) {
    struct blob_attr *tb[__CLIENT_TABLE_MAX];

    if(!msg)
    {
        return -1;
    }

    if(!blob_data(msg))
    {
        return -1;
    }

    if(blob_len(msg) <= 0)
    {
        return -1;
    }

    blobmsg_parse(client_table_policy, __CLIENT_TABLE_MAX, tb, blob_data(msg), blob_len(msg));

    if (tb[CLIENT_TABLE] && tb[CLIENT_TABLE_BSSID] && tb[CLIENT_TABLE_FREQ] && tb[CLIENT_TABLE_HT] &&
        tb[CLIENT_TABLE_VHT]) {
        dump_client_table(blobmsg_data(tb[CLIENT_TABLE]), blobmsg_data_len(tb[CLIENT_TABLE]),
                          blobmsg_data(tb[CLIENT_TABLE_BSSID]), blobmsg_get_u32(tb[CLIENT_TABLE_FREQ]),
                          blobmsg_get_u8(tb[CLIENT_TABLE_HT]), blobmsg_get_u8(tb[CLIENT_TABLE_VHT]));
        ap ap_entry;
        hwaddr_aton(blobmsg_data(tb[CLIENT_TABLE_BSSID]), ap_entry.bssid_addr);
        ap_entry.freq = blobmsg_get_u32(tb[CLIENT_TABLE_FREQ]);
        ap_entry.ht = blobmsg_get_u8(tb[CLIENT_TABLE_HT]);
        ap_entry.vht = blobmsg_get_u8(tb[CLIENT_TABLE_VHT]);
        ap_entry.channel_utilization = blobmsg_get_u32(tb[CLIENT_TABLE_CHAN_UTIL]);
        strcpy((char*)ap_entry.ssid, blobmsg_get_string(tb[CLIENT_TABLE_SSID]));

        if (tb[CLIENT_TABLE_NUM_STA]) {
            ap_entry.station_count = blobmsg_get_u32(tb[CLIENT_TABLE_NUM_STA]);
        } else {
            ap_entry.station_count = 0;
        }

        insert_to_ap_array(ap_entry);

        if (do_kick) {
            kick_clients(ap_entry.bssid_addr, id);
        }
    }
    return 0;
}

static void ubus_get_clients_cb(struct ubus_request *req, int type, struct blob_attr *msg) {

    if (!msg)
        return;

    send_blob_attr_via_network(msg, "clients");
    parse_to_clients(msg, 1, req->peer);

    print_client_array();
    print_ap_array();
}

static int ubus_get_clients() {
    for (int i = 0; i <= hostapd_sock_last; i++) {
        int timeout = 1;
        ubus_invoke(ctx_clients, hostapd_sock_arr[i], "get_clients", NULL, ubus_get_clients_cb, NULL, timeout * 1000);
    }
    return 0;
}

void update_clients(struct uloop_timeout *t) {
    ubus_get_clients();
    // maybe to much?! don't set timer again...
    uloop_timeout_set(&client_timer, timeout_config.update_client * 1000);
}

void update_hostapd_sockets(struct uloop_timeout *t) {
    subscribe_to_hostapd_interfaces(hostapd_dir_glob);
    uloop_timeout_set(&hostapd_timer, timeout_config.update_hostapd * 1000);
}

void del_client_all_interfaces(const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time) {
    /* Problem:
      On which interface is the client?
      First send to all ifaces to ban client... xD
      Maybe Hashmap?

      * get_clients method and look if client is there
      * save on which hostapd the client is...
    */

    blob_buf_init(&b, 0);
    blobmsg_add_macaddr(&b, "addr", client_addr);
    blobmsg_add_u32(&b, "reason", reason);
    blobmsg_add_u8(&b, "deauth", deauth);
    blobmsg_add_u32(&b, "ban_time", ban_time);

    for (int i = 0; i <= hostapd_sock_last; i++) {
        int timeout = 1;
        ubus_invoke(ctx_clients, hostapd_sock_arr[i], "del_client", b.head, NULL, NULL, timeout * 1000);
    }
}

void del_client_interface(uint32_t id, const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time) {

    blob_buf_init(&b, 0);
    blobmsg_add_macaddr(&b, "addr", client_addr);
    blobmsg_add_u32(&b, "reason", reason);
    blobmsg_add_u8(&b, "deauth", deauth);
    blobmsg_add_u32(&b, "ban_time", ban_time);

    int timeout = 1;
    ubus_invoke(ctx_clients, id, "del_client", b.head, NULL, NULL, timeout * 1000);
}

static void ubus_umdns_cb(struct ubus_request *req, int type, struct blob_attr *msg) {

    if (!msg)
        return;

    char *str = blobmsg_format_json(msg, true);
    printf("UMDNS:\n%s", str);
}

int ubus_call_umdns() {
    u_int32_t id;
    if (ubus_lookup_id(ctx, "umdns", &id)) {
        fprintf(stderr, "Failed to look up test object for %s\n", "umdns");
        return -1;
    }

    int timeout = 1;
    ubus_invoke(ctx_clients, id, "browse", NULL, ubus_umdns_cb, NULL, timeout * 1000);
    return 0;
}

int ubus_send_probe_via_network(struct probe_entry_s probe_entry) {

    printf("SENDING PROBE VIA NETWORK!\n");

    blob_buf_init(&b_probe, 0);
    blobmsg_add_macaddr(&b_probe, "bssid", probe_entry.bssid_addr);
    blobmsg_add_macaddr(&b_probe, "address", probe_entry.client_addr);
    blobmsg_add_macaddr(&b_probe, "target", probe_entry.target_addr);
    blobmsg_add_u32(&b_probe, "signal", probe_entry.signal);
    blobmsg_add_u32(&b_probe, "freq", probe_entry.freq);
    blobmsg_add_u8(&b_probe, "ht_support", probe_entry.ht_support);
    blobmsg_add_u8(&b_probe, "vht_support", probe_entry.vht_support);

    send_blob_attr_via_network(b_probe.head, "probe");

    return 0;
}

int send_set_probe(uint8_t client_addr[])
{

    printf("SENDING SET PROBE VIA NETWORK!\n");

    blob_buf_init(&b_probe, 0);
    blobmsg_add_macaddr(&b_probe, "bssid", client_addr);
    blobmsg_add_macaddr(&b_probe, "address", client_addr);

    send_blob_attr_via_network(b_probe.head, "set_probe");

    return 0;
}

enum {
    MAC_ADDR,
    __ADD_DEL_MAC_MAX
};

static const struct blobmsg_policy add_del_policy[__ADD_DEL_MAC_MAX] = {
        [MAC_ADDR] = { "addr", BLOBMSG_TYPE_STRING },
};

static const struct ubus_method dawn_methods[] = {
        UBUS_METHOD("add_mac", add_mac, add_del_policy),
        UBUS_METHOD_NOARG("get_hearing_map", get_hearing_map),
        UBUS_METHOD_NOARG("get_network", get_network)
        //UBUS_METHOD_NOARG("get_aps");
        //UBUS_METHOD_NOARG("get_clients");
};

static struct ubus_object_type dawn_object_type =
        UBUS_OBJECT_TYPE("dawn", dawn_methods);

static struct ubus_object dawn_object = {
        .name = "dawn",
        .type = &dawn_object_type,
        .methods = dawn_methods,
        .n_methods = ARRAY_SIZE(dawn_methods),
};

static int add_mac(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg) {

    struct blob_attr *tb[__ADD_DEL_MAC_MAX];
    uint8_t addr[ETH_ALEN];

    blobmsg_parse(add_del_policy, __ADD_DEL_MAC_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[MAC_ADDR])
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (hwaddr_aton(blobmsg_data(tb[MAC_ADDR]), addr))
        return UBUS_STATUS_INVALID_ARGUMENT;

    if(insert_to_maclist(addr) == 0)
    {
        write_mac_to_file("/etc/dawn/mac_list", addr);
    }

    return 0;
}

static int get_hearing_map(struct ubus_context *ctx, struct ubus_object *obj,
                   struct ubus_request_data *req, const char *method,
                   struct blob_attr *msg) {

    build_hearing_map_sort_client(&b);
    ubus_send_reply(ctx, req, b.head);
    return 0;
}


static int get_network(struct ubus_context *ctx, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg) {

    build_network_overview(&b);
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static void ubus_add_oject()
{
    int ret;

    ret = ubus_add_object(ctx, &dawn_object);
    if (ret)
        fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
    printf("ADDED UBUS OBJECT!!!\n");

    /*ret = ubus_register_subscriber(ctx, &test_event);
    if (ret)
        fprintf(stderr, "Failed to add watch handler: %s\n", ubus_strerror(ret));
    */
}