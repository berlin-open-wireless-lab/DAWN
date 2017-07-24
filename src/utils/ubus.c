#include <ctype.h>
#include <dirent.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <sys/types.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#include "ubus.h"

#include "networksocket.h"
#include "utils.h"

static struct ubus_context *ctx;
static struct ubus_subscriber hostapd_event;
static struct blob_buf b;

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
    CLIENT_TABLE_FREQ,
    CLIENT_TABLE_HT,
    CLIENT_TABLE_VHT,
    __CLIENT_TABLE_MAX,
};

static const struct blobmsg_policy client_table_policy[__CLIENT_TABLE_MAX] = {
        [CLIENT_TABLE] = {.name = "clients", .type = BLOBMSG_TYPE_TABLE},
        [CLIENT_TABLE_BSSID] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
        [CLIENT_TABLE_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
        [CLIENT_TABLE_HT] = {.name = "ht_supported", .type = BLOBMSG_TYPE_INT8},
        [CLIENT_TABLE_VHT] = {.name = "vht_supported", .type = BLOBMSG_TYPE_INT8},
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

static int subscribe_to_hostapd_interfaces(char *hostapd_dir);

static int ubus_get_clients();

/*
static int decide_function(probe_entry *prob_req) {
  // TODO: Refactor...
  if (prob_req->counter < MIN_PROBE_REQ) {
    return 0;
  }

  int ret =
      mac_first_in_probe_list(prob_req->bssid_addr, prob_req->client_addr);
  if (ret) {
    printf("Mac will be accepted!\n");
  } else {
    printf("Mac will be declined!\n");
  }
  return ret;
}
*/
static void hostapd_handle_remove(struct ubus_context *ctx,
                                  struct ubus_subscriber *s, uint32_t id) {
    fprintf(stderr, "Object %08x went away\n", id);
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

static int hostapd_notify(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg) {
    probe_entry prob_req;
    parse_to_probe_req(msg, &prob_req);
    //insert_to_list(prob_req, 1);
    insert_to_array(prob_req, 1);

    // send probe via network
    char *str;
    str = blobmsg_format_json(msg, true);
    send_string(str);

    printf("[WC] Hostapd-Probe: %s : %s\n", method, str);

    print_array();

    // sleep(2); // sleep for 2s

    // deny access
    //if (!decide_function(&prob_req)) {
    //  return UBUS_STATUS_UNKNOWN_ERROR;
    //}

    // allow access
    return 0;
}

static int add_subscriber(char *name) {
    uint32_t id = 0;

    if (ubus_lookup_id(ctx, name, &id)) {
        fprintf(stderr, "Failed to look up test object for %s\n", name);
        return -1;
    }

    // add callbacks
    hostapd_event.remove_cb = hostapd_handle_remove;
    hostapd_event.cb = hostapd_notify;

    int ret = ubus_subscribe(ctx, &hostapd_event, id);

    fprintf(stderr, "Watching object %08x: %s\n", id, ubus_strerror(ret));

    return 0;
}

static int subscribe_to_hostapd_interfaces(char *hostapd_dir) {
    DIR *dirp;
    struct dirent *entry;

    int ret = ubus_register_subscriber(ctx, &hostapd_event);
    if (ret) {
        fprintf(stderr, "Failed to add watch handler: %s\n", ubus_strerror(ret));
        return -1;
    }

    dirp = opendir(hostapd_dir);  // error handling?
    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            char subscribe_name[256];
            sprintf(subscribe_name, "hostapd.%s", entry->d_name);
            printf("Subscribing to %s\n", subscribe_name);
            add_subscriber(subscribe_name);
        }
    }
    // free(hostapd_dir); // free string
    return 0;
}

int dawn_init_ubus(const char *ubus_socket, char *hostapd_dir) {
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

    subscribe_to_hostapd_interfaces(hostapd_dir);

    ubus_get_clients();

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

    //char mac_buf_client[20];
    //char mac_buf_ap[20];

    //sprintf(mac_buf_ap, "%x:%x:%x:%x:%x:%x", MAC2STR(client_entry.bssid_addr));
    //sprintf(mac_buf_client, "%x:%x:%x:%x:%x:%x", MAC2STR(client_entry.client_addr));
    //printf("Frequency is: %d\n",freq);
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
        sscanf((char *) hdr->name, "%x:%x:%x:%x:%x:%x", STR2MAC(tmp_int_mac));
        for (int i = 0; i < ETH_ALEN; ++i)
            tmp_mac[i] = (uint8_t) tmp_int_mac[i];

        dump_client(tb, tmp_mac, bssid_addr, freq, ht_supported, vht_supported);
    }
}

int parse_to_clients(struct blob_attr *msg) {
    struct blob_attr *tb[__CLIENT_TABLE_MAX];

    blobmsg_parse(client_table_policy, __CLIENT_TABLE_MAX, tb, blob_data(msg), blob_len(msg));

    if (tb[CLIENT_TABLE] && tb[CLIENT_TABLE_BSSID] && tb[CLIENT_TABLE_FREQ] && tb[CLIENT_TABLE_HT] &&
        tb[CLIENT_TABLE_VHT]) {
        dump_client_table(blobmsg_data(tb[CLIENT_TABLE]), blobmsg_data_len(tb[CLIENT_TABLE]),
                          blobmsg_data(tb[CLIENT_TABLE_BSSID]), blobmsg_get_u32(tb[CLIENT_TABLE_FREQ]),
                          blobmsg_get_u8(tb[CLIENT_TABLE_HT]), blobmsg_get_u8(tb[CLIENT_TABLE_VHT]));

        /* BSSID */
        /*
          * here i know my bssid to kick the clients
          * seems a good idea ?!
         */
        uint8_t bssid[ETH_ALEN];
        hwaddr_aton(blobmsg_data(tb[CLIENT_TABLE_BSSID]), bssid);
        kick_clients(bssid);
    }

    return 0;
}

static void ubus_get_clients_cb(struct ubus_request *req, int type, struct blob_attr *msg) {
    if (!msg)
        return;

    parse_to_clients(msg);

    char *str = blobmsg_format_json(msg, true);
    send_string(str);
    print_client_array();
}

static int ubus_get_clients() {
    DIR *dirp;
    struct dirent *entry;

    dirp = opendir(hostapd_dir_glob);  // error handling?
    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            char hostapd_iface[256];
            uint32_t id;
            sprintf(hostapd_iface, "hostapd.%s", entry->d_name);
            int ret = ubus_lookup_id(ctx, hostapd_iface, &id);
            if (!ret) {
                int timeout = 1;
                ubus_invoke(ctx, id, "get_clients", NULL, ubus_get_clients_cb, NULL, timeout * 1000);
            }
        }
    }
    return 0;
}

void *update_clients_thread(void *arg) {
    while (1) {
        sleep(TIME_THRESHOLD_CLIENT_UPDATE);
        printf("[Thread] : Updating clients!\n");
        ubus_get_clients();
    }
    return 0;
}

/* hostapd function */
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

static void
bblobmsg_add_macaddr(struct blob_buf *buf, const char *name, const uint8_t *addr) {
    char *s;

    s = blobmsg_alloc_string_buffer(buf, name, 20);
    sprintf(s, MACSTR, MAC2STR(addr));
    blobmsg_add_string_buffer(buf);
}

void del_client(const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time) {
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

    DIR *dirp;
    struct dirent *entry;
    dirp = opendir(hostapd_dir_glob);  // error handling?
    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            char hostapd_iface[256];
            uint32_t id;
            sprintf(hostapd_iface, "hostapd.%s", entry->d_name);
            int ret = ubus_lookup_id(ctx, hostapd_iface, &id);
            if (!ret) {
                int timeout = 1;
                ubus_invoke(ctx, id, "del_client", b.head, NULL, NULL, timeout * 1000);
            }
        }
    }
}