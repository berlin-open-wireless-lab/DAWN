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

enum {
  PROB_BSSID_ADDR,
  PROB_CLIENT_ADDR,
  PROB_TARGET_ADDR,
  PROB_SIGNAL,
  PROB_FREQ,
  __PROB_MAX,
};

static const struct blobmsg_policy prob_policy[__PROB_MAX] = {
        [PROB_BSSID_ADDR] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
        [PROB_CLIENT_ADDR] = {.name = "address", .type = BLOBMSG_TYPE_STRING},
        [PROB_TARGET_ADDR] = {.name = "target", .type = BLOBMSG_TYPE_STRING},
        [PROB_SIGNAL] = {.name = "signal", .type = BLOBMSG_TYPE_INT32},
        [PROB_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
};

enum {
  CLIENT_TABLE,
  CLIENT_TABLE_FREQ,
  __CLIENT_TABLE_MAX,
};

static const struct blobmsg_policy client_table_policy[__CLIENT_TABLE_MAX] = {
    [CLIENT_TABLE] = {.name = "clients", .type = BLOBMSG_TYPE_TABLE},
    [CLIENT_TABLE_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
};

enum {
  //CLIENT_TABLE,
  //CLIENT_TABLE_FREQ,
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
    //[CLIENT_TABLE] = {.name = "clients", .type = BLOBMSG_TYPE_TABLE},
    //[CLIENT_TABLE_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
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
dump_client(struct blob_attr **tb)
{
  printf("DUMPING CLIENT:\n");

  if (tb[CLIENT_AUTH]) {
    printf("AUTH: %d\n", blobmsg_get_u8(tb[CLIENT_AUTH]));
  }
  if (tb[CLIENT_ASSOC]) {
    printf("ASSOC: %d\n", blobmsg_get_u8(tb[CLIENT_ASSOC]));
  }

  if(tb[CLIENT_PREAUTH]){
    printf("Preauth: %d\n", blobmsg_get_u8(tb[CLIENT_PREAUTH]));
  }
  if(tb[CLIENT_HT]){
    printf("HT: %d\n", blobmsg_get_u8(tb[CLIENT_HT]));
  }
  if(tb[CLIENT_HT]){
    printf("AID: %d\n", blobmsg_get_u32(tb[CLIENT_AID]));
  }
  printf("Dumped Client!\n");
}

static void
dump_client_table(struct blob_attr *head, int len)
{
  struct blob_attr *attr;
  struct blobmsg_hdr *hdr;

  __blob_for_each_attr(attr, head, len) {
    hdr = blob_data(attr);
    printf("%s\n", hdr->name); // mac client

    struct blob_attr *tb[__CLIENT_MAX];
    blobmsg_parse(client_policy, __CLIENT_MAX, tb, blobmsg_data(attr), blobmsg_len(attr));
    char* str = blobmsg_format_json_indent(attr, true, -1);
    printf("%s\n", str);

    dump_client(tb);
  }
}

static int parse_to_clients(struct blob_attr *msg) {
  struct blob_attr *tb[__CLIENT_TABLE_MAX];

  blobmsg_parse(client_table_policy, __CLIENT_TABLE_MAX, tb, blob_data(msg), blob_len(msg));

  if (tb[CLIENT_TABLE]) {
    dump_client_table(blobmsg_data(tb[CLIENT_TABLE]), blobmsg_data_len(tb[CLIENT_TABLE]));
  }

  printf("Parsing client request success!!!\n");
  return 0;
}

static void ubus_get_clients_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
  char *str;
  if (!msg)
    return;

  parse_to_clients(msg);

  str = blobmsg_format_json_indent(msg, true, -1);
  printf("%s\n", str);
  free(str);
}

static int ubus_get_clients() {
  uint32_t id;
  int ret = ubus_lookup_id(ctx, "hostapd.wlan0", &id);
  if (ret)
    return ret;
  int timeout = 1;
  int ubus_shit = ubus_invoke(ctx, id, "get_clients", NULL, ubus_get_clients_cb, NULL, timeout * 1000);
  printf("Ubus Shit: %d", ubus_shit);
  return ubus_shit;
}