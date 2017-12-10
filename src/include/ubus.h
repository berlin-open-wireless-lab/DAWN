#ifndef __DAWN_UBUS_H
#define __DAWN_UBUS_H

#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>

#include "datastorage.h"

#define MIN_PROBE_REQ 2  // TODO: Parse from config file...

int dawn_init_ubus(const char *ubus_socket, char *hostapd_dir);

int parse_to_probe_req(struct blob_attr *msg, probe_entry *prob_req);

int parse_to_auth_req(struct blob_attr *msg, auth_entry *auth_req);

int parse_to_assoc_req(struct blob_attr *msg, assoc_entry *assoc_req);

int parse_to_clients(struct blob_attr *msg, int do_kick, uint32_t id);

void del_client_interface(uint32_t id, const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time);

void del_client_all_interfaces(const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time);

void *update_clients_thread(void *arg);

char *hostapd_dir_glob;

int ubus_call_umdns();

int ubus_send_probe_via_network(struct probe_entry_s probe_entry);

void update_hostapd_sockets(struct uloop_timeout *t);

void add_client_update_timer(time_t time);

#endif
