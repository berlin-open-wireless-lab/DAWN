#ifndef __DAWN_UBUS_H
#define __DAWN_UBUS_H

#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>

#include "datastorage.h"

void start_umdns_update();

int dawn_init_ubus(const char *ubus_socket, const char *hostapd_dir);

int parse_to_probe_req(struct blob_attr *msg, probe_entry *prob_req);

int parse_to_auth_req(struct blob_attr *msg, auth_entry *auth_req);

int parse_to_assoc_req(struct blob_attr *msg, assoc_entry *assoc_req);

int parse_to_clients(struct blob_attr *msg, int do_kick, uint32_t id);

int parse_to_hostapd_notify(struct blob_attr *msg, hostapd_notify_entry *notify_req);

void del_client_interface(uint32_t id, const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time);

void del_client_all_interfaces(const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time);

void *update_clients_thread(void *arg);

void *update_connections_thread(void *arg);

const char *hostapd_dir_glob;

int ubus_call_umdns();

int ubus_send_probe_via_network(struct probe_entry_s probe_entry);

void update_hostapd_sockets(struct uloop_timeout *t);

void add_client_update_timer(time_t time);

int handle_network_msg(char* msg);

int send_blob_attr_via_network(struct blob_attr *msg, char* method);

void blobmsg_add_macaddr(struct blob_buf *buf, const char *name, const uint8_t *addr);

int send_set_probe(uint8_t client_addr[]);

int send_add_mac(uint8_t* client_addr);

#endif
