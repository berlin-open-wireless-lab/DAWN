#ifndef __DAWN_UBUS_H
#define __DAWN_UBUS_H

#include "datastorage.h"

#define MIN_PROBE_REQ 2  // TODO: Parse from config file...

int dawn_init_ubus(const char *ubus_socket, char *hostapd_dir);
int parse_to_probe_req(struct blob_attr *msg, probe_entry *prob_req);
int parse_to_clients(struct blob_attr *msg);
void *update_clients_thread(void *arg);

char* hostapd_dir_glob;

#endif
