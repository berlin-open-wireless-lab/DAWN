#ifndef __DAWN_UBUS_H
#define __DAWN_UBUS_H

#include "datastorage.h"

int dawn_init_ubus(const char *ubus_socket);
int parse_to_probe_req(struct blob_attr *msg, probe_entry* prob_req);


#endif
