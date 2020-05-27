#ifndef __DAWN_MSGHANDLER_H
#define __DAWN_MSGHANDLER_H

#include <libubox/blobmsg_json.h>

#include "datastorage.h"

/**
 * Parse to probe request.
 * @param msg
 * @param prob_req
 * @return
 */
int parse_to_probe_req(struct blob_attr* msg, probe_entry* prob_req);

/**
 * Dump a client array into the database.
 * @param msg - message to parse.
 * @param do_kick - use the automatic kick function when updating the clients.
 * @param id - ubus id.
 * @return
 */
int parse_to_clients(struct blob_attr* msg, int do_kick, uint32_t id);

/**
 * Parse to hostapd notify.
 * Notify are such notifications like:
 * + Disassociation
 * + Deauthentication
 * + ...
 * @param msg
 * @param notify_req
 * @return
 */
int parse_to_hostapd_notify(struct blob_attr* msg, hostapd_notify_entry* notify_req);

/**
 * Handle network messages.
 * @param msg
 * @return
 */
int handle_network_msg(char* msg);


int handle_deauth_req(struct blob_attr* msg);

#endif
