#ifndef __DAWN_UBUS_H
#define __DAWN_UBUS_H

#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>


#include "datastorage.h"

// 802.11 Status codes
#define WLAN_STATUS_SUCCESS 0
#define WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA 17
#define WLAN_STATUS_DENIED_NOT_HT_SUPPORT 27
#define WLAN_STATUS_DENIED_NOT_VHT_SUPPORT 104

// Disassociation Reason
#define UNSPECIFIED_REASON 0
#define NO_MORE_STAS 5

const char *hostapd_dir_glob;

/**
 * Init ubus.
 * Setup tcp socket.
 * Start ubus timer.
 * @param ubus_socket
 * @param hostapd_dir
 * @return
 */
int dawn_init_ubus(const char *ubus_socket, const char *hostapd_dir);

/**
 * Start the umdns timer for updating the zeroconfiguration properties.
 */
void start_umdns_update();

/**
 * Call umdns update to update the TCP connections.
 * @return
 */
int ubus_call_umdns();

/**
 * Parse to probe request.
 * @param msg
 * @param prob_req
 * @return
 */
int parse_to_probe_req(struct blob_attr *msg, probe_entry *prob_req);

/**
 * Parse to authentication request.
 * @param msg
 * @param auth_req
 * @return
 */
int parse_to_auth_req(struct blob_attr *msg, auth_entry *auth_req);

/**
 * Parse to association request.
 * @param msg
 * @param assoc_req
 * @return
 */
int parse_to_assoc_req(struct blob_attr *msg, assoc_entry *assoc_req);

/**
 * Dump a client array into the database.
 * @param msg - message to parse.
 * @param do_kick - use the automatic kick function when updating the clients.
 * @param id - ubus id.
 * @return
 */
int parse_to_clients(struct blob_attr *msg, int do_kick, uint32_t id);

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
int parse_to_hostapd_notify(struct blob_attr *msg, hostapd_notify_entry *notify_req);

/**
 * Kick client from all hostapd interfaces.
 * @param client_addr - the client adress of the client to kick.
 * @param reason - the reason to kick the client.
 * @param deauth - if the client should be deauthenticated.
 * @param ban_time - the ban time the client is not allowed to connect again.
 */
void del_client_all_interfaces(const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time);

/**
 * Update the hostapd sockets.
 * @param t
 */
void update_hostapd_sockets(struct uloop_timeout *t);

/**
 * Handle network messages.
 * @param msg
 * @return
 */
int handle_network_msg(char *msg);

/**
 * Send message via network.
 * @param msg
 * @param method
 * @return
 */
int send_blob_attr_via_network(struct blob_attr *msg, char *method);

/**
 * Add mac to a list that contains addresses of clients that can not be controlled.
 * @param buf
 * @param name
 * @param addr
 */
void blobmsg_add_macaddr(struct blob_buf *buf, const char *name, const uint8_t *addr);

/**
 * Send control message to all hosts to add the mac to a don't control list.
 * @param client_addr
 * @return
 */
int send_add_mac(uint8_t *client_addr);

int uci_send_via_network();

int build_hearing_map_sort_client(struct blob_buf *b);

int build_network_overview(struct blob_buf *b);

int ap_get_nr(struct blob_buf *b, uint8_t own_bssid_addr[]);

#endif
