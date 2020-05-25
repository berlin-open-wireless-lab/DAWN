#ifndef __DAWN_UFACE_H
#define __DAWN_UFACE_H

/**
 * Set client timer for updating the clients.
 * @param time
 */
void add_client_update_timer(time_t time);

/**
 * Kick client from hostapd interface.
 * @param id - the ubus id.
 * @param client_addr - the client adress of the client to kick.
 * @param reason - the reason to kick the client.
 * @param deauth - if the client should be deauthenticated.
 * @param ban_time - the ban time the client is not allowed to connect again.
 */
void del_client_interface(uint32_t id, const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time);

/**
 * Function to set the probe counter to the min probe request.
 * This allows that the client is able to connect directly without sending multiple probe requests to the Access Point.
 * @param client_addr
 * @return
 */
int send_set_probe(uint8_t client_addr[]);

void ubus_send_beacon_report(uint8_t client[], int id);

/**
 * Send probe message via the network.
 * @param probe_entry
 * @return
 */
int ubus_send_probe_via_network(struct probe_entry_s probe_entry);

void uloop_add_data_cbs();

void wnm_disassoc_imminent(uint32_t id, const uint8_t *client_addr, char* dest_ap, uint32_t duration);

#endif // __DAWN_UFACE_H
