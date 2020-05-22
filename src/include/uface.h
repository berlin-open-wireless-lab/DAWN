void send_beacon_report(uint8_t client[], int id);
int send_probe_via_network(struct probe_entry_s probe_entry);

int send_set_probe(uint8_t client_addr[]);
void wnm_disassoc_imminent(uint32_t id, const uint8_t *client_addr, char* dest_ap, uint32_t duration);
void add_client_update_timer(time_t time);
void del_client_interface(uint32_t id, const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time);

