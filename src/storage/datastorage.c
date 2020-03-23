#include "datastorage.h"

#include <limits.h>
#include <libubox/uloop.h>

#include "ubus.h"
#include "dawn_iwinfo.h"
#include "utils.h"
#include "ieee80211_utils.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

int go_next_help(char sort_order[], int i, probe_entry entry,
                 probe_entry next_entry);

int go_next(char sort_order[], int i, probe_entry entry,
            probe_entry next_entry);

void remove_old_probe_entries(time_t current_time, long long int threshold);

int client_array_go_next(char sort_order[], int i, client entry,
                         client next_entry);

int client_array_go_next_help(char sort_order[], int i, client entry,
                              client next_entry);

void remove_old_client_entries(time_t current_time, long long int threshold);

int eval_probe_metric(struct probe_entry_s probe_entry);

int kick_client(struct client_s client_entry);

void ap_array_insert(ap entry);

ap ap_array_delete(ap entry);

void remove_old_ap_entries(time_t current_time, long long int threshold);

void print_ap_entry(ap entry);

int probe_array_update_rssi(uint8_t bssid_addr[], uint8_t client_addr[], uint32_t rssi);

int is_connected(uint8_t bssid_addr[], uint8_t client_addr[]);

int is_connected_somehwere(uint8_t client_addr[]);

int compare_station_count(uint8_t *bssid_addr_own, uint8_t *bssid_addr_to_compare, uint8_t *client_addr,
                          int automatic_kick);

int compare_ssid(uint8_t *bssid_addr_own, uint8_t *bssid_addr_to_compare);

void denied_req_array_insert(auth_entry entry);

auth_entry denied_req_array_delete(auth_entry entry);

int denied_req_array_go_next(char sort_order[], int i, auth_entry entry,
                             auth_entry next_entry);

int denied_req_array_go_next_help(char sort_order[], int i, auth_entry entry,
                                  auth_entry next_entry);

int probe_entry_last = -1;
int client_entry_last = -1;
int ap_entry_last = -1;
int mac_list_entry_last = -1;
int denied_req_last = -1;

void remove_probe_array_cb(struct uloop_timeout *t);

struct uloop_timeout probe_timeout = {
        .cb = remove_probe_array_cb
};

void remove_client_array_cb(struct uloop_timeout *t);

struct uloop_timeout client_timeout = {
        .cb = remove_client_array_cb
};

void remove_ap_array_cb(struct uloop_timeout *t);

struct uloop_timeout ap_timeout = {
        .cb = remove_ap_array_cb
};

void denied_req_array_cb(struct uloop_timeout *t);

struct uloop_timeout denied_req_timeout = {
        .cb = denied_req_array_cb
};

int build_hearing_map_sort_client(struct blob_buf *b) {
    print_probe_array();
    pthread_mutex_lock(&probe_array_mutex);

    void *client_list, *ap_list, *ssid_list;
    char ap_mac_buf[20];
    char client_mac_buf[20];

    blob_buf_init(b, 0);
    int m;
    for (m = 0; m <= ap_entry_last; m++) {
        if (m > 0) {
            if (strcmp((char *) ap_array[m].ssid, (char *) ap_array[m - 1].ssid) == 0) {
                continue;
            }
        }
        ssid_list = blobmsg_open_table(b, (char *) ap_array[m].ssid);

        int i;
        for (i = 0; i <= probe_entry_last; i++) {
            /*if(!mac_is_equal(ap_array[m].bssid_addr, probe_array[i].bssid_addr))
            {
                continue;
            }*/

            ap ap_entry_i = ap_array_get_ap(probe_array[i].bssid_addr);

            if (!mac_is_equal(ap_entry_i.bssid_addr, probe_array[i].bssid_addr)) {
                continue;
            }

            if (strcmp((char *) ap_entry_i.ssid, (char *) ap_array[m].ssid) != 0) {
                continue;
            }

            int k;
            sprintf(client_mac_buf, MACSTR, MAC2STR(probe_array[i].client_addr));
            client_list = blobmsg_open_table(b, client_mac_buf);
            for (k = i; k <= probe_entry_last; k++) {
                ap ap_entry = ap_array_get_ap(probe_array[k].bssid_addr);

                if (!mac_is_equal(ap_entry.bssid_addr, probe_array[k].bssid_addr)) {
                    continue;
                }

                if (strcmp((char *) ap_entry.ssid, (char *) ap_array[m].ssid) != 0) {
                    continue;
                }

                if (!mac_is_equal(probe_array[k].client_addr, probe_array[i].client_addr)) {
                    i = k - 1;
                    break;
                } else if (k == probe_entry_last) {
                    i = k;
                }

                sprintf(ap_mac_buf, MACSTR, MAC2STR(probe_array[k].bssid_addr));
                ap_list = blobmsg_open_table(b, ap_mac_buf);
                blobmsg_add_u32(b, "signal", probe_array[k].signal);
                blobmsg_add_u32(b, "freq", probe_array[k].freq);
                blobmsg_add_u8(b, "ht_capabilities", probe_array[k].ht_capabilities);
                blobmsg_add_u8(b, "vht_capabilities", probe_array[k].vht_capabilities);


                // check if ap entry is available
                blobmsg_add_u32(b, "channel_utilization", ap_entry.channel_utilization);
                blobmsg_add_u32(b, "num_sta", ap_entry.station_count);
                blobmsg_add_u8(b, "ht_support", ap_entry.ht_support);
                blobmsg_add_u8(b, "vht_support", ap_entry.vht_support);

                blobmsg_add_u32(b, "score", eval_probe_metric(probe_array[k]));
                blobmsg_close_table(b, ap_list);
            }
            blobmsg_close_table(b, client_list);
        }
        blobmsg_close_table(b, ssid_list);
    }
    pthread_mutex_unlock(&probe_array_mutex);
    return 0;
}

int build_network_overview(struct blob_buf *b) {
    void *client_list, *ap_list, *ssid_list;
    char ap_mac_buf[20];
    char client_mac_buf[20];

    blob_buf_init(b, 0);
    int m;
    for (m = 0; m <= ap_entry_last; m++) {
        if (m > 0) {
            if (strcmp((char *) ap_array[m].ssid, (char *) ap_array[m - 1].ssid) == 0) {
                continue;
            }
        }

        ssid_list = blobmsg_open_table(b, (char *) ap_array[m].ssid);

        int i;
        for (i = 0; i <= client_entry_last; i++) {
            ap ap_entry_i = ap_array_get_ap(client_array[i].bssid_addr);

            if (strcmp((char *) ap_entry_i.ssid, (char *) ap_array[m].ssid) != 0) {
                continue;
            }
            int k;
            sprintf(ap_mac_buf, MACSTR, MAC2STR(client_array[i].bssid_addr));
            ap_list = blobmsg_open_table(b, ap_mac_buf);

            blobmsg_add_u32(b, "freq", ap_entry_i.freq);
            blobmsg_add_u32(b, "channel_utilization", ap_entry_i.channel_utilization);
            blobmsg_add_u32(b, "num_sta", ap_entry_i.station_count);
            blobmsg_add_u8(b, "ht_support", ap_entry_i.ht_support);
            blobmsg_add_u8(b, "vht_support", ap_entry_i.vht_support);            

            for (k = i; k <= client_entry_last; k++) {
                if (!mac_is_equal(client_array[k].bssid_addr, client_array[i].bssid_addr)) {
                    i = k - 1;
                    break;
                } else if (k == client_entry_last) {
                    i = k;
                }

                sprintf(client_mac_buf, MACSTR, MAC2STR(client_array[k].client_addr));
                client_list = blobmsg_open_table(b, client_mac_buf);
                if(strlen(client_array[k].signature) != 0)
                {
                    char *s;
                    s = blobmsg_alloc_string_buffer(b, "signature", 1024);
                    sprintf(s, "%s", client_array[k].signature);
                    blobmsg_add_string_buffer(b);
                }
                blobmsg_add_u8(b, "ht", client_array[k].ht);
                blobmsg_add_u8(b, "vht", client_array[k].vht);
                blobmsg_add_u32(b, "collision_count", ap_get_collision_count(ap_array[m].collision_domain));

                int n;
                for(n = 0; n <= probe_entry_last; n++)
                {
                    if (mac_is_equal(client_array[k].client_addr, probe_array[n].client_addr) &&
                            mac_is_equal(client_array[k].bssid_addr, probe_array[n].bssid_addr)) {
                        blobmsg_add_u32(b, "signal", probe_array[n].signal);
                        break;
                    }
                }
                blobmsg_close_table(b, client_list);
            }
            blobmsg_close_table(b, ap_list);
        }
        blobmsg_close_table(b, ssid_list);
    }
    return 0;
}

int eval_probe_metric(struct probe_entry_s probe_entry) {

    int score = 0;

    ap ap_entry = ap_array_get_ap(probe_entry.bssid_addr);

    // check if ap entry is available
    if (mac_is_equal(ap_entry.bssid_addr, probe_entry.bssid_addr)) {
        score += probe_entry.ht_capabilities && ap_entry.ht_support ? dawn_metric.ht_support : 0;
        score += !probe_entry.ht_capabilities && !ap_entry.ht_support ? dawn_metric.no_ht_support : 0;

        // performance anomaly?
        if (network_config.bandwidth >= 1000 || network_config.bandwidth == -1) {
            score += probe_entry.vht_capabilities && ap_entry.vht_support ? dawn_metric.vht_support : 0;
        }

        score += !probe_entry.vht_capabilities && !ap_entry.vht_support ? dawn_metric.no_vht_support : 0;
        score += ap_entry.channel_utilization <= dawn_metric.chan_util_val ? dawn_metric.chan_util : 0;
        score += ap_entry.channel_utilization > dawn_metric.max_chan_util_val ? dawn_metric.max_chan_util : 0;

        score += ap_entry.ap_weight;
    }

    score += (probe_entry.freq > 5000) ? dawn_metric.freq : 0;
    score += (probe_entry.signal >= dawn_metric.rssi_val) ? dawn_metric.rssi : 0;
    score += (probe_entry.signal <= dawn_metric.low_rssi_val) ? dawn_metric.low_rssi : 0;

    if (score < 0)
        score = -2; // -1 already used...

    printf("Score: %d of:\n", score);
    print_probe_entry(probe_entry);

    return score;
}

int compare_ssid(uint8_t *bssid_addr_own, uint8_t *bssid_addr_to_compare) {
    ap ap_entry_own = ap_array_get_ap(bssid_addr_own);
    ap ap_entry_to_compre = ap_array_get_ap(bssid_addr_to_compare);

    if (mac_is_equal(ap_entry_own.bssid_addr, bssid_addr_own) &&
        mac_is_equal(ap_entry_to_compre.bssid_addr, bssid_addr_to_compare)) {
        return (strcmp((char *) ap_entry_own.ssid, (char *) ap_entry_to_compre.ssid) == 0);
    }
    return 0;
}

int compare_station_count(uint8_t *bssid_addr_own, uint8_t *bssid_addr_to_compare, uint8_t *client_addr,
                          int automatic_kick) {

    ap ap_entry_own = ap_array_get_ap(bssid_addr_own);
    ap ap_entry_to_compre = ap_array_get_ap(bssid_addr_to_compare);

    // check if ap entry is available
    if (mac_is_equal(ap_entry_own.bssid_addr, bssid_addr_own)
        && mac_is_equal(ap_entry_to_compre.bssid_addr, bssid_addr_to_compare)
            ) {
        printf("Comparing own %d to %d\n", ap_entry_own.station_count, ap_entry_to_compre.station_count);


        int sta_count = ap_entry_own.station_count;
        int sta_count_to_compare = ap_entry_to_compre.station_count;
        if (is_connected(bssid_addr_own, client_addr)) {
            printf("Own is already connected! Decrease counter!\n");
            sta_count--;
        }

        if (is_connected(bssid_addr_to_compare, client_addr)) {
            printf("Comparing station is already connected! Decrease counter!\n");
            sta_count_to_compare--;
        }
        printf("Comparing own station count %d to %d\n", sta_count, sta_count_to_compare);

        return sta_count - sta_count_to_compare > dawn_metric.max_station_diff;
    }

    return 0;
}


int better_ap_available(uint8_t bssid_addr[], uint8_t client_addr[], int automatic_kick) {
    int own_score = -1;

    // find first client entry in probe array
    int i;
    for (i = 0; i <= probe_entry_last; i++) {
        if (mac_is_equal(probe_array[i].client_addr, client_addr)) {
            break;
        }
    }

    // find own probe entry and calculate score
    int j;
    for (j = i; j <= probe_entry_last; j++) {
        if (!mac_is_equal(probe_array[j].client_addr, client_addr)) {
            // this shouldn't happen!
            //return 1; // kick client!
            //return 0;
            break;
        }
        if (mac_is_equal(bssid_addr, probe_array[j].bssid_addr)) {
            printf("Calculating own score!\n");
            own_score = eval_probe_metric(probe_array[j]);
            break;
        }
    }

    // no entry for own ap
    if (own_score == -1) {
        return -1;
    }

    int k;
    for (k = i; k <= probe_entry_last; k++) {
        int score_to_compare;

        if (!mac_is_equal(probe_array[k].client_addr, client_addr)) {
            break;
        }

        if (mac_is_equal(bssid_addr, probe_array[k].bssid_addr)) {
            printf("Own Score! Skipping!\n");
            print_probe_entry(probe_array[k]);
            continue;
        }

        // check if same ssid!
        if (!compare_ssid(bssid_addr, probe_array[k].bssid_addr)) {
            continue;
        }

        printf("Calculating score to compare!\n");
        score_to_compare = eval_probe_metric(probe_array[k]);

        if (own_score < score_to_compare) {
            return 1;
        }
        if (dawn_metric.use_station_count && own_score == score_to_compare) {

            // only compare if score is bigger or equal 0
            if (own_score >= 0) {

                // if ap have same value but station count is different...
                if (compare_station_count(bssid_addr, probe_array[k].bssid_addr, probe_array[k].client_addr,
                                          automatic_kick)) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

int kick_client(struct client_s client_entry) {
    return !mac_in_maclist(client_entry.client_addr) &&
           better_ap_available(client_entry.bssid_addr, client_entry.client_addr, 1);
}

void kick_clients(uint8_t bssid[], uint32_t id) {
    pthread_mutex_lock(&client_array_mutex);
    pthread_mutex_lock(&probe_array_mutex);
    printf("-------- KICKING CLIENS!!!---------\n");
    char mac_buf_ap[20];
    sprintf(mac_buf_ap, MACSTR, MAC2STR(bssid));
    printf("EVAL %s\n", mac_buf_ap);

    // Seach for BSSID
    int i;
    for (i = 0; i <= client_entry_last; i++) {
        if (mac_is_equal(client_array[i].bssid_addr, bssid)) {
            break;
        }
    }

    // Go threw clients
    int j;
    for (j = i; j <= client_entry_last; j++) {
        if (!mac_is_equal(client_array[j].bssid_addr, bssid)) {
            break;
        }

        // update rssi
        int rssi = get_rssi_iwinfo(client_array[j].client_addr);
        int exp_thr = get_expected_throughput_iwinfo(client_array[j].client_addr);
        double exp_thr_tmp = iee80211_calculate_expected_throughput_mbit(exp_thr);
        printf("Expectd throughput %f Mbit/sec\n", exp_thr_tmp);

        if (rssi != INT_MIN) {
            pthread_mutex_unlock(&probe_array_mutex);
            if (!probe_array_update_rssi(client_array[j].bssid_addr, client_array[j].client_addr, rssi)) {
                printf("Failed to update rssi!\n");
            } else {
                printf("Updated rssi: %d\n", rssi);
            }
            pthread_mutex_lock(&probe_array_mutex);

        }

        int do_kick = kick_client(client_array[j]);

        // better ap available
        if (do_kick > 0) {

            // kick after algorithm decided to kick several times
            // + rssi is changing a lot
            // + chan util is changing a lot
            // + ping pong behavior of clients will be reduced
            client_array[j].kick_count++;
            printf("Comparing kick count! kickcount: %d to min_kick_count: %d!\n", client_array[j].kick_count,
                   dawn_metric.min_kick_count);
            if (client_array[j].kick_count < dawn_metric.min_kick_count) {
                continue;
            }

            printf("Better AP available. Kicking client:\n");
            print_client_entry(client_array[j]);
            printf("Check if client is active receiving!\n");

            float rx_rate, tx_rate;
            if (get_bandwidth_iwinfo(client_array[j].client_addr, &rx_rate, &tx_rate)) {
                // only use rx_rate for indicating if transmission is going on
                // <= 6MBits <- probably no transmission
                // tx_rate has always some weird value so don't use ist
                if (rx_rate > dawn_metric.bandwith_threshold) {
                    printf("Client is probably in active transmisison. Don't kick! RxRate is: %f\n", rx_rate);
                    continue;
                }
            }
            printf("Client is probably NOT in active transmisison. KICK! RxRate is: %f\n", rx_rate);


            // here we should send a messsage to set the probe.count for all aps to the min that there is no delay between switching
            // the hearing map is full...
            send_set_probe(client_array[j].client_addr);

            // don't deauth station? <- deauth is better!
            // maybe we can use handovers...
            del_client_interface(id, client_array[j].client_addr, NO_MORE_STAS, 1, 1000);
            client_array_delete(client_array[j]);

            // don't delete clients in a row. use update function again...
            // -> chan_util update, ...
            add_client_update_timer(timeout_config.update_client * 1000 / 4);
            break;

            // no entry in probe array for own bssid
        } else if (do_kick == -1) {
            printf("No Information about client. Force reconnect:\n");
            print_client_entry(client_array[j]);
            del_client_interface(id, client_array[j].client_addr, 0, 1, 0);

            // ap is best
        } else {
            printf("AP is best. Client will stay:\n");
            print_client_entry(client_array[j]);
            // set kick counter to 0 again
            client_array[j].kick_count = 0;
        }
    }

    printf("---------------------------\n");

    pthread_mutex_unlock(&probe_array_mutex);
    pthread_mutex_unlock(&client_array_mutex);
}

int is_connected_somehwere(uint8_t client_addr[]) {
    int i;
    int found_in_array = 0;

    if (client_entry_last == -1) {
        return 0;
    }

    for (i = 0; i <= client_entry_last; i++) {
        if (mac_is_equal(client_addr, client_array[i].client_addr)) {
            found_in_array = 1;
            break;
        }
    }
    return found_in_array;
}

int is_connected(uint8_t bssid_addr[], uint8_t client_addr[]) {
    int i;
    int found_in_array = 0;

    if (client_entry_last == -1) {
        return 0;
    }

    for (i = 0; i <= client_entry_last; i++) {

        if (mac_is_equal(bssid_addr, client_array[i].bssid_addr) &&
            mac_is_equal(client_addr, client_array[i].client_addr)) {
            found_in_array = 1;
            break;
        }
    }
    return found_in_array;
}

int client_array_go_next_help(char sort_order[], int i, client entry,
                              client next_entry) {
    switch (sort_order[i]) {
        // bssid-mac
        case 'b':
            return mac_is_greater(entry.bssid_addr, next_entry.bssid_addr);
            // client-mac
        case 'c':
            return mac_is_greater(entry.client_addr, next_entry.client_addr) &&
                   mac_is_equal(entry.bssid_addr, next_entry.bssid_addr);
        default:
            break;
    }
    return 0;
}

int client_array_go_next(char sort_order[], int i, client entry,
                         client next_entry) {
    int conditions = 1;
    for (int j = 0; j < i; j++) {
        i &= !(client_array_go_next(sort_order, j, entry, next_entry));
    }
    return conditions && client_array_go_next_help(sort_order, i, entry, next_entry);
}

void client_array_insert(client entry) {
    if (client_entry_last == -1) {
        client_array[0] = entry;
        client_entry_last++;
        return;
    }

    int i;
    for (i = 0; i <= client_entry_last; i++) {
        if (!client_array_go_next("bc", 2, entry, client_array[i])) {
            break;
        }
    }
    for (int j = client_entry_last; j >= i; j--) {
        if (j + 1 <= ARRAY_CLIENT_LEN) {
            client_array[j + 1] = client_array[j];
        }
    }
    client_array[i] = entry;

    if (client_entry_last < ARRAY_CLIENT_LEN) {
        client_entry_last++;
    }
}

client client_array_delete(client entry) {

    int i;
    int found_in_array = 0;
    client tmp;

    if (client_entry_last == -1) {
        return tmp;
    }

    for (i = 0; i <= client_entry_last; i++) {
        if (mac_is_equal(entry.bssid_addr, client_array[i].bssid_addr) &&
            mac_is_equal(entry.client_addr, client_array[i].client_addr)) {
            found_in_array = 1;
            tmp = client_array[i];
            break;
        }
    }

    for (int j = i; j < client_entry_last; j++) {
        client_array[j] = client_array[j + 1];
    }

    if (client_entry_last > -1 && found_in_array) {
        client_entry_last--;
    }
    return tmp;
}


void probe_array_insert(probe_entry entry) {
    if (probe_entry_last == -1) {
        probe_array[0] = entry;
        probe_entry_last++;
        return;
    }

    int i;
    for (i = 0; i <= probe_entry_last; i++) {
        if (!go_next(sort_string, SORT_NUM, entry, probe_array[i])) {
            break;
        }
    }
    for (int j = probe_entry_last; j >= i; j--) {
        if (j + 1 <= PROBE_ARRAY_LEN) {
            probe_array[j + 1] = probe_array[j];
        }
    }
    probe_array[i] = entry;

    if (probe_entry_last < PROBE_ARRAY_LEN) {
        probe_entry_last++;
    }
}

probe_entry probe_array_delete(probe_entry entry) {
    int i;
    int found_in_array = 0;
    probe_entry tmp;

    if (probe_entry_last == -1) {
        return tmp;
    }

    for (i = 0; i <= probe_entry_last; i++) {
        if (mac_is_equal(entry.bssid_addr, probe_array[i].bssid_addr) &&
            mac_is_equal(entry.client_addr, probe_array[i].client_addr)) {
            found_in_array = 1;
            tmp = probe_array[i];
            break;
        }
    }

    for (int j = i; j < probe_entry_last; j++) {
        probe_array[j] = probe_array[j + 1];
    }

    if (probe_entry_last > -1 && found_in_array) {
        probe_entry_last--;
    }
    return tmp;
}

int probe_array_set_all_probe_count(uint8_t client_addr[], uint32_t probe_count) {

    int updated = 0;

    if (probe_entry_last == -1) {
        return 0;
    }

    pthread_mutex_lock(&probe_array_mutex);
    for (int i = 0; i <= probe_entry_last; i++) {
        if (mac_is_equal(client_addr, probe_array[i].client_addr)) {
            printf("Setting probecount for given mac!\n");
            probe_array[i].counter = probe_count;
        } else if (!mac_is_greater(client_addr, probe_array[i].client_addr)) {
            printf("MAC not found!\n");
            break;
        }
    }
    pthread_mutex_unlock(&probe_array_mutex);

    return updated;
}

int probe_array_update_rssi(uint8_t bssid_addr[], uint8_t client_addr[], uint32_t rssi) {

    int updated = 0;

    if (probe_entry_last == -1) {
        return 0;
    }


    pthread_mutex_lock(&probe_array_mutex);
    for (int i = 0; i <= probe_entry_last; i++) {
        if (mac_is_equal(bssid_addr, probe_array[i].bssid_addr) &&
            mac_is_equal(client_addr, probe_array[i].client_addr)) {
            probe_array[i].signal = rssi;
            updated = 1;
            ubus_send_probe_via_network(probe_array[i]);
            break;
            //TODO: break?!
        }
    }
    pthread_mutex_unlock(&probe_array_mutex);

    return updated;
}

probe_entry probe_array_get_entry(uint8_t bssid_addr[], uint8_t client_addr[]) {

    int i;
    probe_entry tmp = {.bssid_addr = {0, 0, 0, 0, 0, 0}, .client_addr = {0, 0, 0, 0, 0, 0}};

    if (probe_entry_last == -1) {
        return tmp;
    }

    pthread_mutex_lock(&probe_array_mutex);
    for (i = 0; i <= probe_entry_last; i++) {
        if (mac_is_equal(bssid_addr, probe_array[i].bssid_addr) &&
            mac_is_equal(client_addr, probe_array[i].client_addr)) {
            tmp = probe_array[i];
            break;
        }
    }
    pthread_mutex_unlock(&probe_array_mutex);

    return tmp;
}

void print_probe_array() {
    printf("------------------\n");
    printf("Probe Entry Last: %d\n", probe_entry_last);
    for (int i = 0; i <= probe_entry_last; i++) {
        print_probe_entry(probe_array[i]);
    }
    printf("------------------\n");
}

probe_entry insert_to_array(probe_entry entry, int inc_counter) {
    pthread_mutex_lock(&probe_array_mutex);

    entry.time = time(0);
    entry.counter = 0;
    probe_entry tmp = probe_array_delete(entry);

    if (mac_is_equal(entry.bssid_addr, tmp.bssid_addr)
        && mac_is_equal(entry.client_addr, tmp.client_addr)) {
        entry.counter = tmp.counter;
    }

    if (inc_counter) {

        entry.counter++;
    }

    probe_array_insert(entry);

    pthread_mutex_unlock(&probe_array_mutex);

    return entry;
}

ap insert_to_ap_array(ap entry) {
    pthread_mutex_lock(&ap_array_mutex);

    entry.time = time(0);
    ap_array_delete(entry);
    ap_array_insert(entry);
    pthread_mutex_unlock(&ap_array_mutex);

    return entry;
}

int ap_get_collision_count(int col_domain) {

    int ret_sta_count = 0;

    pthread_mutex_lock(&ap_array_mutex);
    int i;

    for (i = 0; i <= ap_entry_last; i++) {
        if (ap_array[i].collision_domain == col_domain)
            ret_sta_count += ap_array[i].station_count;
    }
    pthread_mutex_unlock(&ap_array_mutex);

    return ret_sta_count;
}

ap ap_array_get_ap(uint8_t bssid_addr[]) {
    ap ret = {.bssid_addr = {0, 0, 0, 0, 0, 0}};

    if (ap_entry_last == -1) {
        return ret;
    }

    pthread_mutex_lock(&ap_array_mutex);
    int i;

    for (i = 0; i <= ap_entry_last; i++) {
        if (mac_is_equal(bssid_addr, ap_array[i].bssid_addr)) {
            //|| mac_is_greater(ap_array[i].bssid_addr, bssid_addr)) {
            break;
        }
    }
    ret = ap_array[i];
    pthread_mutex_unlock(&ap_array_mutex);

    return ret;
}

void ap_array_insert(ap entry) {
    if (ap_entry_last == -1) {
        ap_array[0] = entry;
        ap_entry_last++;
        return;
    }

    int i;
    for (i = 0; i <= ap_entry_last; i++) {
        if (mac_is_greater(entry.bssid_addr, ap_array[i].bssid_addr) &&
            strcmp((char *) entry.ssid, (char *) ap_array[i].ssid) == 0) {
            continue;
        }

        if (!string_is_greater(entry.ssid, ap_array[i].ssid)) {
            break;
        }

    }
    for (int j = ap_entry_last; j >= i; j--) {
        if (j + 1 <= ARRAY_AP_LEN) {
            ap_array[j + 1] = ap_array[j];
        }
    }
    ap_array[i] = entry;

    if (ap_entry_last < ARRAY_AP_LEN) {
        ap_entry_last++;
    }
}

ap ap_array_delete(ap entry) {
    int i;
    int found_in_array = 0;
    ap tmp;

    if (ap_entry_last == -1) {
        return tmp;
    }

    for (i = 0; i <= ap_entry_last; i++) {
        if (mac_is_equal(entry.bssid_addr, ap_array[i].bssid_addr)) {
            found_in_array = 1;
            tmp = ap_array[i];
            break;
        }
    }

    for (int j = i; j < ap_entry_last; j++) {
        ap_array[j] = ap_array[j + 1];
    }

    if (ap_entry_last > -1 && found_in_array) {
        ap_entry_last--;
    }
    return tmp;
}

void remove_old_client_entries(time_t current_time, long long int threshold) {
    for (int i = 0; i <= client_entry_last; i++) {
        if (client_array[i].time < current_time - threshold) {
            client_array_delete(client_array[i]);
        }
    }
}

void remove_old_probe_entries(time_t current_time, long long int threshold) {
    for (int i = 0; i <= probe_entry_last; i++) {
        if (probe_array[i].time < current_time - threshold) {
            if (!is_connected(probe_array[i].bssid_addr, probe_array[i].client_addr))
                probe_array_delete(probe_array[i]);
        }
    }
}

void remove_old_ap_entries(time_t current_time, long long int threshold) {
    for (int i = 0; i <= ap_entry_last; i++) {
        if (ap_array[i].time < current_time - threshold) {
            ap_array_delete(ap_array[i]);
        }
    }
}

void uloop_add_data_cbs() {
    uloop_timeout_add(&probe_timeout);
    uloop_timeout_add(&client_timeout);
    uloop_timeout_add(&ap_timeout);

    if (dawn_metric.use_driver_recog) {
        uloop_timeout_add(&denied_req_timeout);
    }
}

void remove_probe_array_cb(struct uloop_timeout *t) {
    pthread_mutex_lock(&probe_array_mutex);
    printf("[Thread] : Removing old probe entries!\n");
    remove_old_probe_entries(time(0), timeout_config.remove_probe);
    printf("[Thread] : Removing old entries finished!\n");
    pthread_mutex_unlock(&probe_array_mutex);
    uloop_timeout_set(&probe_timeout, timeout_config.remove_probe * 1000);
}

void remove_client_array_cb(struct uloop_timeout *t) {
    pthread_mutex_lock(&client_array_mutex);
    printf("[Thread] : Removing old client entries!\n");
    remove_old_client_entries(time(0), timeout_config.update_client);
    pthread_mutex_unlock(&client_array_mutex);
    uloop_timeout_set(&client_timeout, timeout_config.update_client * 1000);
}

void remove_ap_array_cb(struct uloop_timeout *t) {
    pthread_mutex_lock(&ap_array_mutex);
    printf("[ULOOP] : Removing old ap entries!\n");
    remove_old_ap_entries(time(0), timeout_config.remove_ap);
    pthread_mutex_unlock(&ap_array_mutex);
    uloop_timeout_set(&ap_timeout, timeout_config.remove_ap * 1000);
}

void denied_req_array_cb(struct uloop_timeout *t) {
    pthread_mutex_lock(&denied_array_mutex);
    printf("[ULOOP] : Processing denied authentication!\n");

    time_t current_time = time(0);

    for (int i = 0; i <= denied_req_last; i++) {
        // check counter

        //check timer
        if (denied_req_array[i].time < current_time - timeout_config.denied_req_threshold) {

            // client is not connected for a given time threshold!
            if (!is_connected_somehwere(denied_req_array[i].client_addr)) {
                printf("Client has propaly a bad driver!\n");

                // problem that somehow station will land into this list
                // maybe delete again?
                if (insert_to_maclist(denied_req_array[i].client_addr) == 0) {
                    send_add_mac(denied_req_array[i].client_addr);
                    write_mac_to_file("/tmp/dawn_mac_list", denied_req_array[i].client_addr);
                }
            }
            denied_req_array_delete(denied_req_array[i]);
        }
    }
    pthread_mutex_unlock(&denied_array_mutex);
    uloop_timeout_set(&denied_req_timeout, timeout_config.denied_req_threshold * 1000);
}

void insert_client_to_array(client entry) {
    pthread_mutex_lock(&client_array_mutex);
    entry.time = time(0);
    entry.kick_count = 0;

    client client_tmp = client_array_delete(entry);

    if (mac_is_equal(entry.bssid_addr, client_tmp.bssid_addr)) {
        entry.kick_count = client_tmp.kick_count;
    }

    client_array_insert(entry);

    pthread_mutex_unlock(&client_array_mutex);
}

void insert_macs_from_file() {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen("/tmp/dawn_mac_list", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, fp)) != -1) {
        printf("Retrieved line of length %zu :\n", read);
        printf("%s", line);

        int tmp_int_mac[ETH_ALEN];
        sscanf(line, MACSTR, STR2MAC(tmp_int_mac));

        mac_list_entry_last++;
        for (int i = 0; i < ETH_ALEN; ++i) {
            mac_list[mac_list_entry_last][i] = (uint8_t) tmp_int_mac[i];
        }
    }

    printf("Printing MAC list:\n");
    for (int i = 0; i <= mac_list_entry_last; i++) {
        char mac_buf_target[20];
        sprintf(mac_buf_target, MACSTR, MAC2STR(mac_list[i]));
        printf("%d: %s\n", i, mac_buf_target);
    }

    fclose(fp);
    if (line)
        free(line);
    //exit(EXIT_SUCCESS);
}

int insert_to_maclist(uint8_t mac[]) {
    if (mac_in_maclist(mac)) {
        return -1;
    }

    mac_list_entry_last++;
    for (int i = 0; i < ETH_ALEN; ++i) {
        mac_list[mac_list_entry_last][i] = mac[i];
    }

    return 0;
}


int mac_in_maclist(uint8_t mac[]) {
    for (int i = 0; i <= mac_list_entry_last; i++) {
        if (mac_is_equal(mac, mac_list[i])) {
            return 1;
        }
    }
    return 0;
}

auth_entry insert_to_denied_req_array(auth_entry entry, int inc_counter) {
    pthread_mutex_lock(&denied_array_mutex);

    entry.time = time(0);
    entry.counter = 0;
    auth_entry tmp = denied_req_array_delete(entry);

    if (mac_is_equal(entry.bssid_addr, tmp.bssid_addr)
        && mac_is_equal(entry.client_addr, tmp.client_addr)) {
        entry.counter = tmp.counter;
    }

    if (inc_counter) {

        entry.counter++;
    }

    denied_req_array_insert(entry);

    pthread_mutex_unlock(&denied_array_mutex);

    return entry;
}

int denied_req_array_go_next_help(char sort_order[], int i, auth_entry entry,
                                  auth_entry next_entry) {
    switch (sort_order[i]) {
        // bssid-mac
        case 'b':
            return mac_is_greater(entry.bssid_addr, next_entry.bssid_addr);
            // client-mac
        case 'c':
            return mac_is_greater(entry.client_addr, next_entry.client_addr) &&
                   mac_is_equal(entry.bssid_addr, next_entry.bssid_addr);
        default:
            break;
    }
    return 0;
}

int denied_req_array_go_next(char sort_order[], int i, auth_entry entry,
                             auth_entry next_entry) {
    int conditions = 1;
    for (int j = 0; j < i; j++) {
        i &= !(denied_req_array_go_next(sort_order, j, entry, next_entry));
    }
    return conditions && denied_req_array_go_next_help(sort_order, i, entry, next_entry);
}

void denied_req_array_insert(auth_entry entry) {
    if (denied_req_last == -1) {
        denied_req_array[0] = entry;
        denied_req_last++;
        return;
    }

    int i;
    for (i = 0; i <= denied_req_last; i++) {
        if (!denied_req_array_go_next("bc", 2, entry, denied_req_array[i])) {
            break;
        }
    }
    for (int j = denied_req_last; j >= i; j--) {
        if (j + 1 <= DENY_REQ_ARRAY_LEN) {
            denied_req_array[j + 1] = denied_req_array[j];
        }
    }
    denied_req_array[i] = entry;

    if (denied_req_last < DENY_REQ_ARRAY_LEN) {
        denied_req_last++;
    }
}

auth_entry denied_req_array_delete(auth_entry entry) {

    int i;
    int found_in_array = 0;
    auth_entry tmp;

    if (denied_req_last == -1) {
        return tmp;
    }

    for (i = 0; i <= denied_req_last; i++) {
        if (mac_is_equal(entry.bssid_addr, denied_req_array[i].bssid_addr) &&
            mac_is_equal(entry.client_addr, denied_req_array[i].client_addr)) {
            found_in_array = 1;
            tmp = denied_req_array[i];
            break;
        }
    }

    for (int j = i; j < denied_req_last; j++) {
        denied_req_array[j] = denied_req_array[j + 1];
    }

    if (denied_req_last > -1 && found_in_array) {
        denied_req_last--;
    }
    return tmp;
}

int go_next_help(char sort_order[], int i, probe_entry entry,
                 probe_entry next_entry) {
    switch (sort_order[i]) {
        // bssid-mac
        case 'b':
            return mac_is_greater(entry.bssid_addr, next_entry.bssid_addr) &&
                   mac_is_equal(entry.client_addr, next_entry.client_addr);
            break;

            // client-mac
        case 'c':
            return mac_is_greater(entry.client_addr, next_entry.client_addr);
            break;

            // frequency
            // mac is 5 ghz or 2.4 ghz?
        case 'f':
            return //entry.freq < next_entry.freq &&
                    entry.freq < 5000 &&
                    next_entry.freq >= 5000 &&
                    //entry.freq < 5 &&
                    mac_is_equal(entry.client_addr, next_entry.client_addr);
            break;

            // signal strength (RSSI)
        case 's':
            return entry.signal < next_entry.signal &&
                   mac_is_equal(entry.client_addr, next_entry.client_addr);
            break;

        default:
            return 0;
            break;
    }
}

int go_next(char sort_order[], int i, probe_entry entry,
            probe_entry next_entry) {
    int conditions = 1;
    for (int j = 0; j < i; j++) {
        i &= !(go_next(sort_order, j, entry, next_entry));
    }
    return conditions && go_next_help(sort_order, i, entry, next_entry);
}

int mac_is_equal(uint8_t addr1[], uint8_t addr2[]) {
    return memcmp(addr1, addr2, ETH_ALEN * sizeof(uint8_t)) == 0;
}

int mac_is_greater(uint8_t addr1[], uint8_t addr2[]) {
    for (int i = 0; i < ETH_ALEN; i++) {
        if (addr1[i] > addr2[i]) {
            return 1;
        }
        if (addr1[i] < addr2[i]) {
            return 0;
        }

        // if equal continue...
    }
    return 0;
}

void print_probe_entry(probe_entry entry) {
    char mac_buf_ap[20];
    char mac_buf_client[20];
    char mac_buf_target[20];

    sprintf(mac_buf_ap, MACSTR, MAC2STR(entry.bssid_addr));
    sprintf(mac_buf_client, MACSTR, MAC2STR(entry.client_addr));
    sprintf(mac_buf_target, MACSTR, MAC2STR(entry.target_addr));

    printf(
            "bssid_addr: %s, client_addr: %s, signal: %d, freq: "
            "%d, counter: %d, vht: %d, min_rate: %d, max_rate: %d\n",
            mac_buf_ap, mac_buf_client, entry.signal, entry.freq, entry.counter, entry.vht_capabilities,
            entry.min_supp_datarate, entry.max_supp_datarate);
}

void print_auth_entry(auth_entry entry) {
    char mac_buf_ap[20];
    char mac_buf_client[20];
    char mac_buf_target[20];

    sprintf(mac_buf_ap, MACSTR, MAC2STR(entry.bssid_addr));
    sprintf(mac_buf_client, MACSTR, MAC2STR(entry.client_addr));
    sprintf(mac_buf_target, MACSTR, MAC2STR(entry.target_addr));

    printf(
            "bssid_addr: %s, client_addr: %s, signal: %d, freq: "
            "%d\n",
            mac_buf_ap, mac_buf_client, entry.signal, entry.freq);
}

void print_client_entry(client entry) {
    char mac_buf_ap[20];
    char mac_buf_client[20];

    sprintf(mac_buf_ap, MACSTR, MAC2STR(entry.bssid_addr));
    sprintf(mac_buf_client, MACSTR, MAC2STR(entry.client_addr));

    printf("bssid_addr: %s, client_addr: %s, freq: %d, ht_supported: %d, vht_supported: %d, ht: %d, vht: %d, kick: %d\n",
           mac_buf_ap, mac_buf_client, entry.freq, entry.ht_supported, entry.vht_supported, entry.ht, entry.vht,
           entry.kick_count);
}

void print_client_array() {
    printf("--------Clients------\n");
    printf("Client Entry Last: %d\n", client_entry_last);
    for (int i = 0; i <= client_entry_last; i++) {
        print_client_entry(client_array[i]);
    }
    printf("------------------\n");
}

void print_ap_entry(ap entry) {
    char mac_buf_ap[20];

    sprintf(mac_buf_ap, MACSTR, MAC2STR(entry.bssid_addr));
    printf("ssid: %s, bssid_addr: %s, freq: %d, ht: %d, vht: %d, chan_utilz: %d, col_d: %d, bandwidth: %d, col_count: %d\n",
           entry.ssid, mac_buf_ap, entry.freq, entry.ht_support, entry.vht_support,
           entry.channel_utilization, entry.collision_domain, entry.bandwidth,
           ap_get_collision_count(entry.collision_domain)
    );
}

void print_ap_array() {
    printf("--------APs------\n");
    for (int i = 0; i <= ap_entry_last; i++) {
        print_ap_entry(ap_array[i]);
    }
    printf("------------------\n");
}