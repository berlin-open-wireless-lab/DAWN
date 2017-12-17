#include "datastorage.h"

#include <limits.h>
#include <libubox/uloop.h>

#include "ubus.h"
#include "dawn_iwinfo.h"
#include "utils.h"

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

int compare_station_count(uint8_t *bssid_addr_own, uint8_t *bssid_addr_to_compare, int automatic_kick);

int probe_entry_last = -1;
int client_entry_last = -1;
int ap_entry_last = -1;

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

int eval_probe_metric(struct probe_entry_s probe_entry) {

    int score = 0;

    ap ap_entry = ap_array_get_ap(probe_entry.bssid_addr);

    // check if ap entry is available
    if (mac_is_equal(ap_entry.bssid_addr, probe_entry.bssid_addr)) {
        score += probe_entry.ht_support && ap_entry.ht ? dawn_metric.ht_support : 0;
        score += !probe_entry.ht_support && !ap_entry.ht ? dawn_metric.no_ht_support : 0;
        score += probe_entry.vht_support && ap_entry.vht ? dawn_metric.vht_support : 0;
        score += !probe_entry.vht_support && !ap_entry.vht ? dawn_metric.no_vht_support : 0;
        score += ap_entry.channel_utilization <= dawn_metric.chan_util_val ? dawn_metric.chan_util : 0;
        score += ap_entry.channel_utilization > dawn_metric.max_chan_util_val ? dawn_metric.max_chan_util : 0;
    }

    score += (probe_entry.freq > 5000) ? dawn_metric.freq : 0;
    score += (probe_entry.signal >= dawn_metric.rssi_val) ? dawn_metric.rssi : 0;
    score += (probe_entry.signal <= dawn_metric.low_rssi_val) ? dawn_metric.low_rssi : 0;

    //printf("SCORE: %d\n", score);
    //print_probe_entry(probe_entry);

    return score;
}

int compare_station_count(uint8_t *bssid_addr_own, uint8_t *bssid_addr_to_compare, int automatic_kick) {

    ap ap_entry_own = ap_array_get_ap(bssid_addr_own);
    ap ap_entry_to_compre = ap_array_get_ap(bssid_addr_to_compare);

    // check if ap entry is available
    if (mac_is_equal(ap_entry_own.bssid_addr, bssid_addr_own)
            && mac_is_equal(ap_entry_to_compre.bssid_addr, bssid_addr_to_compare)
            ) {
        //printf("Comparing own %d to %d\n", ap_entry_own.station_count, ap_entry_to_compre.station_count);
        if(automatic_kick){
            return (ap_entry_own.station_count - 1) > ap_entry_to_compre.station_count;
        } else {
            return ap_entry_own.station_count > ap_entry_to_compre.station_count;
        }
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
        if (!mac_is_equal(probe_array[k].client_addr, client_addr)) {
            break;
        }
        if (!mac_is_equal(bssid_addr, probe_array[k].bssid_addr) &&
            own_score <
            eval_probe_metric(probe_array[k])) // that's wrong! find client_entry OR write things in probe array struct!
        {
            return 1;
        }
        if ( dawn_metric.use_station_count && !mac_is_equal(bssid_addr, probe_array[k].bssid_addr) &&
                own_score == eval_probe_metric(probe_array[k]))
        {
            // if ap have same value but station count is different...
            return compare_station_count(bssid_addr, probe_array[k].bssid_addr, automatic_kick);
        }
    }
    return 0;
}

int kick_client(struct client_s client_entry) {
    return better_ap_available(client_entry.bssid_addr, client_entry.client_addr, 1);
}

void kick_clients(uint8_t bssid[], uint32_t id) {
    pthread_mutex_lock(&client_array_mutex);
    pthread_mutex_lock(&probe_array_mutex);

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
        if (rssi != INT_MIN) {
            pthread_mutex_unlock(&probe_array_mutex);
            if (!probe_array_update_rssi(client_array[j].bssid_addr, client_array[j].client_addr, rssi)) {
                printf("Failed to update RSSI!\n");
            } else {
                printf("RSSI UPDATED: RSSI: %d\n\n", rssi);
            }
            pthread_mutex_lock(&probe_array_mutex);

        }

        // better ap available
        if (kick_client(client_array[j]) > 0) {
            printf("Better AP available. Kicking client:\n");
            print_client_entry(client_array[j]);
            printf("Check if client is active receiving!\n");

            float rx_rate, tx_rate;
            if(get_bandwidth_iwinfo(client_array[j].client_addr, &rx_rate, &tx_rate))
            {
                // only use rx_rate for indicating if transmission is going on
                // <= 6MBits <- probably no transmission
                // tx_rate has always some weird value so don't use ist
                if(rx_rate > dawn_metric.bandwith_threshold){
                    printf("Client is probably in active transmisison. Don't kick! RxRate is: %f\n", rx_rate);
                    continue;
                }
            }
            printf("Client is probably NOT in active transmisison. KICK! RxRate is: %f\n", rx_rate);

            del_client_interface(id, client_array[j].client_addr, 5, 1, 1000);
            client_array_delete(client_array[j]);

            // don't delete clients in a row. use update function again...
            // -> chan_util update, ...
            add_client_update_timer(timeout_config.update_client * 1000 / 4);
            break;

            // no entry in probe array for own bssid
        } else if (kick_client(client_array[j]) == -1) {
            printf("No Information about client. Force reconnect:\n");
            print_client_entry(client_array[j]);
            del_client_interface(id, client_array[j].client_addr, 0, 0, 0);

            // ap is best
        } else {
            printf("AP is best. Client will stay:\n");
            print_client_entry(client_array[j]);
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);
    pthread_mutex_unlock(&client_array_mutex);
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
            return mac_is_greater(entry.bssid_addr, next_entry.bssid_addr) &&
                   mac_is_equal(entry.client_addr, next_entry.client_addr);
            break;

            // client-mac
        case 'c':
            return mac_is_greater(entry.client_addr, next_entry.client_addr);
            break;

            // frequency
            // mac is 5 ghz or 2.4 ghz?
            // case 'f':
            //  return //entry.freq < next_entry.freq &&
            //    entry.freq < 5000 &&
            //    next_entry.freq >= 5000 &&
            //    //entry.freq < 5 &&
            //    mac_is_equal(entry.client_addr, next_entry.client_addr);
            //  break;

            // signal strength (RSSI)
            //case 's':
            //  return entry.signal < next_entry.signal &&
            //         mac_is_equal(entry.client_addr, next_entry.client_addr);
            //  break;

        default:
            return 0;
            break;
    }
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

client *client_array_delete(client entry) {

    int i;
    int found_in_array = 0;
    client *tmp = NULL;

    if (client_entry_last == -1) {
        return NULL;
    }

    for (i = 0; i <= client_entry_last; i++) {
        if (mac_is_equal(entry.bssid_addr, client_array[i].bssid_addr) &&
            mac_is_equal(entry.client_addr, client_array[i].client_addr)) {
            found_in_array = 1;
            tmp = &client_array[i];
            break;
        }
    }

    for (int j = i; j <= client_entry_last; j++) {
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

    for (int j = i; j <= probe_entry_last; j++) {
        probe_array[j] = probe_array[j + 1];
    }

    if (probe_entry_last > -1 && found_in_array) {
        probe_entry_last--;
    }
    return tmp;
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
        }
    }
    pthread_mutex_unlock(&probe_array_mutex);

    return updated;
}

probe_entry probe_array_get_entry(uint8_t bssid_addr[], uint8_t client_addr[]) {

    int i;
    probe_entry tmp;

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

ap ap_array_get_ap(uint8_t bssid_addr[]) {
    ap ret;

    //char bssid_mac_string[20];
    //sprintf(bssid_mac_string, MACSTR, MAC2STR(bssid_addr));
    //printf("Try to find: %s\n", bssid_mac_string);
    //printf("in\n");
    //print_ap_array();

    if (ap_entry_last == -1) {
        return ret;
    }


    pthread_mutex_lock(&ap_array_mutex);
    int i;

    for (i = 0; i <= ap_entry_last; i++) {
        if (mac_is_equal(bssid_addr, ap_array[i].bssid_addr) || mac_is_greater(ap_array[i].bssid_addr, bssid_addr)) {
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
        if (!mac_is_greater(entry.bssid_addr, ap_array[i].bssid_addr)) {
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

    for (int j = i; j <= ap_entry_last; j++) {
        ap_array[j] = ap_array[j + 1];
    }

    if (ap_entry_last > -1 && found_in_array) {
        ap_entry_last--;
    }
    return tmp;
}

void remove_old_client_entries(time_t current_time, long long int threshold) {
    for (int i = 0; i < probe_entry_last; i++) {
        if (client_array[i].time < current_time - threshold) {
            client_array_delete(client_array[i]);
        }
    }
}

void remove_old_probe_entries(time_t current_time, long long int threshold) {
    for (int i = 0; i < probe_entry_last; i++) {
        if (probe_array[i].time < current_time - threshold) {
            if (!is_connected(probe_array[i].bssid_addr, probe_array[i].client_addr))
                probe_array_delete(probe_array[i]);
        }
    }
}

void remove_old_ap_entries(time_t current_time, long long int threshold) {
    for (int i = 0; i < probe_entry_last; i++) {
        if (ap_array[i].time < current_time - threshold) {
            ap_array_delete(ap_array[i]);
        }
    }
}

void uloop_add_data_cbs()
{
    uloop_timeout_add(&probe_timeout);
    uloop_timeout_add(&client_timeout);
    uloop_timeout_add(&ap_timeout);
}

void remove_probe_array_cb(struct uloop_timeout *t) {
    pthread_mutex_lock(&probe_array_mutex);
    printf("[Thread] : Removing old entries!\n");
    remove_old_probe_entries(time(0), timeout_config.remove_probe);
    pthread_mutex_unlock(&probe_array_mutex);
    uloop_timeout_set(&probe_timeout, timeout_config.remove_probe * 1000);
}

void remove_client_array_cb(struct uloop_timeout *t)
{
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

void insert_client_to_array(client entry) {
    pthread_mutex_lock(&client_array_mutex);
    entry.time = time(0);

    client_array_delete(entry);
    client_array_insert(entry);

    pthread_mutex_unlock(&client_array_mutex);
}


node *delete_probe_req(node **ret_remove, node *head, uint8_t bssid_addr[],
                       uint8_t client_addr[]);

int mac_is_first_in_list(node *head, uint8_t bssid_addr[],
                         uint8_t client_addr[]);

node *remove_node(node *head, node *curr, node *prev);

node *remove_old_entries(node *head, time_t current_time,
                         long long int threshold);

void print_list_with_head(node *head);

void insert_to_list(probe_entry entry, int inc_counter) {
    pthread_mutex_lock(&list_mutex);

    entry.time = time(0);
    entry.counter = 0;


    // first delete probe request
    // probe_list_head = remove_old_entries(probe_list_head, time(0),
    // TIME_THRESHOLD);
    node *tmp_probe_req = NULL;
    probe_list_head = delete_probe_req(&tmp_probe_req, probe_list_head,
                                       entry.bssid_addr, entry.client_addr);

    if (tmp_probe_req) {
        // local ubus
        tmp_probe_req->data.signal = entry.signal;
        tmp_probe_req->data.time = entry.time;
        if (inc_counter) {
            // when network don't increase counter...
            tmp_probe_req->data.counter++;
        }

        // is this correct?
        probe_list_head = insert(probe_list_head, tmp_probe_req->data);
        free(tmp_probe_req);
    } else {
        printf("New entry!\n");
        probe_list_head = insert(probe_list_head, entry);
    }

    pthread_mutex_unlock(&list_mutex);
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

node *insert(node *head, probe_entry entry) {
    node *temp, *prev, *next;
    temp = (node *) malloc(sizeof(node));
    temp->data = entry;
    temp->ptr = NULL;

    // length of sorting string
    // char sort_string[] = "cfsb";
    int i = 0;

    if (!head) {
        head = temp;
    } else {
        prev = NULL;
        next = head;
        while (next) {
            if (go_next(sort_string, i, entry, next->data)) {
                prev = next;
                next = next->ptr;
            } else if (i < strlen(sort_string)) {
                i++;
            } else {
                break;
            }
        }
        if (!next) {
            prev->ptr = temp;
        } else {
            if (prev) {
                temp->ptr = prev->ptr;
                prev->ptr = temp;
            } else {
                temp->ptr = head;
                head = temp;
            }
        }
    }
    return head;
}

node *delete_probe_req(node **ret_remove, node *head, uint8_t bssid_addr[],
                       uint8_t client_addr[]) {
    if (!head) {
        return head;
    }

    if (mac_is_equal(client_addr, head->data.client_addr) &&
        mac_is_equal(bssid_addr, head->data.bssid_addr)) {
        node *temp = head;
        head = head->ptr;
        *ret_remove = temp;
        // don't free pointer
        // free(temp);
        return head;
    }

    node *prev = NULL;
    node *next = head;
    while (next) {
        if (mac_is_greater(next->data.client_addr, client_addr)) {
            break;
        }

        if (mac_is_equal(client_addr, next->data.client_addr) &&
            mac_is_equal(bssid_addr, next->data.bssid_addr)) {
            node *temp = next;
            prev->ptr = next->ptr;
            // free(temp);
            *ret_remove = temp;
            return head;
        }
        prev = next;
        next = next->ptr;
    }
    return head;
}

void *remove_thread(void *arg) {
    while (1) {
        sleep(TIME_THRESHOLD);
        pthread_mutex_lock(&list_mutex);
        printf("[Thread] : Removing old entries!\n");
        probe_list_head =
                remove_old_entries(probe_list_head, time(0), TIME_THRESHOLD);
        pthread_mutex_unlock(&list_mutex);
        // print_list();
    }
    return 0;
}

node *remove_old_entries(node *head, time_t current_time,
                         long long int threshold) {
    if (head) {
        node *prev = NULL;
        node *next = head;
        while (next) {
            if (next->data.time < current_time - threshold) {
                head = remove_node(head, next, prev);
                // print_list_with_head(head);
                if (prev == NULL)  // removed head
                {
                    next = head;
                } else {
                    next = prev->ptr;
                }
            } else {
                prev = next;
                next = next->ptr;
            }
        }
    }
    return head;
}

// return headpointer
node *remove_node(node *head, node *curr, node *prev) {
    if (curr == head) {
        node *temp = head;
        head = head->ptr;
        free(temp);
    } else {
        node *temp = curr;
        prev->ptr = curr->ptr;
        free(temp);
    }
    // printf("Removed old entry!\n");
    return head;
}

int mac_is_first_in_list(node *head, uint8_t bssid_addr[],
                         uint8_t client_addr[]) {
    if (!head) {
        return 1;
    }
    node *next = head;
    while (next) {
        if (mac_is_greater(next->data.client_addr, client_addr)) {
            break;
        }

        if (mac_is_equal(client_addr, next->data.client_addr)) {
            print_probe_entry(next->data);
            return mac_is_equal(bssid_addr, next->data.bssid_addr);
        }
        next = next->ptr;
    }
    return 0;
}

int mac_first_in_probe_list(uint8_t bssid_addr[], uint8_t client_addr[]) {
    pthread_mutex_lock(&list_mutex);
    int ret = mac_is_first_in_list(probe_list_head, bssid_addr, client_addr);
    pthread_mutex_unlock(&list_mutex);
    return ret;
}

void free_list(node *head) {
    node *prev = head;
    node *cur = head;
    while (cur) {
        prev = cur;
        cur = prev->ptr;
        free(prev);
    }
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

void print_list_with_head(node *head) {
    pthread_mutex_lock(&list_mutex);
    printf("------------------\n");
    if (head) {
        node *next;
        next = head;
        while (next) {
            print_probe_entry(next->data);
            next = next->ptr;
        }
    }
    printf("------------------\n");
    pthread_mutex_unlock(&list_mutex);
}

void print_list() {
    pthread_mutex_lock(&list_mutex);
    printf("------------------\n");
    node *head = probe_list_head;
    if (head) {
        node *next;
        next = head;
        while (next) {
            print_probe_entry(next->data);
            next = next->ptr;
        }
    }
    printf("------------------\n");
    pthread_mutex_unlock(&list_mutex);
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
                    "%d, counter: %d, vht: %d\n",
            mac_buf_ap, mac_buf_client, entry.signal, entry.freq, entry.counter, entry.vht_support);
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

    printf("bssid_addr: %s, client_addr: %s, freq: %d, ht_supported: %d, vht_supported: %d, ht: %d, vht: %d\n",
           mac_buf_ap, mac_buf_client, entry.freq, entry.ht_supported, entry.vht_supported, entry.ht, entry.vht);
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
    printf("bssid_addr: %s, freq: %d, ht: %d, vht: %d, chan_utilz: %d\n",
           mac_buf_ap, entry.freq, entry.ht, entry.vht, entry.channel_utilization);
}

void print_ap_array() {
    printf("--------APs------\n");
    for (int i = 0; i <= ap_entry_last; i++) {
        print_ap_entry(ap_array[i]);
    }
    printf("------------------\n");
}