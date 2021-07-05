#include <stdbool.h>
#include <stdio.h>

#include "memory_utils.h"
#include "dawn_iwinfo.h"
#include "dawn_uci.h"
#include "mac_utils.h"
#include "ieee80211_utils.h"

#include "datastorage.h"
#include "test_storage.h"
#include "msghandler.h"
#include "ubus.h"

struct probe_metric_s dawn_metric;
struct network_config_s network_config;
struct time_config_s timeout_config;

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

#ifndef BIT
#define BIT(x) (1U << (x))
#endif
#define WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE BIT(4)
#define WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE BIT(5)
#define WLAN_RRM_CAPS_BEACON_REPORT_TABLE BIT(6)

static int probe_compare(probe_entry *probe1, probe_entry *probe2);

static int kick_client(ap *kicking_ap, struct client_s *client_entry, char* neighbor_report);

static void print_ap_entry(ap *entry);

static int is_connected(struct dawn_mac bssid_mac, struct dawn_mac client_mac);

static int compare_station_count(ap* ap_entry_own, ap* ap_entry_to_compare, struct dawn_mac client_addr);


// ---------------- Global variables ----------------
struct auth_entry_s *denied_req_set = NULL;
int denied_req_last = 0;
pthread_mutex_t denied_array_mutex;

// Ratio of skiping entries to all entries.
// Approx sqrt() of large data set, and power of 2 for efficient division when adding entries.
#define DAWN_PROBE_SKIP_RATIO 128
static struct probe_entry_s* probe_skip_set = NULL;
static uint32_t probe_skip_entry_last = 0;
struct probe_entry_s* probe_set = NULL;
static uint32_t probe_entry_last = 0;
pthread_mutex_t probe_array_mutex;

struct ap_s *ap_set = NULL;
static int ap_entry_last = 0;
pthread_mutex_t ap_array_mutex;

#define DAWN_CLIENT_SKIP_RATIO 32
static struct client_s* client_skip_set = NULL;
static uint32_t client_skip_entry_last = 0;
struct client_s* client_set_bc = NULL; // Ordered by BSSID + client MAC
struct client_s* client_set_c = NULL; // Ordered by client MAC only
static int client_entry_last = 0;
pthread_mutex_t client_array_mutex;

// TODO: How big does this get?
struct mac_entry_s* mac_set = NULL;
int mac_set_last = 0;

// TODO: No longer used in code: retained to not break message xfer, etc
char sort_string[SORT_LENGTH];

// Used as a filler where a value is required but not used functionally
static const struct dawn_mac dawn_mac_null = { .u8 = {0,0,0,0,0,0} };

/*
** The ..._find_first() functions perform an efficient search of the core storage linked lists.
** "Skipping" linear searches and binary searches are used depending on anticipated array size.
** TODO:  It may be more efficient to use skipping lists for all?  Telemetry required.
** The return is a pointer to the linked list field that references the element indicated by the
** target parameters. In this context "indicated by" means the first element in the list that matches
** the search parameters, or if the element is not in the list the position where it would be inserted.
** In other words, if A precedes B and B is sought then a pointer to the field in A that references B
** is returned.  If A links to C and B would be positioned between then the same pointer is returned.
** Hence the return should be checked to see if the element it references is the target or not.  If not
** then the target element does not exist, but can be inserted by using the returned reference.
*/

static struct probe_entry_s** probe_skip_array_find_first_entry(struct dawn_mac client_mac, struct dawn_mac bssid_mac, int do_bssid)
{
    int lo = 0;
    struct probe_entry_s** lo_ptr = &probe_skip_set;
    int hi = probe_skip_entry_last;

    while (lo < hi) {
        struct probe_entry_s** i = lo_ptr;
        int scan_pos = lo;

        // m is next test position of binary search
        int m = (lo + hi) / 2;

        // find entry with ordinal position m
        while (scan_pos++ < m)
        {
            i = &((*i)->next_probe_skip);
        }

        int this_cmp = mac_compare_bb((*i)->client_addr, client_mac);

        if (this_cmp == 0 && do_bssid)
            this_cmp = mac_compare_bb((*i)->bssid_addr, bssid_mac);

        if (this_cmp < 0)
        {
            lo = m + 1;
            lo_ptr = &((*i)->next_probe_skip);
        }
        else
        {
            hi = m;
        }
    }

    return lo_ptr;
}

static probe_entry** probe_array_find_first_entry(struct dawn_mac client_mac, struct dawn_mac bssid_mac, bool do_bssid)
{
    probe_entry** lo_skip_ptr = &probe_skip_set;
    probe_entry** lo_ptr = &probe_set;

    while ((*lo_skip_ptr != NULL))
    {
        int this_cmp = mac_compare_bb(((*lo_skip_ptr))->client_addr, client_mac);

        if (this_cmp == 0 && do_bssid)
            this_cmp = mac_compare_bb(((*lo_skip_ptr))->bssid_addr, bssid_mac);

        if (this_cmp >= 0)
            break;

        lo_ptr = &((*lo_skip_ptr)->next_probe);
        lo_skip_ptr = &((*lo_skip_ptr)->next_probe_skip);
    }

    while ((*lo_ptr != NULL))
    {
        int this_cmp = mac_compare_bb((*lo_ptr)->client_addr, client_mac);

        if (this_cmp == 0 && do_bssid)
            this_cmp = mac_compare_bb((*lo_ptr)->bssid_addr, bssid_mac);

        if (this_cmp >= 0)
            break;

        lo_ptr = &((*lo_ptr)->next_probe);
    }

    return lo_ptr;
}

static ap** ap_array_find_first_entry(struct dawn_mac bssid_mac, const uint8_t* ssid)
{
    int lo = 0;
    ap** lo_ptr = &ap_set;
    int hi = ap_entry_last;

    while (lo < hi) {
        ap** i = lo_ptr;
        int scan_pos = lo;
        int this_cmp;

        // m is next test position of binary search
        int m = (lo + hi) / 2;

        // find entry with ordinal position m
        while (scan_pos++ < m)
        {
            i = &((*i)->next_ap);
        }

        if (ssid)
        {
            this_cmp = strcmp((char*)(*i)->ssid, (char*)ssid);
        }
        else
        {
            this_cmp = 0;
        }
        this_cmp = this_cmp ? this_cmp : mac_compare_bb((*i)->bssid_addr, bssid_mac);

        if (this_cmp < 0)
        {
            lo = m + 1;
            lo_ptr = &((*i)->next_ap);
        }
        else
        {
            hi = m;
        }
    }

    return lo_ptr;
}

// Manage a list of client entries sorted by BSSID and client MAC
static struct client_s** client_skip_array_find_first_entry(struct dawn_mac client_mac, struct dawn_mac bssid_mac, bool do_bssid)
{
    int lo = 0;
    struct client_s** lo_ptr = &client_skip_set;
    int hi = client_skip_entry_last;

    while (lo < hi) {
        struct client_s** i = lo_ptr;
        int scan_pos = lo;

        // m is next test position of binary search
        int m = (lo + hi) / 2;

        // find entry with ordinal position m
        while (scan_pos++ < m)
        {
            i = &((*i)->next_skip_entry_bc);
        }

        int this_cmp = mac_compare_bb((*i)->client_addr, client_mac);

        if (this_cmp == 0 && do_bssid)
            this_cmp = mac_compare_bb((*i)->bssid_addr, bssid_mac);

        if (this_cmp < 0)
        {
            lo = m + 1;
            lo_ptr = &((*i)->next_skip_entry_bc);
        }
        else
        {
            hi = m;
        }
    }

    return lo_ptr;
}

static client** client_find_first_bc_entry(struct dawn_mac bssid_mac, struct dawn_mac client_mac, bool do_client)
{
    client ** lo_skip_ptr = &client_skip_set;
    client ** lo_ptr = &client_set_bc;

    while ((*lo_skip_ptr != NULL))
    {
        int this_cmp = mac_compare_bb(((*lo_skip_ptr))->bssid_addr, bssid_mac);

        if (this_cmp == 0 && do_client)
            this_cmp = mac_compare_bb(((*lo_skip_ptr))->client_addr, client_mac);

        if (this_cmp >= 0)
            break;

        lo_ptr = &((*lo_skip_ptr)->next_entry_bc);
        lo_skip_ptr = &((*lo_skip_ptr)->next_skip_entry_bc);
    }

    while ((*lo_ptr != NULL))
    {
        int this_cmp = mac_compare_bb((*lo_ptr)->bssid_addr, bssid_mac);

        if (this_cmp == 0 && do_client)
            this_cmp = mac_compare_bb((*lo_ptr)->client_addr, client_mac);

        if (this_cmp >= 0)
            break;

        lo_ptr = &((*lo_ptr)->next_entry_bc);
    }

    return lo_ptr;
}

#ifndef DAWN_CLIENT_SCAN_BC_ONLY
// Manage a list of client entries srted by client MAC only
static client** client_find_first_c_entry(struct dawn_mac client_mac)
{
    int lo = 0;
    client** lo_ptr = &client_set_c;
    int hi = client_entry_last;

    while (lo < hi) {
        client** i = lo_ptr;
        int scan_pos = lo;

        // m is next test position of binary search
        int m = (lo + hi) / 2;

        // find entry with ordinal position m
        while (scan_pos++ < m)
        {
            i = &((*i)->next_entry_c);
        }

        int this_cmp = mac_compare_bb((*i)->client_addr, client_mac);

        if (this_cmp < 0)
        {
            lo = m + 1;
            lo_ptr = &((*i)->next_entry_c);
        }
        else
        {
            hi = m;
        }
    }

    return lo_ptr;
}
#endif

auth_entry** auth_entry_find_first_entry(struct dawn_mac bssid_mac, struct dawn_mac client_mac)
{
    int lo = 0;
    auth_entry** lo_ptr = &denied_req_set;
    int hi = denied_req_last;

    while (lo < hi) {
        auth_entry** i = lo_ptr;
        int scan_pos = lo;

        // m is next test position of binary search
        int m = (lo + hi) / 2;

        // find entry with ordinal position m
        while (scan_pos++ < m)
        {
            i = &((*i)->next_auth);
        }

        int this_cmp = mac_compare_bb((*i)->bssid_addr, bssid_mac);

        if (this_cmp == 0)
            this_cmp = mac_compare_bb((*i)->client_addr, client_mac);

        if (this_cmp < 0)
        {
            lo = m + 1;
            lo_ptr = &((*i)->next_auth);
        }
        else
        {
            hi = m;
        }
    }

    return lo_ptr;
}

static struct mac_entry_s** mac_find_first_entry(struct dawn_mac mac)
{
    int lo = 0;
    struct mac_entry_s** lo_ptr = &mac_set;
    int hi = mac_set_last;

    while (lo < hi) {
        struct mac_entry_s** i = lo_ptr;
        int scan_pos = lo;

        // m is next test position of binary search
        int m = (lo + hi) / 2;

        // find entry with ordinal position m
        while (scan_pos++ < m)
        {
            i = &((*i)->next_mac);
        }

        int this_cmp = mac_compare_bb((*i)->mac, mac);

        if (this_cmp < 0)
        {
            lo = m + 1;
            lo_ptr = &((*i)->next_mac);
        }
        else
        {
            hi = m;
        }
    }

    return lo_ptr;
}

void send_beacon_reports(struct dawn_mac bssid, int id) {
    pthread_mutex_lock(&client_array_mutex);

    // Seach for BSSID
    client* i = *client_find_first_bc_entry(bssid, dawn_mac_null, false);

    // Go threw clients
    while (i != NULL && mac_is_equal_bb(i->bssid_addr, bssid)) {
        if (i->rrm_enabled_capa &
            (WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE |
                WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE |
                WLAN_RRM_CAPS_BEACON_REPORT_TABLE))
            ubus_send_beacon_report(i->client_addr, id);

        i = i->next_entry_bc;
    }

    pthread_mutex_unlock(&client_array_mutex);
}

// TODO: Can metric be cached once calculated? Add score_fresh indicator and reset when signal changes
// TODO: as rest of values look to be static fr any given entry.
int eval_probe_metric(struct probe_entry_s* probe_entry, ap* ap_entry) {

    int score = 0;

    // check if ap entry is available
    if (ap_entry != NULL) {
        score += probe_entry->ht_capabilities && ap_entry->ht_support ? dawn_metric.ht_support : 0;
        score += !probe_entry->ht_capabilities && !ap_entry->ht_support ? dawn_metric.no_ht_support : 0;  // TODO: Is both devices not having a capability worthy of scoring?

        // performance anomaly?
        if (network_config.bandwidth >= 1000 || network_config.bandwidth == -1) {
            score += probe_entry->vht_capabilities && ap_entry->vht_support ? dawn_metric.vht_support : 0;
        }

        score += !probe_entry->vht_capabilities && !ap_entry->vht_support ? dawn_metric.no_vht_support : 0;  // TODO: Is both devices not having a capability worthy of scoring?
        score += ap_entry->channel_utilization <= dawn_metric.chan_util_val ? dawn_metric.chan_util : 0;
        score += ap_entry->channel_utilization > dawn_metric.max_chan_util_val ? dawn_metric.max_chan_util : 0;

        score += ap_entry->ap_weight;
    }

    score += (probe_entry->freq > 5000) ? dawn_metric.freq : 0;

    // TODO: Should RCPI be used here as well?
    // TODO: Should this be more scaled?  Should -63dB on current and -77dB on other both score 0 if low / high are -80db and -60dB?
    // TODO: That then lets device capabilites dominate score - making them more important than RSSI difference of 14dB.
    score += (probe_entry->signal >= dawn_metric.rssi_val) ? dawn_metric.rssi : 0;
    score += (probe_entry->signal <= dawn_metric.low_rssi_val) ? dawn_metric.low_rssi : 0;

    // TODO: This magic value never checked by caller.  What does it achieve?
    if (score < 0)
        score = -2; // -1 already used...

    printf("Score: %d of:\n", score);
    print_probe_entry(probe_entry);

    return score;
}


static int compare_station_count(ap* ap_entry_own, ap* ap_entry_to_compare, struct dawn_mac client_addr) {

    printf("Comparing own %d to %d\n", ap_entry_own->station_count, ap_entry_to_compare->station_count);

    int sta_count = ap_entry_own->station_count;
    int sta_count_to_compare = ap_entry_to_compare->station_count;
    if (is_connected(ap_entry_own->bssid_addr, client_addr)) {
        printf("Own is already connected! Decrease counter!\n");
        sta_count--;
    }

    if (is_connected(ap_entry_to_compare->bssid_addr, client_addr)) {
        printf("Comparing station is already connected! Decrease counter!\n");
        sta_count_to_compare--;
    }
    printf("Comparing own station count %d to %d\n", sta_count, sta_count_to_compare);

    return sta_count - sta_count_to_compare > dawn_metric.max_station_diff;
}

int better_ap_available(ap *kicking_ap, struct dawn_mac client_mac, char* neighbor_report) {

    // This remains set to the current AP of client for rest of function
    probe_entry* own_probe = *probe_array_find_first_entry(client_mac, kicking_ap->bssid_addr, true);
    int own_score = -1;
    if (own_probe != NULL && mac_is_equal_bb(own_probe->client_addr, client_mac) && mac_is_equal_bb(own_probe->bssid_addr, kicking_ap->bssid_addr)) {
        printf("Calculating own score!\n");

        own_score = eval_probe_metric(own_probe, kicking_ap);  //TODO: Should the -2 return be handled?
    }
    // no entry for own ap - should never happen?
    else {
        printf("Current AP not found in probe array!\n");
        return -1;
    }

    int max_score = own_score;
    int kick = 0;
    // Now carry on through entries for this client looking for better score
    probe_entry* i = *probe_array_find_first_entry(client_mac, dawn_mac_null, false);

    while (i != NULL && mac_is_equal_bb(i->client_addr, client_mac)) {
        if (i == own_probe) {
            printf("Own Score! Skipping!\n");
            print_probe_entry(i);
            i = i->next_probe;
            continue;
        }

        ap* candidate_ap = ap_array_get_ap(i->bssid_addr, kicking_ap->ssid);

        if (candidate_ap == NULL) {
            i = i->next_probe;
            continue;
        }

        // check if same ssid!
        if (strcmp((char*)kicking_ap->ssid, (char*)candidate_ap->ssid) != 0) {
            i = i->next_probe;
            continue;
        }

        printf("Calculating score to compare!\n");
        int score_to_compare = eval_probe_metric(i, candidate_ap);

        // Find better score...
        if (score_to_compare > max_score) {
            if(neighbor_report == NULL)
            {
                fprintf(stderr,"Neigbor-Report is NULL!\n");
                return 1;  // TODO: Should this be -1?
            }

            kick = 1;

            // instead of returning we append a neighbor report list...
            strcpy(neighbor_report, candidate_ap->neighbor_report);

            max_score = score_to_compare;
        }
        // if ap have same value but station count is different...
        // TODO: Is absolute number meaningful when AP have diffeent capacity?
        else if (dawn_metric.use_station_count > 0 && score_to_compare == max_score ) {

            if (compare_station_count(kicking_ap, candidate_ap, client_mac)) {
                if (neighbor_report == NULL)
                {
                    fprintf(stderr, "Neigbor-Report is NULL!\n");
                    return 1;  // TODO: Should this be -1?
                }

                kick = 1;

                strcpy(neighbor_report, candidate_ap->neighbor_report);
            }
        }

        i = i->next_probe;
    }

    return kick;
}

static int kick_client(ap* kicking_ap, struct client_s *client_entry, char* neighbor_report) {
    int ret = 0;

    if (!mac_in_maclist(client_entry->client_addr)) {
        ret = better_ap_available(kicking_ap, client_entry->client_addr, neighbor_report);
    }

    return ret;
}

int kick_clients(ap* kicking_ap, uint32_t id) {
    pthread_mutex_lock(&client_array_mutex);
    pthread_mutex_lock(&probe_array_mutex);

    int kicked_clients = 0;

    printf("-------- KICKING CLIENTS!!!---------\n");
    char mac_buf_ap[20];
    sprintf(mac_buf_ap, MACSTR, MAC2STR(kicking_ap->bssid_addr.u8));
    printf("EVAL %s\n", mac_buf_ap);

    // Seach for BSSID
    client *j = *client_find_first_bc_entry(kicking_ap->bssid_addr, dawn_mac_null, false);

    // Go threw clients
    while (j  != NULL && mac_is_equal_bb(j->bssid_addr, kicking_ap->bssid_addr)) {
        char neighbor_report[NEIGHBOR_REPORT_LEN] = "";

        int do_kick = kick_client(kicking_ap, j, neighbor_report);
        printf("Chosen AP %s\n", neighbor_report);

        // better ap available
        if (do_kick > 0) {

            // kick after algorithm decided to kick several times
            // + rssi is changing a lot
            // + chan util is changing a lot
            // + ping pong behavior of clients will be reduced
            j->kick_count++;
            printf("Comparing kick count! kickcount: %d to min_kick_count: %d!\n", j->kick_count,
                dawn_metric.min_kick_count);
            if (j->kick_count >= dawn_metric.min_kick_count) {
                printf("Better AP available. Kicking client:\n");
                print_client_entry(j);
                printf("Check if client is active receiving!\n");

                float rx_rate, tx_rate;
                if (get_bandwidth_iwinfo(j->client_addr, &rx_rate, &tx_rate)) {
                    printf("No active transmission data for client. Don't kick!\n");
                }
                else
                {
                    // only use rx_rate for indicating if transmission is going on
                    // <= 6MBits <- probably no transmission
                    // tx_rate has always some weird value so don't use ist
                    if (rx_rate > dawn_metric.bandwidth_threshold) {
                        printf("Client is probably in active transmisison. Don't kick! RxRate is: %f\n", rx_rate);
                    }
                    else
                    {
                        printf("Client is probably NOT in active transmisison. KICK! RxRate is: %f\n", rx_rate);

                        // here we should send a messsage to set the probe.count for all aps to the min that there is no delay between switching
                        // the hearing map is full...
                        send_set_probe(j->client_addr);

                        // don't deauth station? <- deauth is better!
                        // maybe we can use handovers...
                        //del_client_interface(id, client_array[j].client_addr, NO_MORE_STAS, 1, 1000);
                        int sync_kick = wnm_disassoc_imminent(id, j->client_addr, neighbor_report, 12);

                        // Synchronous kick is a test harness feature to indicate arrays have been updated, so don't change further
                        if (sync_kick)
                        {
                            kicked_clients++;
                        }
                        else
                        {
                            client_array_delete(j, false);

                            // don't delete clients in a row. use update function again...
                            // -> chan_util update, ...
                            add_client_update_timer(timeout_config.update_client * 1000 / 4);
                            break;
                        }
                    }
                }
            }
        }
        // no entry in probe array for own bssid
        // TODO: Is test against -1 from (1 && -1) portable?
        else if (do_kick == -1) {
            printf("No Information about client. Force reconnect:\n");
            print_client_entry(j);
            del_client_interface(id, j->client_addr, 0, 1, 0);
        }
        // ap is best
        else {
            printf("AP is best. Client will stay:\n");
            print_client_entry(j);
            // set kick counter to 0 again
            j->kick_count = 0;
        }

        j = j->next_entry_bc;
    }

    printf("---------------------------\n");

    pthread_mutex_unlock(&probe_array_mutex);
    pthread_mutex_unlock(&client_array_mutex);

    return kicked_clients;
}

void update_iw_info(struct dawn_mac bssid_mac) {
    pthread_mutex_lock(&client_array_mutex);
    pthread_mutex_lock(&probe_array_mutex);

    printf("-------- IW INFO UPDATE!!!---------\n");
    char mac_buf_ap[20];
    sprintf(mac_buf_ap, MACSTR, MAC2STR(bssid_mac.u8));
    printf("EVAL %s\n", mac_buf_ap);

    // Seach for BSSID
    // Go threw clients
    for (client* j = *client_find_first_bc_entry(bssid_mac, dawn_mac_null, false);
            j != NULL && mac_is_equal_bb(j->bssid_addr, bssid_mac); j = j->next_entry_bc) {
        // update rssi
        int rssi = get_rssi_iwinfo(j->client_addr);
        int exp_thr = get_expected_throughput_iwinfo(j->client_addr);
        double exp_thr_tmp = iee80211_calculate_expected_throughput_mbit(exp_thr);
        printf("Expected throughput %f Mbit/sec\n", exp_thr_tmp);

        if (rssi != INT_MIN) {
            if (!probe_array_update_rssi(j->bssid_addr, j->client_addr, rssi, true)) {
                printf("Failed to update rssi!\n");
            }
            else {
                printf("Updated rssi: %d\n", rssi);
            }
        }
    }

    printf("---------------------------\n");

    pthread_mutex_unlock(&probe_array_mutex);
    pthread_mutex_unlock(&client_array_mutex);
}

int is_connected_somehwere(struct dawn_mac client_addr) {
    int found_in_array = 0;

#ifndef DAWN_CLIENT_SCAN_BC_ONLY
    client* i = *client_find_first_c_entry(client_addr);
#else
    client* i = client_set_bc;
    while (i != NULL && !mac_is_equal_bb(client_addr, i->client_addr))
    {
        i = i->next_entry_bc;
    }
#endif

    if (i != NULL && mac_is_equal_bb(client_addr, i->client_addr))
    {
        found_in_array = 1;
    }

    return found_in_array;
}

static int is_connected(struct dawn_mac bssid_mac, struct dawn_mac client_mac) {
    int found_in_array = 0;

    client** i = client_find_first_bc_entry(bssid_mac, client_mac, true);

    if (*i != NULL && mac_is_equal_bb((*i)->bssid_addr, bssid_mac) && mac_is_equal_bb((*i)->client_addr, client_mac))
        found_in_array = 1;

    return found_in_array;
}

static struct client_s* insert_to_client_bc_skip_array(struct client_s* entry) {

    struct client_s** insert_pos = client_skip_array_find_first_entry(entry->client_addr, entry->bssid_addr, true);

    entry->next_skip_entry_bc = *insert_pos;
    *insert_pos = entry;
    client_skip_entry_last++;

    return entry;
}

void client_array_insert(client *entry, client** insert_pos) {
    // Passed insert_pos is where to insert in bc set
    if (insert_pos == NULL)
        insert_pos = client_find_first_bc_entry(entry->bssid_addr, entry->client_addr, true);
    entry->next_entry_bc = *insert_pos;
    *insert_pos = entry;

#ifndef DAWN_CLIENT_SCAN_BC_ONLY
    insert_pos = client_find_first_c_entry(entry->client_addr);
    entry->next_entry_c = *insert_pos;
    *insert_pos = entry;
#endif

    client_entry_last++;

    if (client_entry_last == ARRAY_CLIENT_LEN) {
        printf("warning: client_array overflowing (now contains %d entries)!\n", client_entry_last);
    }

    // Try to keep skip list density stable
    if ((client_entry_last / DAWN_CLIENT_SKIP_RATIO) > client_skip_entry_last)
    {
        entry->next_skip_entry_bc = NULL;
        insert_to_client_bc_skip_array(entry);
    }
}

client *client_array_get_client(const struct dawn_mac client_addr) {
    //pthread_mutex_lock(&client_array_mutex);

#ifndef DAWN_CLIENT_SCAN_BC_ONLY
    client* ret = *client_find_first_c_entry(client_addr);
#else
    client* ret = client_set_bc;
    while (ret != NULL && !mac_is_equal_bb(client_addr, ret->client_addr))
    {
        ret = ret->next_entry_bc;
    }
#endif

    if (ret != NULL && !mac_is_equal_bb(client_addr, ret->client_addr))
        ret = NULL;

    //pthread_mutex_unlock(&client_array_mutex);

    return ret;
}

static client* client_array_unlink_entry(client** ref_bc, int unlink_only)
{
    client* entry = *ref_bc; // Both ref_bc and ref_c point to the entry we're deleting

    for (struct client_s** s = &client_skip_set; *s != NULL; s = &((*s)->next_skip_entry_bc)) {
        if (*s == entry) {
            *s = (*s)->next_skip_entry_bc;

            client_skip_entry_last--;
            break;
        }
    }

    //  Accident of history that we always pass in the _bc ref, so need to find _c ref
#ifndef DAWN_CLIENT_SCAN_BC_ONLY
    client** ref_c = &client_set_c;
    while ( *ref_c != NULL && *ref_c != entry)
        ref_c = &((*ref_c)->next_entry_c);

    *ref_c = entry->next_entry_c;
#endif
    *ref_bc = entry->next_entry_bc;
    client_entry_last--;

    if (unlink_only)
    {
        entry->next_entry_bc = NULL;
#ifndef DAWN_CLIENT_SCAN_BC_ONLY
        entry->next_entry_c = NULL;
#endif
    }
    else
    {
        dawn_free(entry);
        entry = NULL;
    }

    return entry;
}

client *client_array_delete(client *entry, int unlink_only) {
    client* ret = NULL;

    client** ref_bc = NULL;

    // Bodyless for-loop: test done in control logic
    for (ref_bc = &client_set_bc; (*ref_bc != NULL) && (*ref_bc != entry); ref_bc = &((*ref_bc)->next_entry_bc));

    // Should never fail, but better to be safe...
    if (*ref_bc == entry)
        ret = client_array_unlink_entry(ref_bc, unlink_only);

    return ret;
}

static __inline__ int probe_compare(probe_entry* probe1, probe_entry* probe2) {
    int ret = 0;

    if (ret == 0)
    {
        ret = mac_compare_bb(probe1->client_addr, probe2->client_addr);
    }

    if (ret == 0)
    {
        ret = mac_compare_bb(probe1->bssid_addr, probe2->bssid_addr);
    }

#if 0
    // TODO: Is this needed for ordering?  Is it a key field?
    if (ret == 0)
    {
        ret = ((probe1->freq < 5000) && (probe2->freq >= 5000));
    }

    // TODO: Is this needed for ordering?  Is it a key field?
    if (ret == 0)
    {
        ret = (probe1->signal < probe2->signal);
    }
#endif

    return ret;
}

static __inline__ void probe_array_unlink_next(probe_entry** i)
{
probe_entry* victim = *i;

    // TODO: Can we pre-test that entry is in skip set with 
    // if ((*s)->next_probe_skip != NULL)... ???
    for (struct probe_entry_s** s = &probe_skip_set; *s != NULL; s = &((*s)->next_probe_skip)) {
        if (*s == victim) {
            *s = (*s)->next_probe_skip;

            probe_skip_entry_last--;
            break;
        }
    }

    *i = victim->next_probe;
    dawn_free(victim);

    probe_entry_last--;
}

int probe_array_delete(probe_entry *entry) {
    int found_in_array = false;

    for (probe_entry** i = &probe_set; *i != NULL; i = &((*i)->next_probe)) {
        if (*i == entry) {
            probe_array_unlink_next(i);
            found_in_array = true;
            break;
        }
    }

    return found_in_array;
}

int probe_array_set_all_probe_count(struct dawn_mac client_addr, uint32_t probe_count) {

    int updated = 0;

    // MUSTDO: Has some code been lost here?  updated never set... Certain to hit not found...
    pthread_mutex_lock(&probe_array_mutex);
    for (probe_entry *i = probe_set; i != NULL; i = i->next_probe) {
        if (mac_is_equal_bb(client_addr, i->client_addr)) {
            printf("Setting probecount for given mac!\n");
            i->counter = probe_count;
        } else if (mac_compare_bb(client_addr, i->client_addr) > 0) {
            printf("MAC not found!\n");
            break;
        }
    }
    pthread_mutex_unlock(&probe_array_mutex);

    return updated;
}

int probe_array_update_rssi(struct dawn_mac bssid_addr, struct dawn_mac client_addr, uint32_t rssi, int send_network)
{
    int updated = 0;

    probe_entry* i = probe_array_get_entry(bssid_addr, client_addr);

    if (i != NULL) {
        i->signal = rssi;
        updated = 1;
        if (send_network)
        {
            ubus_send_probe_via_network(i);
        }
    }

    return updated;
}

int probe_array_update_rcpi_rsni(struct dawn_mac bssid_addr, struct dawn_mac client_addr, uint32_t rcpi, uint32_t rsni, int send_network)
{
    int updated = 0;

    pthread_mutex_lock(&probe_array_mutex);

    probe_entry* i = probe_array_get_entry(bssid_addr, client_addr);

    if (i != NULL) {
        i->rcpi = rcpi;
        i->rsni = rsni;
        updated = 1;

        if (send_network)
            ubus_send_probe_via_network(i);
    }

    pthread_mutex_unlock(&probe_array_mutex);

    return updated;
}

probe_entry *probe_array_get_entry(struct dawn_mac bssid_mac, struct dawn_mac client_mac) {
    probe_entry* ret = *probe_array_find_first_entry(client_mac, bssid_mac, true);

    // Check if we've been given the insert position rather than actually finding the entry
    if ((ret == NULL) || !mac_is_equal_bb(ret->client_addr, client_mac) || !mac_is_equal_bb(ret->bssid_addr, bssid_mac))
        ret = NULL;

    return ret;
}

void print_probe_array() {
    printf("------------------\n");
    printf("Probe Entry Last: %d\n", probe_entry_last);
    for (probe_entry* i = probe_set; i != NULL ; i = i->next_probe) {
        print_probe_entry(i);
    }
    printf("------------------\n");
}

static struct probe_entry_s* insert_to_skip_array(struct probe_entry_s* entry) {

    struct probe_entry_s** insert_pos = probe_skip_array_find_first_entry(entry->client_addr, entry->bssid_addr, true);

    entry->next_probe_skip = *insert_pos;
    *insert_pos = entry;
    probe_skip_entry_last++;

    return entry;
}

probe_entry* insert_to_array(probe_entry* entry, int inc_counter, int save_80211k, int is_beacon, time_t expiry) {
    pthread_mutex_lock(&probe_array_mutex);

    entry->time = expiry;

    // TODO: Add a packed / unpacked wrapper pair?
    probe_entry** existing_entry = probe_array_find_first_entry(entry->client_addr, entry->bssid_addr, true);

    if (((*existing_entry) != NULL)
            && mac_is_equal_bb((*existing_entry)->client_addr, entry->client_addr)
            && mac_is_equal_bb((*existing_entry)->bssid_addr, entry->bssid_addr)) {
        (*existing_entry)->time = expiry;
        if (inc_counter)
            (*existing_entry)->counter++;

        if (entry->signal)
            (*existing_entry)->signal = entry->signal;

        if(entry->ht_capabilities)
            (*existing_entry)->ht_capabilities = entry->ht_capabilities;

        if(entry->vht_capabilities)
            (*existing_entry)->vht_capabilities = entry->vht_capabilities;

        if (save_80211k && entry->rcpi != -1)
            (*existing_entry)->rcpi = entry->rcpi;

        if (save_80211k && entry->rsni != -1)
            (*existing_entry)->rsni = entry->rsni;

        entry = *existing_entry;
    }
    else
    {
        //printf("Adding...\n");
        if (inc_counter)
            entry->counter = 1;
        else
            entry->counter = 0;

        entry->next_probe_skip = NULL;
        entry->next_probe = *existing_entry;
        *existing_entry = entry;
        probe_entry_last++;

        if (probe_entry_last == PROBE_ARRAY_LEN) {
            printf("warning: probe_array overflowing (now contains %d entries)!\n", probe_entry_last);
        }

        // Try to keep skip list density stable
        if ((probe_entry_last / DAWN_PROBE_SKIP_RATIO) > probe_skip_entry_last)
        {
            insert_to_skip_array(entry);
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);

    return entry;  // return pointer to what we used, which may not be what was passed in
}

ap *insert_to_ap_array(ap* entry, time_t expiry) {
    pthread_mutex_lock(&ap_array_mutex);


    // TODO: Why do we delete and add here?
    ap* old_entry = *ap_array_find_first_entry(entry->bssid_addr, entry->ssid);

    if (old_entry != NULL &&
            !mac_is_equal_bb((old_entry)->bssid_addr, entry->bssid_addr) &&
            !strcmp((char*)old_entry->ssid, (char*)entry->ssid))
        old_entry = NULL;

    if (old_entry != NULL)
        ap_array_delete(old_entry);

    entry->time = expiry;
    ap_array_insert(entry);
    pthread_mutex_unlock(&ap_array_mutex);

    return entry;
}


// TODO: What is collision domain used for?
int ap_get_collision_count(int col_domain) {

    int ret_sta_count = 0;

    pthread_mutex_lock(&ap_array_mutex);

    for (ap* i = ap_set; i != NULL; i = i->next_ap) {
        if (i->collision_domain == col_domain)
            ret_sta_count += i->station_count;
    }
    pthread_mutex_unlock(&ap_array_mutex);

    return ret_sta_count;
}


// TODO: Do we need to order this set?  Scan of randomly arranged elements is just
// as quick if we're not using an optimised search.
void ap_array_insert(ap* entry) {
    ap** i;
    for (i = &ap_set; *i != NULL; i = &((*i)->next_ap)) {
        // TODO: Not sure these tests are right way around to ensure SSID / MAC ordering
        // TODO: Do we do any SSID checks elsewhere?
        int sc = strcmp((char*)entry->ssid, (char*)(*i)->ssid);
        if ((sc < 0) || (sc == 0 && mac_compare_bb(entry->bssid_addr, (*i)->bssid_addr) < 0)) {
            break;
        }
    }

    entry->next_ap = *i;
    *i = entry;
    ap_entry_last++;

    if (ap_entry_last == ARRAY_AP_LEN) {
        printf("warning: ap_array overflowing (contains %d entries)!\n", ap_entry_last);
    }
}

ap* ap_array_get_ap(struct dawn_mac bssid_mac, const uint8_t* ssid) {

    pthread_mutex_lock(&ap_array_mutex);

    ap* ret = *ap_array_find_first_entry(bssid_mac, ssid);

    pthread_mutex_unlock(&ap_array_mutex);

    if (ret != NULL && !mac_is_equal_bb((ret)->bssid_addr, bssid_mac))
        ret = NULL;

    return ret;
}

static __inline__ void ap_array_unlink_next(ap** i)
{
    ap* entry = *i;
    *i = entry->next_ap;
    dawn_free(entry);
    ap_entry_last--;
}

int ap_array_delete(ap *entry) {
    int not_found = 1;

    // TODO: Some parts of AP entry management look at SSID as well.  Not this?
    ap** i = &ap_set;
    while ( *i != NULL) {
        if (*i == entry) {
            ap_array_unlink_next(i);
            not_found = 0;
            break;
        }

        i = &((*i)->next_ap);
    }

    return not_found;
}

void remove_old_client_entries(time_t current_time, long long int threshold) {
    client **i = &client_set_bc;
    while (*i  != NULL) {
        if ((*i)->time < current_time - threshold) {
            client_array_unlink_entry(i, false);
        }
        else {
            i = &((*i)->next_entry_bc);
        }
    }
}

void remove_old_probe_entries(time_t current_time, long long int threshold) {
    probe_entry **i = &probe_set;
    while (*i != NULL ) {
        if (((*i)->time < current_time - threshold) && !is_connected((*i)->bssid_addr, (*i)->client_addr)) {
            probe_array_unlink_next(i);
        }
        else {
            i = &((*i)->next_probe);
        }
    }
}

void remove_old_ap_entries(time_t current_time, long long int threshold) {
    ap **i = &ap_set;
    while (*i != NULL) {
        if (((*i)->time) < (current_time - threshold)) {
            ap_array_unlink_next(i);
        }
        else {
            i = &((*i)->next_ap);
        }
    }
}

void remove_old_denied_req_entries(time_t current_time, long long int threshold, int logmac) {
    auth_entry** i = &denied_req_set;
    while (*i != NULL) {
        // check counter

        //check timer
        if ((*i)->time < (current_time - threshold)) {

            // client is not connected for a given time threshold!
            if (logmac && !is_connected_somehwere((*i)->client_addr)) {
                printf("Client has probably a bad driver!\n");

                // problem that somehow station will land into this list
                // maybe delete again?
                if (insert_to_maclist((*i)->client_addr) == 0) {
                    send_add_mac((*i)->client_addr);
                    // TODO: File can grow arbitarily large.  Resource consumption risk.
                    // TODO: Consolidate use of file across source: shared resource for name, single point of access?
                    write_mac_to_file("/tmp/dawn_mac_list", (*i)->client_addr);
                }
            }
            // TODO: Add unlink function to save rescan to find element
            denied_req_array_delete(*i);
        }
        else
        {
            i = &((*i)->next_auth);
        }
    }
}

client *insert_client_to_array(client *entry, time_t expiry) {
client * ret = NULL;

    client **client_tmp = client_find_first_bc_entry(entry->bssid_addr, entry->client_addr, true);

    if (*client_tmp == NULL || !mac_is_equal_bb(entry->bssid_addr, (*client_tmp)->bssid_addr) || !mac_is_equal_bb(entry->client_addr, (*client_tmp)->client_addr)) {
        entry->kick_count = 0;
        entry->time = expiry;
        client_array_insert(entry, client_tmp);
        ret = entry;
    }
    else
        (*client_tmp)->time = expiry;

    return ret;
}

void insert_macs_from_file() {
    FILE *fp;
    char *line = NULL;
#ifdef DAWN_MEMORY_AUDITING
    char *old_line = NULL;
#endif
    size_t len = 0;
    ssize_t read;

// TODO: Loading to array is not constrained by array checks.  Buffer overrun can occur.
    fp = fopen("/tmp/dawn_mac_list", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);
    dawn_regmem(fp);

    while ((read = getline(&line, &len, fp)) != -1) {
#ifdef DAWN_MEMORY_AUDITING
        if (old_line != line)
        {
            if (old_line != NULL)
                dawn_unregmem(old_line);
            old_line = line;
            dawn_regmem(old_line);
        }
#endif

        printf("Retrieved line of length %zu :\n", read);
        printf("%s", line);

        // Need to scanf to an array of ints as there is no byte format specifier
        int tmp_int_mac[ETH_ALEN];
        sscanf(line, MACSTR, STR2MAC(tmp_int_mac));

        struct mac_entry_s* new_mac = dawn_malloc(sizeof(struct mac_entry_s));
        if (new_mac == NULL)
        {
            printf("dawn_malloc of MAC struct failed!\n");
        }
        else
        {
            new_mac->next_mac = NULL;
            for (int i = 0; i < ETH_ALEN; ++i) {
                new_mac->mac.u8[i] = (uint8_t)tmp_int_mac[i];
            }

            insert_to_mac_array(new_mac, NULL);
        }
    }

    printf("Printing MAC list:\n");
    for (struct mac_entry_s *i = mac_set; i != NULL; i = i->next_mac) {
        char mac_buf_target[20];
        sprintf(mac_buf_target, MACSTR, MAC2STR(i->mac.u8));
        printf("%s\n", mac_buf_target);
    }

    fclose(fp);
    dawn_unregmem(fp);
    if (line)
        dawn_free(line);
    //exit(EXIT_SUCCESS);
}


// TODO: This list only ever seems to get longer.  Why do we need it?
int insert_to_maclist(struct dawn_mac mac) {
int ret = 0;
struct mac_entry_s** i = mac_find_first_entry(mac);

    if (*i != NULL && mac_is_equal_bb((*i)->mac, mac))
    {
        ret = -1;
    }
    else
    {
        struct mac_entry_s* new_mac = dawn_malloc(sizeof(struct mac_entry_s));
        if (new_mac == NULL)
        {
            printf("dawn_malloc of MAC struct failed!\n");
        }
        else
        {
            new_mac->next_mac = NULL;
            new_mac->mac = mac;

            insert_to_mac_array(new_mac, i);
        }
    }

    return ret;
}

// TODO: How big is it in a large network?
int mac_in_maclist(struct dawn_mac mac) {
int ret = 0;
struct mac_entry_s** i = mac_find_first_entry(mac);

    if (*i != NULL && mac_is_equal_bb((*i)->mac, mac))
    {
        ret = 1;
    }

    return ret;
}

auth_entry* insert_to_denied_req_array(auth_entry* entry, int inc_counter, time_t expiry) {
    pthread_mutex_lock(&denied_array_mutex);

    auth_entry** i = auth_entry_find_first_entry(entry->bssid_addr, entry->client_addr);

    if ((*i) != NULL && mac_is_equal_bb(entry->bssid_addr, (*i)->bssid_addr) && mac_is_equal_bb(entry->client_addr, (*i)->client_addr)) {

        entry = *i;

        entry->time = expiry;
        if (inc_counter) {
            entry->counter++;
        }
    }
    else
    {
        entry->time = expiry;
        if (inc_counter)
            entry->counter++;
        else
            entry->counter = 0;

        entry->next_auth = *i;
        *i = entry;
        denied_req_last++;

        if (denied_req_last == DENY_REQ_ARRAY_LEN) {
            printf("warning: denied_req_array overflowing (now contains %d entries)!\n", denied_req_last);
        }
    }

    pthread_mutex_unlock(&denied_array_mutex);

    return entry;
}

void denied_req_array_delete(auth_entry* entry) {

    auth_entry** i;

    for (i = &denied_req_set; *i != NULL; i = &((*i)->next_auth)) {
        if (*i == entry) {
            *i = entry->next_auth;
            denied_req_last--;
            dawn_free(entry);
            break;
        }
    }

    return;
}

struct mac_entry_s* insert_to_mac_array(struct mac_entry_s* entry, struct mac_entry_s** insert_pos) {
    if (insert_pos == NULL)
        insert_pos = mac_find_first_entry(entry->mac);

    entry->next_mac = *insert_pos;
    *insert_pos = entry;
    mac_set_last++;

    if (mac_set_last == DENY_REQ_ARRAY_LEN) {
        printf("warning: denied_req_array overflowing (now contains %d entries)!\n", mac_set_last);
    }

    return entry;
}

void mac_array_delete(struct mac_entry_s* entry) {

    struct mac_entry_s** i;

    for (i = &mac_set; *i != NULL; i = &((*i)->next_mac)) {
        if (*i == entry) {
            *i = entry->next_mac;
            mac_set_last--;
            dawn_free(entry);
        }
    }

    return;
}

void print_probe_entry(probe_entry *entry) {
#ifndef DAWN_NO_OUTPUT
    char mac_buf_ap[20];
    char mac_buf_client[20];
    char mac_buf_target[20];

    sprintf(mac_buf_ap, MACSTR, MAC2STR(entry->bssid_addr.u8));
    sprintf(mac_buf_client, MACSTR, MAC2STR(entry->client_addr.u8));
    sprintf(mac_buf_target, MACSTR, MAC2STR(entry->target_addr.u8));


    printf(
            "bssid_addr: %s, client_addr: %s, signal: %d, freq: "
            "%d, counter: %d, vht: %d, min_rate: %d, max_rate: %d\n",
            mac_buf_ap, mac_buf_client, entry->signal, entry->freq, entry->counter, entry->vht_capabilities,
            entry->min_supp_datarate, entry->max_supp_datarate);
#endif
}

void print_auth_entry(auth_entry *entry) {
#ifndef DAWN_NO_OUTPUT
    char mac_buf_ap[20];
    char mac_buf_client[20];
    char mac_buf_target[20];

    sprintf(mac_buf_ap, MACSTR, MAC2STR(entry->bssid_addr.u8));
    sprintf(mac_buf_client, MACSTR, MAC2STR(entry->client_addr.u8));
    sprintf(mac_buf_target, MACSTR, MAC2STR(entry->target_addr.u8));

    printf(
            "bssid_addr: %s, client_addr: %s, signal: %d, freq: "
            "%d\n",
            mac_buf_ap, mac_buf_client, entry->signal, entry->freq);
#endif
}

void print_client_entry(client *entry) {
#ifndef DAWN_NO_OUTPUT
    char mac_buf_ap[20];
    char mac_buf_client[20];

    sprintf(mac_buf_ap, MACSTR, MAC2STR(entry->bssid_addr.u8));
    sprintf(mac_buf_client, MACSTR, MAC2STR(entry->client_addr.u8));

    printf("bssid_addr: %s, client_addr: %s, freq: %d, ht_supported: %d, vht_supported: %d, ht: %d, vht: %d, kick: %d\n",
           mac_buf_ap, mac_buf_client, entry->freq, entry->ht_supported, entry->vht_supported, entry->ht, entry->vht,
           entry->kick_count);
#endif
}

void print_client_array() {
    printf("--------Clients------\n");
    printf("Client Entry Last: %d\n", client_entry_last);
    for (client* i = client_set_bc; i != NULL; i = i->next_entry_bc) {
        print_client_entry(i);
    }
    printf("------------------\n");
}

static void print_ap_entry(ap *entry) {
#ifndef DAWN_NO_OUTPUT
    char mac_buf_ap[20];

    sprintf(mac_buf_ap, MACSTR, MAC2STR(entry->bssid_addr.u8));
    printf("ssid: %s, bssid_addr: %s, freq: %d, ht: %d, vht: %d, chan_utilz: %d, col_d: %d, bandwidth: %d, col_count: %d neighbor_report: %s\n",
           entry->ssid, mac_buf_ap, entry->freq, entry->ht_support, entry->vht_support,
           entry->channel_utilization, entry->collision_domain, entry->bandwidth,
           ap_get_collision_count(entry->collision_domain), entry->neighbor_report
    );
#endif
}

void print_ap_array() {
    printf("--------APs------\n");
    for (ap *i = ap_set; i != NULL; i = i->next_ap) {
        print_ap_entry(i);
    }
    printf("------------------\n");
}

void destroy_mutex() {

    // free resources
    fprintf(stdout, "Freeing mutex resources\n");
    pthread_mutex_destroy(&probe_array_mutex);
    pthread_mutex_destroy(&client_array_mutex);
    pthread_mutex_destroy(&ap_array_mutex);

    return;
}

int init_mutex() {

    if (pthread_mutex_init(&probe_array_mutex, NULL) != 0) {
        fprintf(stderr, "Mutex init failed!\n");
        return 1;
    }

    if (pthread_mutex_init(&client_array_mutex, NULL) != 0) {
        fprintf(stderr, "Mutex init failed!\n");
        return 1;
    }

    if (pthread_mutex_init(&ap_array_mutex, NULL) != 0) {
        fprintf(stderr, "Mutex init failed!\n");
        return 1;
    }

    if (pthread_mutex_init(&denied_array_mutex, NULL) != 0) {
        fprintf(stderr, "Mutex init failed!\n");
        return 1;
    }
    return 0;
}
