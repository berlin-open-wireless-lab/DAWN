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
struct local_config_s local_config;

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

static int probe_compare(probe_entry *probe1, probe_entry *probe2);

static int is_connected(struct dawn_mac bssid_mac, struct dawn_mac client_mac);

static int compare_station_count(ap* ap_entry_own, ap* ap_entry_to_compare, struct dawn_mac client_addr);


// ---------------- Global variables ----------------
// config section name
const char *band_config_name[__DAWN_BAND_MAX] = {
    "802_11g",
    "802_11a"
};

// starting frequency
// TODO: make this configurable
const int max_band_freq[__DAWN_BAND_MAX] = {
    2500,
    5925 // This may cause trouble because there's overlap between bands in different countries
};

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

static struct probe_entry_s** probe_skip_array_find_first_entry(struct dawn_mac client_mac, struct dawn_mac bssid_mac, bool do_bssid)
{
    int lo = 0;
    struct probe_entry_s** lo_ptr = &probe_skip_set;
    int hi = probe_skip_entry_last;

    dawnlog_debug_func("Entering...");

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

    dawnlog_debug_func("Entering...");

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

    dawnlog_debug_func("Entering...");

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

    dawnlog_debug_func("Entering...");

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

    dawnlog_debug_func("Entering...");

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

    dawnlog_debug_func("Entering...");

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


static struct mac_entry_s** mac_find_first_entry(struct dawn_mac mac)
{
    int lo = 0;
    struct mac_entry_s** lo_ptr = &mac_set;
    int hi = mac_set_last;

    dawnlog_debug_func("Entering...");

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

void send_beacon_reports(ap *a, int id) {
    pthread_mutex_lock(&client_array_mutex);

    dawnlog_debug_func("Entering...");

    // Seach for BSSID
    client* i = *client_find_first_bc_entry(a->bssid_addr, dawn_mac_null, false);

    // Go through clients
    while (i != NULL && mac_is_equal_bb(i->bssid_addr, a->bssid_addr)) {
        if (dawnlog_showing(DAWNLOG_DEBUG))
            dawnlog_debug("Station " MACSTR ": rrm_enabled_capa=%02x: PASSIVE=%d, ACTIVE=%d, TABLE=%d\n",
                MAC2STR(i->client_addr.u8), i->rrm_enabled_capa,
                !!(i->rrm_enabled_capa & WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE),
                !!(i->rrm_enabled_capa & WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE),
                !!(i->rrm_enabled_capa & WLAN_RRM_CAPS_BEACON_REPORT_TABLE));

        if (i->rrm_enabled_capa & dawn_metric.rrm_mode_mask)
            ubus_send_beacon_report(i, a, id);

        i = i->next_entry_bc;
    }

    pthread_mutex_unlock(&client_array_mutex);
}

int get_band(int freq) {
    int band;

    dawnlog_debug_func("Entering...");

    for (band=0; band < __DAWN_BAND_MAX; band++)
        if (freq <= max_band_freq[band])
            return band;
    band--;
    dawnlog_warning("frequency %d is beyond the last known band. "
                    "Using '%s' band parameters.\n", freq, band_config_name[band]);
    return band;
}

// TODO: Can metric be cached once calculated? Add score_fresh indicator and reset when signal changes
// TODO: as rest of values look to be static fr any given entry.
int eval_probe_metric(struct probe_entry_s* probe_entry, ap* ap_entry) {

    int band, score = 0;

    dawnlog_debug_func("Entering...");

    // TODO: Should RCPI be used here as well?
    band = get_band(probe_entry->freq);
    score = dawn_metric.initial_score[band];
    score += probe_entry->signal >= dawn_metric.rssi_val[band] ? dawn_metric.rssi[band] : 0;
    score += probe_entry->signal <= dawn_metric.low_rssi_val[band] ? dawn_metric.low_rssi[band] : 0;
    score += (probe_entry->signal - dawn_metric.rssi_center[band]) * dawn_metric.rssi_weight[band];

    // check if ap entry is available
    if (ap_entry != NULL) {
        score += probe_entry->ht_capabilities && ap_entry->ht_support ? dawn_metric.ht_support[band] : 0;
        score += !probe_entry->ht_capabilities && !ap_entry->ht_support ? dawn_metric.no_ht_support[band] : 0;  // TODO: Is both devices not having a capability worthy of scoring?

        // performance anomaly?
        if (network_config.bandwidth >= 1000 || network_config.bandwidth == -1) {
            score += probe_entry->vht_capabilities && ap_entry->vht_support ? dawn_metric.vht_support[band] : 0;
        }

        score += !probe_entry->vht_capabilities && !ap_entry->vht_support ? dawn_metric.no_vht_support[band] : 0;  // TODO: Is both devices not having a capability worthy of scoring?
        score += ap_entry->channel_utilization <= dawn_metric.chan_util_val[band] ? dawn_metric.chan_util[band] : 0;
        score += ap_entry->channel_utilization > dawn_metric.max_chan_util_val[band] ? dawn_metric.max_chan_util[band] : 0;

        score += ap_entry->ap_weight;
    }

    // TODO: This magic value never checked by caller.  What does it achieve?
    if (score < 0)
        score = -2; // -1 already used...

    return score;
}


static int compare_station_count(ap* ap_entry_own, ap* ap_entry_to_compare, struct dawn_mac client_addr) {

    dawnlog_debug_func("Entering...");

    dawnlog_info("Comparing own %d to %d\n", ap_entry_own->station_count, ap_entry_to_compare->station_count);

    int sta_count = ap_entry_own->station_count;
    int sta_count_to_compare = ap_entry_to_compare->station_count;
    if (is_connected(ap_entry_own->bssid_addr, client_addr)) {
        dawnlog_debug("Own is already connected! Decrease counter!\n");
        sta_count--;
    }

    if (is_connected(ap_entry_to_compare->bssid_addr, client_addr)) {
        dawnlog_debug("Comparing station is already connected! Decrease counter!\n");
        sta_count_to_compare--;
    }
    dawnlog_info("Comparing own station count %d to %d\n", sta_count, sta_count_to_compare);

    if (sta_count - sta_count_to_compare > dawn_metric.max_station_diff)
        return 1;
    else if (sta_count_to_compare - sta_count > dawn_metric.max_station_diff)
        return -1;
    else
        return 0;
}

static struct kicking_nr *find_position(struct kicking_nr *nrlist, int score) {
    struct kicking_nr *ret = NULL;

    dawnlog_debug_func("Entering...");

    while (nrlist && nrlist->score < score) {
        ret = nrlist;
        nrlist = nrlist->next;
    }
    return ret;
}

static void remove_kicking_nr_list(struct kicking_nr *nr_list) {
    struct kicking_nr *n;

    dawnlog_debug_func("Entering...");

    while(nr_list) {
        n = nr_list->next;
        dawn_free(nr_list);
        nr_list = n;
    }
}

static struct kicking_nr *prune_kicking_nr_list(struct kicking_nr *nr_list, int min_score) {
    struct kicking_nr *next;

    dawnlog_debug_func("Entering...");

    while (nr_list && nr_list->score <= min_score) {
        next = nr_list->next;
        dawn_free(nr_list);
        nr_list = next;
    }
    return nr_list;
}

static struct kicking_nr *insert_kicking_nr(struct kicking_nr *head, char *nr, int score, bool prune) {
    struct kicking_nr *new_entry, *pos;

    dawnlog_debug_func("Entering...");

    if (prune)
        head = prune_kicking_nr_list(head, score - dawn_metric.kicking_threshold);

    // we are giving no error information here (not really critical)
    if (!(new_entry = dawn_malloc(sizeof (struct kicking_nr))))
        return head;

    strncpy(new_entry->nr, nr, NEIGHBOR_REPORT_LEN);
    new_entry->score = score;
    pos = find_position(head, score);
    if (pos) {
        new_entry->next = pos->next;
        pos -> next = new_entry;
    } else {
        new_entry->next = head;
        head = new_entry;
    }
    return head;
}

int better_ap_available(ap *kicking_ap, struct dawn_mac client_mac, struct kicking_nr **neighbor_report) {

    dawnlog_debug_func("Entering...");

    // This remains set to the current AP of client for rest of function
    probe_entry* own_probe = *probe_array_find_first_entry(client_mac, kicking_ap->bssid_addr, true);
    int own_score = -1;
    if (own_probe != NULL
            && mac_is_equal_bb(own_probe->client_addr, client_mac)
            && mac_is_equal_bb(own_probe->bssid_addr, kicking_ap->bssid_addr)) {
        own_score = eval_probe_metric(own_probe, kicking_ap);  //TODO: Should the -2 return be handled?
        dawnlog_trace("Current AP score = %d for:\n", own_score);
        print_probe_entry(DAWNLOG_TRACE, own_probe);
    }
    // no entry for own ap - should never happen?
    else {
        dawnlog_warning("Current AP not found in probe array!\n");
        return -1;
    }

    int max_score = own_score;
    int kick = 0;
    int ap_count = 0;
    // Now go through all AP entries for this client looking for better score
    probe_entry* i = *probe_array_find_first_entry(client_mac, dawn_mac_null, false);

    while (i != NULL && mac_is_equal_bb(i->client_addr, client_mac)) {
        if (i == own_probe) {
            dawnlog_trace("Own Score! Skipping!\n");
            i = i->next_probe;
            continue;
        }

        ap* candidate_ap = ap_array_get_ap(i->bssid_addr, kicking_ap->ssid);

        if (candidate_ap == NULL) {
            dawnlog_trace("Candidate AP not in array\n");
            i = i->next_probe;
            continue;
        }

        // check if same ssid!
        if (strcmp((char*)kicking_ap->ssid, (char*)candidate_ap->ssid) != 0) {
            dawnlog_trace("Candidate AP has different SSID\n");
            i = i->next_probe;
            continue;
        }

        ap_count++;

        int score_to_compare = eval_probe_metric(i, candidate_ap);
        dawnlog_trace("Candidate score = %d from:\n", score_to_compare);
        print_probe_entry(DAWNLOG_TRACE, i);

        int ap_outcome = 0; // No kicking

        // Find better score...
        // FIXME: Do we mean to use 'kick' like this here?  It is set when we find an AP with bigger score
        // then any more have to also be 'kicking_threshold' bigger
        if (score_to_compare > max_score + (kick ? 0 : dawn_metric.kicking_threshold)) {
            ap_outcome = 2; // Add and prune

            max_score = score_to_compare;
        }
        // if AP have same value but station count might improve it...
        // TODO: Is absolute number meaningful when AP have diffeent capacity?
        else if (score_to_compare == max_score && dawn_metric.use_station_count > 0 ) {
            int compare = compare_station_count(kicking_ap, candidate_ap, client_mac);

            if (compare > 0) {
                ap_outcome = 2; // Add and prune
            }
            else if (compare == 0 && kick) {
                ap_outcome = 1; // Add but no prune
            }
        }
        else if (score_to_compare >= max_score && kick) {
            ap_outcome = 1; // Add but no prune
        }

        if (ap_outcome == 0)
        {
            dawnlog_trace("Not a better AP after full evaluation\n");
        }
        else
        {
            dawnlog_trace("Better AP after full evaluation - add to NR (%s pruning)\n", ap_outcome == 2 ? "with" : "without");
            // Pointer is NULL if we're only finding a better AP without actually using it
            if (neighbor_report != NULL)
            {
                // Test this_kick_outcome for pruning
                *neighbor_report = insert_kicking_nr(*neighbor_report, candidate_ap->neighbor_report,
                    score_to_compare, ap_outcome == 2);
            }

            // If we find a single candidate then we will be kicking
            kick = 1;
        }

        // Short circuit loop if we're only finding a better AP without actually using it
        if (kick && neighbor_report == NULL)
        {
            i = NULL;
        }
        else
        {
            i = i->next_probe;
        }
    }

    if (neighbor_report != NULL)
        dawnlog_info("Station " MACSTR ": Compared %d alternate AP candidates\n", MAC2STR(client_mac.u8), ap_count);

    return kick;
}

int kick_clients(ap* kicking_ap, uint32_t id) {
    dawnlog_debug_func("Entering...");

    pthread_mutex_lock(&client_array_mutex);
    pthread_mutex_lock(&probe_array_mutex);

    int kicked_clients = 0;

    dawnlog_info("AP BSSID " MACSTR ": Looking for candidates to kick\n", MAC2STR(kicking_ap->bssid_addr.u8));

    // Seach for BSSID
    client *j = *client_find_first_bc_entry(kicking_ap->bssid_addr, dawn_mac_null, false);

    // Go through clients
    while (j  != NULL && mac_is_equal_bb(j->bssid_addr, kicking_ap->bssid_addr)) {
        struct kicking_nr *neighbor_report = NULL;

        int do_kick = 0;

        if (mac_in_maclist(j->client_addr)) {
            dawnlog_info("Station " MACSTR ": Suppressing check due to MAC list entry\n", MAC2STR(j->client_addr.u8));
        }
        else {
            do_kick = better_ap_available(kicking_ap, j->client_addr, &neighbor_report);
        }

        // better ap available
        if (do_kick > 0) {

            // kick after algorithm decided to kick several times
            // + rssi is changing a lot
            // + chan util is changing a lot
            // + ping pong behavior of clients will be reduced
            j->kick_count++;
            if (j->kick_count < dawn_metric.min_number_to_kick) {
                dawnlog_info("Station " MACSTR ": kickcount %d below threshold of %d!\n", MAC2STR(j->client_addr.u8), j->kick_count,
                    dawn_metric.min_number_to_kick);
            }
            else {
                float rx_rate, tx_rate;
                bool have_bandwidth_iwinfo = get_bandwidth_iwinfo(j->client_addr, &rx_rate, &tx_rate);
                if (!have_bandwidth_iwinfo && dawn_metric.bandwidth_threshold > 0) {
                    dawnlog_info("Station " MACSTR ": No active transmission data for client. Don't kick!\n", MAC2STR(j->client_addr.u8));
                }
                else
                {
                    // only use rx_rate for indicating if transmission is going on
                    // <= 6MBits <- probably no transmission
                    // tx_rate has always some weird value so don't use ist
                    if (have_bandwidth_iwinfo && rx_rate > dawn_metric.bandwidth_threshold) {
                        dawnlog_info("Station " MACSTR ": Client is probably in active transmisison. Don't kick! RxRate is: %f\n", MAC2STR(j->client_addr.u8), rx_rate);
                    }
                    else
                    {
                        if (have_bandwidth_iwinfo)
                            dawnlog_always("Station " MACSTR ": Kicking as probably NOT in active transmisison. RxRate is: %f\n", MAC2STR(j->client_addr.u8), rx_rate);
                        else
                            dawnlog_always("Station " MACSTR ": Kicking as no active transmission data for client, but bandwidth_threshold=%d is OK.\n",
                                MAC2STR(j->client_addr.u8), dawn_metric.bandwidth_threshold);

                        print_client_entry(DAWNLOG_TRACE, j);

                        if (dawnlog_showing(DAWNLOG_INFO))
                        {
                            for (struct kicking_nr* n = neighbor_report; n; n = n->next)
                                dawnlog_info("Kicking NR entry: " NR_MACSTR ", score=%d\n", NR_MAC2STR(n->nr), n->score);
                        }

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
            dawnlog_info("Station " MACSTR ": No Information about client. Force reconnect:\n", MAC2STR(j->client_addr.u8));
            print_client_entry(DAWNLOG_TRACE, j);
            del_client_interface(id, j->client_addr, 0, 1, 0);
        }
        // ap is best
        else {
            dawnlog_info("Station " MACSTR ": Current AP is best. Client will stay:\n", MAC2STR(j->client_addr.u8));
            print_client_entry(DAWNLOG_TRACE, j);
            // set kick counter to 0 again
            j->kick_count = 0;
        }

        remove_kicking_nr_list(neighbor_report);
        neighbor_report = NULL;

        j = j->next_entry_bc;
    }

    dawnlog_trace("KICKING: --------- AP Finished ---------\n");

    pthread_mutex_unlock(&probe_array_mutex);
    pthread_mutex_unlock(&client_array_mutex);

    return kicked_clients;
}

void update_iw_info(struct dawn_mac bssid_mac) {
    dawnlog_debug_func("Entering...");

    pthread_mutex_lock(&client_array_mutex);
    pthread_mutex_lock(&probe_array_mutex);

    dawnlog_trace("-------- IW INFO UPDATE!!!---------\n");
    dawnlog_trace("EVAL " MACSTR "\n", MAC2STR(bssid_mac.u8));

    // Seach for BSSID
    // Go through clients
    for (client* j = *client_find_first_bc_entry(bssid_mac, dawn_mac_null, false);
            j != NULL && mac_is_equal_bb(j->bssid_addr, bssid_mac); j = j->next_entry_bc) {
        // update rssi
        int rssi = get_rssi_iwinfo(j->client_addr);
        dawnlog_trace("Expected throughput %f Mbit/sec\n",
                iee80211_calculate_expected_throughput_mbit(get_expected_throughput_iwinfo(j->client_addr)));

        if (rssi != INT_MIN) {
            if (!probe_array_update_rssi(j->bssid_addr, j->client_addr, rssi, true)) {
                dawnlog_warning("Failed to update rssi!\n");
            }
            else {
                dawnlog_trace("Updated rssi: %d\n", rssi);
            }
        }
    }

    dawnlog_trace("---------------------------\n");

    pthread_mutex_unlock(&probe_array_mutex);
    pthread_mutex_unlock(&client_array_mutex);
}

int is_connected_somehwere(struct dawn_mac client_addr) {
    int found_in_array = 0;

    dawnlog_debug_func("Entering...");

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

    dawnlog_debug_func("Entering...");

    client** i = client_find_first_bc_entry(bssid_mac, client_mac, true);

    if (*i != NULL && mac_is_equal_bb((*i)->bssid_addr, bssid_mac) && mac_is_equal_bb((*i)->client_addr, client_mac))
        found_in_array = 1;

    return found_in_array;
}

static struct client_s* insert_to_client_bc_skip_array(struct client_s* entry) {
    dawnlog_debug_func("Entering...");


    struct client_s** insert_pos = client_skip_array_find_first_entry(entry->client_addr, entry->bssid_addr, true);

    entry->next_skip_entry_bc = *insert_pos;
    *insert_pos = entry;
    client_skip_entry_last++;

    return entry;
}

void client_array_insert(client *entry, client** insert_pos) {
    dawnlog_debug_func("Entering...");

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

    // Try to keep skip list density stable
    if ((client_entry_last / DAWN_CLIENT_SKIP_RATIO) > client_skip_entry_last)
    {
        entry->next_skip_entry_bc = NULL;
        insert_to_client_bc_skip_array(entry);
    }
}

client *client_array_get_client(const struct dawn_mac client_addr) {
    dawnlog_debug_func("Entering...");

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

    dawnlog_debug_func("Entering...");

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

    dawnlog_debug_func("Entering...");

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

    dawnlog_debug_func("Entering...");

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
    victim = NULL;

    probe_entry_last--;
}

int probe_array_delete(probe_entry *entry) {
    int found_in_array = false;

    dawnlog_debug_func("Entering...");

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

    dawnlog_debug_func("Entering...");

    // MUSTDO: Has some code been lost here?  updated never set... Certain to hit not found...
    pthread_mutex_lock(&probe_array_mutex);
    for (probe_entry *i = probe_set; i != NULL; i = i->next_probe) {
        if (mac_is_equal_bb(client_addr, i->client_addr)) {
            dawnlog_debug("Setting probecount for given mac!\n");
            i->counter = probe_count;
        } else if (mac_compare_bb(client_addr, i->client_addr) > 0) {
            dawnlog_info("MAC not found!\n");
            break;
        }
    }
    pthread_mutex_unlock(&probe_array_mutex);

    return updated;
}

int probe_array_update_rssi(struct dawn_mac bssid_addr, struct dawn_mac client_addr, uint32_t rssi, int send_network)
{
    int updated = 0;

    dawnlog_debug_func("Entering...");

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

    dawnlog_debug_func("Entering...");

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
    dawnlog_debug_func("Entering...");

    probe_entry* ret = *probe_array_find_first_entry(client_mac, bssid_mac, true);

    // Check if we've been given the insert position rather than actually finding the entry
    if ((ret == NULL) || !mac_is_equal_bb(ret->client_addr, client_mac) || !mac_is_equal_bb(ret->bssid_addr, bssid_mac))
        ret = NULL;

    return ret;
}

void print_probe_array() {
    if (dawnlog_showing(DAWNLOG_DEBUG))
    {
        dawnlog_debug("------------------\n");
        dawnlog_debug("Probe Entry Last: %d\n", probe_entry_last);
        for (probe_entry* i = probe_set; i != NULL; i = i->next_probe) {
            print_probe_entry(DAWNLOG_DEBUG, i);
        }
        dawnlog_debug("------------------\n");
    }
}

static struct probe_entry_s* insert_to_skip_array(struct probe_entry_s* entry) {

    dawnlog_debug_func("Entering...");

    struct probe_entry_s** insert_pos = probe_skip_array_find_first_entry(entry->client_addr, entry->bssid_addr, true);

    entry->next_probe_skip = *insert_pos;
    *insert_pos = entry;
    probe_skip_entry_last++;

    return entry;
}

probe_entry* insert_to_array(probe_entry* entry, int inc_counter, int save_80211k, int is_beacon, time_t expiry) {
    dawnlog_debug_func("Entering...");

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
        dawnlog_debug("Adding...\n");
        if (inc_counter)
            entry->counter = 1;
        else
            entry->counter = 0;

        entry->next_probe_skip = NULL;
        entry->next_probe = *existing_entry;
        *existing_entry = entry;
        probe_entry_last++;

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
    dawnlog_debug_func("Entering...");

    pthread_mutex_lock(&ap_array_mutex);

    // TODO: Why do we delete and add here rather than update existing?
    ap* old_entry = *ap_array_find_first_entry(entry->bssid_addr, entry->ssid);

    if (old_entry != NULL &&
            mac_is_equal_bb((old_entry)->bssid_addr, entry->bssid_addr) &&
            !strcmp((char*)old_entry->ssid, (char*)entry->ssid))
        ap_array_delete(old_entry);

    entry->time = expiry;
    ap_array_insert(entry);
    pthread_mutex_unlock(&ap_array_mutex);

    print_ap_array();

    return entry;
}


// TODO: What is collision domain used for?
int ap_get_collision_count(int col_domain) {

    int ret_sta_count = 0;

    dawnlog_debug_func("Entering...");;

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
    dawnlog_debug_func("Entering...");;

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
}

ap* ap_array_get_ap(struct dawn_mac bssid_mac, const uint8_t* ssid) {

    dawnlog_debug_func("Entering...");;

    pthread_mutex_lock(&ap_array_mutex);

    ap* ret = *ap_array_find_first_entry(bssid_mac, ssid);

    pthread_mutex_unlock(&ap_array_mutex);

    if (ret != NULL && !mac_is_equal_bb((ret)->bssid_addr, bssid_mac))
        ret = NULL;

    return ret;
}

static __inline__ void ap_array_unlink_next(ap** i)
{
    dawnlog_debug_func("Entering...");;

    ap* entry = *i;
    *i = entry->next_ap;
    dawn_free(entry);
    entry = NULL;
    ap_entry_last--;
}

int ap_array_delete(ap *entry) {
    int not_found = 1;

    dawnlog_debug_func("Entering...");;

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
    dawnlog_debug_func("Entering...");

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
    dawnlog_debug_func("Entering...");

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


client *insert_client_to_array(client *entry, time_t expiry) {
client * ret = NULL;

    dawnlog_debug_func("Entering...");

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
    size_t len = 0;
    ssize_t read;

    dawnlog_debug_func("Entering...");

    fp = fopen("/tmp/dawn_mac_list", "r");
    if (fp == NULL)
    {
        dawnlog_error("Failed opening MAC list file - quitting!\n");
        exit(EXIT_FAILURE);
    }

    dawn_regmem(fp);

    read = getline(&line, &len, fp);
#ifdef DAWN_MEMORY_AUDITING
    if (line)
        dawn_regmem(line);
#endif

    while (read != -1) {

        dawnlog_debug("Retrieved line of length %zu :\n", read);
        dawnlog_debug("%s", line);

        // Need to scanf to an array of ints as there is no byte format specifier
        int tmp_int_mac[ETH_ALEN];
        sscanf(line, MACSTR, STR2MAC(tmp_int_mac));

        struct mac_entry_s* new_mac = dawn_malloc(sizeof(struct mac_entry_s));
        if (new_mac == NULL)
        {
            dawnlog_error("malloc of MAC struct failed!\n");
        }
        else
        {
            new_mac->next_mac = NULL;
            for (int i = 0; i < ETH_ALEN; ++i) {
                new_mac->mac.u8[i] = (uint8_t)tmp_int_mac[i];
            }

            insert_to_mac_array(new_mac, NULL);
        }

#ifdef DAWN_MEMORY_AUDITING
        char* old_line = line;
#endif
        read = getline(&line, &len, fp);
#ifdef DAWN_MEMORY_AUDITING
        if (old_line != line)
        {
            dawn_unregmem(old_line);
            dawn_regmem(line);
        }
#endif
    }

    if (dawnlog_showing(DAWNLOG_DEBUG))
    {
        dawnlog_debug("Printing MAC list:\n");
        for (struct mac_entry_s* i = mac_set; i != NULL; i = i->next_mac) {
            dawnlog_debug(MACSTR "\n", MAC2STR(i->mac.u8));
        }
    }

    fclose(fp);
    dawn_unregmem(fp);
    if (line)
    {
        free(line);
        dawn_unregmem(line);
    }

    //exit(EXIT_SUCCESS);
}


// TODO: This list only ever seems to get longer.  Why do we need it?
int insert_to_maclist(struct dawn_mac mac) {
int ret = 0;
struct mac_entry_s** i = mac_find_first_entry(mac);

    dawnlog_debug_func("Entering...");

    if (*i != NULL && mac_is_equal_bb((*i)->mac, mac))
    {
        ret = -1;
    }
    else
    {
        struct mac_entry_s* new_mac = dawn_malloc(sizeof(struct mac_entry_s));
        if (new_mac == NULL)
        {
            dawnlog_error("malloc of MAC struct failed!\n");
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

    dawnlog_debug_func("Entering...");

    if (*i != NULL && mac_is_equal_bb((*i)->mac, mac))
    {
        ret = 1;
    }

    return ret;
}


struct mac_entry_s* insert_to_mac_array(struct mac_entry_s* entry, struct mac_entry_s** insert_pos) {
    dawnlog_debug_func("Entering...");;

    if (insert_pos == NULL)
        insert_pos = mac_find_first_entry(entry->mac);

    entry->next_mac = *insert_pos;
    *insert_pos = entry;
    mac_set_last++;

    return entry;
}

void mac_array_delete(struct mac_entry_s* entry) {

    struct mac_entry_s** i;

    dawnlog_debug_func("Entering...");;

    for (i = &mac_set; *i != NULL; i = &((*i)->next_mac)) {
        if (*i == entry) {
            *i = entry->next_mac;
            mac_set_last--;
            dawn_free(entry);
            entry = NULL;
        }
    }

    return;
}

void print_probe_entry(int level, probe_entry *entry) {
    if (dawnlog_showing(level))
    {
        dawnlog(level,
            "bssid_addr: " MACSTR ", client_addr: " MACSTR ", signal : % d, freq : "
            "%d, counter: %d, vht: %d, min_rate: %d, max_rate: %d\n",
            MAC2STR(entry->bssid_addr.u8), MAC2STR(entry->client_addr.u8),
            entry->signal, entry->freq, entry->counter, entry->vht_capabilities,
            entry->min_supp_datarate, entry->max_supp_datarate);
    }
}

void print_client_req_entry(int level, client_req_entry *entry) {
    if (dawnlog_showing(DAWNLOG_INFO))
    {
        dawnlog_info(
            "bssid_addr: " MACSTR ", client_addr: " MACSTR ", signal : % d, freq : %d\n",
            MAC2STR(entry->bssid_addr.u8), MAC2STR(entry->client_addr.u8), entry->signal, entry->freq);
    }
}

void print_client_entry(int level, client *entry) {
    if (dawnlog_showing(level))
    {
        dawnlog(level, "bssid_addr: " MACSTR ", client_addr: " MACSTR ", freq: %d, ht_supported: %d, vht_supported: %d, ht: %d, vht: %d, kick: %d\n",
            MAC2STR(entry->bssid_addr.u8), MAC2STR(entry->client_addr.u8), entry->freq, entry->ht_supported, entry->vht_supported, entry->ht, entry->vht,
            entry->kick_count);
    }
}

void print_client_array() {
    if (dawnlog_showing(DAWNLOG_DEBUG))
    {
        dawnlog_debug("--------Clients------\n");
        dawnlog_debug("Client Entry Last: %d\n", client_entry_last);
        for (client* i = client_set_bc; i != NULL; i = i->next_entry_bc) {
            print_client_entry(DAWNLOG_DEBUG, i);
        }
        dawnlog_debug("------------------\n");
    }
}

static void print_ap_entry(int level, ap *entry) {
    if (dawnlog_showing(DAWNLOG_INFO))
    {
        dawnlog_info("ssid: %s, bssid_addr: " MACSTR ", freq: %d, ht: %d, vht: %d, chan_utilz: %d, col_d: %d, bandwidth: %d, col_count: %d neighbor_report: %s\n",
            entry->ssid, MAC2STR(entry->bssid_addr.u8), entry->freq, entry->ht_support, entry->vht_support,
            entry->channel_utilization, entry->collision_domain, entry->bandwidth,
            ap_get_collision_count(entry->collision_domain), entry->neighbor_report
        );
    }
}

void print_ap_array() {
    if (dawnlog_showing(DAWNLOG_DEBUG))
    {
        dawnlog_debug("--------APs------\n");
        for (ap* i = ap_set; i != NULL; i = i->next_ap) {
            print_ap_entry(DAWNLOG_DEBUG, i);
        }
        dawnlog_debug("------------------\n");
    }
}

void destroy_mutex() {

    // free resources
    dawnlog_info("Freeing mutex resources\n");
    pthread_mutex_destroy(&probe_array_mutex);
    pthread_mutex_destroy(&client_array_mutex);
    pthread_mutex_destroy(&ap_array_mutex);

    return;
}

int init_mutex() {

    if (pthread_mutex_init(&probe_array_mutex, NULL) != 0) {
        dawnlog_error("Mutex init failed!\n");
        return 1;
    }

    if (pthread_mutex_init(&client_array_mutex, NULL) != 0) {
        dawnlog_error("Mutex init failed!\n");
        return 1;
    }

    if (pthread_mutex_init(&ap_array_mutex, NULL) != 0) {
        dawnlog_error("Mutex init failed!\n");
        return 1;
    }

    return 0;
}
