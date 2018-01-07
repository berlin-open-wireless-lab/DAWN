#include "dawn_iwinfo.h"

#include <limits.h>
#include <iwinfo.h>
#include <dirent.h>

#include "utils.h"
#include "ubus.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

int call_iwinfo(char *client_addr);

int parse_rssi(char *iwinfo_string);

int get_rssi(const char *ifname, uint8_t *client_addr);

int get_bandwidth(const char *ifname, uint8_t *client_addr, float *rx_rate, float *tx_rate);

#define IWINFO_BUFSIZE    24 * 1024

#define IWINFO_ESSID_MAX_SIZE    32


int compare_essid_iwinfo(__uint8_t *bssid_addr, __uint8_t *bssid_addr_to_compare) {
    const struct iwinfo_ops *iw;

    char mac_buf[20];
    char mac_buf_to_compare[20];
    sprintf(mac_buf, MACSTR, MAC2STR(bssid_addr));
    sprintf(mac_buf_to_compare, MACSTR, MAC2STR(bssid_addr_to_compare));

    DIR *dirp;
    struct dirent *entry;
    dirp = opendir(hostapd_dir_glob);  // error handling?
    if (!dirp) {
        fprintf(stderr, "[COMPARE ESSID] No hostapd sockets!\n");
        return 0;
    }

    char *essid = NULL;
    char *essid_to_compare = NULL;

    char buf_essid[IWINFO_ESSID_MAX_SIZE + 1] = {0};
    char buf_essid_to_compare[IWINFO_ESSID_MAX_SIZE + 1] = {0};

    while ((entry = readdir(dirp)) != NULL && (essid == NULL || essid_to_compare == NULL)) {
        if (entry->d_type == DT_SOCK) {

            iw = iwinfo_backend(entry->d_name);

            static char buf_bssid[18] = {0};
            if (iw->bssid(entry->d_name, buf_bssid))
                snprintf(buf_bssid, sizeof(buf_bssid), "00:00:00:00:00:00");

            if (strcmp(mac_buf, buf_bssid) == 0) {

                if (iw->ssid(entry->d_name, buf_essid))
                    memset(buf_essid, 0, sizeof(buf_essid));
                essid = buf_essid;
            }

            if (strcmp(mac_buf_to_compare, buf_bssid) == 0) {
                if (iw->ssid(entry->d_name, buf_essid_to_compare))
                    memset(buf_essid_to_compare, 0, sizeof(buf_essid_to_compare));
                essid_to_compare = buf_essid_to_compare;
            }
        }
    }
    closedir(dirp);

    printf("Comparing: %s with %s\n", essid, essid_to_compare);

    if (essid == NULL || essid_to_compare == NULL) {
        return -1;
    }

    if (strcmp(essid, essid_to_compare) == 0) {
        return 0;
    }

    return -1;
}

int get_bandwidth_iwinfo(__uint8_t *client_addr, float *rx_rate, float *tx_rate) {

    DIR *dirp;
    struct dirent *entry;
    dirp = opendir(hostapd_dir_glob);  // error handling?
    if (!dirp) {
        fprintf(stderr, "[BANDWITH INFO]No hostapd sockets!\n");
        return 0;
    }

    int sucess = 0;

    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            if (get_bandwidth(entry->d_name, client_addr, rx_rate, tx_rate)) {
                sucess = 1;
                break;
            }
        }
    }
    closedir(dirp);
    return sucess;
}

int get_bandwidth(const char *ifname, uint8_t *client_addr, float *rx_rate, float *tx_rate) {

    int i, len;
    char buf[IWINFO_BUFSIZE];
    struct iwinfo_assoclist_entry *e;
    const struct iwinfo_ops *iw;

    iw = iwinfo_backend(ifname);

    if (iw->assoclist(ifname, buf, &len)) {
        printf("No information available\n");
        return 0;
    } else if (len <= 0) {
        printf("No station connected\n");
        return 0;
    }

    for (i = 0; i < len; i += sizeof(struct iwinfo_assoclist_entry)) {
        e = (struct iwinfo_assoclist_entry *) &buf[i];

        if (mac_is_equal(client_addr, e->mac)) {
            //struct iwinfo_assoclist_entry * rx_rate = e->rx_rate;
            //struct iwinfo_assoclist_entry * tx_rate = e->tx_rate;
            *rx_rate = e->rx_rate.rate / 1000;
            *tx_rate = e->tx_rate.rate / 1000;
            return 1;
        }
        //    return  e->signal;


    }

    return 0;
}

int get_rssi_iwinfo(__uint8_t *client_addr) {

    DIR *dirp;
    struct dirent *entry;
    dirp = opendir(hostapd_dir_glob);  // error handling?
    if (!dirp) {
        fprintf(stderr, "[RSSI INFO] No hostapd sockets!\n");
        return INT_MIN;
    }

    int rssi = INT_MIN;

    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            rssi = get_rssi(entry->d_name, client_addr);
            if (rssi != INT_MIN)
                break;
        }
    }
    closedir(dirp);
    return rssi;
}

int get_rssi(const char *ifname, uint8_t *client_addr) {

    int i, len;
    char buf[IWINFO_BUFSIZE];
    struct iwinfo_assoclist_entry *e;
    const struct iwinfo_ops *iw;

    iw = iwinfo_backend(ifname);

    if (iw->assoclist(ifname, buf, &len)) {
        printf("No information available\n");
        return INT_MIN;
    } else if (len <= 0) {
        printf("No station connected\n");
        return INT_MIN;
    }

    for (i = 0; i < len; i += sizeof(struct iwinfo_assoclist_entry)) {
        e = (struct iwinfo_assoclist_entry *) &buf[i];

        if (mac_is_equal(client_addr, e->mac))
            return e->signal;
    }

    return INT_MIN;
}