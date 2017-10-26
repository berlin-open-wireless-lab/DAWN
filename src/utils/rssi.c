#include "rssi.h"

#include <limits.h>
#include <iwinfo.h>
#include <dirent.h>

#include "utils.h"
#include "ubus.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

int call_iwinfo(char *client_addr);

int parse_rssi(char *iwinfo_string);

int get_rssi(const char *ifname, uint8_t *client_addr);

#define IWINFO_BUFSIZE	24 * 1024

int get_rssi_iwinfo(__uint8_t *client_addr) {

    DIR *dirp;
    struct dirent *entry;
    dirp = opendir(hostapd_dir_glob);  // error handling?
    if (!dirp) {
        fprintf(stderr, "No hostapd sockets!\n");
        return -1;
    }

    int rssi = INT_MIN;

    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            rssi = get_rssi(entry->d_name, client_addr);
            if(rssi != INT_MIN)
                break;
        }
    }
    closedir(dirp);
    return rssi;
}

int get_rssi(const char *ifname, uint8_t *client_addr){

    int i, len;
    char buf[IWINFO_BUFSIZE];
    struct iwinfo_assoclist_entry *e;
    const struct iwinfo_ops *iw;

    iw = iwinfo_backend(ifname);

    if (iw->assoclist(ifname, buf, &len))
    {
        printf("No information available\n");
        return INT_MIN;
    }
    else if (len <= 0)
    {
        printf("No station connected\n");
        return INT_MIN;
    }

    for (i = 0; i < len; i += sizeof(struct iwinfo_assoclist_entry))
    {
        e = (struct iwinfo_assoclist_entry *) &buf[i];

        if(mac_is_equal(client_addr, e->mac))
            return  e->signal;
    }

    return INT_MIN;
}