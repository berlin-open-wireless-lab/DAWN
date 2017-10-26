#include "rssi.h"

#include <limits.h>

#include "utils.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

int call_iwinfo(char *client_addr);

int parse_rssi(char *iwinfo_string);

int get_rssi_from_iwinfo(__uint8_t *client_addr) {
    char mac_buf[20];
    sprintf(mac_buf, "%02X:%02X:%02X:%02X:%02X:%02X", MAC2STR(client_addr));
    char mac_buf_conv[20];

    convert_mac(mac_buf, mac_buf_conv);

    return call_iwinfo(mac_buf_conv);
}

int call_iwinfo(char *client_addr) {
    // TODO: REFACTOR THIS! USE NET LINK... LOOK AT IWINFO

    FILE *fp;
    char path[1035];

    int rssi = INT_MIN;
    int command_length = 68;
    char iwinfo_command[command_length];
    char *first_command = "(iwinfo wlan0 assoc && iwinfo wlan1 assoc) | grep ";
    size_t length_first_command = strlen(first_command);
    memcpy(iwinfo_command, first_command, length_first_command);
    memcpy(iwinfo_command + length_first_command, client_addr, strlen(client_addr));
    iwinfo_command[command_length - 1] = '\0';
    printf("iwinfo command:\n%s\n", iwinfo_command);

    fp = popen(iwinfo_command, "r");
    if (fp == NULL) {
        printf("Failed to run command\n");
        exit(1);
    }

    /* Read the output a line at a time - output it. */
    while (fgets(path, sizeof(path) - 1, fp) != NULL) {
        rssi = parse_rssi(path);
    }

    /* close */
    pclose(fp);

    return rssi;
}

int parse_rssi(char *iwinfo_string) {
    char cut_1[] = " ";
    char cut_2[] = "dBm";
    char *p_1 = strstr(iwinfo_string, cut_1);
    char *p_2 = strstr(iwinfo_string, cut_2);
    int rssi = INT_MIN;
    if (p_1 != NULL && p_2 != NULL) {
        int length = (int) (p_2 - p_1);
        char dest[length + 1];
        memcpy(dest, p_1, (int) (p_2 - p_1));
        dest[length] = '\0';
        rssi = atoi(dest);
    }
    return rssi;
}