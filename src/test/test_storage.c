#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

#include "dawn_iwinfo.h"
#include "utils.h"
#include "ieee80211_utils.h"

#include "datastorage.h"
#include "uface.h"

/*** External functions ***/
void ap_array_insert(ap entry);
ap ap_array_delete(ap entry);

/*** Testing structures, etc ***/
union __attribute__((__packed__)) mac_mangler
{
    struct {
        uint8_t b[6];
        uint8_t packing[2];
    } u8;
    uint64_t u64;
};

/*** Test code */
int ap_array_helper_auto(int action, int i0, int i1);
int ap_array_helper_auto(int action, int i0, int i1)
{
int m;
int step = (i0 > i1) ? -1 : 1;
int ret = 0;

    switch (action)
    {
    case 0:
    case 1:
        m = i0;
        int cont = 1;
        while (cont) {
        union mac_mangler this_mac;
        ap ap0;

            this_mac.u64 = m;
            memcpy(ap0.bssid_addr, this_mac.u8.b, sizeof(ap0.bssid_addr));
	    if (action == 0)
                ap_array_insert(ap0);
	    else
                ap_array_delete(ap0);

            if (m == i1)
                cont = 0;
            else
                m += step;
        }
        break;
    default:
        ret = 1;
        break;
    }

    return ret;
}

int main(int argc, char** argv)
{
int ret = 0;
int args_ok = 1;
int arg_consumed = 0;

    printf("DAWN datastorage.c test harness.  Ready for commands...\n");

    int this_arg = 1;
    argv++;

    while (args_ok)
    {
        if (strcmp(*argv, "help") == 0)
        {
            arg_consumed = 1;
	    if (this_arg + arg_consumed > argc) goto next_command;

	    printf("Help is on its way...\n");
        }
	else if (strcmp(*argv, "ap_show") == 0)
	{
            arg_consumed = 1;
	    if (this_arg + arg_consumed > argc) goto next_command;

            print_ap_array();
	}
        else if (strcmp(*argv, "ap_add_auto") == 0)
	{
            arg_consumed = 3;
	    if (this_arg + arg_consumed > argc) goto next_command;

	    ap_array_helper_auto(0, atoi(*(argv + 1)), atoi(*(argv + 2)));
	}
	else if (strcmp(*argv, "ap_del_auto") == 0)
	{
            arg_consumed = 3;
	    if (this_arg + arg_consumed > argc) goto next_command;

	    ap_array_helper_auto(1, atoi(*(argv + 1)), atoi(*(argv + 2)));
	}
	else
	{
            arg_consumed = 1;
	    if (this_arg + arg_consumed > argc) goto next_command;

	    printf("COMMAND \"%s\": Unknown - skipping!\n", *argv);
	}

next_command:
	this_arg += arg_consumed;
        if (this_arg > argc)
	{
            printf("Commands are mangled at: \"%s\"!\n", *argv);
            args_ok = 0;
	}
        else if (this_arg == argc)
            args_ok = 0;
        else
	    argv += arg_consumed;
    }

    printf("\n\nDAWN datastorage.c test harness - finshed.  \n");

    return ret;
}

void ubus_send_beacon_report(uint8_t client[], int id)
{
    printf("send_beacon_report() was called...\n");
}

int send_set_probe(uint8_t client_addr[])
{
    printf("send_set_probe() was called...\n");
    return 0;
}

void wnm_disassoc_imminent(uint32_t id, const uint8_t *client_addr, char* dest_ap, uint32_t duration)
{
    printf("wnm_disassoc_imminent() was called...\n");
}

void add_client_update_timer(time_t time)
{
    printf("add_client_update_timer() was called...\n");
}

void del_client_interface(uint32_t id, const uint8_t *client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time)
{
    printf("del_client_interface() was called...\n");
}

int ubus_send_probe_via_network(struct probe_entry_s probe_entry)
{
    printf("send_probe_via_network() was called...\n");
    return 0;
}

int get_rssi_iwinfo(uint8_t *client_addr)
{
    printf("get_rssi_iwinfo() was called...\n");
    return 0;
}

int get_expected_throughput_iwinfo(uint8_t *client_addr)
{
    printf("get_expected_throughput_iwinfo() was called...\n");
    return 0;
}

int get_bandwidth_iwinfo(uint8_t *client_addr, float *rx_rate, float *tx_rate)
{
    printf("get_bandwidth_iwinfo() was called...\n");
    return 0;
}

