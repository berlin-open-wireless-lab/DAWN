#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include "dawn_iwinfo.h"
#include "utils.h"
#include "ieee80211_utils.h"

#include "datastorage.h"
#include "uface.h"

/*** SUT functions we use that are not in header files (like "friend" functions) ***/
void ap_array_insert(ap entry);
ap ap_array_delete(ap entry);

/*** Testing structures, etc ***/
union __attribute__((__packed__)) pac_a_mac
{
    struct {
        uint8_t pos[6]; 
        uint8_t packing[2];
    } u8;
    uint64_t u64;
};

/*** Test Stub Functions - Called by SUT ***/
void ubus_send_beacon_report(uint8_t client[], int id)
{
    printf("send_beacon_report() was called...\n");
}

int send_set_probe(uint8_t client_addr[])
{
    printf("send_set_probe() was called...\n");
    return 0;
}

void wnm_disassoc_imminent(uint32_t id, const uint8_t* client_addr, char* dest_ap, uint32_t duration)
{
    printf("wnm_disassoc_imminent() was called...\n");
}

void add_client_update_timer(time_t time)
{
    printf("add_client_update_timer() was called...\n");
}

void del_client_interface(uint32_t id, const uint8_t* client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time)
{
    printf("del_client_interface() was called...\n");
}

int ubus_send_probe_via_network(struct probe_entry_s probe_entry)
{
    printf("send_probe_via_network() was called...\n");
    return 0;
}

int get_rssi_iwinfo(uint8_t* client_addr)
{
    printf("get_rssi_iwinfo() was called...\n");
    return 0;
}

int get_expected_throughput_iwinfo(uint8_t* client_addr)
{
    printf("get_expected_throughput_iwinfo() was called...\n");
    return 0;
}

int get_bandwidth_iwinfo(uint8_t* client_addr, float* rx_rate, float* tx_rate)
{
    printf("get_bandwidth_iwinfo() was called...\n");
    return 0;
}

/*** Local Function Prototypes ***/
#define HELPER_ACTION_ADD 0x0000
#define HELPER_ACTION_DEL 0x1000
#define HELPER_ACTION_MASK 0x1000

#define HELPER_AP 0x0001
#define HELPER_CLIENT 0x0002
#define HELPER_AUTH_ENTRY 0x0004
#define HELPER_PROBE_ARRAY 0x0008

int array_auto_helper(int action, int i0, int i1);
int client_array_auto_helper(int action, int i0, int i1);
int auth_entry_array_auto_helper(int action, int i0, int i1);
int probe_array_auto_helper(int action, int i0, int i1);

/*** Test narness code */
int array_auto_helper(int action, int i0, int i1)
{
    int m = i0;
    int step = (i0 > i1) ? -1 : 1;
    int ret = 0;

    int cont = 1;
    while (cont) {
        union pac_a_mac this_mac;

        this_mac.u64 = m;
        switch (action & ~HELPER_ACTION_MASK)
        {
        case HELPER_AP:
            ; // Empty statement to allow label before declaration
            ap ap0;
            memcpy(ap0.bssid_addr, &this_mac.u8.pos[0], sizeof(ap0.bssid_addr));

            if ((action & HELPER_ACTION_MASK) == HELPER_ACTION_ADD)
                ap_array_insert(ap0);
            else
                ap_array_delete(ap0);
            break;
        case HELPER_CLIENT:
            ; // Empty statement to allow label before declaration
            client client0;
            memcpy(client0.bssid_addr, &this_mac.u8.pos[0], sizeof(client0.bssid_addr));
            memcpy(client0.client_addr, &this_mac.u8.pos[0], sizeof(client0.client_addr));

            if ((action & HELPER_ACTION_MASK) == HELPER_ACTION_ADD)
                client_array_insert(client0);
            else
                client_array_delete(client0);
            break;
        case HELPER_PROBE_ARRAY:
            ; // Empty statement to allow label before declaration
            probe_entry probe0;
            memcpy(probe0.bssid_addr, &this_mac.u8.pos[0], sizeof(probe0.bssid_addr));
            memcpy(probe0.client_addr, &this_mac.u8.pos[0], sizeof(probe0.client_addr));

            if ((action & HELPER_ACTION_MASK) == HELPER_ACTION_ADD)
                probe_array_insert(probe0);
            else
                probe_array_delete(probe0);
            break;
        case HELPER_AUTH_ENTRY:
            ; // Empty statement to allow label before declaration
            auth_entry auth_entry0;
            memcpy(auth_entry0.bssid_addr, &this_mac.u8.pos[0], sizeof(auth_entry0.bssid_addr));
            memcpy(auth_entry0.client_addr, &this_mac.u8.pos[0], sizeof(auth_entry0.client_addr));

            if ((action & HELPER_ACTION_MASK) == HELPER_ACTION_ADD)
                denied_req_array_insert(auth_entry0);
            else
                denied_req_array_delete(auth_entry0);
            break;
        default:
            printf("HELPER error - which entity?\n");
            ret = -1;
        }

        if (m == i1)
            cont = 0;
        else
            m += step;
    }

    return ret;
}

int consume_actions(int argc, char* argv[]);

int consume_actions(int argc, char* argv[])
{
    int ret = 0;
    int args_required = 0; // Suppress compiler warming by assigning initial value

    int curr_arg = 0;

    while (curr_arg < argc && ret == 0)
    {
        if (strcmp(*argv, "probe_sort") == 0)
        {
            args_required = 2;
            if (curr_arg + args_required <= argc)
            {
                strcpy(sort_string, argv[1]);
            }
        }
        else if (strcmp(*argv, "ap_show") == 0)
        {
            args_required = 1;

            print_ap_array();
        }
        else if (strcmp(*argv, "probe_show") == 0)
        {
            args_required = 1;

            print_probe_array();
        }
        else if (strcmp(*argv, "client_show") == 0)
        {
            args_required = 1;

            print_client_array();
        }
        else if (strcmp(*argv, "auth_entry_show") == 0)
        {
            args_required = 1;

            printf("--------APs------\n");
            for (int i = 0; i <= denied_req_last; i++) {
                print_auth_entry(denied_req_array[i]);
            }
            printf("------------------\n");
        }
        else if (strcmp(*argv, "ap_add_auto") == 0)
        {
            args_required = 3;
            if (curr_arg + args_required <= argc)
            {
                ret = array_auto_helper(HELPER_AP | HELPER_ACTION_ADD, atoi(*(argv + 1)), atoi(*(argv + 2)));
            }
        }
        else if (strcmp(*argv, "ap_del_auto") == 0)
        {
            args_required = 3;
            if (curr_arg + args_required <= argc)
            {
                ret = array_auto_helper(HELPER_AP | HELPER_ACTION_DEL, atoi(*(argv + 1)), atoi(*(argv + 2)));
            }
        }
        else if (strcmp(*argv, "probe_add_auto") == 0)
        {
            args_required = 3;
            if (curr_arg + args_required <= argc)
            {
                ret = array_auto_helper(HELPER_PROBE_ARRAY | HELPER_ACTION_ADD, atoi(*(argv + 1)), atoi(*(argv + 2)));
            }
        }
        else if (strcmp(*argv, "probe_del_auto") == 0)
        {
            args_required = 3;
            if (curr_arg + args_required <= argc)
            {
                ret = array_auto_helper(HELPER_PROBE_ARRAY | HELPER_ACTION_DEL, atoi(*(argv + 1)), atoi(*(argv + 2)));
            }
        }
        else if (strcmp(*argv, "client_add_auto") == 0)
        {
            args_required = 3;
            if (curr_arg + args_required <= argc)
            {
                ret = array_auto_helper(HELPER_CLIENT | HELPER_ACTION_ADD, atoi(*(argv + 1)), atoi(*(argv + 2)));
            }
        }
        else if (strcmp(*argv, "client_del_auto") == 0)
        {
            args_required = 3;
            if (curr_arg + args_required <= argc)
            {
                ret = array_auto_helper(HELPER_CLIENT | HELPER_ACTION_DEL, atoi(*(argv + 1)), atoi(*(argv + 2)));
            }
        }
        else if (strcmp(*argv, "auth_entry_add_auto") == 0)
        {
            args_required = 3;
            if (curr_arg + args_required <= argc)
            {
                ret = array_auto_helper(HELPER_AUTH_ENTRY | HELPER_ACTION_ADD, atoi(*(argv + 1)), atoi(*(argv + 2)));
            }
        }
        else if (strcmp(*argv, "auth_entry_del_auto") == 0)
        {
            args_required = 3;
            if (curr_arg + args_required <= argc)
            {
                ret = array_auto_helper(HELPER_AUTH_ENTRY | HELPER_ACTION_DEL, atoi(*(argv + 1)), atoi(*(argv + 2)));
            }
        }
        else
	    {
            args_required = 1;

	        printf("COMMAND \"%s\": Unknown - stopping!\n", *argv);
            ret = -1;
	    }

	    curr_arg += args_required;
        if (curr_arg <= argc)
        {
            // Still need to continue consuming args
            argv += args_required;
        }
        else
        {
            // There aren't enough args left to give the parameters of the current action
            printf("Commands are mangled at: \"%s\"!\n", *argv);
            ret = -1;
        }
    }

    return ret;
}

int process_script_line(char* line, size_t len);
#define MAX_LINE_ARGS 5
int process_script_line(char* line, size_t len)
{
    int argc = 0;
    char* argv[MAX_LINE_ARGS];
    bool in_white = true;
    bool force_blank = false;
    
    int ret = 0;

    //printf("%lu: \"%s\"\n", len, line);
    while (len > 0 && !ret)
    {
        if (isblank(*line) || (*line == '\n') || (*line == '\r') || (*line == '#') || force_blank)
        {
            if (*line == '#')
            {
                //printf("Blanking 0x%02X...\n", *line);
                force_blank = true;
            }

            //printf("Zapping 0x%02X...\n", *line);
            *line = '\0';
            in_white = true;
        }
        else
        {
            if (in_white)
            {
                //printf("Marking 0x%02X...\n", *line);
                if (argc == MAX_LINE_ARGS)
                {
                    printf("ERROR: Script line exceeds permitted arg count!\n");
                    ret = -1;
                }
                else
                {
                    argv[argc] = line;
                    argc++;

                    in_white = false;
                }
            }
        }

        len--;
        line++;
    }

    if (!ret)
        ret = consume_actions(argc, argv);

    return ret;
}

int main(int argc, char* argv[])
{
    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;

    int ret = 0;

    printf("DAWN datastorage.c test harness...\n\n");

    if ((argc == 1) || !strcmp(*(argv + 1), "help") || !strcmp(*(argv + 1), "--help") || !strcmp(*(argv + 1), "-h"))
    {
        printf("Usage: %s [commands]\n\n", *argv);
        printf("  [action [arg...]]... : Read test actions from command line\n");
        printf("    --script [file]... : Read test script from file(s) (NB: \"-\" is a valid name\n");
        printf("                         indicating STDIN) {-s}\n");
        printf("                     - : Read test script from STDIN (and remaining arguments\n");
        printf("                         as script file names)\n");
        printf("                --help : This help message {-h, help}\n");
        printf("NB: Contents of {braces} indicate equivalent command\n");
    }
    else
    {
        // Step past command name on args, ie argv[0]
        argc--;
        argv++;

        if (!strcmp(*argv, "--script") || !strcmp(*argv, "-s") || !strcmp(*argv, "-"))
        {
            if (!strcmp(*argv, "--script") || !strcmp(*argv, "-s"))
            {
                argc--;
                argv++;
            }

            // Read script from file[s]
            while (argc > 0 && ret == 0)
            {
                if (!strcmp(*argv, "-"))
                {
                    fp = stdin;
                    printf("Consuming script from STDIN\n");
                }
                else
                {
                    fp = fopen(*argv, "r");
                    if (fp == NULL)
                    {
                        printf("Error opening script file: %s\n", *argv);
                        ret = -1;
                    }
                    else
                    {
                        printf("Consuming script file: %s\n", *argv);
                    }
                }

                if (ret == 0)
                {
                    read = getline(&line, &len, fp);
                    while (!ret && read != -1)
                    {
                        printf("Processing: %s\n", line);
                        ret = process_script_line(line, read);
                        if (!ret)
                            read = getline(&line, &len, fp);
                    }

                    if (fp != stdin)
                        fclose(fp);

                    if (line)
                        free(line);
                }

                argc--;
                argv++;
            }
        }
        else
        {
            // Take direct input on command line
            ret = consume_actions(argc, argv);
        }
    }
    printf("\nDAWN datastorage.c test harness - finshed.  \n");

    return ret;
}
