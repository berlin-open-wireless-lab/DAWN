#include <libubus.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "datastorage.h"
#include "networksocket.h"
#include "ubus.h"
#include "dawn_uci.h"
#include "crypto.h"

#define BUFSIZE 17
#define BUFSIZE_DIR 256

void daemon_shutdown();

void signal_handler(int sig);

struct sigaction newSigAction;

void daemon_shutdown() {
    // kill threads
    printf("Cancelling Threads!\n");
    uloop_cancelled = true;

    // free ressources
    printf("Freeing mutex ressources\n");
    pthread_mutex_destroy(&list_mutex);
    pthread_mutex_destroy(&probe_array_mutex);
    pthread_mutex_destroy(&client_array_mutex);
    pthread_mutex_destroy(&ap_array_mutex);
}

void signal_handler(int sig) {
    printf("SOME SIGNAL RECEIVED!\n");
    switch (sig) {
        case SIGHUP:
            break;
        case SIGINT:
        case SIGTERM:
            daemon_shutdown();
            exit(EXIT_SUCCESS);
            break;
        default:
            break;
    }
}

int main(int argc, char **argv) {
    //free_counter = 0;

    const char *ubus_socket = NULL;
    int ch;

    char opt_broadcast_ip[BUFSIZE];
    char opt_broadcast_port[BUFSIZE];
    char opt_hostapd_dir[BUFSIZE_DIR];

    char shared_key[BUFSIZE_DIR];
    char iv[BUFSIZE_DIR];
    int multicast = 0;

    while ((ch = getopt(argc, argv, "cs:p:i:b:o:h:i:k:v:")) != -1) {
        switch (ch) {
            case 's':
                ubus_socket = optarg;
                break;
            case 'p':
                snprintf(opt_broadcast_port, BUFSIZE, "%s", optarg);
                printf("broadcast port: %s\n", opt_broadcast_port);
                break;
            case 'i':
                snprintf(opt_broadcast_ip, BUFSIZE, "%s", optarg);
                printf("broadcast ip: %s\n", opt_broadcast_ip);
                break;
            case 'o':
                snprintf(sort_string, SORT_NUM, "%s", optarg);
                printf("sort string: %s\n", sort_string);
                break;
            case 'h':
                snprintf(opt_hostapd_dir, BUFSIZE_DIR, "%s", optarg);
                printf("hostapd dir: %s\n", opt_hostapd_dir);
                hostapd_dir_glob = optarg;
                break;
            case 'k':
                snprintf(shared_key, BUFSIZE_DIR, "%s", optarg);
                printf("Key: %s\n", shared_key);
                break;
            case 'v':
                snprintf(iv, BUFSIZE_DIR, "%s", optarg);
                printf("IV: %s\n", iv);
                break;
            case 'm':
                multicast = 1;
            default:
                break;
        }
    }

    argc -= optind;
    argv += optind;

    /* Set up a signal handler */
    newSigAction.sa_handler = signal_handler;
    sigemptyset(&newSigAction.sa_mask);
    newSigAction.sa_flags = 0;

    /* Signals to handle */
    sigaction(SIGHUP, &newSigAction, NULL);     /* catch hangup signal */
    sigaction(SIGTERM, &newSigAction, NULL);    /* catch term signal */
    sigaction(SIGINT, &newSigAction, NULL);     /* catch interrupt signal */


    gcrypt_init();
    gcrypt_set_key_and_iv(shared_key, iv);

    struct time_config_s time_config = uci_get_time_config();
    timeout_config = time_config; // TODO: Refactor...

    if (pthread_mutex_init(&list_mutex, NULL) != 0) {
        printf("\n mutex init failed\n");
        return 1;
    }

    if (pthread_mutex_init(&probe_array_mutex, NULL) != 0) {
        printf("\n mutex init failed\n");
        return 1;
    }

    if (pthread_mutex_init(&client_array_mutex, NULL) != 0) {
        printf("\n mutex init failed\n");
        return 1;
    }

    if (pthread_mutex_init(&ap_array_mutex, NULL) != 0) {
        printf("\n mutex init failed\n");
        return 1;
    }

    init_socket_runopts(opt_broadcast_ip, opt_broadcast_port, multicast);

    dawn_init_ubus(ubus_socket, opt_hostapd_dir);

    return 0;
}