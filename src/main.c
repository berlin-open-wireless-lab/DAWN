#include <libubus.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "datastorage.h"
#include "networksocket.h"
#include "ubus.h"
#include "dawn_uci.h"
#include "dawn_uci.h"
#include "crypto.h"

#define BUFSIZE 17
#define BUFSIZE_DIR 256

void daemon_shutdown();

void signal_handler(int sig);

struct sigaction newSigAction;

void daemon_shutdown() {
    // kill threads
    close_socket();
    uci_clear();
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
   // int ch;

    argc -= optind;
    argv += optind;

    newSigAction.sa_handler = signal_handler;
    sigemptyset(&newSigAction.sa_mask);
    newSigAction.sa_flags = 0;

    sigaction(SIGHUP, &newSigAction, NULL);
    sigaction(SIGTERM, &newSigAction, NULL);
    sigaction(SIGINT, &newSigAction, NULL);

    uci_init();
    struct network_config_s net_config = uci_get_dawn_network();
    printf("Broadcst bla: %s\n", net_config.broadcast_ip);

    gcrypt_init();
    gcrypt_set_key_and_iv(net_config.shared_key, net_config.iv);

    struct time_config_s time_config = uci_get_time_config();
    timeout_config = time_config; // TODO: Refactor...

    hostapd_dir_glob = uci_get_dawn_hostapd_dir();
    sort_string = (char*) uci_get_dawn_sort_order();

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

    init_socket_runopts(net_config.broadcast_ip, net_config.broadcast_port, net_config.bool_multicast);

    //insert_macs_from_file();
    dawn_init_ubus(ubus_socket, hostapd_dir_glob);

    return 0;
}