#include <libubus.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "datastorage.h"
#include "networksocket.h"
#include "ubus.h"
#include "dawn_uci.h"
#include "tcpsocket.h"

#define BUFSIZE 17
#define BUFSIZE_DIR 256

#include "crypto.h"
#include "dawn_iwinfo.h"

void daemon_shutdown();

void signal_handler(int sig);

int run_tcp_server();

int init_mutex();

struct sigaction signal_action;

pthread_t tid_tcp_server;
pthread_t tid_connections;

void daemon_shutdown() {
    // kill threads
    close_socket();
    uci_clear();
    uloop_cancelled = true;

    // free ressources
    printf("Freeing mutex ressources\n");
    pthread_mutex_destroy(&list_mutex);
    pthread_mutex_destroy(&probe_array_mutex);
    pthread_mutex_destroy(&client_array_mutex);
    pthread_mutex_destroy(&ap_array_mutex);
    pthread_mutex_destroy(&tcp_array_mutex);
}

void signal_handler(int sig) {
    switch (sig) {
        case SIGHUP:
            daemon_shutdown();
            break;
        case SIGINT:
            daemon_shutdown();
            break;
        case SIGTERM:
            daemon_shutdown();
            exit(EXIT_SUCCESS);
        default:
            daemon_shutdown();
            break;
    }
}

int init_mutex() {
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

    if (pthread_mutex_init(&tcp_array_mutex, NULL) != 0) {
        printf("\n mutex init failed\n");
        return 1;
    }

    if (pthread_mutex_init(&denied_array_mutex, NULL) != 0) {
        printf("\n mutex init failed\n");
        return 1;
    }
    return 0;
}

int run_tcp_server() {
    //run_server(1027);
    //pthread_create(&tid_tcp_server, NULL, &run_tcp_socket, NULL);
    //start_umdns_update();
    return 0;
}

int main(int argc, char **argv) {

    const char *ubus_socket = NULL;

    argc -= optind;
    argv += optind;

    // connect signals
    signal_action.sa_handler = signal_handler;
    sigemptyset(&signal_action.sa_mask);
    signal_action.sa_flags = 0;
    sigaction(SIGHUP, &signal_action, NULL);
    sigaction(SIGTERM, &signal_action, NULL);
    sigaction(SIGINT, &signal_action, NULL);

    uci_init();
    struct network_config_s net_config = uci_get_dawn_network();
    network_config = net_config;
    printf("Broadcst bla: %s\n", net_config.broadcast_ip);

    gcrypt_init();
    gcrypt_set_key_and_iv(net_config.shared_key, net_config.iv);

    struct time_config_s time_config = uci_get_time_config();
    timeout_config = time_config; // TODO: Refactor...

    hostapd_dir_glob = uci_get_dawn_hostapd_dir();
    sort_string = (char *) uci_get_dawn_sort_order();

    init_mutex();

    switch (net_config.network_option) {
        case 0:
            init_socket_runopts(net_config.broadcast_ip, net_config.broadcast_port, 0);
            break;
        case 1:
            init_socket_runopts(net_config.broadcast_ip, net_config.broadcast_port, 1);
            break;
        default:
            break;
    }

    insert_macs_from_file();
    dawn_init_ubus(ubus_socket, hostapd_dir_glob);

    return 0;
}