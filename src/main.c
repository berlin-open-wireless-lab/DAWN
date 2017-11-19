#include <libubus.h>
#include <stdio.h>

#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "datastorage.h"
#include "networksocket.h"
#include "ubus.h"
#include "dawn_uci.h"
#include "rssi.h"

#define BUFSIZE 17
#define BUFSIZE_DIR 256


#include "crypto.h"

#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>

//static void* (*real_malloc)(size_t)=NULL;
//static void* (*real_free)(void *p)=NULL;

void daemon_shutdown();

void signal_handler(int sig);

struct sigaction newSigAction;

//int free_counter = 0;

pthread_t tid_probe;
pthread_t tid_client;
pthread_t tid_get_client;
pthread_t tid_update_hostapd_socks;
pthread_t tid_kick_clients;
pthread_t tid_ap;

void daemon_shutdown() {
    // kill threads
    printf("Cancelling Threads!\n");
    pthread_cancel(tid_probe);
    //pthread_cancel(tid_client);
    pthread_cancel(tid_get_client);
    //pthread_cancel(tid_kick_clients);
    //pthread_cancel(tid_ap);

    // free ressources
    printf("Freeing mutex ressources\n");
    pthread_mutex_destroy(&list_mutex);
    pthread_mutex_destroy(&probe_array_mutex);
    pthread_mutex_destroy(&client_array_mutex);
    pthread_mutex_destroy(&ap_array_mutex);

    //printf("Free Counter: %d\n", free_counter);
}

void signal_handler(int sig) {
    printf("SOME SIGNAL RECEIVED!\n");
    switch (sig) {
        case SIGHUP:
            //syslog(LOG_WARNING, "Received SIGHUP signal.");
            break;
        case SIGINT:
        case SIGTERM:
            //syslog(LOG_INFO, "Daemon exiting");
            //daemonShutdown();
            daemon_shutdown();
            exit(EXIT_SUCCESS);
            break;
        default:
            //syslog(LOG_WARNING, "Unhandled signal %s", strsignal(sig));
            break;
    }
}

/*
static void mtrace_init(void)
{
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    if (NULL == real_malloc) {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
    }
    real_free = dlsym(RTLD_NEXT, "free");
    if (NULL == real_free) {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
    }
}

void *malloc(size_t size)
{
    mtrace_init();
    if(real_malloc==NULL) {
        mtrace_init();
    }

    void *p = NULL;
    fprintf(stderr, "malloc(%d) = ", size);
    p = real_malloc(size);
    fprintf(stderr, "%p\n", p);
    free_counter++;
    return p;
}

void free(void *p)
{
    mtrace_init();
    if(real_free==NULL) {
        mtrace_init();
    }
    p = real_free(p);
    fprintf(stderr, "free: ");
    fprintf(stderr, "%p\n", p);
    free_counter--;
}*/

int main(int argc, char **argv) {
    //free_counter = 0;

    const char *ubus_socket = NULL;
    int ch;

    char opt_broadcast_ip[BUFSIZE];
    char opt_broadcast_port[BUFSIZE];
    char opt_hostapd_dir[BUFSIZE_DIR];

    char shared_key[BUFSIZE_DIR];
    char iv[BUFSIZE_DIR];

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

    init_socket_runopts(opt_broadcast_ip, opt_broadcast_port, 1);

    pthread_create(&tid_probe, NULL, &remove_probe_array_thread, (void *) &time_config.remove_probe);
    pthread_create(&tid_client, NULL, &remove_client_array_thread, (void *) &time_config.remove_client);
    pthread_create(&tid_get_client, NULL, &update_clients_thread, (void *) &time_config.update_client);
    pthread_create(&tid_update_hostapd_socks, NULL, &update_hostapd_sockets, &time_config.update_hostapd);


    //pthread_create(&tid_kick_clients, NULL, &kick_clients_thread, NULL);
    //pthread_create(&tid_ap, NULL, &remove_ap_array_thread, NULL);

    //pthread_create(&tid, NULL, &remove_thread, NULL);

    dawn_init_ubus(ubus_socket, opt_hostapd_dir);
    //free_list(probe_list_head);

    return 0;
}