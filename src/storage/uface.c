#include <libubox/uloop.h>
#include "datastorage.h"
#include "utils.h"
#include "ubus.h"
#include "uface.h"

void remove_probe_array_cb(struct uloop_timeout *t);

struct uloop_timeout probe_timeout = {
        .cb = remove_probe_array_cb
};

void remove_client_array_cb(struct uloop_timeout *t);

struct uloop_timeout client_timeout = {
        .cb = remove_client_array_cb
};

void remove_ap_array_cb(struct uloop_timeout *t);

struct uloop_timeout ap_timeout = {
        .cb = remove_ap_array_cb
};

void denied_req_array_cb(struct uloop_timeout *t);

struct uloop_timeout denied_req_timeout = {
        .cb = denied_req_array_cb
};

void uloop_add_data_cbs() {
    uloop_timeout_add(&probe_timeout);
    uloop_timeout_add(&client_timeout);
    uloop_timeout_add(&ap_timeout);

    if (dawn_metric.use_driver_recog) {
        uloop_timeout_add(&denied_req_timeout);
    }
}

void remove_probe_array_cb(struct uloop_timeout *t) {
    pthread_mutex_lock(&probe_array_mutex);
    printf("[Thread] : Removing old probe entries!\n");
    remove_old_probe_entries(time(0), timeout_config.remove_probe);
    printf("[Thread] : Removing old entries finished!\n");
    pthread_mutex_unlock(&probe_array_mutex);
    uloop_timeout_set(&probe_timeout, timeout_config.remove_probe * 1000);
}

void remove_client_array_cb(struct uloop_timeout *t) {
    pthread_mutex_lock(&client_array_mutex);
    printf("[Thread] : Removing old client entries!\n");
    remove_old_client_entries(time(0), timeout_config.update_client);
    pthread_mutex_unlock(&client_array_mutex);
    uloop_timeout_set(&client_timeout, timeout_config.update_client * 1000);
}

void remove_ap_array_cb(struct uloop_timeout *t) {
    pthread_mutex_lock(&ap_array_mutex);
    printf("[ULOOP] : Removing old ap entries!\n");
    remove_old_ap_entries(time(0), timeout_config.remove_ap);
    pthread_mutex_unlock(&ap_array_mutex);
    uloop_timeout_set(&ap_timeout, timeout_config.remove_ap * 1000);
}

void denied_req_array_cb(struct uloop_timeout *t) {
    pthread_mutex_lock(&denied_array_mutex);
    printf("[ULOOP] : Processing denied authentication!\n");

    time_t current_time = time(0);

    for (int i = 0; i <= denied_req_last; i++) {
        // check counter

        //check timer
        if (denied_req_array[i].time < current_time - timeout_config.denied_req_threshold) {

            // client is not connected for a given time threshold!
            if (!is_connected_somehwere(denied_req_array[i].client_addr)) {
                printf("Client has probably a bad driver!\n");

                // problem that somehow station will land into this list
                // maybe delete again?
                if (insert_to_maclist(denied_req_array[i].client_addr) == 0) {
                    send_add_mac(denied_req_array[i].client_addr);
// TODO: File can grow arbitarily large.  Resource consumption risk.
// TODO: Consolidate use of file across source: shared resource for name, single point of access?
                    write_mac_to_file("/tmp/dawn_mac_list", denied_req_array[i].client_addr);
                }
            }
            denied_req_array_delete(denied_req_array[i]);
        }
    }
    pthread_mutex_unlock(&denied_array_mutex);
    uloop_timeout_set(&denied_req_timeout, timeout_config.denied_req_threshold * 1000);
}
