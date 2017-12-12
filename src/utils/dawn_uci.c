#include <uci.h>
#include <stdlib.h>
#include <datastorage.h>

#include "dawn_uci.h"

/*

dawn.metric.ht_support
dawn.metric.vht_support'
dawn.metric.rssi
dawn.metric.freq

 */

/*
    config settings times
	option update_client    '50'
	option remove_client    '120'
	option remove_probe     '120'
 */

struct time_config_s uci_get_time_config() {
    struct time_config_s ret;

    struct uci_context *c;
    struct uci_ptr ptr;

    c = uci_alloc_context();

    printf("Loading TImes!");


    char tmp_update_client[] = "dawn.times.update_client";
    if (uci_lookup_ptr(c, &ptr, tmp_update_client, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.update_client = atoi(ptr.o->v.string);

    char tmp_remove_client[] = "dawn.times.remove_client";
    if (uci_lookup_ptr(c, &ptr, tmp_remove_client, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.remove_client = atoi(ptr.o->v.string);

    char tmp_remove_probe[] = "dawn.times.remove_probe";
    if (uci_lookup_ptr(c, &ptr, tmp_remove_probe, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.remove_probe = atoi(ptr.o->v.string);

    char tmp_update_hostapd[] = "dawn.times.update_hostapd";
    if (uci_lookup_ptr(c, &ptr, tmp_update_hostapd, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.update_hostapd = atoi(ptr.o->v.string);

    char tmp_remove_ap[] = "dawn.times.remove_ap";
    if (uci_lookup_ptr(c, &ptr, tmp_remove_ap, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.remove_ap = atoi(ptr.o->v.string);

    printf("Times: %lu, %lu, %lu %lu\n", ret.update_client, ret.remove_client, ret.remove_probe, ret.update_hostapd);

    uci_free_context(c);

    return ret;
}

struct probe_metric_s uci_get_dawn_metric() {
    struct probe_metric_s ret;

    struct uci_context *c;
    struct uci_ptr ptr;

    c = uci_alloc_context();

    char tmp_ht_support[] = "dawn.metric.ht_support";
    if (uci_lookup_ptr(c, &ptr, tmp_ht_support, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.ht_support = atoi(ptr.o->v.string);

    char tmp_vht_support[] = "dawn.metric.vht_support";
    if (uci_lookup_ptr(c, &ptr, tmp_vht_support, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.vht_support = atoi(ptr.o->v.string);

    char tmp_no_ht_support[] = "dawn.metric.no_ht_support";
    if (uci_lookup_ptr(c, &ptr, tmp_no_ht_support, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.no_ht_support = atoi(ptr.o->v.string);

    char tmp_no_vht_support[] = "dawn.metric.no_vht_support";
    if (uci_lookup_ptr(c, &ptr, tmp_no_vht_support, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.no_vht_support = atoi(ptr.o->v.string);

    char tmp_rssi[] = "dawn.metric.rssi";
    if (uci_lookup_ptr(c, &ptr, tmp_rssi, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.rssi = atoi(ptr.o->v.string);

    char tmp_freq[] = "dawn.metric.freq";
    if (uci_lookup_ptr(c, &ptr, tmp_freq, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.freq = atoi(ptr.o->v.string);

    char tmp_util[] = "dawn.metric.chan_util";
    if (uci_lookup_ptr(c, &ptr, tmp_util, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.chan_util = atoi(ptr.o->v.string);

    char tmp_rssi_val[] = "dawn.metric.rssi_val";
    if (uci_lookup_ptr(c, &ptr, tmp_rssi_val, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.rssi_val = atoi(ptr.o->v.string);

    char tmp_max_chan_util[] = "dawn.metric.max_chan_util";
    if (uci_lookup_ptr(c, &ptr, tmp_max_chan_util, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.max_chan_util = atoi(ptr.o->v.string);

    char tmp_chan_util_val[] = "dawn.metric.chan_util_val";
    if (uci_lookup_ptr(c, &ptr, tmp_chan_util_val, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.chan_util_val = atoi(ptr.o->v.string);


    char tmp_max_chan_util_val[] = "dawn.metric.max_chan_util_val";
    if (uci_lookup_ptr(c, &ptr, tmp_max_chan_util_val, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.max_chan_util_val = atoi(ptr.o->v.string);


    printf("Try to load min_probe_count\n");
    char tmp_min_probe_count[] = "dawn.metric.min_probe_count";
    if (uci_lookup_ptr(c, &ptr, tmp_min_probe_count, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.min_probe_count = atoi(ptr.o->v.string);

    char tmp_low_rssi[] = "dawn.metric.low_rssi";
    if (uci_lookup_ptr(c, &ptr, tmp_low_rssi, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.low_rssi = atoi(ptr.o->v.string);

    char tmp_low_rssi_val[] = "dawn.metric.low_rssi_val";
    if (uci_lookup_ptr(c, &ptr, tmp_low_rssi_val, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.low_rssi_val = atoi(ptr.o->v.string);

    char tmp_bandwith_threshold[] = "dawn.metric.bandwith_threshold";
    if (uci_lookup_ptr(c, &ptr, tmp_bandwith_threshold, 1) != UCI_OK) {
        uci_perror(c, "uci_get_daw_metric Error");
        return ret;
    }
    if (ptr.o->type == UCI_TYPE_STRING)
        ret.bandwith_threshold = atoi(ptr.o->v.string);

    printf("Loaded metric: %d\n", ret.min_probe_count);

    uci_free_context(c);

    return ret;
}