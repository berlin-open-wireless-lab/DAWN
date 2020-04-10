#include <uci.h>
#include <stdlib.h>
#include <datastorage.h>

#include "dawn_uci.h"


static struct uci_context *uci_ctx;
static struct uci_package *uci_pkg;

// why is this not included in uci lib...?!
// found here: https://github.com/br101/pingcheck/blob/master/uci.c
static int uci_lookup_option_int(struct uci_context *uci, struct uci_section *s,
                                 const char *name) {
    const char *str = uci_lookup_option_string(uci, s, name);
    return str == NULL ? -1 : atoi(str);
}

struct time_config_s uci_get_time_config() {
    struct time_config_s ret;

    struct uci_element *e;
    uci_foreach_element(&uci_pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "times") == 0) {
            ret.update_client = uci_lookup_option_int(uci_ctx, s, "update_client");
            ret.remove_client = uci_lookup_option_int(uci_ctx, s, "remove_client");
            ret.remove_probe = uci_lookup_option_int(uci_ctx, s, "remove_probe");
            ret.update_hostapd = uci_lookup_option_int(uci_ctx, s, "update_hostapd");
            ret.remove_ap = uci_lookup_option_int(uci_ctx, s, "remove_ap");
            ret.update_tcp_con = uci_lookup_option_int(uci_ctx, s, "update_tcp_con");
            ret.denied_req_threshold = uci_lookup_option_int(uci_ctx, s, "denied_req_threshold");
            ret.update_chan_util = uci_lookup_option_int(uci_ctx, s, "update_chan_util");
            ret.update_beacon_reports = uci_lookup_option_int(uci_ctx, s, "update_beacon_reports");
            return ret;
        }
    }

    return ret;
}

struct probe_metric_s uci_get_dawn_metric() {
    struct probe_metric_s ret;

    struct uci_element *e;
    uci_foreach_element(&uci_pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "metric") == 0) {
            ret.ap_weight = uci_lookup_option_int(uci_ctx, s, "ap_weight");
            ret.kicking = uci_lookup_option_int(uci_ctx, s, "kicking");
            ret.ht_support = uci_lookup_option_int(uci_ctx, s, "ht_support");
            ret.vht_support = uci_lookup_option_int(uci_ctx, s, "vht_support");
            ret.no_ht_support = uci_lookup_option_int(uci_ctx, s, "no_ht_support");
            ret.no_vht_support = uci_lookup_option_int(uci_ctx, s, "no_vht_support");
            ret.rssi = uci_lookup_option_int(uci_ctx, s, "rssi");
            ret.freq = uci_lookup_option_int(uci_ctx, s, "freq");
            ret.rssi_val = uci_lookup_option_int(uci_ctx, s, "rssi_val");
            ret.chan_util = uci_lookup_option_int(uci_ctx, s, "chan_util");
            ret.max_chan_util = uci_lookup_option_int(uci_ctx, s, "max_chan_util");
            ret.chan_util_val = uci_lookup_option_int(uci_ctx, s, "chan_util_val");
            ret.max_chan_util_val = uci_lookup_option_int(uci_ctx, s, "max_chan_util_val");
            ret.min_probe_count = uci_lookup_option_int(uci_ctx, s, "min_probe_count");
            ret.low_rssi = uci_lookup_option_int(uci_ctx, s, "low_rssi");
            ret.low_rssi_val = uci_lookup_option_int(uci_ctx, s, "low_rssi_val");
            ret.bandwidth_threshold = uci_lookup_option_int(uci_ctx, s, "bandwidth_threshold");
            ret.use_station_count = uci_lookup_option_int(uci_ctx, s, "use_station_count");
            ret.eval_probe_req = uci_lookup_option_int(uci_ctx, s, "eval_probe_req");
            ret.eval_auth_req = uci_lookup_option_int(uci_ctx, s, "eval_auth_req");
            ret.eval_assoc_req = uci_lookup_option_int(uci_ctx, s, "eval_assoc_req");
            ret.deny_auth_reason = uci_lookup_option_int(uci_ctx, s, "deny_auth_reason");
            ret.deny_assoc_reason = uci_lookup_option_int(uci_ctx, s, "deny_assoc_reason");
            ret.max_station_diff = uci_lookup_option_int(uci_ctx, s, "max_station_diff");
            ret.use_driver_recog = uci_lookup_option_int(uci_ctx, s, "use_driver_recog");
            ret.min_kick_count = uci_lookup_option_int(uci_ctx, s, "min_number_to_kick");
            ret.chan_util_avg_period = uci_lookup_option_int(uci_ctx, s, "chan_util_avg_period");
            ret.op_class = uci_lookup_option_int(uci_ctx, s, "op_class");
            ret.duration = uci_lookup_option_int(uci_ctx, s, "duration");
            ret.mode = uci_lookup_option_int(uci_ctx, s, "mode");
            ret.scan_channel = uci_lookup_option_int(uci_ctx, s, "scan_channel");
            return ret;
        }
    }

    return ret;
}

struct network_config_s uci_get_dawn_network() {
    struct network_config_s ret;

    struct uci_element *e;
    uci_foreach_element(&uci_pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "network") == 0) {
            ret.broadcast_ip = uci_lookup_option_string(uci_ctx, s, "broadcast_ip");
            ret.broadcast_port = uci_lookup_option_int(uci_ctx, s, "broadcast_port");
            ret.bool_multicast = uci_lookup_option_int(uci_ctx, s, "multicast");
            ret.shared_key = uci_lookup_option_string(uci_ctx, s, "shared_key");
            ret.iv = uci_lookup_option_string(uci_ctx, s, "iv");
            ret.network_option = uci_lookup_option_int(uci_ctx, s, "network_option");
            ret.tcp_port = uci_lookup_option_int(uci_ctx, s, "tcp_port");
            ret.use_symm_enc = uci_lookup_option_int(uci_ctx, s, "use_symm_enc");
            ret.collision_domain = uci_lookup_option_int(uci_ctx, s, "collision_domain");
            ret.bandwidth = uci_lookup_option_int(uci_ctx, s, "bandwidth");
            return ret;
        }
    }

    return ret;
}

const char *uci_get_dawn_hostapd_dir() {
    struct uci_element *e;
    uci_foreach_element(&uci_pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "hostapd") == 0) {
            return uci_lookup_option_string(uci_ctx, s, "hostapd_dir");
        }
    }
    return NULL;
}

const char *uci_get_dawn_sort_order() {
    struct uci_element *e;
    uci_foreach_element(&uci_pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "ordering") == 0) {
            return uci_lookup_option_string(uci_ctx, s, "sort_order");
        }
    }
    return NULL;
}

int uci_reset()
{
    uci_unload(uci_ctx, uci_pkg);
    uci_load(uci_ctx, "dawn", &uci_pkg);

    return 0;
}

int uci_init() {
    struct uci_context *ctx = uci_ctx;

    if (!ctx) {
        ctx = uci_alloc_context();
        uci_ctx = ctx;

        ctx->flags &= ~UCI_FLAG_STRICT;
    } else {
        // shouldn't happen?
        uci_pkg = uci_lookup_package(ctx, "dawn");
        if (uci_pkg)
            uci_unload(ctx, uci_pkg);
    }

    if (uci_load(ctx, "dawn", &uci_pkg))
        return -1;

    return 1;
}

int uci_clear() {
    if (uci_pkg != NULL) {
        uci_unload(uci_ctx, uci_pkg);
    }
    if (uci_ctx != NULL) {
        uci_free_context(uci_ctx);
    }
    return 1;
}

int uci_set_network(char* uci_cmd)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    struct uci_context *ctx;

    ctx = uci_alloc_context();
    ctx->flags |= UCI_FLAG_STRICT;

    if (uci_lookup_ptr(ctx, &ptr, uci_cmd, 1) != UCI_OK) {
        return 1;
    }

    ret = uci_set(ctx, &ptr);


    if (uci_lookup_ptr(ctx, &ptr, "dawn", 1) != UCI_OK) {
        return 1;
    }

    if (uci_commit(ctx, &ptr.p, 0) != UCI_OK) {
        fprintf(stderr, "Failed to commit UCI cmd: %s\n", uci_cmd);
    }

    return ret;
}