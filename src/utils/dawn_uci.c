#include <ctype.h>
#include <uci.h>
#include <stdlib.h>
#include <string.h>

#include "memory_utils.h"
#include "datastorage.h"
#include "dawn_iwinfo.h"
#include "dawn_uci.h"


static struct uci_context *uci_ctx = NULL;
static struct uci_package *uci_pkg = NULL;

// why is this not included in uci lib...?!
// found here: https://github.com/br101/pingcheck/blob/master/uci.c
static int uci_lookup_option_int(struct uci_context *uci, struct uci_section *s,
                                 const char *name) {
    const char *str = uci_lookup_option_string(uci, s, name);
    return str == NULL ? -1 : atoi(str);
}

void uci_get_hostname(char* hostname)
{
    char path[]= "system.@system[0].hostname";
    struct  uci_ptr ptr;
    struct  uci_context *c = uci_alloc_context();
    dawn_regmem(c);

    if(!c){
        return;
    }

    if ((uci_lookup_ptr(c, &ptr, path, true) != UCI_OK) || (ptr.o==NULL || ptr.o->v.string==NULL)){
        uci_free_context(c);
        dawn_unregmem(c);
        return;
    }

    if(ptr.flags & UCI_LOOKUP_COMPLETE)
    {
        char *dot = strchr(ptr.o->v.string, '.');
        size_t len = HOST_NAME_MAX - 1;

        if (dot && dot < ptr.o->v.string + len)
        {
            len = dot - ptr.o->v.string;
        }
        snprintf(hostname, HOST_NAME_MAX, "%.*s", (int)len, ptr.o->v.string);
    }

    uci_free_context(c);
    dawn_unregmem(c);
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


static int get_rrm_mode_val(char mode) {
    switch (tolower(mode)) {
        case 'a':
            return WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE;
            break;
        case 'p':
            return WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE;
            break;
        case 'b':
        case 't':
             return WLAN_RRM_CAPS_BEACON_REPORT_TABLE;
             break;
    }
    return 0;
}

static int parse_rrm_mode(int *rrm_mode_order, const char *mode_string) {
    int len, mode_val;
    int mask = 0, order = 0, pos = 0;

    if (!mode_string)
        mode_string = DEFAULT_RRM_MODE_ORDER;
    len = strlen(mode_string);

    while (order < __RRM_BEACON_RQST_MODE_MAX) {
        if (pos >= len) {
            rrm_mode_order[order++] = 0;
        } else {
            mode_val = get_rrm_mode_val(mode_string[pos++]);
            if (mode_val && !(mask & mode_val))
                mask |= (rrm_mode_order[order++] = mode_val);
        }
    }
    return mask;
}


struct probe_metric_s uci_get_dawn_metric() {
    struct probe_metric_s ret = {0};

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
            ret.set_hostapd_nr = uci_lookup_option_int(uci_ctx, s, "set_hostapd_nr");
            ret.op_class = uci_lookup_option_int(uci_ctx, s, "op_class");
            ret.duration = uci_lookup_option_int(uci_ctx, s, "duration");
            ret.rrm_mode_mask = parse_rrm_mode(ret.rrm_mode_order,
                                               uci_lookup_option_string(uci_ctx, s, "rrm_mode"));
            ret.scan_channel = uci_lookup_option_int(uci_ctx, s, "scan_channel");
            return ret;
        }
    }

    return ret;
}

struct network_config_s uci_get_dawn_network() {
    struct network_config_s ret;
    memset(&ret, 0, sizeof(ret));

    struct uci_element *e;
    uci_foreach_element(&uci_pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "network") == 0) {
            const char* str_broadcast = uci_lookup_option_string(uci_ctx, s, "broadcast_ip");
            strncpy(ret.broadcast_ip, str_broadcast, MAX_IP_LENGTH);

            const char* str_server_ip = uci_lookup_option_string(uci_ctx, s, "server_ip");
            if(str_server_ip)
                strncpy(ret.server_ip, str_server_ip, MAX_IP_LENGTH);
            else
                ret.server_ip[0] = '\0';

            ret.broadcast_port = uci_lookup_option_int(uci_ctx, s, "broadcast_port");

            const char* str_shared_key = uci_lookup_option_string(uci_ctx, s, "shared_key");
            strncpy(ret.shared_key, str_shared_key, MAX_KEY_LENGTH);

            const char* str_iv = uci_lookup_option_string(uci_ctx, s, "iv");
            strncpy(ret.iv, str_iv, MAX_KEY_LENGTH);

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

bool uci_get_dawn_hostapd_dir() {
    struct uci_element *e;
    uci_foreach_element(&uci_pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "hostapd") == 0) {
            const char* str = uci_lookup_option_string(uci_ctx, s, "hostapd_dir");
            strncpy(hostapd_dir_glob, str, HOSTAPD_DIR_LEN);
            return true;
        }
    }
    return false;
}

bool uci_get_dawn_sort_order() {
    struct uci_element *e;
    uci_foreach_element(&uci_pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "ordering") == 0) {
            const char* str = uci_lookup_option_string(uci_ctx, s, "sort_order");
            strncpy(sort_string, str, SORT_LENGTH);
            return true;
        }
    }
    return false;
}

int uci_reset()
{
    struct uci_context *ctx = uci_ctx;

    if (!ctx) {
        ctx = uci_alloc_context();
        dawn_regmem(ctx);
        uci_ctx = ctx;
    }
    uci_pkg = uci_lookup_package(ctx, "dawn");
    uci_unload(uci_ctx, uci_pkg);
    dawn_unregmem(uci_pkg);
    uci_load(uci_ctx, "dawn", &uci_pkg);
    dawn_regmem(uci_pkg);

    return 0;
}

int uci_init() {
    struct uci_context *ctx = uci_ctx;

    if (!ctx) {
        ctx = uci_alloc_context();
        dawn_regmem(ctx);
        uci_ctx = ctx;

        ctx->flags &= ~UCI_FLAG_STRICT;
    } else {
        ctx->flags &= ~UCI_FLAG_STRICT;
        // shouldn't happen?
        uci_pkg = uci_lookup_package(ctx, "dawn");
        if (uci_pkg)
        {
            uci_unload(ctx, uci_pkg);
            dawn_unregmem(uci_pkg);
            uci_pkg = NULL;
        }
    }

    if (uci_load(ctx, "dawn", &uci_pkg))
        return -1;
    else
        dawn_regmem(uci_pkg);

    return 1;
}

int uci_clear() {
    if (uci_pkg != NULL) {
        uci_unload(uci_ctx, uci_pkg);
        dawn_unregmem(uci_pkg);
        uci_pkg = NULL;
    }
    if (uci_ctx != NULL) {
        uci_free_context(uci_ctx);
        dawn_unregmem(uci_ctx);
    }
    return 1;
}

int uci_set_network(char* uci_cmd)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    struct uci_context *ctx  = uci_ctx;

    if (!ctx) {
        ctx = uci_alloc_context();
        dawn_regmem(ctx);
        uci_ctx = ctx;
    }

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
