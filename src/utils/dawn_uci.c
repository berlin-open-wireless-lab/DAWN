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


static void set_if_present(int *ret, struct uci_section *s, const char* option) {
    const char *str;

    if (s && (str = uci_lookup_option_string(uci_ctx, s, option)))
        *ret = atoi(str);
}

static struct uci_section *uci_find_metric_section(const char *name) {
    struct uci_section *s;
    struct uci_element *e;

    uci_foreach_element(&uci_pkg->sections, e) {
        s = uci_to_section(e);
        if (strcmp(s->type, "metric") == 0 &&
            ((!name && s->anonymous) || strcmp(e->name, name) == 0)) {
            return s;
        }
    }
    return NULL;
}

#define DAWN_SET_CONFIG_INT(m, s, conf) \
    set_if_present(&m.conf, s, #conf)

#define DAWN_SET_BANDS_CONFIG_INT(m, global_s, band_s, conf) \
    do for (int band = 0; band < __DAWN_BAND_MAX; band++) { \
        if (global_s) \
            set_if_present(&m.conf[band], global_s, #conf); \
        if (band_s[band]) \
            set_if_present(&m.conf[band], band_s[band], #conf); \
    } while (0)

struct probe_metric_s uci_get_dawn_metric() {
    struct probe_metric_s ret = {0};    // TODO: Set reasonable defaults
    struct uci_section *global_s, *band_s[__DAWN_BAND_MAX];

    if (!(global_s = uci_find_metric_section("global"))) {
        if (!(global_s = uci_find_metric_section(NULL))) {
            fprintf(stderr, "Warning: config metric global section not found! Using defaults.\n");
        } else {
            fprintf(stderr, "Warning: config metric global section not found. "
                            "Using first unnamed config metric.\n"
                            "Consider naming a 'global' metric section to avoid ambiguity.\n");
        }
    }
    if (global_s) {
        // True global configuration
        DAWN_SET_CONFIG_INT(ret, global_s, kicking);
        DAWN_SET_CONFIG_INT(ret, global_s, min_probe_count);
        DAWN_SET_CONFIG_INT(ret, global_s, use_station_count);
        DAWN_SET_CONFIG_INT(ret, global_s, eval_auth_req);
        DAWN_SET_CONFIG_INT(ret, global_s, eval_assoc_req);
        DAWN_SET_CONFIG_INT(ret, global_s, deny_auth_reason);
        DAWN_SET_CONFIG_INT(ret, global_s, deny_assoc_reason);
        DAWN_SET_CONFIG_INT(ret, global_s, eval_probe_req);
        DAWN_SET_CONFIG_INT(ret, global_s, min_number_to_kick);
        DAWN_SET_CONFIG_INT(ret, global_s, set_hostapd_nr);
        DAWN_SET_CONFIG_INT(ret, global_s, max_station_diff);
        DAWN_SET_CONFIG_INT(ret, global_s, bandwidth_threshold);
        DAWN_SET_CONFIG_INT(ret, global_s, use_driver_recog);
        DAWN_SET_CONFIG_INT(ret, global_s, chan_util_avg_period);
        DAWN_SET_CONFIG_INT(ret, global_s, duration);
        ret.rrm_mode_mask = parse_rrm_mode(ret.rrm_mode_order,
                                           uci_lookup_option_string(uci_ctx, global_s, "rrm_mode"));
    }
    for (int band = 0; band < __DAWN_BAND_MAX; band++)
        band_s[band] = uci_find_metric_section(band_config_name[band]);

    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, ap_weight);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, ht_support);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, vht_support);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, no_ht_support);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, no_vht_support);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, rssi);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, rssi_val);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, freq);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, chan_util);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, max_chan_util);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, chan_util_val);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, max_chan_util_val);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, low_rssi);
    DAWN_SET_BANDS_CONFIG_INT(ret, global_s, band_s, low_rssi_val);
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
