#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#include "networksocket.h"
#include "ubus.h"
#include "utils.h"

static struct ubus_context *ctx;
static struct ubus_subscriber hostapd_event;

enum {
	PROB_BSSID_ADDR,
	PROB_CLIENT_ADDR,
	PROB_TARGET_ADDR,
	PROB_SIGNAL,
	PROB_FREQ,
	__PROB_MAX,
};

static const struct blobmsg_policy prob_policy[__PROB_MAX] = {
	[PROB_BSSID_ADDR] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
	[PROB_CLIENT_ADDR] = { .name = "address", .type = BLOBMSG_TYPE_STRING },
	[PROB_TARGET_ADDR] = { .name = "target", .type = BLOBMSG_TYPE_STRING },
	[PROB_SIGNAL] = { .name = "signal", .type = BLOBMSG_TYPE_INT32 },
	[PROB_FREQ] = { .name = "freq", .type = BLOBMSG_TYPE_INT32 },
};

/* Function Definitions */
static void hostapd_handle_remove(struct ubus_context *ctx, struct ubus_subscriber *s, uint32_t id);
static int hostapd_notify(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg);
static int add_subscriber(char* name);
//int parse_to_probe_req(struct blob_attr *msg, probe_entry* prob_req);
static int subscribe_to_hostapd_interfaces();

static int decide_function(probe_entry* prob_req)
{
	int ret = mac_first_in_probe_list(prob_req->bssid_addr, prob_req->client_addr);
	if(ret)
	{
		printf("Mac will be accepted!\n");
	} else 
	{
		printf("Mac will be declined!\n");
	}
	return ret;
}

static void hostapd_handle_remove(struct ubus_context *ctx, struct ubus_subscriber *s, uint32_t id)
{
	fprintf(stderr, "Object %08x went away\n", id);
}


int parse_to_probe_req(struct blob_attr *msg, probe_entry* prob_req)
{
	struct blob_attr *tb[__PROB_MAX];
	blobmsg_parse(prob_policy, __PROB_MAX, tb, blob_data(msg), blob_len(msg));

	if (hwaddr_aton(blobmsg_data(tb[PROB_BSSID_ADDR]), prob_req->bssid_addr))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (hwaddr_aton(blobmsg_data(tb[PROB_CLIENT_ADDR]), prob_req->client_addr))
		return UBUS_STATUS_INVALID_ARGUMENT;
	
	if (hwaddr_aton(blobmsg_data(tb[PROB_TARGET_ADDR]), prob_req->target_addr))
		return UBUS_STATUS_INVALID_ARGUMENT;
	
	if (tb[PROB_SIGNAL])
	{
		prob_req->signal = blobmsg_get_u32(tb[PROB_SIGNAL]);
	}

	if (tb[PROB_FREQ])
	{
		prob_req->freq = blobmsg_get_u32(tb[PROB_FREQ]);
	}	
	return 0;
}

static int hostapd_notify(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
	// write probe to table
	probe_entry prob_req;
	parse_to_probe_req(msg, &prob_req);
	insert_to_list(prob_req);

	// send probe via network
	char *str;
	str = blobmsg_format_json(msg, true);
	send_string(str);

	printf("[WC] Hostapd-Probe: %s : %s\n", method, str);
	print_list();

	// deny access
	if(!decide_function(&prob_req))
	{
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	// allow access	
	return 0;
}

static int add_subscriber(char* name)
{
	uint32_t id = 0;

	if (ubus_lookup_id(ctx, name, &id)) {
		fprintf(stderr, "Failed to look up test object for %s\n", name);
		return -1;
	}

	// add callbacks
	hostapd_event.remove_cb = hostapd_handle_remove;
	hostapd_event.cb = hostapd_notify;

	int ret = ubus_subscribe(ctx, &hostapd_event, id);

	fprintf(stderr, "Watching object %08x: %s\n", id, ubus_strerror(ret));

	return 0;
}

static int subscribe_to_hostapd_interfaces()
{
	DIR * dirp;
	struct dirent * entry;

	int ret = ubus_register_subscriber(ctx, &hostapd_event);
	if (ret)
	{
		fprintf(stderr, "Failed to add watch handler: %s\n", ubus_strerror(ret));
		return -1;
	}

	dirp = opendir("/var/run/hostapd"); // error handling?
	while ((entry = readdir(dirp)) != NULL) {
		if (entry->d_type == DT_SOCK) {
			char subscribe_name[256];
			sprintf(subscribe_name, "hostapd.%s", entry->d_name);
			printf("Subscribing to %s\n", subscribe_name);
			add_subscriber(subscribe_name); 
    	}
    }
    return 0;
}

int dawn_init_ubus(const char *ubus_socket)
{
	uloop_init();
	signal(SIGPIPE, SIG_IGN);

	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	} else {
		printf("Connected to ubus\n");
	}

	ubus_add_uloop(ctx);

	subscribe_to_hostapd_interfaces();
	
	uloop_run();

	close_socket();


	ubus_free(ctx);
	uloop_done();
	return 0;
}