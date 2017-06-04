#include <stdio.h>
#include <libubus.h>

#include "ubus.h"
#include "datastorage.h"
#include "networksocket.h"

#define BUFSIZE 17

int main(int argc, char **argv)
{
	const char *ubus_socket = NULL;
	int ch;

	char opt_broadcast_ip[BUFSIZE];
	char opt_broadcast_port[BUFSIZE];

	while ((ch = getopt(argc, argv, "cs:p:i:b:o:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		case 'p':
			snprintf(opt_broadcast_port,BUFSIZE,"%s",optarg);
			printf("broadcast port: %s\n", opt_broadcast_port);
			break;
		case 'i':
			snprintf(opt_broadcast_ip,BUFSIZE,"%s",optarg);
			printf("broadcast ip: %s\n", opt_broadcast_ip);
			break;
		case 'o':
			snprintf(sort_string,SORT_NUM,"%s",optarg);
			printf("sort string: %s\n", sort_string);
		default:
			break;
		}
	}
	argc -= optind;
	argv += optind;

	init_socket_runopts(opt_broadcast_ip, opt_broadcast_port);

	dawn_init_ubus(ubus_socket);

    return 0;
}