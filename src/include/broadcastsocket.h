#ifndef __DAWN_BROADCASTSOCKET_H
#define __DAWN_BROADCASTSOCKET_H

#include "ubus.h"

int init_socket_runopts(char *broadcast_ip, char *broadcast_port);
int init_socket_conffile();
int init_socket(const char *_broadcastIP, unsigned short _broadcastPort);
int send_string(char *msg);
void close_socket();

#endif
