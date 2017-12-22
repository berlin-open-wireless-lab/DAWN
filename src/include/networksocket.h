#ifndef __DAWN_NETWORKSOCKET_H
#define __DAWN_NETWORKSOCKET_H

#include <pthread.h>

pthread_mutex_t send_mutex;

int init_socket_runopts(const char *_ip, int _port, int _multicast_socket);

int send_string(char *msg);

int send_string_enc(char *msg);

void close_socket();

// save connections
// struct sockaddr_in addr[100];

#endif
