#ifndef __DAWN_NETWORKSOCKET_H
#define __DAWN_NETWORKSOCKET_H

#include <pthread.h>

pthread_mutex_t send_mutex;

int init_socket_runopts(char *_ip, char *_port, int broadcast_socket);
int send_string(char *msg);
void close_socket();

#endif
