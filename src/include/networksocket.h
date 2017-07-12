#ifndef __DAWN_NETWORKSOCKET_H
#define __DAWN_NETWORKSOCKET_H

int init_socket_runopts(char *_ip, char *_port, int broadcast_socket);
int send_string(char *msg);
void close_socket();

#endif
