#ifndef __DAWN_BROADCASTSOCKET_H
#define __DAWN_BROADCASTSOCKET_H

// TODO: Consider to remove this...

int setup_broadcast_socket(const char *_broadcast_ip, unsigned short _broadcast_port, struct sockaddr_in *addr);

#endif
