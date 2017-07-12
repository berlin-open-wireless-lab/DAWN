#ifndef __DAWN_MULTICASTSTSOCKET_H
#define __DAWN_MULTICASTSSOCKET_H

int setup_multicast_socket(const char *_multicast_ip, unsigned short _multicast_port, struct sockaddr_in *addr);

#endif
