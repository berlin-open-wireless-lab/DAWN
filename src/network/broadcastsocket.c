#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "networksocket.h"
#include "broadcastsocket.h"

int setup_broadcast_socket(const char *_broadcast_ip, unsigned short _broadcast_port, struct sockaddr_in *addr) {
    int sock;
    int broadcast_permission;

    // Create socket
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "Failed to create socket.\n");
        return -1;
    }

    // Allow broadcast
    broadcast_permission = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &broadcast_permission,
                   sizeof(broadcast_permission)) < 0) {
        fprintf(stderr, "Failed to create socket.\n");
        return -1;
    }

    // Constract addess
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(_broadcast_ip);
    addr->sin_port = htons(_broadcast_port);

    // Bind socket
    while (bind(sock, (struct sockaddr *) addr, sizeof(*addr)) < 0) {
        fprintf(stderr, "Binding socket failed!\n");
        sleep(1);
    }
    return sock;
}