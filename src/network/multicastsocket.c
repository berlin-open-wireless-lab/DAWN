#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "multicastsocket.h"

// TODO: Consider to remove this...


static struct ip_mreq command;

int setup_multicast_socket(const char *_multicast_ip, unsigned short _multicast_port, struct sockaddr_in *addr) {
    int loop = 1;
    int sock;

    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(_multicast_ip);
    addr->sin_port = htons (_multicast_port);

    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    /* Mehr Prozessen erlauben, denselben Port zu nutzen */
    loop = 1;
    if (setsockopt(sock,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &loop, sizeof(loop)) < 0) {
        perror("setsockopt:SO_REUSEADDR");
        exit(EXIT_FAILURE);
    }
    if (bind(sock,
             (struct sockaddr *) addr,
             sizeof(*addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    /* Broadcast auf dieser Maschine zulassen */
    loop = 1;
    if (setsockopt(sock,
                   IPPROTO_IP,
                   IP_MULTICAST_LOOP,
                   &loop, sizeof(loop)) < 0) {
        perror("setsockopt:IP_MULTICAST_LOOP");
        exit(EXIT_FAILURE);
    }

    /* Join the broadcast group: */
    command.imr_multiaddr.s_addr = inet_addr(_multicast_ip);
    command.imr_interface.s_addr = htonl (INADDR_ANY);
    if (command.imr_multiaddr.s_addr == -1) {
        perror("Wrong multicast address!\n");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(sock,
                   IPPROTO_IP,
                   IP_ADD_MEMBERSHIP,
                   &command, sizeof(command)) < 0) {
        perror("setsockopt:IP_ADD_MEMBERSHIP");
    }
    return sock;
}

int remove_multicast_socket(int socket) {
    if (setsockopt(socket,
                   IPPROTO_IP,
                   IP_DROP_MEMBERSHIP,
                   &command, sizeof(command)) < 0) {
        perror("setsockopt:IP_DROP_MEMBERSHIP");
        return -1;
    }
    return 0;
}