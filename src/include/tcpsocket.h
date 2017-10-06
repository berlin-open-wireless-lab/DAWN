//
// Created by nick on 19.09.17.
//

#ifndef DAWN_TCPSOCKET_H
#define DAWN_TCPSOCKET_H

#include <netinet/in.h>

void *run_tcp_socket(void *arg);
int add_tcp_conncection(char* ipv4, int port);

struct network_con_s
{
    int sockfd;
    struct sockaddr_in sock_addr;
};

#endif //DAWN_TCPSOCKET_H
