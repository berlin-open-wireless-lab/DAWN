//
// Created by nick on 19.09.17.
//

#ifndef DAWN_TCPSOCKET_H
#define DAWN_TCPSOCKET_H

#include <netinet/in.h>
#include <pthread.h>

struct network_con_s
{
    int sockfd;
    struct sockaddr_in sock_addr;
};

void *run_tcp_socket(void *arg);
int add_tcp_conncection(char* ipv4, int port);

void print_tcp_array();
pthread_mutex_t tcp_array_mutex;
int insert_to_tcp_array(struct network_con_s entry);
int tcp_array_contains_address(struct sockaddr_in entry);
void send_tcp(char* msg);



#endif //DAWN_TCPSOCKET_H
