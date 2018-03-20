#ifndef DAWN_TCPSOCKET_H
#define DAWN_TCPSOCKET_H

#include <libubox/ustream.h>
#include <netinet/in.h>
#include <pthread.h>

#define ARRAY_NETWORK_LEN 50

struct network_con_s {
    int sockfd;
    struct sockaddr_in sock_addr;
    struct ustream_fd s;
};

struct network_con_s network_array[ARRAY_NETWORK_LEN];

pthread_mutex_t tcp_array_mutex;

/**
 * Add tcp connection.
 * @param ipv4
 * @param port
 * @return
 */
int add_tcp_conncection(char *ipv4, int port);

/**
 * Opens a tcp server and adds it to the uloop.
 * @param port
 * @return
 */
int run_server(int port);

/**
 * Insert tcp connection to tcp array.
 * @param entry
 * @return
 */
int insert_to_tcp_array(struct network_con_s entry);

/**
 * Checks if a tcp address is already contained in the database.
 * @param entry
 * @return
 */
int tcp_array_contains_address(struct sockaddr_in entry);

/**
 * Send message via tcp to all other hosts.
 * @param msg
 */
void send_tcp(char *msg);

/**
 * Debug message.
 */
void print_tcp_array();


#endif //DAWN_TCPSOCKET_H
