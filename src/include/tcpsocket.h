#ifndef DAWN_TCPSOCKET_H
#define DAWN_TCPSOCKET_H

#include <libubox/ustream.h>
#include <netinet/in.h>

#define ARRAY_NETWORK_LEN 50

struct network_con_s {
    struct list_head list;

    struct uloop_fd fd;
    struct ustream_fd stream;
    struct sockaddr_in sock_addr;
    int connected;
};

/**
 * Add tcp connection.
 * @param ipv4
 * @param port
 * @return
 */
int add_tcp_connection(char *ipv4, int port);

/**
 * Opens a tcp server and adds it to the uloop.
 * @param port
 * @return
 */
int run_server(int port);

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
