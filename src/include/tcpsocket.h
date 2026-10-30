#ifndef DAWN_TCPSOCKET_H
#define DAWN_TCPSOCKET_H

#include <libubox/ustream.h>
#include <netinet/in.h>
#include <net/if.h>

/* room for an address plus %interface scope suffix */
#define DAWN_CON_ADDR_LEN (INET6_ADDRSTRLEN + IF_NAMESIZE + 2)
#define DAWN_CON_MAX_ADDRS 3

#define ARRAY_NETWORK_LEN 50
#define CHECK_TIMEOUT 10

struct network_con_s {
    struct list_head list;

    struct uloop_fd fd;
    struct ustream_fd stream;
    struct sockaddr_storage sock_addr;
    int connected;
    time_t time_alive;

    /* candidate addresses for this peer, most preferred first */
    char addrs[DAWN_CON_MAX_ADDRS][DAWN_CON_ADDR_LEN];
    int naddrs;
    int cur_addr;
    int port;
};

/**
 * Add tcp connection.
 * @param ipv4
 * @param port
 * @return
 */
int add_tcp_connection(char *ipv4, int port);

/**
 * Add tcp connection with a list of candidate addresses for the peer,
 * most preferred first. Falls back down the list on connection failure.
 */
int add_tcp_connection_list(char (*addrs)[DAWN_CON_ADDR_LEN], int naddrs, int port);

/**
 * Opens a tcp server and adds it to the uloop.
 * @param port
 * @return
 */
int run_server(char *ipv4, int port);

/**
 * Send message via tcp to all other hosts.
 * @param msg
 */
void send_tcp(char *msg);

/**
 * Send ping to clients
 */
void server_to_clients_ping(void);

/**
 * Check sockets timeouts.
 */
void check_timeout(int timeout);

/**
 * Debug message.
 */
void print_tcp_array();


#endif //DAWN_TCPSOCKET_H
