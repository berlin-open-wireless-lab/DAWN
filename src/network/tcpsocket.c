#include <libubox/usock.h>
#include <libubox/ustream.h>
#include <libubox/uloop.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tcpsocket.h"
#include "ubus.h"
#include <arpa/inet.h>

// based on:
// https://github.com/xfguo/libubox/blob/master/examples/ustream-example.c

int tcp_array_insert(struct network_con_s entry);

int tcp_array_contains_address_help(struct sockaddr_in entry);

void print_tcp_entry(struct network_con_s entry);

int tcp_entry_last = -1;

static struct uloop_fd server;
struct client *next_client = NULL;

struct client {
    struct sockaddr_in sin;

    struct ustream_fd s;
    int ctr;
};

static void client_close(struct ustream *s) {
    struct client *cl = container_of(s,
    struct client, s.stream);

    fprintf(stderr, "Connection closed\n");
    ustream_free(s);
    close(cl->s.fd.fd);
    free(cl);
}

static void client_notify_write(struct ustream *s, int bytes) {
    return;
}

static void client_notify_state(struct ustream *s) {
    struct client *cl = container_of(s,
    struct client, s.stream);

    if (!s->eof)
        return;

    fprintf(stderr, "eof!, pending: %d, total: %d\n", s->w.data_bytes, cl->ctr);
    if (!s->w.data_bytes)
        return client_close(s);

}

static void client_read_cb(struct ustream *s, int bytes) {
    char *str;
    int len;

    do {
        str = ustream_get_read_buf(s, &len);
        if (!str)
            break;

        printf("RECEIVED String: %s\n", str);
        handle_network_msg(str);
        ustream_consume(s, len);

    } while (1);

    if (s->w.data_bytes > 256 && !ustream_read_blocked(s)) {
        fprintf(stderr, "Block read, bytes: %d\n", s->w.data_bytes);
        ustream_set_read_blocked(s, true);
    }
}

static void server_cb(struct uloop_fd *fd, unsigned int events) {
    struct client *cl;
    unsigned int sl = sizeof(struct sockaddr_in);
    int sfd;

    if (!next_client)
        next_client = calloc(1, sizeof(*next_client));

    cl = next_client;
    sfd = accept(server.fd, (struct sockaddr *) &cl->sin, &sl);
    if (sfd < 0) {
        fprintf(stderr, "Accept failed\n");
        return;
    }

    cl->s.stream.string_data = 1;
    cl->s.stream.notify_read = client_read_cb;
    cl->s.stream.notify_state = client_notify_state;
    cl->s.stream.notify_write = client_notify_write;
    ustream_fd_init(&cl->s, sfd);
    next_client = NULL;
    fprintf(stderr, "New connection\n");
}

int run_server(int port) {
    char port_str[12];
    sprintf(port_str, "%d", port);

    server.cb = server_cb;
    server.fd = usock(USOCK_TCP | USOCK_SERVER | USOCK_IPV4ONLY | USOCK_NUMERIC, INADDR_ANY, port_str);
    if (server.fd < 0) {
        perror("usock");
        return 1;
    }

    uloop_fd_add(&server, ULOOP_READ);

    return 0;
}

int add_tcp_conncection(char *ipv4, int port) {
    int sockfd;
    struct sockaddr_in serv_addr;

    char port_str[12];
    sprintf(port_str, "%d", port);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ipv4);
    serv_addr.sin_port = htons(port);

    print_tcp_array();

    if (tcp_array_contains_address(serv_addr)) {
        return 0;
    }

    sockfd = usock(USOCK_TCP | USOCK_NONBLOCK, ipv4, port_str);

    struct network_con_s tmp =
            {
                    .sock_addr = serv_addr,
                    .sockfd = sockfd
            };

    insert_to_tcp_array(tmp);

    printf("NEW TCP CONNECTION!!! to %s:%d\n", ipv4, port);

    return 0;
}

int insert_to_tcp_array(struct network_con_s entry) {
    pthread_mutex_lock(&tcp_array_mutex);

    int ret = tcp_array_insert(entry);
    pthread_mutex_unlock(&tcp_array_mutex);

    return ret;
}

void print_tcp_entry(struct network_con_s entry) {
    printf("Conenctin to Port: %d\n", entry.sock_addr.sin_port);
}

void send_tcp(char *msg) {
    printf("SENDING TCP!\n");
    pthread_mutex_lock(&tcp_array_mutex);
    for (int i = 0; i <= tcp_entry_last; i++) {
        if (send(network_array[i].sockfd, msg, strlen(msg), 0) < 0) {
            close(network_array->sockfd);
            printf("Removing bad TCP connection!\n");
            for (int j = i; j < tcp_entry_last; j++) {
                network_array[j] = network_array[j + 1];
            }

            if (tcp_entry_last > -1) {
                tcp_entry_last--;
            }
        }
    }
    pthread_mutex_unlock(&tcp_array_mutex);
}


void print_tcp_array() {
    printf("--------Connections------\n");
    for (int i = 0; i <= tcp_entry_last; i++) {
        print_tcp_entry(network_array[i]);
    }
    printf("------------------\n");
}

int tcp_array_insert(struct network_con_s entry) {
    if (tcp_entry_last == -1) {
        network_array[0] = entry;
        tcp_entry_last++;
        return 1;
    }

    int i;
    for (i = 0; i <= tcp_entry_last; i++) {
        if (entry.sock_addr.sin_addr.s_addr < network_array[i].sock_addr.sin_addr.s_addr) {
            break;
        }
        if (entry.sock_addr.sin_addr.s_addr == network_array[i].sock_addr.sin_addr.s_addr) {
            return 0;
        }
    }
    for (int j = tcp_entry_last; j >= i; j--) {
        if (j + 1 <= ARRAY_NETWORK_LEN) {
            network_array[j + 1] = network_array[j];
        }
    }
    network_array[i] = entry;

    if (tcp_entry_last < ARRAY_NETWORK_LEN) {
        tcp_entry_last++;
    }
    return 1;
}

int tcp_array_contains_address(struct sockaddr_in entry) {
    pthread_mutex_lock(&tcp_array_mutex);

    int ret = tcp_array_contains_address_help(entry);
    pthread_mutex_unlock(&tcp_array_mutex);

    return ret;
}

int tcp_array_contains_address_help(struct sockaddr_in entry) {
    if (tcp_entry_last == -1) {
        return 0;
    }

    int i;
    for (i = 0; i <= tcp_entry_last; i++) {
        if (entry.sin_addr.s_addr == network_array[i].sock_addr.sin_addr.s_addr) {
            return 1;
        }
    }
    return 0;
}