#include <libubox/usock.h>
#include <libubox/ustream.h>
#include <libubox/uloop.h>
#include <libubox/utils.h> // base64 encoding
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tcpsocket.h"
#include <arpa/inet.h>
#include "ubus.h"
#include "crypto.h"

LIST_HEAD(tcp_sock_list);

struct network_con_s *tcp_list_contains_address(struct sockaddr_in entry);

static struct uloop_fd server;
struct client *next_client = NULL;

struct client {
    struct sockaddr_in sin;

    struct ustream_fd s;
    int ctr;
    int counter;
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

static void client_to_server_close(struct ustream *s) {
    struct network_con_s *con = container_of(s,
    struct network_con_s, stream.stream);

    fprintf(stderr, "Connection to server closed\n");
    ustream_free(s);
    close(con->fd.fd);
    list_del(&con->list);
    free(con);
}

static void client_to_server_state(struct ustream *s) {
    struct client *cl = container_of(s,
    struct client, s.stream);

    if (!s->eof)
        return;

    fprintf(stderr, "eof!, pending: %d, total: %d\n", s->w.data_bytes, cl->ctr);

    if (!s->w.data_bytes)
        return client_to_server_close(s);

}

static void client_read_cb(struct ustream *s, int bytes) {
    char *str;
    int len = 0;
    uint32_t final_len;
    int max_retry = 3, tried = 0;

    do {
        str = ustream_get_read_buf(s, &len);
        if (!str)
            break;

        if (network_config.use_symm_enc) {
            final_len = ntohl(*(uint32_t *)str);
            if(len < final_len) {//not complete msg, wait for next recv
                fprintf(stderr,"not complete msg, len:%d, expected len:%u\n", len, final_len);
                if (tried++ == max_retry) {
                    ustream_consume(s, len);
                    return;//drop package
                }
                continue;
            }
            char *dec = gcrypt_decrypt_msg(str+sizeof(final_len), final_len-sizeof(final_len));
        
            handle_network_msg(dec);
            free(dec);
            ustream_consume(s, final_len);//one msg is processed
            tried = 0;
        } else {
            final_len = ntohl(*(uint32_t *)str);
            if(len < final_len){
                fprintf(stderr,"not complete msg, len:%d, expected len:%u\n", len, final_len);
                if (tried++ == max_retry) {
                    ustream_consume(s, len);
                    return;
                }
                continue;
            } 
            char* msg = malloc(final_len);
            memcpy(msg, str+sizeof(final_len), final_len-sizeof(final_len));
            handle_network_msg(msg);
            ustream_consume(s, final_len);//one msg is processed
            free(msg);
            tried = 0;
        }
    } while(1);
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
    printf("Adding socket!\n");
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

static void client_not_be_used_read_cb(struct ustream *s, int bytes) {
    int len;
    char buf[2048];

    len = ustream_read(s, buf, sizeof(buf));
    buf[len] = '\0';
    printf("Read %d bytes from SSL connection: %s\n", len, buf);
}

static void connect_cb(struct uloop_fd *f, unsigned int events) {

    struct network_con_s *entry = container_of(f, struct network_con_s, fd);

    if (f->eof || f->error) {
        fprintf(stderr, "Connection failed (%s)\n", f->eof ? "EOF" : "ERROR");
        close(entry->fd.fd);
        list_del(&entry->list);
        free(entry);
        return;
    }

    fprintf(stderr, "Connection established\n");
    uloop_fd_delete(&entry->fd);

    entry->stream.stream.notify_read = client_not_be_used_read_cb;
    entry->stream.stream.notify_state = client_to_server_state;

    ustream_fd_init(&entry->stream, entry->fd.fd);
    entry->connected = 1;
}

int add_tcp_conncection(char *ipv4, int port) {
    struct sockaddr_in serv_addr;

    char port_str[12];
    sprintf(port_str, "%d", port);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ipv4);
    serv_addr.sin_port = htons(port);

    struct network_con_s *tmp = tcp_list_contains_address(serv_addr);
    if (tmp != NULL) {
        if(tmp->connected == true)
        {
            return 0;
        } else{
            // Delete already existing entry
            close(tmp->fd.fd);
            list_del(&tmp->list);
            free(tmp);
        }
    }

    struct network_con_s *tcp_entry = calloc(1, sizeof(struct network_con_s));
    tcp_entry->fd.fd = usock(USOCK_TCP | USOCK_NONBLOCK, ipv4, port_str);
    tcp_entry->sock_addr = serv_addr;

    if (tcp_entry->fd.fd < 0) {
        free(tcp_entry);
        return -1;
    }
    tcp_entry->fd.cb = connect_cb;
    uloop_fd_add(&tcp_entry->fd, ULOOP_WRITE | ULOOP_EDGE_TRIGGER);

    printf("New TCP connection to %s:%d\n", ipv4, port);
    list_add(&tcp_entry->list, &tcp_sock_list);

    return 0;
}

void send_tcp(char *msg) {
    print_tcp_array();
    if (network_config.use_symm_enc) {
        int length_enc;
        size_t msglen = strlen(msg)+1;
        char *enc = gcrypt_encrypt_msg(msg, msglen, &length_enc);

        struct network_con_s *con;
        uint32_t final_len = length_enc + sizeof(final_len);
        char *final_str = malloc(final_len);
        uint32_t *msg_header = (uint32_t *)final_str;
        *msg_header = htonl(final_len);
        memcpy(final_str+sizeof(final_len), enc, length_enc);
        list_for_each_entry(con, &tcp_sock_list, list)
        {
            if (con->connected) {
                int len_ustream = ustream_write(&con->stream.stream, final_str, final_len, 0);
                printf("Ustream send: %d\n", len_ustream);
                if (len_ustream <= 0) {
                    fprintf(stderr,"Ustream error!\n");
                    //TODO: ERROR HANDLING!
                }
            }

        }

        free(final_str);
        free(enc);
    } else {
        size_t msglen = strlen(msg) + 1;
        uint32_t final_len = msglen + sizeof(final_len);
        char *final_str = malloc(final_len);
        uint32_t *msg_header = (uint32_t *)final_str;
        *msg_header = htonl(final_len);
        memcpy(final_str+sizeof(final_len), msg, msglen);
        struct network_con_s *con;

        list_for_each_entry(con, &tcp_sock_list, list)
        {
            if (con->connected) {
                int len_ustream = ustream_write(&con->stream.stream, final_str, final_len, 0);
                printf("Ustream send: %d\n", len_ustream);
                if (len_ustream <= 0) {
                    //TODO: ERROR HANDLING!
                    fprintf(stderr,"Ustream error!\n");
                }
            }
        }
        free(final_str);
    }
}

struct network_con_s* tcp_list_contains_address(struct sockaddr_in entry) {
    struct network_con_s *con;

    list_for_each_entry(con, &tcp_sock_list, list)
    {
        if(entry.sin_addr.s_addr == con->sock_addr.sin_addr.s_addr)
        {
            return con;
        }
    }
    return NULL;
}

void print_tcp_array() {
    struct network_con_s *con;

    printf("--------Connections------\n");
    list_for_each_entry(con, &tcp_sock_list, list)
    {
        printf("Connecting to Port: %d, Connected: %s\n", ntohs(con->sock_addr.sin_port), con->connected ? "True" : "False");
    }
    printf("------------------\n");
}
