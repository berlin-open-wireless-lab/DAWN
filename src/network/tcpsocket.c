#include <libubox/usock.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "memory_utils.h"
#include "msghandler.h"
#include "crypto.h"
#include "datastorage.h"
#include "tcpsocket.h"

#define STR_EVAL(x) #x
#define STR_QUOTE(x) STR_EVAL(x)

LIST_HEAD(tcp_sock_list);

struct network_con_s *tcp_list_contains_address(struct sockaddr_in entry);

static struct uloop_fd server;
static struct client *next_client = NULL; // TODO: Why here? Only used in sever_cb()

enum socket_read_status {
    READ_STATUS_READY,
    READ_STATUS_COMMENCED,
    READ_STATUS_COMPLETE
};

struct client {
    struct sockaddr_in sin;

    struct ustream_fd s;
    int ctr;
    int counter;
    char *str; // message buffer
    enum socket_read_status state; // messge read state
    uint32_t final_len; // full message length
    uint32_t curr_len; // bytes read so far
};

static void client_close(struct ustream *s) {
    struct client *cl = container_of(s, struct client, s.stream);

    fprintf(stderr, "Connection closed\n");
    ustream_free(s);
    close(cl->s.fd.fd);
    dawn_free(cl);
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
    dawn_free(con);
}

static void client_to_server_state(struct ustream *s) {
    struct client *cl = container_of(s, struct client, s.stream);

    if (!s->eof)
        return;

    fprintf(stderr, "eof!, pending: %d, total: %d\n", s->w.data_bytes, cl->ctr);

    if (!s->w.data_bytes)
        return client_to_server_close(s);

}

static void client_read_cb(struct ustream *s, int bytes) {
    struct client *cl = container_of(s, struct client, s.stream);
    struct ustream_fd* ufd = container_of(s, struct ustream_fd, stream);
    
    while(1) {
        printf("tcp_socket: looping - U-EOF = %d, U-error = %d...\n", ufd->fd.eof, ufd->fd.error);
        if (cl->state == READ_STATUS_READY)
        {
            printf("tcp_socket: commencing message...\n");
            uint32_t min_len = sizeof(uint32_t); // big enough to get msg length
            cl->str = dawn_malloc(min_len);
            if (!cl->str) {
                fprintf(stderr,"tcp_socket: not enough memory (" STR_QUOTE(__LINE__) ")\n");
                break;
            }

            uint32_t avail_len = ustream_pending_data(s, false);

            if (avail_len < min_len){//ensure recv sizeof(uint32_t)
                printf("tcp_socket: not complete msg, len:%d, expected len:%u\n", avail_len, min_len);
                dawn_free(cl->str);
                cl->str = NULL;
                break;
            }

            if (ustream_read(s, cl->str, min_len) != min_len) // read msg length bytes
            {
                fprintf(stdout,"tcp_socket: msg length read failed\n");
                dawn_free(cl->str);
                cl->str = NULL;
                break;
            }        

            cl->curr_len += min_len;
            cl->final_len = ntohl(*(uint32_t *)cl->str);

            // On failure, dawn_realloc returns a null pointer. The original pointer str
            // remains valid and may need to be deallocated.
            char *str_tmp = dawn_realloc(cl->str, cl->final_len);
            if (!str_tmp) {
                fprintf(stderr,"tcp_socket: not enough memory (%" PRIu32 " @ " STR_QUOTE(__LINE__) ")\n", cl->final_len);
                dawn_free(cl->str);
                cl->str = NULL;
                break;
            }

            cl->str = str_tmp;
            str_tmp = NULL; // Aboutt o go out of scope, but just in case it gets moved around...
            cl->state = READ_STATUS_COMMENCED;
        }

        if (cl->state == READ_STATUS_COMMENCED)
        {
            printf("tcp_socket: reading message...\n");
            uint32_t read_len = ustream_pending_data(s, false);

            if (read_len == 0)
                break;

            if (read_len > (cl->final_len - cl->curr_len))
                    read_len = cl->final_len - cl->curr_len;

            printf("tcp_socket: reading %" PRIu32 " bytes to add to %" PRIu32 " of %" PRIu32 "...\n",
                    read_len, cl->curr_len, cl->final_len);

            uint32_t this_read = ustream_read(s, cl->str + cl->curr_len, read_len);
            cl->curr_len += this_read;
            printf("tcp_socket: ...and we're back, now have %" PRIu32 " bytes\n", cl->curr_len);
            if (cl->curr_len == cl->final_len){//ensure recv final_len bytes.
                // Full message now received
                cl->state = READ_STATUS_COMPLETE;
                printf("tcp_socket: message completed\n");
            }
        }

        if (cl->state == READ_STATUS_COMPLETE)
        {
            printf("tcp_socket: processing message...\n");
            if (network_config.use_symm_enc) {
                char *dec = gcrypt_decrypt_msg(cl->str + 4, cl->final_len - 4);
                if (!dec) {
                    fprintf(stderr,"tcp_socket: not enough memory (" STR_QUOTE(__LINE__) ")\n");
                    dawn_free(cl->str);
                    cl->str = NULL;
                    break;
                }
                handle_network_msg(dec);
                dawn_free(dec);
            } else {
                handle_network_msg(cl->str + 4);
            }

            cl->state = READ_STATUS_READY;
            cl->curr_len = 0;
            cl->final_len = 0;
            dawn_free(cl->str);
            cl->str = NULL;
        }
    }

    printf("tcp_socket: leaving\n");

    return;
}

static void server_cb(struct uloop_fd *fd, unsigned int events) {
    struct client *cl; //MUSTDO: check free() of this
    unsigned int sl = sizeof(struct sockaddr_in);
    int sfd;

    if (!next_client)
        next_client = dawn_calloc(1, sizeof(*next_client));

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
    next_client = NULL;  // TODO: Why is this here?  To avoid resetting if above return happens?
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
        dawn_free(entry);
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
            // TODO: Removed free(tmp) here - was it needed?
        }
    }

    struct network_con_s *tcp_entry = dawn_calloc(1, sizeof(struct network_con_s));
    tcp_entry->fd.fd = usock(USOCK_TCP | USOCK_NONBLOCK, ipv4, port_str);
    tcp_entry->sock_addr = serv_addr;

    if (tcp_entry->fd.fd < 0) {
        dawn_free(tcp_entry);
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
    struct network_con_s *con, *tmp;
    if (network_config.use_symm_enc) {
        int length_enc;
        size_t msglen = strlen(msg)+1;
        char *enc = gcrypt_encrypt_msg(msg, msglen, &length_enc);
        if (!enc){
            fprintf(stderr, "Ustream error: not enought memory (" STR_QUOTE(__LINE__) ")\n");
            return;
        }

        uint32_t final_len = length_enc + sizeof(final_len);
        char *final_str = dawn_malloc(final_len);
        if (!final_str){
            dawn_free(enc);
            fprintf(stderr, "Ustream error: not enought memory (" STR_QUOTE(__LINE__) ")\n");
            return;
        }
        uint32_t *msg_header = (uint32_t *)final_str;
        *msg_header = htonl(final_len);
        memcpy(final_str+sizeof(final_len), enc, length_enc);
        list_for_each_entry_safe(con, tmp, &tcp_sock_list, list)
        {
            if (con->connected) {
                int len_ustream = ustream_write(&con->stream.stream, final_str, final_len, 0);
                printf("Ustream send: %d\n", len_ustream);
                if (len_ustream <= 0) {
                    fprintf(stderr,"Ustream error(" STR_QUOTE(__LINE__) ")!\n");
                    //ERROR HANDLING!
                    if (con->stream.stream.write_error) {
                        ustream_free(&con->stream.stream);
                        close(con->fd.fd);
                        list_del(&con->list);
                        dawn_free(con);
                    }
                }
            }

        }

        dawn_free(final_str);
        dawn_free(enc);
    } else {
        size_t msglen = strlen(msg) + 1;
        uint32_t final_len = msglen + sizeof(final_len);
        char *final_str = dawn_malloc(final_len);
        if (!final_str){
            fprintf(stderr, "Ustream error: not enought memory (" STR_QUOTE(__LINE__) ")\n");
            return;
        }
        uint32_t *msg_header = (uint32_t *)final_str;
        *msg_header = htonl(final_len);
        memcpy(final_str+sizeof(final_len), msg, msglen);

        list_for_each_entry_safe(con, tmp, &tcp_sock_list, list)
        {
            if (con->connected) {
                int len_ustream = ustream_write(&con->stream.stream, final_str, final_len, 0);
                printf("Ustream send: %d\n", len_ustream);
                if (len_ustream <= 0) {
                    //ERROR HANDLING!
                    fprintf(stderr,"Ustream error(" STR_QUOTE(__LINE__) ")!\n");
                    if (con->stream.stream.write_error) {
                        ustream_free(&con->stream.stream);
                        close(con->fd.fd);
                        list_del(&con->list);
                        dawn_free(con);
                    }
                }
            }
        }
        dawn_free(final_str);
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
