#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libubox/blobmsg_json.h>

#include "networksocket.h"
#include "datastorage.h"
#include "multicastsocket.h"
#include "broadcastsocket.h"
#include "ubus.h"
#include "crypto.h"

/* Network Defines */
#define MAX_RECV_STRING 2048

/* Network Attributes */
int sock;
struct sockaddr_in addr;
const char *ip;
unsigned short port;
char recv_string[MAX_RECV_STRING + 1];
int recv_string_len;
int multicast_socket;

void *receive_msg(void *args);

void *receive_msg_enc(void *args);

int init_socket_runopts(const char *_ip, int _port, int _multicast_socket) {

    port = _port;
    ip = _ip;
    multicast_socket = _multicast_socket;

    if (multicast_socket) {
        printf("Settingup multicastsocket!\n");
        sock = setup_multicast_socket(ip, port, &addr);
    } else {
        sock = setup_broadcast_socket(ip, port, &addr);
    }

    pthread_t sniffer_thread;
    if (network_config.use_symm_enc) {
        if (pthread_create(&sniffer_thread, NULL, receive_msg_enc, NULL)) {
            fprintf(stderr, "Could not create receiving thread!\n");
            return -1;
        }
    } else {
        if (pthread_create(&sniffer_thread, NULL, receive_msg, NULL)) {
            fprintf(stderr, "Could not create receiving thread!\n");
            return -1;
        }
    }

    fprintf(stdout, "Connected to %s:%d\n", ip, port);

    return 0;
}

void *receive_msg(void *args) {
    while (1) {
        if ((recv_string_len =
                     recvfrom(sock, recv_string, MAX_RECV_STRING, 0, NULL, 0)) < 0) {
            fprintf(stderr, "Could not receive message!");
            continue;
        }

        if (recv_string == NULL) {
            return 0;
        }

        if (strlen(recv_string) <= 0) {
            return 0;
        }
        recv_string[recv_string_len] = '\0';

        printf("Received network message: %s\n", recv_string);
        handle_network_msg(recv_string);
    }
}

void *receive_msg_enc(void *args) {
    while (1) {
        if ((recv_string_len =
                     recvfrom(sock, recv_string, MAX_RECV_STRING, 0, NULL, 0)) < 0) {
            fprintf(stderr, "Could not receive message!\n");
            continue;
        }

        if (recv_string == NULL) {
            return 0;
        }

        if (strlen(recv_string) <= 0) {
            return 0;
        }
        recv_string[recv_string_len] = '\0';

        char *base64_dec_str = malloc(B64_DECODE_LEN(strlen(recv_string)));
        int base64_dec_length = b64_decode(recv_string, base64_dec_str, B64_DECODE_LEN(strlen(recv_string)));
        char *dec = gcrypt_decrypt_msg(base64_dec_str, base64_dec_length);

        printf("Received network message: %s\n", dec);
        free(base64_dec_str);
        handle_network_msg(dec);
        free(dec);
    }
}

int send_string(char *msg) {
    pthread_mutex_lock(&send_mutex);
    size_t msglen = strlen(msg);

    if (sendto(sock,
               msg,
               msglen,
               0,
               (struct sockaddr *) &addr,
               sizeof(addr)) < 0) {
        perror("sendto()");
        pthread_mutex_unlock(&send_mutex);
        exit(EXIT_FAILURE);
    }
    pthread_mutex_unlock(&send_mutex);

    return 0;
}

int send_string_enc(char *msg) {
    pthread_mutex_lock(&send_mutex);

    int length_enc;
    size_t msglen = strlen(msg);
    char *enc = gcrypt_encrypt_msg(msg, msglen + 1, &length_enc);

    char *base64_enc_str = malloc(B64_ENCODE_LEN(length_enc));
    size_t base64_enc_length = b64_encode(enc, length_enc, base64_enc_str, B64_ENCODE_LEN(length_enc));

    if (sendto(sock,
               base64_enc_str,
               base64_enc_length, // very important to use actual length of string because of '\0' in encrypted msg
               0,
               (struct sockaddr *) &addr,
               sizeof(addr)) < 0) {
        perror("sendto()");
        pthread_mutex_unlock(&send_mutex);
        exit(EXIT_FAILURE);
    }
    free(base64_enc_str);
    free(enc);
    pthread_mutex_unlock(&send_mutex);
    return 0;
}

void close_socket() {
    if (multicast_socket) {
        remove_multicast_socket(sock);
    }
    close(sock);
}
