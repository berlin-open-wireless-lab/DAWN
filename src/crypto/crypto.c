#include "crypto.h"

#include <stdio.h>
#include <gcrypt.h>
#include <stdint.h>

#define GCRY_CIPHER GCRY_CIPHER_AES128   // Pick the cipher here
#define GCRY_C_MODE GCRY_CIPHER_MODE_ECB // Pick the cipher mode here

gcry_error_t gcry_error_handle;
gcry_cipher_hd_t gcry_cipher_hd;

void gcrypt_init() {
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "gcrypt: library version mismatch");
    }
    gcry_error_t err = 0;
    err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    err |= gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    err |= gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    err |= gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (err) {
        fprintf(stderr, "gcrypt: failed initialization");
    }
}

void gcrypt_set_key_and_iv(char *key, char *iv) {
    size_t keylen = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
    size_t blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER);

    gcry_error_handle = gcry_cipher_open(
            &gcry_cipher_hd, // gcry_cipher_hd_t *
            GCRY_CIPHER,   // int
            GCRY_C_MODE,   // int
            0);
    if (gcry_error_handle) {
        fprintf(stderr, "gcry_cipher_open failed:  %s/%s\n",
                gcry_strsource(gcry_error_handle),
                gcry_strerror(gcry_error_handle));
        return;
    }

    gcry_error_handle = gcry_cipher_setkey(gcry_cipher_hd, key, keylen);
    if (gcry_error_handle) {
        fprintf(stderr, "gcry_cipher_setkey failed:  %s/%s\n",
                gcry_strsource(gcry_error_handle),
                gcry_strerror(gcry_error_handle));
        return;
    }

    gcry_error_handle = gcry_cipher_setiv(gcry_cipher_hd, iv, blklen);
    if (gcry_error_handle) {
        fprintf(stderr, "gcry_cipher_setiv failed:  %s/%s\n",
                gcry_strsource(gcry_error_handle),
                gcry_strerror(gcry_error_handle));
        return;
    }
}

// free out buffer after using!
char *gcrypt_encrypt_msg(char *msg, size_t msg_length) {
    if (0U != (msg_length & 0xfU))
        msg_length += 0x10U - (msg_length & 0xfU);

    //msg_length++; // increase because of \0
    char *out = malloc(msg_length);
    gcry_error_handle = gcry_cipher_encrypt(
            gcry_cipher_hd, // gcry_cipher_hd_t
            out,    // void *
            msg_length,    // size_t
            msg,    // const void *
            msg_length);   // size_t
    if (gcry_error_handle) {
        printf("gcry_cipher_encrypt failed:  %s/%s\n",
               gcry_strsource(gcry_error_handle),
               gcry_strerror(gcry_error_handle));
        return NULL;
    }
    return out;
}

// free out buffer after using!
char *gcrypt_decrypt_msg(char *msg, size_t msg_length) {
    if (0U != (msg_length & 0xfU))
        msg_length += 0x10U - (msg_length & 0xfU);

    char *out_buffer = malloc(msg_length);
    gcry_error_handle = gcry_cipher_decrypt(
            gcry_cipher_hd, // gcry_cipher_hd_t
            out_buffer,    // void *
            msg_length,    // size_t
            msg,    // const void *
            msg_length);   // size_t
    if (gcry_error_handle) {
        printf("gcry_cipher_encrypt failed:  %s/%s\n",
               gcry_strsource(gcry_error_handle),
               gcry_strerror(gcry_error_handle));
        free(out_buffer);
        return NULL;
    }
    char *out = malloc(strlen(out_buffer) + 1);
    strcpy(out, out_buffer);
    free(out_buffer);
    return out;
}

/* Base Encoding
 *  Source: https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
*/



static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char) data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char) data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char) data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char) data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char) data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char) data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char) data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
                          + (sextet_b << 2 * 6)
                          + (sextet_c << 1 * 6)
                          + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}


void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_cleanup() {
    free(decoding_table);
}


