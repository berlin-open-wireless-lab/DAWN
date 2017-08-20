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
char *gcrypt_encrypt_msg(char *msg, size_t msg_length, int* out_length) {
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
    *out_length = msg_length;
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

static const unsigned char pr2six[256] =
        {
                /* ASCII table */
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
                64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
                15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
                64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
        };

int Base64decode_len(const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

int Base64decode(char *bufplain, const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
        *(bufout++) =
                (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
        *(bufout++) =
                (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        *(bufout++) =
                (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
        *(bufout++) =
                (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
        *(bufout++) =
                (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
        *(bufout++) =
                (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    *(bufout++) = '\0';
    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

static const char basis_64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64encode_len(int len)
{
    return ((len + 2) / 3 * 4) + 1;
}

int Base64encode(char *encoded, const char *string, int len)
{
    int i;
    char *p;

    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
        *p++ = basis_64[(string[i] >> 2) & 0x3F];
        *p++ = basis_64[((string[i] & 0x3) << 4) |
                        ((int) (string[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
                        ((int) (string[i + 2] & 0xC0) >> 6)];
        *p++ = basis_64[string[i + 2] & 0x3F];
    }
    if (i < len) {
        *p++ = basis_64[(string[i] >> 2) & 0x3F];
        if (i == (len - 1)) {
            *p++ = basis_64[((string[i] & 0x3) << 4)];
            *p++ = '=';
        }
        else {
            *p++ = basis_64[((string[i] & 0x3) << 4) |
                            ((int) (string[i + 1] & 0xF0) >> 4)];
            *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
        }
        *p++ = '=';
    }

    *p++ = '\0';
    return p - encoded;
}


