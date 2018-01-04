#ifndef DAWN_CRYPTO_H
#define DAWN_CRYPTO_H

#include <stdlib.h>

char *base_64(const unsigned char *input, int length);

char *unbase_64(unsigned char *input, int length);

void gcrypt_init();

void gcrypt_set_key_and_iv(const char *key, const char *iv);

//char *gcrypt_encrypt_msg(char *msg, size_t msg_length);
char *gcrypt_encrypt_msg(char *msg, size_t msg_length, int *out_length);


char *gcrypt_decrypt_msg(char *msg, size_t msg_length);


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

void build_decoding_table();

void base64_cleanup();

int Base64decode_len(const char *bufcoded);

int Base64encode_len(int len);

int Base64encode(char *encoded, const char *string, int len);

int Base64decode(char *bufplain, const char *bufcoded);


#endif //DAWN_CRYPTO_H
