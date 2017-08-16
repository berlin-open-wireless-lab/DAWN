#ifndef DAWN_CRYPTO_H
#define DAWN_CRYPTO_H

#include <stdlib.h>

void gcrypt_init();

void gcrypt_set_key_and_iv(char *key, char *iv);

char *gcrypt_encrypt_msg(char *msg, size_t msg_length);

char *gcrypt_decrypt_msg(char *msg, size_t msg_length);


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

void build_decoding_table();

void base64_cleanup();


#endif //DAWN_CRYPTO_H
