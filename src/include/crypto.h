#ifndef DAWN_CRYPTO_H
#define DAWN_CRYPTO_H

#include <stdlib.h>

void gcrypt_init();

void gcrypt_set_key_and_iv(char *key, char *iv);

char *gcrypt_encrypt_msg(char *msg, size_t msg_length);

char *gcrypt_decrypt_msg(char *msg, size_t msg_length);

#endif //DAWN_CRYPTO_H
