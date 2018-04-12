#ifndef __DAWN_UTILS_H
#define __DAWN_UTILS_H

#include <stdint.h>
#include <ctype.h>

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define STR2MAC(a) &(a)[0], &(a)[1], &(a)[2], &(a)[3], &(a)[4], &(a)[5]

#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"

/**
 * Convert char to binary.
 * @param ch
 * @return
 */
int hex_to_bin(char ch);

/**
 * Convert mac adress string to mac adress.
 * @param txt
 * @param addr
 * @return
 */
int hwaddr_aton(const char *txt, uint8_t *addr);

/**
 * Convert mac to use big characters.
 * @param in
 * @param out
 * @return
 */
int convert_mac(char *in, char *out);

/**
 * Write mac to a file.
 * @param path
 * @param addr
 */
void write_mac_to_file(char *path, uint8_t addr[]);

/**
 * Check if a string is greater than another one.
 * @param str
 * @param str_2
 * @return
 */
int string_is_greater(uint8_t *str, uint8_t *str_2);

#endif