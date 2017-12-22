#ifndef __DAWN_UTILS_H
#define __DAWN_UTILS_H

#include <stdint.h>
#include <ctype.h>

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define STR2MAC(a) &(a)[0], &(a)[1], &(a)[2], &(a)[3], &(a)[4], &(a)[5]

#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"

int hex_to_bin(char ch);

int hwaddr_aton(const char *txt, uint8_t *addr);

int convert_mac(char *in, char *out);

void write_mac_to_file(char* path, uint8_t addr[]);

#endif