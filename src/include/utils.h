#ifndef __DAWN_UTILS_H
#define __DAWN_UTILS_H

#include <stdint.h>

/**
 * Convert char to binary.
 * @param ch
 * @return
 */
int hex_to_dec(char ch);

/**
 * Check if a string is greater than another one.
 * @param str
 * @param str_2
 * @return
 */
int string_is_greater(uint8_t *str, uint8_t *str_2);

#endif