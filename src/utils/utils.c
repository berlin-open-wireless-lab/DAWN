#include <string.h>
#include <ctype.h>

#include "utils.h"

int string_is_greater(uint8_t *str, uint8_t *str_2) {

    int length_1 = strlen((char *) str);
    int length_2 = strlen((char *) str_2);

    int length = length_1 < length_2 ? length_1 : length_2;

    for (int i = 0; i < length; i++) {
        if (str[i] > str_2[i]) {
            return 1;
        }
        if (str[i] < str_2[i]) {
            return 0;
        }
    }
    return length_1 > length_2;
}

// source: https://elixir.bootlin.com/linux/v4.9/source/lib/hexdump.c#L28
int hex_to_dec(char ch) {
    if ((ch >= '0') && (ch <= '9')) return ch - '0';
    ch = tolower(ch);
    if ((ch >= 'a') && (ch <= 'f')) return ch - 'a' + 10;
    return -1;
}
