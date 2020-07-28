#include <string.h>
#include <ctype.h>

#include "utils.h"

int string_is_greater(char *str, char *str_2) {

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
