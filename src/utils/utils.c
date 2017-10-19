#include "utils.h"
#include "ubus.h"

int hex_to_bin(char ch) {
    if ((ch >= '0') && (ch <= '9')) return ch - '0';
    ch = tolower(ch);
    if ((ch >= 'a') && (ch <= 'f')) return ch - 'a' + 10;
    return -1;
}

int hwaddr_aton(const char *txt, uint8_t *addr) {
    int i;

    for (i = 0; i < ETH_ALEN; i++) {
        int a, b;

        a = hex_to_bin(*txt++);
        if (a < 0) return -1;
        b = hex_to_bin(*txt++);
        if (b < 0) return -1;
        *addr++ = (a << 4) | b;
        if (i < 5 && *txt++ != ':') return -1;
    }

    return 0;
}

int convert_mac(char* in, char* out) {
    int i,j = 0;

    for (i = 0; i < 6; i++) {
        if(in[j+1] != ':' && in[j+1] != '\0') {
            out[3 * i] = toupper(in[j]);
            out[(3 * i) + 1] = toupper(in[j + 1]);
            out[(3 * i) + 2] = in[j + 2];
            j+= 3;
        } else {
            out[3 * i] = '0';
            out[(3 * i) + 1] = toupper(in[j]);
            out[(3 * i) + 2] = toupper(in[j+1]);
            j += 2;
        }
    }
    return 0;
}

