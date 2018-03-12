#include "utils.h"
#include "ubus.h"

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
int hex_to_bin(char ch) {
    if ((ch >= '0') && (ch <= '9')) return ch - '0';
    ch = tolower(ch);
    if ((ch >= 'a') && (ch <= 'f')) return ch - 'a' + 10;
    return -1;
}

// based on: hostapd src/utils/common.c
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

int convert_mac(char *in, char *out) {
    int i, j = 0;

    for (i = 0; i < 6; i++) {
        if (in[j + 1] != ':' && in[j + 1] != '\0') {
            out[3 * i] = toupper(in[j]);
            out[(3 * i) + 1] = toupper(in[j + 1]);
            out[(3 * i) + 2] = in[j + 2];
            j += 3;
        } else {
            out[3 * i] = '0';
            out[(3 * i) + 1] = toupper(in[j]);
            out[(3 * i) + 2] = toupper(in[j + 1]);
            j += 2;
        }
    }
    return 0;
}

void write_mac_to_file(char *path, uint8_t addr[]) {
    FILE *f = fopen(path, "a");
    if (f == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    char mac_buf[20];
    sprintf(mac_buf, MACSTR, MAC2STR(addr));

    fprintf(f, "%s\n", mac_buf);

    fclose(f);
}