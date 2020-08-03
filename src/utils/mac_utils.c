#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "utils.h"
#include "mac_utils.h"

// source: https://elixir.bootlin.com/linux/v4.9/source/lib/hexdump.c#L28
// based on: hostapd src/utils/common.c
int hwaddr_aton(const char* txt, uint8_t* addr) {
    int i;

    for (i = 0; i < ETH_ALEN; i++) {
        int a = 0;
        char ch = *txt++;

        if ((ch >= '0') && (ch <= '9'))
            a = ch - '0';
        else if ((ch >= 'a') && (ch <= 'f'))
            a = ch - 'a' + 10;
        else if ((ch >= 'A') && (ch <= 'F'))
            a = ch - 'A' + 10;
        else
            return -1;

        ch = *txt++;
        a *= 16;

        if ((ch >= '0') && (ch <= '9'))
            a += ch - '0';
        else if ((ch >= 'a') && (ch <= 'f'))
            a += ch - 'a' + 10;
        else if ((ch >= 'A') && (ch <= 'F'))
            a += ch - 'A' + 10;
        else
            return -1;

        *addr++ = a;

        // TODO: Should NUL terminator be checked for? Is aa:bb:cc:dd:ee:ff00 valid input?
        if (i != (ETH_ALEN - 1) && *txt++ != ':')
            return -1;
    }

    return 0;
}

void write_mac_to_file(char* path, struct dawn_mac addr) {
    FILE* f = fopen(path, "a");
    if (f == NULL) {
        fprintf(stderr, "Error opening mac file!\n");

        // TODO: Should this be an exit()?
        exit(1);
    }

    char mac_buf[20];
    sprintf(mac_buf, MACSTR, MAC2STR(addr.u8));

    fprintf(f, "%s\n", mac_buf);

    fclose(f);
}
