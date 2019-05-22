#include <stdio.h>

#include "device.h"
#include "util.h"
#include "applets/applet.h"

int main(int argc, char * argv[])
{
    uint8_t ccidbuf[1024];
    uint32_t sz;
    printf("Hello CCID/OpenPGP\n");

    ccid_init();

    printf("Init CCID\n");

    while (1)
    {
        if ((sz = ccid_recv(ccidbuf)) > 0)
        {
            printf(">> "); dump_hex(ccidbuf, sz);
        }
    }

    return 0;
}
