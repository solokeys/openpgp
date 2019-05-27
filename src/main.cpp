#include <stdio.h>

#include "device.h"
#include "util.h"
#include "solofactory.h"
#include "util.h"
#include "applets/applet.h"
#include "applets/apduconst.h"

int main(int argc, char * argv[])
{
	uint8_t ccidbuf[1024];
    uint32_t sz;
    printf("Hello CCID/OpenPGP\n");

    ccid_init();

    printf("Init CCID\n");

    Factory::SoloFactory factory;
    Applet::APDUExecutor executor = factory.GetAPDUExecutor();

    printf("OpenPGP factory OK.\n");


	uint8_t result[1024] = {0};
    while (1)
    {
    	auto resstr = bstr(result);
        if ((sz = ccid_recv(ccidbuf)) > 0)
        {
            printf(">> "); dump_hex(ccidbuf, sz);

        	// pack("<BiBBBH", msg_type, len(data), slot, seq, rsv, param) + data
        	if (ccidbuf[0] != 0x6f)
        		printf("warning: msg_type not 6f. 0x%02x\n", ccidbuf[0]);
        	if (ccidbuf[1] + 10U != sz)
        		printf("warning: length error. data len %d pck len %d", sz, ccidbuf[1]);

        	auto apdu = bstr(&ccidbuf[10], sz - 10);
            executor.Execute(apdu, resstr);

            printf("<< "); dump_hex(resstr);
            ccid_send(resstr.uint8Data(), resstr.length());

        }
    }

    return 0;
}
