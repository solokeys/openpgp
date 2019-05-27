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
    	auto resstr = bstr(&result[10], 0, sizeof(result) - 10);
        if ((sz = ccid_recv(ccidbuf)) > 0)
        {
            printf(">> "); dump_hex(ccidbuf, sz);

        	// pack("<BiBBBH", msg_type, len(data), slot, seq, rsv, param) + data
        	if (ccidbuf[0] != 0x6f)
        		printf("warning: msg_type not 6f. 0x%02x\n", ccidbuf[0]);
        	size_t len = ccidbuf[1] + (ccidbuf[2] << 8) + (ccidbuf[3] << 16) + (ccidbuf[4] << 24);
        	if (len + 10U != sz)
        		printf("warning: length error. data len %d pck len %d", sz, ccidbuf[1]);

        	auto apdu = bstr(&ccidbuf[10], sz - 10);
            executor.Execute(apdu, resstr);

            printf("<< "); dump_hex(resstr);

            // msg_type = msg[0]; data_len = msg[1] + (msg[2] << 8) + (msg[3] << 16) + (msg[4] << 24)
            // slot = msg[5]; seq = msg[6]; status = msg[7]; error = msg[8]; chain = msg[9]; data = msg[10:]
            result[0] = ccidbuf[0];
            size_t rlen = resstr.length();
            result[1] = rlen & 0xff;
            result[2] = (rlen >> 8) & 0xff;
            result[3] = (rlen >> 16) & 0xff;
            result[4] = (rlen >> 24) & 0xff;
            // slot
            result[5] = ccidbuf[5];
            // seq
            result[6] = ccidbuf[6];

            ccid_send(result, rlen + 10);

        }
    }

    return 0;
}
