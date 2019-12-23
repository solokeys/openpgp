#include <stdio.h>
#include <cstdlib>
#include <chrono>
#include <thread>

#include "device.h"
#include "solofactory.h"
#include "util.h"
#include "applets/apduconst.h"
#include "ccid.h"

#define USBIP_MODE

Applet::APDUExecutor *fexecutor;
void exchangeFunc(uint8_t *datain, size_t datainlen, uint8_t *dataout, size_t *outlen) {
	*outlen = 0;

	uint8_t apdu_result[4096] = {0};
	auto resstr = bstr(apdu_result, 0, sizeof(apdu_result) - 10);
	auto apdu = bstr(datain, datainlen);

	printf("================\n");
	printf("a>> "); dump_hex(apdu);
    fexecutor->Execute(apdu, resstr);
    printf("a<< "); dump_hex(resstr);

    *outlen = resstr.length();
    memcpy(dataout, apdu_result, *outlen);
}

int main(int argc, char * argv[])
{
	uint8_t ccidbuf[350];
    uint32_t sz;
    printf("------------------\n");
    printf("OpenPGP Starting...\n");

    hwinit();
    printf("Init hardware ok\n");

    ccid_init();
    printf("Init CCID ok\n");

    Factory::SoloFactory &factory = Factory::SoloFactory::GetSoloFactory();
    factory.Init();  // init solokey
    Applet::APDUExecutor executor = factory.GetAPDUExecutor();
    fexecutor = &executor;

    printf("OpenPGP factory ok.\n");

#ifdef USBIP_MODE
    printf("USBIP mode.\n");
    std::thread t([] {
    		std::this_thread::sleep_for(std::chrono::seconds(2));
    		// needs too add NOPASSWD line to /etc/sudoers file!!!
    		int res = system("sudo usbip attach -r 127.0.0.1 -b 1-1");
    		if (!res)
    			printf("attach ok\n");
    });
    //t.detach();

    usbip_ccid_start(&exchangeFunc);
    return 0;
#endif

	uint8_t result[300] = {0};
    while (1)
    {
    	auto resstr = bstr(&result[10], 0, sizeof(result) - 10);
        if ((sz = ccid_recv(ccidbuf)) > 0)
        {
        	// pack("<BiBBBH", msg_type, len(data), slot, seq, rsv, param) + data
        	if (ccidbuf[0] != 0x6f)
        		printf("warning: msg_type not 6f. 0x%02x\n", ccidbuf[0]);
        	size_t len = ccidbuf[1] + (ccidbuf[2] << 8) + (ccidbuf[3] << 16) + (ccidbuf[4] << 24);
        	if (len + 10U != sz)
        		printf("warning: length error. data len %d pck len %d", sz, ccidbuf[1]);

        	auto apdu = bstr(&ccidbuf[10], sz - 10);
            printf(">> "); dump_hex(apdu);

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
