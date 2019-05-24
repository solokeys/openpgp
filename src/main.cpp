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
    Applet::AppletStorage *applet_storage = factory.GetAppletStorage();
    if (applet_storage == nullptr) {
    	printf("factory initialization error");
    	return 1;
    }

    printf("OpenPGP factory OK.\n");


	uint8_t result[1024] = {0};
    while (1)
    {
    	auto resstr = bstr(result);
        if ((sz = ccid_recv(ccidbuf)) > 0)
        {
            printf(">> "); dump_hex(ccidbuf, sz);
            Applet::Applet *applet = applet_storage->GetSelectedApplet();
            if (applet != nullptr) {

            	//printf("typesize %d\n", bstr(result).typesize());

            	Util::Error err = applet->APDUExchange(bstr(ccidbuf, sz), resstr);
            	if (err == Util::Error::NoError) {


            	} else {
                	printf("appdu exchange error.\n");

                	//switch (err) {

                	//}

            	}

            } else {
            	printf("applet not selected.\n");
            	resstr.clear();
            	resstr.appendAPDUres(Applet::APDUResponse::ConditionsUseNotSatisfied);
            }

            printf("<< "); dump_hex(resstr);
            //ccid_send(buf, size);

        }
    }

    return 0;
}
