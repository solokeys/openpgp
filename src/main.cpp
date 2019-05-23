#include <stdio.h>

#include "device.h"
#include "util.h"
#include "solofactory.h"
#include "applets/applet.h"

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


    while (1)
    {
        if ((sz = ccid_recv(ccidbuf)) > 0)
        {
            printf(">> "); dump_hex(ccidbuf, sz);
            Applet::Applet *applet = applet_storage->GetSelectedApplet();
            if (applet != nullptr) {
/*            	Util::Error err = applet.APDUExchange();
            	if (err != Util::Error::NoError) {

            	} else {
                	printf("appdu exchange error.\n");

                	switch (err) {

                	}

            	}
*/
            } else {
            	printf("applet not selected.\n");
            	// result=6985
            }

            //ccid_send(buf, size);

        }
    }

    return 0;
}
