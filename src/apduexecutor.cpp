/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#include <apduexecutor.h>
#include "applets/apduconst.h"

namespace Applet {

Util::Error APDUExecutor::Execute(bstr apdu, bstr& result) {


    Applet *applet = appletStorage.GetSelectedApplet();
    if (applet != nullptr) {

    	Util::Error err = applet->APDUExchange(apdu, result);
    	if (err == Util::Error::NoError) {


    	} else {
        	printf("appdu exchange error: %s\n", Util::GetStrError(err));

        	//switch (err) {

        	//}

    	}

    } else {
    	printf("applet not selected.\n");
    	result.setAPDURes(APDUResponse::ConditionsUseNotSatisfied);
    }



    return Util::NoError;
}

}

