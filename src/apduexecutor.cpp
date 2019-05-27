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
	result.clear();

	if (apdu.length() < 5) {
    	result.setAPDURes(APDUResponse::WrongLength);
		return Util::Error::WrongAPDUStructure;
	}

	if (apdu.length() != apdu[4] + 5U && apdu.length() != apdu[4] + 6U) {
    	result.setAPDURes(APDUResponse::WrongLength);
		return Util::Error::WrongAPDULength;
	}

    Applet *applet = appletStorage.GetSelectedApplet();
    if (applet != nullptr) {

    	Util::Error err = applet->APDUExchange(apdu, result);
    	if (err == Util::Error::NoError) {
    		result.appendAPDUres(APDUResponse::OK);

    	} else {
        	printf("appdu exchange error: %s\n", Util::GetStrError(err));

        	using Util::Error;
        	switch (err) {
        	case Error::WrongAPDUCLA:
            	result.setAPDURes(APDUResponse::CLAnotSupported);
        		break;
        	case Error::WrongAPDUINS:
            	result.setAPDURes(APDUResponse::INSnotSupported);
        		break;
        	case Error::WrongAPDUP1P2:
            	result.setAPDURes(APDUResponse::WrongParametersP1orP2);
        		break;

        	default:
            	result.setAPDURes(APDUResponse::InternalException);
        	}
    	}
    } else {
    	printf("applet not selected.\n");
    	result.setAPDURes(APDUResponse::ConditionsUseNotSatisfied);
    }

    return Util::NoError;
}

}

