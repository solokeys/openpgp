/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#include "apduexecutor.h"
#include "device.h"
#include "applets/apduconst.h"
#include "applets/applet.h"
#include "solofactory.h"

namespace Applet {

void APDUExecutor::SetResultError(bstr& result, Util::Error error) {
	using Util::Error;
	switch (error) {
	case Error::NoError:
		result.appendAPDUres(APDUResponse::OK);
		break;
	case Error::ConditionsNotSatisfied:
    	result.setAPDURes(APDUResponse::ConditionsUseNotSatisfied);
    	break;
	case Error::AppletNotFound:
    	result.setAPDURes(APDUResponse::FileNotFound);
		break;
	case Error::WrongAPDUCLA:
    	result.setAPDURes(APDUResponse::CLAnotSupported);
		break;
	case Error::WrongAPDUINS:
    	result.setAPDURes(APDUResponse::INSnotSupported);
		break;
	case Error::WrongAPDUP1P2:
    	result.setAPDURes(APDUResponse::WrongParametersP1orP2);
    	break;
	case Error::WrongAPDULength:
    	result.setAPDURes(APDUResponse::WrongLength);
		break;
	case Error::WrongAPDUDataLength:
    	result.setAPDURes(APDUResponse::WrongLength);
		break;
	case Error::DataNotFound:
    	result.setAPDURes(APDUResponse::ReferencedDataNotFound);
		break;
	case Error::AccessDenied:
	case Error::WrongPassword:
    	result.setAPDURes(APDUResponse::SecurityStatusNotSatisfied);
		break;
	case Error::ApplicationTerminated:
    	result.setAPDURes(APDUResponse::SelectInTerminationState);
		break;

	case Error::ErrorPutInData:
    	// error already in the data field
		break;
	default:
    	result.setAPDURes(APDUResponse::InternalException);
	}
}

Util::Error APDUExecutor::Execute(bstr apdu, bstr& result) {
	result.clear();

	if (apdu.length() < 4) {
    	result.setAPDURes(APDUResponse::WrongLength);
		return Util::Error::WrongAPDUStructure;
	}

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	AppletStorage &appletStorage = solo.appletStorage;

	APDUStruct decapdu;
	auto errd = decapdu.decode(apdu);
	if (errd != Util::Error::NoError)
		return errd;

	decapdu.printEx(32);

	// select applet
	if (decapdu.ins == APDUcommands::Select) {
		if (decapdu.cla != 0) {
    		result.appendAPDUres(APDUResponse::CLAnotSupported);
    		return Util::Error::WrongAPDUCLA;
		}
		if (decapdu.p1 != 0x04 || decapdu.p2 != 0x00) {
    		result.appendAPDUres(APDUResponse::WrongParametersP1orP2);
    		return Util::Error::WrongAPDUP1P2;
		}

		sapdu.clear();
		sresult.clear();

		auto err = appletStorage.SelectApplet(decapdu.data, result);
    	SetResultError(result, err);
		return err;
	}

    Applet *applet = appletStorage.GetSelectedApplet();
    if (applet != nullptr) {

    	// output chaining (ins == 0xc0) data
    	if (decapdu.ins == 0xc0) {
    		if (sresult.length()) {
    			// calc sending data length
    			uint16_t need_len = decapdu.le;
    			if (need_len == 0) {
    				if (decapdu.extended_apdu)
    					need_len = MIN(0xffff, sresult.length());
    				else
    					need_len = MIN(0xff, sresult.length());
    			}

    			// copy result
    			result.set(sresult.substr(0, need_len));
    			sresult.del(0, need_len);

    			// add 61xx response
    			uint8_t rest_len = 0;
    			if (sresult.length() < 0xff)
    				rest_len = sresult.length() & 0xff;

    			if (sresult.length())
    				result.appendAPDUres(0x6100 + rest_len);
    		} else {
    			// error - don't have data
    			result.setAPDURes(APDUResponse::WrongLength);
    		}
    		return Util::Error::NoError;
    	}

		sapdu.append(decapdu.data);
    	// cla & 0x10 - input chaining apdu
    	if (decapdu.cla & 0x10) {
        	result.setAPDURes(APDUResponse::OK);
    		return Util::Error::NoError;
    	}
    	decapdu.data = sapdu;

    	// clear result buffer
    	sresult.clear();

    	Util::Error err = applet->APDUExchange(decapdu, sresult);
    	SetResultError(sresult, err);
    	printf_device("appdu result: %s\n", Util::GetStrError(err));

      	// clear apdu buffer
		sapdu.clear();

		// some apdu commands (PSO) needs to have 6100 response!!!  tests bug!!!!!
      	if (sresult.length() > 0xfe || (decapdu.ins == 0x2a && sresult.length() > 2)) {
      		if (sresult.length() > 0xff)
      			result.setAPDURes(0x6100);
      		else
      			result.setAPDURes(0x6100 + (sresult.length() & 0xff));
      	} else {
      		result.append(sresult);
      	}

    } else {
    	printf_device("applet not selected.\n");
    	result.setAPDURes(APDUResponse::ConditionsUseNotSatisfied);
    }

    return Util::Error::NoError;
}

}
