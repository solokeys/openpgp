/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#include <apduexecutor.h>
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


	case Error::ErrorPutInData:
    	// error already in the data field
		break;
	default:
    	result.setAPDURes(APDUResponse::InternalException);
	}
}

Util::Error APDUExecutor::Execute(bstr apdu, bstr& result) {
	result.clear();

	if (apdu.length() < 5) {
    	result.setAPDURes(APDUResponse::WrongLength);
		return Util::Error::WrongAPDUStructure;
	}

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	AppletStorage &appletStorage = solo.appletStorage;

	auto cla = apdu[0];
	auto ins = apdu[1];
	auto p1 = apdu[2];
	auto p2 = apdu[3];
	auto len = apdu[4];

	// with Le and without data
	uint8_t le = 0xff;
	if (apdu.length() == 5 && len > 0) {
		le = apdu[4];
		len = 0;
	}
	// Le at the end
	if (apdu.length() != len + 6U)
		le = apdu[apdu.length() - 1];

	auto data = bstr(apdu.substr(5, len));

	// apdu length check
	if (apdu.length() != len + 5U && apdu.length() != len + 6U) {
    	result.setAPDURes(APDUResponse::WrongLength);
		return Util::Error::WrongAPDULength;
	}

	// select applet
	if (ins == APDUcommands::Select) {
		if (cla != 0) {
    		result.appendAPDUres(APDUResponse::CLAnotSupported);
    		return Util::Error::WrongAPDUCLA;
		}
		if (p1 != 0x04 || p2 != 0x00) {
    		result.appendAPDUres(APDUResponse::WrongParametersP1orP2);
    		return Util::Error::WrongAPDUP1P2;
		}

		sapdu.clear();
		sresult.clear();

		auto err = appletStorage.SelectApplet(data, result);
    	SetResultError(result, err);
		return err;
	}

    Applet *applet = appletStorage.GetSelectedApplet();
    if (applet != nullptr) {

    	// output chaining (ins == 0xc0) data
    	if (ins == 0xc0) {
    		if (sresult.length()) {
    			uint8_t need_len = le;
    			if (need_len == 0)
    				need_len = MIN(0xff, sresult.length());

    			result.set(sresult.substr(0, need_len));
    			sresult.del(0, need_len);

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

    	// cla & 0x10 - input chaining apdu
    	if (cla & 0x10) {
    		if (sapdu.length() == 0) {
    			// first chaining packet
    			sapdu.append(apdu);
        		*sapdu.uint8Data() = *sapdu.uint8Data() & !0x10;
    		} else {
    			// we have data in chaining buffer
    			// check if it the same apdu (ins, p1, p2 the same)
    			if (sapdu.substr(1, 3) == apdu.substr(1, 3)) {
    				// the same apdu - append data only
    				sapdu.append(apdu.substr(5, apdu.length() - 5));
    			} else {
    				// not the same apdu - lost packet error...
    				printf("lost packet... "); dump_hex(sapdu.substr(0, 4));
    	    		sapdu.clear();
    	    		sapdu.append(apdu);
    			}
    		}
        	result.setAPDURes(APDUResponse::OK);
    		return Util::Error::NoError;
    	} else {
    		if (sapdu.length() > 0) {
    			// we have data in chaining buffer
    			// check if it the same apdu (ins, p1, p2 the same)
    			if (sapdu.substr(1, 3) == apdu.substr(1, 3)) {
    				sapdu.append(apdu.substr(5, apdu.length() - 5));
    			} else {
    				printf("lost packet... "); dump_hex(sapdu.substr(0, 4));
    				sapdu.clear();
        			sapdu.append(apdu);
    			}
    			sapdu.uint8Data()[4] = 0xff;
    			dump_hex(sapdu);
    		} else {
    			// no chaining
    			sapdu.append(apdu);
    		}
    	}

    	// TODO: add Le calculation
    	bstr data;
    	if (apdu.length() > 5)
    		data = sapdu.substr(5, sapdu.length() - 5);

    	// clear result buffer
    	sresult.clear();

    	Util::Error err = applet->APDUExchange(sapdu.substr(0, 4), data, sresult);
    	SetResultError(sresult, err);
      	printf("appdu exchange result: %s\n", Util::GetStrError(err));

      	// clear apdu buffer
		sapdu.clear();

		// TODO
      	if (sresult.length() > 0xfe) {
      		//result.append(sresult);
      		result.setAPDURes(0x6100);
      	} else {
      		result.append(sresult);
      	}

    } else {
    	printf("applet not selected.\n");
    	result.setAPDURes(APDUResponse::ConditionsUseNotSatisfied);
    }

    return Util::NoError;
}

}

