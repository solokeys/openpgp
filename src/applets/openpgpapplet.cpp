/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "openpgpapplet.h"
#include "apduconst.h"
#include "openpgp/apdusecuritycheck.h"

namespace Applet {

OpenPGPApplet::OpenPGPApplet(Factory::SoloFactory &solo_factory) : Applet() {
	config.state = LifeCycleState::Created;
	state.pw1Authenticated = false;
	state.pw3Authenticated = false;
}

const bstr* OpenPGPApplet::GetAID() {
	return &aid;
}

Util::Error OpenPGPApplet::APDUExchange(bstr apdu, bstr &result) {
	result.clear();

	if (!selected)
		return Util::Error::AppletNotSelected;

	printf("0>"); dump_hex(apdu);

	//auto cla = apdu[0];
	auto ins = apdu[1];
	//auto p1 = apdu[2];
	//auto p2 = apdu[3];
	//auto len = apdu[4];
//	auto data = bstr(apdu.substr(5, len));

	switch (ins) {
	case APDUcommands::GetData:
		break;

	default:
		return Util::Error::WrongCommand;
	}

/*	result.append(0xaa);
	uint8_t d[3] = {0x01, 0x02, 0x03};
	result.append(d, 3);
	result.append("\xa0\x00\xa1"_bstr);
*/
	printf("0<"); dump_hex(result);

	return Util::Error::NoError;
}

}
