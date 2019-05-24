/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "openpgpapplet.h"

namespace Applet {

OpenPGPApplet::OpenPGPApplet() : Applet() {
	config.state = LifeCycleState::Created;
	state.pw1Authenticated = false;
	state.pw3Authenticated = false;
}

const bstr* OpenPGPApplet::GetAID() {
	return &aid;
}

Util::Error OpenPGPApplet::APDUExchange(bstr apdu, bstr result) {
	result.clear();

	printf("openpgp applet here...\n");
	dump_hex(apdu);
	result.append(0xaa);
	uint8_t d[3] = {0x01, 0x02, 0x03};
	result.append(d, 3);
	result.append("\xa0\x00\xa1"_bstr);
	dump_hex(result);

	if (!selected)
		return Util::Error::AppletNotSelected;




	return Util::Error::NoError;
}

}
