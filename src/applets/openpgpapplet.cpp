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

Util::Error OpenPGPApplet::APDUExchange(bstr* apdu, bstr* result) {
	result->clear();

	if (!selected)
		return Util::Error::AppletNotSelected;




	return Util::Error::NoError;
}

}
