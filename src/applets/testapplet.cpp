/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "testapplet.h"

const bstr* Applet::TestApplet::GetAID() {
	return &aid;
}

Util::Error Applet::TestApplet::APDUExchange(bstr apdu, bstr &result) {
	auto len = apdu[4];
	result.clear();
	result.append(apdu.substr(5, len));
	return Util::Error::NoError;
}
