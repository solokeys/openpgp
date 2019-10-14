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

Util::Error Applet::TestApplet::APDUExchange(APDUStruct &apdu, bstr &result) {
	result.set(apdu.data);
	return Util::Error::NoError;
}
