/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "applet.h"

namespace Applet {

Util::Error Applet::Init() {
	selected = false;

	return Util::Error::NoError;
}

Util::Error Applet::Select() {
	selected = true;

	return Util::Error::NoError;
}

Util::Error Applet::DeSelect() {
	selected = false;

	return Util::Error::NoError;
}

const bstr* Applet::GetAID() {
	return &aid;
}

Util::Error Applet::APDUExchange(bstr* apdu, bstr* result) {
	result->clear();

	if (!selected)
		return Util::Error::AppletNotSelected;

	return Util::Error::NoError;
}

}