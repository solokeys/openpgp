/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "applet.h"

namespace Application {

Application::~Application() {
}

Util::Error Application::Init() {
	selected = false;

	return Util::Error::NoError;
}

Util::Error Application::Select(bstr &result) {
	result.clear();
	selected = true;

	return Util::Error::NoError;
}

Util::Error Application::DeSelect() {
	selected = false;

	return Util::Error::NoError;
}

bool Application::Selected() {
	return selected;
}

const bstr* Application::GetAID() {
	return &aid;
}

Util::Error Application::APDUExchange(APDUStruct &apdu, bstr &result) {
	result.clear();

	if (!selected)
		return Util::Error::AppletNotSelected;

	return Util::Error::NoError;
}

}
