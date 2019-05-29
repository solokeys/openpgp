/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "appletstorage.h"

namespace Applet {

Util::Error AppletStorage::SelectApplet(bstr aid, bstr &result) {
	Applet *sapp = nullptr;
    for(const auto& app: applets) {
    	if (*app->GetAID() == aid) {
    		sapp = app;
    		break;
    	}
    }

    if (sapp == nullptr)
    	return Util::Error::AppletNotFound;

    for(const auto& app: applets)
    	app->DeSelect();

    auto err = sapp->Select(result);
    if (err != Util::Error::NoError)
    	return err;

    selectedApplet = sapp;
	return Util::Error::NoError;
}

Applet* AppletStorage::GetSelectedApplet() {
    for(const auto& app: applets) {
    	if (app->Selected())
    		return app;
    }

	return nullptr;
}

OpenPGPApplet& AppletStorage::GetOpenPGPApplet() {
	return openPGPApplet;
}

}
