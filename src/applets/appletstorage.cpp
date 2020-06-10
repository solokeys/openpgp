/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "appletstorage.h"

namespace Application {

Util::Error ApplicationStorage::SelectApplication(bstr aid, bstr &result) {
	Application *sapp = nullptr;
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
    if (err != Util::Error::NoError &&
        err != Util::Error::ApplicationTerminated)
    	return err;

    selectedApplication = sapp;
	return err;
}

Application* ApplicationStorage::GetSelectedApplication() {
    for(const auto& app: applets) {
    	if (app->Selected())
    		return app;
    }

	return nullptr;
}

OpenPGPApplication& ApplicationStorage::GetOpenPGPApplication() {
	return openPGPApplication;
}

}
