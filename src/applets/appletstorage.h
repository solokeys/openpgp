/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_APPLETSTORAGE_H_
#define SRC_APPLETSTORAGE_H_

#include <cstdint>
#include <array>

#include "applet.h"
#include "errors.h"
#include "applet.h"
#include "openpgpapplet.h"
#include "testapplet.h"

namespace Applet {

class AppletStorage {
private:
	OpenPGPApplet openPGPApplet;
	TestApplet testApplet;

	std::array<Applet*, 2> applets = {&openPGPApplet, &testApplet};

	Applet *selectedApplet = nullptr;

public:
	Util::Error SelectApplet(bstr aid, bstr &result);
	Applet *GetSelectedApplet();

	OpenPGPApplet &GetOpenPGPApplet();
};

}


#endif /* SRC_APPLETSTORAGE_H_ */
