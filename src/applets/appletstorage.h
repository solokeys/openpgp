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

namespace Application {

class ApplicationStorage {
private:
    OpenPGPApplication openPGPApplication;
    TestApplication testApplication;

    std::array<Application*, 2> applets = {&openPGPApplication, &testApplication};

    Application *selectedApplication = nullptr;

public:
    Util::Error SelectApplication(bstr aid, bstr &result);
    Application *GetSelectedApplication();

    OpenPGPApplication &GetOpenPGPApplication();
};

}


#endif /* SRC_APPLETSTORAGE_H_ */
