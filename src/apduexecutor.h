/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_APDUEXECUTOR_H_
#define SRC_APDUEXECUTOR_H_

#include <cstdint>
#include <cstdlib>
#include "opgputil.h"
#include "errors.h"
#include "applets/appletstorage.h"
#include "applets/apduconst.h"

namespace Applet {

class APDUExecutor {
private:
	uint8_t apduBuffer[1130];
	uint8_t resultBuffer[1130];
	bstr sapdu{apduBuffer, 0, sizeof(apduBuffer)};
	bstr sresult{resultBuffer, 0, sizeof(resultBuffer)};

	void SetResultError(bstr &result, Util::Error error);
public:
	Util::Error Execute(bstr apdu, bstr &result);
};

} /* namespace OpenPGP */

#endif /* SRC_APDUEXECUTOR_H_ */
