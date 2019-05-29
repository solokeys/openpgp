/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#include <applets/openpgp/apdusecuritycheck.h>
#include "errors.h"

namespace OpenPGP {

Util::Error APDUSecurityCheck::CommandAccessCheck(
		uint8_t ins, uint8_t p1, uint8_t p2) {

	return Util::Error::NoError;
}

Util::Error APDUSecurityCheck::DataObjectAccessCheck(
		uint16_t dataObjectID, bool writeAccess) {

	return Util::Error::NoError;
}

} /* namespace OpenPGP */

