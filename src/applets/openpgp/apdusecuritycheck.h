/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_APPLETS_OPENPGP_APDUSECURITYCHECK_H_
#define SRC_APPLETS_OPENPGP_APDUSECURITYCHECK_H_

#include <stdint.h>
#include <stddef.h>

#include "errors.h"
#include "applets/openpgpapplet.h"

namespace OpenPGP {

	// OpenPGP application v3.3.1 page 35
	class APDUSecurityCheck {
	private:
		Applet::OpenPGPApplet *openPGPApplet;
	public:
		APDUSecurityCheck(Applet::OpenPGPApplet *applet):openPGPApplet(applet){};

		Util::Error CommandAccessCheck(uint8_t ins, uint8_t p1, uint8_t p2);
		Util::Error DataObjectAccessCheck(uint16_t dataObjectID, bool writeAccess);
};

} /* namespace OpenPGP */

#endif /* SRC_APPLETS_OPENPGP_APDUSECURITYCHECK_H_ */
