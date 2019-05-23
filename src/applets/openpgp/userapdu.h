/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef SRC_APPLETS_OPENPGP_USERAPDU_H_
#define SRC_APPLETS_OPENPGP_USERAPDU_H_

#include "errors.h"
#include "applets/apducommand.h"

namespace OpenPGP {

	class APDUVerify : Applet::APDUCommand {
	public:
		virtual Util::Error Check(uint8_t cla, uint8_t ins);
		virtual Util::Error Process(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, bstr data, bstr dataOut);
	};

	class APDUChangeReferenceData : Applet::APDUCommand {
	public:
		virtual Util::Error Check(uint8_t cla, uint8_t ins);
		virtual Util::Error Process(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, bstr data, bstr dataOut);
	};

	class APDUResetRetryCounter : Applet::APDUCommand {
	public:
		virtual Util::Error Check(uint8_t cla, uint8_t ins);
		virtual Util::Error Process(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, bstr data, bstr dataOut);
	};

	class APDUGetData : Applet::APDUCommand {
	public:
		virtual Util::Error Check(uint8_t cla, uint8_t ins);
		virtual Util::Error Process(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, bstr data, bstr dataOut);
	};

	class APDUPutData : Applet::APDUCommand {
	public:
		virtual Util::Error Check(uint8_t cla, uint8_t ins);
		virtual Util::Error Process(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, bstr data, bstr dataOut);
	};

}

#endif /* SRC_APPLETS_OPENPGP_USERAPDU_H_ */
