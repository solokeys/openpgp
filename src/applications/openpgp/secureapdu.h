/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef SRC_APPLETS_OPENPGP_SECUREAPDU_H_
#define SRC_APPLETS_OPENPGP_SECUREAPDU_H_

#include <string_view>
#include "errors.h"
#include "applications/apducommand.h"

namespace OpenPGP {

	class APDUActivateFile : public Application::APDUCommand {
	public:
		virtual Util::Error Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2);
		virtual Util::Error Process(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr &dataOut);
		virtual std::string_view GetName();
	};

	class APDUTerminateDF : public Application::APDUCommand {
	public:
		virtual Util::Error Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2);
		virtual Util::Error Process(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr &dataOut);
		virtual std::string_view GetName();
	};

	class APDUManageSecurityEnvironment : public Application::APDUCommand {
	public:
		virtual Util::Error Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2);
		virtual Util::Error Process(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr &dataOut);
		virtual std::string_view GetName();
	};


	class APDUSoloReboot : public Application::APDUCommand {
	public:
		virtual Util::Error Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2);
		virtual Util::Error Process(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr &dataOut);
		virtual std::string_view GetName();
	};
}

#endif /* SRC_APPLETS_OPENPGP_SECUREAPDU_H_ */
