/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "apducommand.h"
#include "errors.h"

namespace Application {

APDUCommand::~APDUCommand() {
}

Util::Error APDUCommand::Check(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2) {

	return Util::Error::WrongCommand;
}

Util::Error APDUCommand::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, uint8_t le, bstr &dataOut) {

	return Util::Error::WrongCommand;
}

std::string_view APDUCommand::GetName() {
	using namespace std::literals;
	return "base class"sv;
}

} // namespace Applet
