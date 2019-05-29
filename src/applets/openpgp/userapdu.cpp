/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "userapdu.h"

namespace OpenPGP {

Util::Error APDUVerify::Check(uint8_t cla, uint8_t ins) {
	return Util::Error::WrongCommand;
}

Util::Error APDUVerify::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, bstr dataOut) {
	return Util::Error::WrongCommand;
}

Util::Error APDUChangeReferenceData::Check(uint8_t cla, uint8_t ins) {
	return Util::Error::WrongCommand;
}

Util::Error APDUChangeReferenceData::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, bstr dataOut) {
	return Util::Error::WrongCommand;
}

Util::Error APDUResetRetryCounter::Check(uint8_t cla, uint8_t ins) {
	return Util::Error::WrongCommand;
}

Util::Error APDUResetRetryCounter::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, bstr dataOut) {
	return Util::Error::WrongCommand;
}

Util::Error APDUGetData::Check(uint8_t cla, uint8_t ins) {
	return Util::Error::WrongCommand;
}

Util::Error APDUGetData::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, bstr dataOut) {
	return Util::Error::WrongCommand;
}

Util::Error APDUPutData::Check(uint8_t cla, uint8_t ins) {
	return Util::Error::WrongCommand;
}

Util::Error APDUPutData::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, bstr dataOut) {
	return Util::Error::WrongCommand;
}

} // namespace OpenPGP
