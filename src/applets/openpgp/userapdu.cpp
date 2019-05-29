/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "userapdu.h"
#include "applets/apduconst.h"
#include "solofactory.h"
#include "applets/openpgp/openpgpfactory.h"
#include "applets/openpgp/apdusecuritycheck.h"

namespace OpenPGP {

Util::Error APDUVerify::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	return Util::Error::WrongCommand;
}

Util::Error APDUVerify::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, bstr dataOut) {
	return Util::Error::WrongCommand;
}

Util::Error APDUChangeReferenceData::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	return Util::Error::WrongCommand;
}

Util::Error APDUChangeReferenceData::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, bstr dataOut) {
	return Util::Error::WrongCommand;
}

Util::Error APDUResetRetryCounter::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	return Util::Error::WrongCommand;
}

Util::Error APDUResetRetryCounter::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, bstr dataOut) {
	return Util::Error::WrongCommand;
}

// Open PGP application v 3.3.1 page 49
Util::Error APDUGetData::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	printf("cla %x ins %x\n", cla, ins);
	if ((cla == 0x00 || cla == 0x0c) &&
		(ins == Applet::APDUcommands::GetData || ins == Applet::APDUcommands::GetData2))
		return Util::Error::NoError;

	return Util::Error::WrongCommand;
}

Util::Error APDUGetData::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, bstr dataOut) {

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::APDUSecurityCheck &security = opgp_factory.GetAPDUSecurityCheck();

	uint16_t object_id = (p1 << 8) + p2;
	auto err = security.DataObjectAccessCheck(object_id, false);
	if (err != Util::Error::NoError)
		return err;

	printf("object id = 0x%04x\n", object_id);


	return Util::Error::NoError;
}

Util::Error APDUPutData::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	return Util::Error::WrongCommand;
}

Util::Error APDUPutData::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, bstr dataOut) {
	return Util::Error::WrongCommand;
}

} // namespace OpenPGP
