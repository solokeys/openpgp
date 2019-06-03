/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "cryptoapdu.h"
#include "applets/apduconst.h"
#include "solofactory.h"
#include "applets/openpgp/openpgpfactory.h"
#include "applets/openpgpapplet.h"
#include "applets/openpgp/apdusecuritycheck.h"
#include "applets/openpgp/openpgpconst.h"

namespace OpenPGP {

Util::Error APDUGetChallenge::Check(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2) {
	return Util::Error::WrongCommand;
}

Util::Error APDUGetChallenge::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, bstr& dataOut) {
	return Util::Error::WrongCommand;
}

Util::Error APDUInternalAuthenticate::Check(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2) {
	return Util::Error::WrongCommand;
}

Util::Error APDUInternalAuthenticate::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, bstr& dataOut) {
	return Util::Error::WrongCommand;
}

Util::Error APDUGenerateAsymmetricKeyPair::Check(uint8_t cla,
		uint8_t ins, uint8_t p1, uint8_t p2) {

	if (ins != Applet::APDUcommands::GenerateAsymmKeyPair)
		return Util::Error::WrongCommand;

	if (cla != 0x00 && cla != 0x0c)
		return Util::Error::WrongAPDUCLA;

	if ((p1 != 0x80 && p1 != 0x81) ||
		(p2 != 0x00))
		return Util::Error::WrongAPDUP1P2;

	return Util::Error::NoError;
}

Util::Error APDUGenerateAsymmetricKeyPair::Process(uint8_t cla,
		uint8_t ins, uint8_t p1, uint8_t p2, bstr data, bstr& dataOut) {

	dataOut.clear();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	printf("as key p - %lu\n", data.length());
	if (data.length() != 2)
		return Util::Error::WrongAPDUDataLength;

	printf("aready\n");
	OpenPGPKeyType key_type = OpenPGPKeyType::Unknown;
	if (data == "\xb6\x00"_bstr)
		key_type = OpenPGPKeyType::DigitalSignature;
	if (data == "\xb8\x00"_bstr)
		key_type = OpenPGPKeyType::Confidentiality;
	if (data == "\xa4\x00"_bstr)
		key_type = OpenPGPKeyType::Authentication;

	// OpenPGP v3.3.1 page 64
	// 0x80 - Generation of key pair
	// 0x81 - Reading of actual public key template
	if (p1 == 0x80) {
		(void)key_type;

		return Util::Error::DataNotFound;
	} else {
		// TODO: this: dataOut.append("\7f\49\00............"_bstr);
		return Util::Error::DataNotFound;
	}

	return Util::Error::NoError;
}

Util::Error APDUPSO::Check(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2) {
	return Util::Error::WrongCommand;
}

Util::Error APDUPSO::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, bstr& dataOut) {
	return Util::Error::WrongCommand;
}

} // namespace OpenPGP
