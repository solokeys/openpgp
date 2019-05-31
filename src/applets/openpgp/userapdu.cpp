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
#include "applets/openpgpapplet.h"
#include "applets/openpgp/apdusecuritycheck.h"
#include "applets/openpgp/openpgpconst.h"
#include "filesystem.h"

namespace OpenPGP {

Util::Error APDUVerify::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	if (ins != Applet::APDUcommands::Verify)
		return Util::Error::WrongCommand;

	if (cla != 0x00 && cla != 0x0c)
		return Util::Error::WrongAPDUCLA;

	if ((p1 != 0x00 && p1 != 0xff) ||
		(p2 != 0x81 && p2 != 0x82 && p2 != 0x83))
		return Util::Error::WrongAPDUP1P2;

	return Util::Error::NoError;
}

Util::Error APDUVerify::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, bstr &dataOut) {
	auto err = Check(cla, ins, p1, p2);
	if (err != Util::Error::NoError)
		return err;

	if (p1 == 0xff && data.length() > 0)
		return Util::Error::WrongAPDULength;

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	//OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	Applet::OpenPGPApplet &applet = solo.GetAppletStorage().GetOpenPGPApplet();
	//File::FileSystem &filesystem = solo.GetFileSystem();

	if (p1 == 0xff && (p2 == 0x81 || p2 == 0x82)){
		applet.ClearAuth(Password::PW1);
		return Util::Error::NoError;
	}

	if (p1 == 0xff && p2 == 0x83){
		applet.ClearAuth(Password::PW3);
		return Util::Error::NoError;
	}

	// mock!!!!
	if (p1 == 0x00 && p2 == 0x81 && data == "123456"_bstr){
		applet.SetAuth(Password::PW1);
		return Util::Error::NoError;
	}

	if (p1 == 0x00 && p2 == 0x82 && data == "123456"_bstr){
		applet.SetAuth(Password::PW1);
		return Util::Error::NoError;
	}

	if (p1 == 0x00 && p2 == 0x83 && data == "12345678"_bstr){
		applet.SetAuth(Password::PW3);
		return Util::Error::NoError;
	}


	return Util::Error::NoError;
}

Util::Error APDUChangeReferenceData::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	return Util::Error::WrongCommand;
}

Util::Error APDUChangeReferenceData::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, bstr &dataOut) {
	return Util::Error::WrongCommand;
}

Util::Error APDUResetRetryCounter::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	return Util::Error::WrongCommand;
}

Util::Error APDUResetRetryCounter::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, bstr &dataOut) {
	return Util::Error::WrongCommand;
}

// Open PGP application v 3.3.1 page 49
Util::Error APDUGetData::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	if (ins != Applet::APDUcommands::GetData && ins != Applet::APDUcommands::GetData2)
		return Util::Error::WrongCommand;

	if (cla != 0x00 && cla != 0x0c)
		return Util::Error::WrongAPDUCLA;

	return Util::Error::NoError;
}

Util::Error APDUGetData::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, bstr &dataOut) {

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::APDUSecurityCheck &security = opgp_factory.GetAPDUSecurityCheck();
	File::FileSystem &filesystem = solo.GetFileSystem();

	uint16_t object_id = (p1 << 8) + p2;
	auto err = security.DataObjectAccessCheck(object_id, false);
	if (err != Util::Error::NoError)
		return err;

	printf("object id = 0x%04x\n", object_id);

	filesystem.ReadFile(File::AppletID::OpenPGP, object_id, File::File, dataOut);

	return Util::Error::NoError;
}

Util::Error APDUPutData::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	return Util::Error::WrongCommand;
}

Util::Error APDUPutData::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, bstr &dataOut) {
	return Util::Error::WrongCommand;
}

} // namespace OpenPGP
