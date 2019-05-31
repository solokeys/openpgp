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
#include "openpgpconst.h"
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
	File::FileSystem &filesystem = solo.GetFileSystem();

	Password passwd_id = Password::PW1;
	if (p2 == 0x83)
		passwd_id = Password::PW3;

	if (p1 == 0xff){
		applet.ClearAuth(passwd_id);
		return Util::Error::NoError;
	}

	size_t min_length = PGPConst::PWMinLength(passwd_id);
	size_t max_length = PGPConst::PWMaxLength(passwd_id);
	uint8_t _passwd[max_length] = {0};
	bstr passwd(_passwd, 0, max_length);

	auto file_err = filesystem.ReadFile(File::AppletID::OpenPGP,
			(passwd_id == Password::PW1) ? File::KeyFileID::PW1 : File::KeyFileID::PW3,
			File::Key,
			passwd);
	if (file_err != Util::Error::NoError)
		return file_err;

	size_t passwd_length = passwd.length();

	if (passwd_length < min_length)
		return Util::Error::InternalError;

	// check password
	if (data != passwd)
		return Util::Error::WrongPassword;

	// TODO: p2 = 0x82 not implemented!!!
	applet.SetAuth(passwd_id);

	return Util::Error::NoError;
}

Util::Error APDUChangeReferenceData::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	if (ins != Applet::APDUcommands::ChangeReferenceData)
		return Util::Error::WrongCommand;

	if (cla != 0x00 && cla != 0x0c)
		return Util::Error::WrongAPDUCLA;

	if ((p1 != 0x00) ||
		(p2 != 0x81 && p2 != 0x83))
		return Util::Error::WrongAPDUP1P2;

	return Util::Error::NoError;
}

Util::Error APDUChangeReferenceData::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, bstr &dataOut) {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	Password passwd_id = Password::PW1;
	if (p2 == 0x83)
		passwd_id = Password::PW3;

	size_t min_length = PGPConst::PWMinLength(passwd_id);
	size_t max_length = PGPConst::PWMaxLength(passwd_id);

	uint8_t _passwd[max_length] = {0};
	bstr passwd(_passwd, 0, max_length);

	auto err = filesystem.ReadFile(File::AppletID::OpenPGP,
			(passwd_id == Password::PW1) ? File::KeyFileID::PW1 : File::KeyFileID::PW3,
			File::Key,
			passwd);
	if (err != Util::Error::NoError)
		return err;

	size_t passwd_length = passwd.length();

	if (passwd_length < min_length)
		return Util::Error::InternalError;

	if ((data.length() < passwd_length + min_length) ||
		(data.length() > passwd_length + max_length))
		return Util::Error::WrongAPDUDataLength;

	if (data.find(passwd) != 0)
		return Util::Error::WrongPassword;

	passwd.clear();
	passwd.append(data.substr(passwd_length, data.length() - passwd_length));

	err = filesystem.WriteFile(File::AppletID::OpenPGP,
			(passwd_id == Password::PW1) ? File::KeyFileID::PW1 : File::KeyFileID::PW3,
			File::Key,
			passwd);
	if (err != Util::Error::NoError)
		return err;

	return Util::Error::NoError;
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
