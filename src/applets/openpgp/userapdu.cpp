/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include <applets/openpgp/security.h>
#include "userapdu.h"
#include "applets/apduconst.h"
#include "solofactory.h"
#include "applets/openpgp/openpgpfactory.h"
#include "applets/openpgpapplet.h"
#include "openpgpconst.h"
#include "openpgpstruct.h"
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
		uint8_t p2, bstr data, uint8_t le, bstr &dataOut) {

	auto err = Check(cla, ins, p1, p2);
	if (err != Util::Error::NoError)
		return err;

	if (p1 == 0xff && data.length() > 0)
		return Util::Error::WrongAPDULength;

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	Password passwd_id = Password::PSOCDS; // p2 == 0x81
	if (p2 == 0x82)
		passwd_id = Password::PW1;
	if (p2 == 0x83)
		passwd_id = Password::PW3;

	// clear authentication status
	if (p1 == 0xff){
		security.ClearAuth(passwd_id);
		return Util::Error::NoError;
	}

	// check status. OpenPGP v3.3.1 page 44. if input data length == 0, return authentication status
	if (data.length() == 0) {
		if (security.GetAuth(passwd_id)) {
			return Util::Error::NoError;
		} else {
			dataOut.appendAPDUres(0x6300 + security.PasswdTryRemains(passwd_id));
			return Util::Error::ErrorPutInData;
		}
	}

	// verify password (strict check)
	return security.VerifyPasswd(passwd_id, data, false, nullptr);
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
		uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr &dataOut) {

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	Password passwd_id = Password::PW1;
	if (p2 == 0x83)
		passwd_id = Password::PW3;

	size_t passwd_length = 0;
	auto err = security.VerifyPasswd(passwd_id, data, true, &passwd_length);
	if (err != Util::Error::NoError)
		return err;

	// set new password
	err = security.SetPasswd(passwd_id, data.substr(passwd_length, data.length() - passwd_length));
	if (err != Util::Error::NoError)
		return err;

	return Util::Error::NoError;
}

Util::Error APDUResetRetryCounter::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	if (ins != Applet::APDUcommands::ResetRetryCounter)
		return Util::Error::WrongCommand;

	if (cla != 0x00 && cla != 0x0c)
		return Util::Error::WrongAPDUCLA;

	if ((p1 != 0x00 && p1 != 0x02) ||
		(p2 != 0x81))
		return Util::Error::WrongAPDUP1P2;

	return Util::Error::NoError;
}

Util::Error APDUResetRetryCounter::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr &dataOut) {

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	auto err = Check(cla, ins, p1, p2);
	if (err != Util::Error::NoError)
		return err;

	// TODO: move some values to PWStatusBytes
	size_t min_length = PGPConst::PW1MinLength;
	size_t max_length = PGPConst::PW1MaxLength;

	bstr passwd;

	// 0x02 - after correct verification of PW3
	// 0x00 - resetting code (RC) in data
	if (p1 == 0x02) {
		if ((data.length() < min_length) ||
			(data.length() > max_length))
			return Util::Error::WrongAPDUDataLength;

		if (!security.GetAuth(Password::PW3))
			return Util::Error::AccessDenied;

		passwd = data;
	} else {
		size_t rc_length = 0;
		auto err = security.VerifyPasswd(Password::RC, data, true, &rc_length);
		if (err != Util::Error::NoError)
			return err;

		passwd = data.substr(rc_length, data.length() - rc_length);
	}

	err = security.SetPasswd(Password::PW1, passwd);
	if (err != Util::Error::NoError)
		return err;

	return Util::Error::NoError;
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
		uint8_t p2, bstr data, uint8_t le, bstr &dataOut) {

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	uint16_t object_id = (p1 << 8) + p2;
	printf("read object id = 0x%04x\n", object_id);

	filesystem.ReadFile(File::AppletID::OpenPGP, object_id, File::File, dataOut);

	return Util::Error::NoError;
}

Util::Error APDUPutData::Check(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
	if (ins != Applet::APDUcommands::PutData && ins != Applet::APDUcommands::PutData2)
		return Util::Error::WrongCommand;

	if (ins == Applet::APDUcommands::PutData2 && (p1 != 0x3f || p2 != 0xff))
		return Util::Error::WrongCommand;

	if (cla != 0x00 && cla != 0x0c && cla != 0x10)
		return Util::Error::WrongAPDUCLA;

	return Util::Error::NoError;
}

Util::Error APDUPutData::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, uint8_t le, bstr &dataOut) {

	dataOut.clear();

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();
	Crypto::KeyStorage &key_storage = solo.GetKeyStorage();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	if (ins == Applet::APDUcommands::PutData) {
		uint16_t object_id = (p1 << 8) + p2;
		printf("write object id = 0x%04x\n", object_id);

		if (OpenPGP::PGPConst::ReadWriteOnlyAllowedFiles) {
			err_check = security.DataObjectInAllowedList(object_id);
			if (err_check != Util::Error::NoError)
				return err_check;
		}

		auto err = filesystem.WriteFile(File::AppletID::OpenPGP, object_id, File::File, data);
		if (err != Util::Error::NoError)
			return err;

		// here list of objects that need to refresh theirs state
		if (object_id == 0xc4)
			security.Reload();

		// reset reseting password code try TODO: check in the datasheet if it correct!
		if (object_id == 0xd3)
			security.ResetPasswdTryRemains(Password::RC);
	} else {
		key_storage.SetKeyExtHeader(File::AppletID::OpenPGP, data);
	}

	return Util::Error::NoError;
}

} // namespace OpenPGP
