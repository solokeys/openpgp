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
	File::FileSystem &filesystem = solo.GetFileSystem();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	PWStatusBytes pwstatus;
	pwstatus.Load(filesystem);

	// TODO: needs to add Password::PSOCDC and get rid of next if
	Password passwd_id = Password::PW1;
	if (p2 == 0x83)
		passwd_id = Password::PW3;

	// clear authentication status
	if (p1 == 0xff){
		security.ClearAuth(passwd_id);
		return Util::Error::NoError;
	}

	size_t min_length = PGPConst::PWMinLength(passwd_id);
	size_t max_length = PGPConst::PWMaxLength(passwd_id);
	uint8_t _passwd[max_length] = {0};
	bstr passwd(_passwd, 0, max_length);

	auto file_err = filesystem.ReadFile(File::AppletID::OpenPGP,
			(passwd_id == Password::PW3) ? File::SecureFileID::PW3 : File::SecureFileID::PW1,
			File::Secure,
			passwd);
	if (file_err != Util::Error::NoError)
		return file_err;

	size_t passwd_length = passwd.length();

	// check status
	if (passwd_length == 0) {
		// OpenPGP v3.3.1 page 44
		// TODO: get rid of this if
		if (p2 == 0x81){
			if (security.GetAuth(Password::PSOCDS)) {
				return Util::Error::NoError;
			} else {
				dataOut.appendAPDUres(0x6300 + pwstatus.PasswdTryRemains(passwd_id));
				return Util::Error::ErrorPutInData;
			}
		} else {
			if (security.GetAuth(passwd_id)) {
				return Util::Error::NoError;
			} else {
				dataOut.appendAPDUres(0x6300 + pwstatus.PasswdTryRemains(passwd_id));
				return Util::Error::ErrorPutInData;
			}
		}
	}

	if (passwd_length < min_length)
		return Util::Error::InternalError;

	// check allowing passwd check
	if (pwstatus.PasswdTryRemains(passwd_id) == 0)
		return Util::Error::PasswordLocked;

	// check password
	if (data != passwd) {
		pwstatus.DecErrorCounter(passwd_id);
		pwstatus.Save(filesystem);
		return Util::Error::WrongPassword;
	}

	// OpenPGP v3.3.1 page 44
	if (p2 == 0x81){
		security.SetAuth(Password::PSOCDS);
	} else {
		security.SetAuth(passwd_id);
	}
	security.ResetPasswdTryRemains(Password::PW1);

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
		uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr &dataOut) {

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	Password passwd_id = Password::PW1;
	if (p2 == 0x83)
		passwd_id = Password::PW3;

	// TODO: move some values to PWStatusBytes
	size_t min_length = PGPConst::PWMinLength(passwd_id);
	size_t max_length = PGPConst::PWMaxLength(passwd_id);

	uint8_t _passwd[max_length] = {0};
	bstr passwd(_passwd, 0, max_length);

	auto err = filesystem.ReadFile(File::AppletID::OpenPGP,
			(passwd_id == Password::PW1) ? File::SecureFileID::PW1 : File::SecureFileID::PW3,
			File::Secure,
			passwd);
	if (err != Util::Error::NoError)
		return err;

	size_t passwd_length = passwd.length();

	if (passwd_length < min_length)
		return Util::Error::InternalError;

	if ((data.length() < passwd_length + min_length) ||
		(data.length() > passwd_length + max_length))
		return Util::Error::WrongAPDUDataLength;

	// check old password
	if (data.substr(0, passwd_length) != passwd)
		return Util::Error::WrongPassword;

	// set new password
	passwd.clear();
	passwd.append(data.substr(passwd_length, data.length() - passwd_length));

	err = filesystem.WriteFile(File::AppletID::OpenPGP,
			(passwd_id == Password::PW1) ? File::SecureFileID::PW1 : File::SecureFileID::PW3,
			File::Secure,
			passwd);
	if (err != Util::Error::NoError)
		return err;

	// clear pw1/pw3 access counter
	security.ResetPasswdTryRemains(passwd_id);

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
	File::FileSystem &filesystem = solo.GetFileSystem();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	auto err = Check(cla, ins, p1, p2);
	if (err != Util::Error::NoError)
		return err;

	// TODO: move some values to PWStatusBytes
	size_t min_length = PGPConst::PW1MinLength;
	size_t max_length = PGPConst::PW1MaxLength;
	size_t max_rc_length = PGPConst::RCMaxLength;

	uint8_t _passwd[MAX(max_length, max_rc_length)] = {0};
	bstr passwd(_passwd, 0, max_length);

	// 0x02 - after correct verification of PW3
	// 0x00 - resetting code (RC) in data
	if (p1 == 0x02) {
		if ((data.length() < min_length) ||
			(data.length() > max_length))
			return Util::Error::WrongAPDUDataLength;

		if (!security.GetAuth(Password::PW3))
			return Util::Error::AccessDenied;

		passwd.append(data);
	} else {
		auto err = filesystem.ReadFile(File::AppletID::OpenPGP,
				0xd3,
				File::File,
				passwd);
		if (err != Util::Error::NoError)
			return err;

		size_t rc_length = passwd.length();

		if ((data.length() < rc_length + min_length) ||
			(data.length() > rc_length + max_length))
			return Util::Error::WrongAPDUDataLength;

		// check RC
		if (data.find(passwd) != 0)
			return Util::Error::WrongPassword;

		// set new password
		passwd.clear();
		passwd.append(data.substr(rc_length, data.length() - rc_length));
	}

	err = filesystem.WriteFile(File::AppletID::OpenPGP,
			File::SecureFileID::PW1,
			File::Secure,
			passwd);
	if (err != Util::Error::NoError)
		return err;

	// clear pw1 access counter
	security.ResetPasswdTryRemains(Password::PW1);

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

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	if (ins == Applet::APDUcommands::PutData) {
		uint16_t object_id = (p1 << 8) + p2;
		printf("write object id = 0x%04x\n", object_id);

		filesystem.WriteFile(File::AppletID::OpenPGP, object_id, File::File, data);
	} else {
		key_storage.SetKeyExtHeader(File::AppletID::OpenPGP, data);
	}

	return Util::Error::NoError;
}

} // namespace OpenPGP
