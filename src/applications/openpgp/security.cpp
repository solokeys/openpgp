/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#include <applications/openpgp/security.h>
#include <array>

#include "errors.h"
#include "applications/apduconst.h"
#include "solofactory.h"

namespace OpenPGP {

struct DOAccess_t {
	uint16_t DO;
	Password PasswdRead;
	Password PasswdWrite;
};

// OpenPGP 3.3.1 page 36
std::array<DOAccess_t, 49> DOAccess = {{
		{0x0101, Password::Any,   Password::PW1},   // Private use
		{0x0102, Password::Any,   Password::PW3},
		{0x0103, Password::PW1,   Password::PW1},
		{0x0104, Password::PW3,   Password::PW3},
		{0x5e,   Password::Any,   Password::PW3},   // Login data
		{0x5b,   Password::Any,   Password::PW3},   // Name
		{0x5f2d, Password::Any,   Password::PW3},   // Language preference
		{0x5f35, Password::Any,   Password::PW3},   // Sex
		{0x5f50, Password::Any,   Password::PW3},   // URL

		// Relevant for all private keys in the application (signature, decryption, authentication)
		{0x5f48, Password::Never, Password::PW3},   // Card holder private key.

		{0x7f21, Password::Any,   Password::PW3},   // Cardholder certificates
		{0x93,   Password::Any,   Password::Never}, // DS-Counter. Internal Reset during key generation
		{0x7a,   Password::Any,   Password::Never}, // DS-Counter container (contains 0x93)

		{0xc0,   Password::Any,   Password::Never}, // Extended Capabilities. Writing possible only during personalisation
		{0xc1,   Password::Any,   Password::PW3},   // Algorithm attributes
		{0xc2,   Password::Any,   Password::PW3},   // Algorithm attributes
		{0xc3,   Password::Any,   Password::PW3},   // Algorithm attributes
		{0xc4,   Password::Any,   Password::PW3},   // PW1 Status bytes. Only 1st byte can be changed, other bytes only during personalisation

		{0xc7,   Password::Any,   Password::PW3},   // Fingerprints
		{0xc8,   Password::Any,   Password::PW3},   // Fingerprints
		{0xc9,   Password::Any,   Password::PW3},   // Fingerprints
		{0xca,   Password::Any,   Password::PW3},   // CA-Fingerprints
		{0xcb,   Password::Any,   Password::PW3},   // CA-Fingerprints
		{0xcc,   Password::Any,   Password::PW3},   // CA-Fingerprints

		{0xce,   Password::Any,   Password::PW3},   // Generation date/time of key pairs
		{0xcf,   Password::Any,   Password::PW3},   // Generation date/time of key pairs
		{0xd0,   Password::Any,   Password::PW3},   // Generation date/time of key pairs

		{0xd1,   Password::Never, Password::PW3},   // SM-Key-ENC
		{0xd2,   Password::Never, Password::PW3},   // SM-Key-MAC
		{0xd3,   Password::Never, Password::PW3},   // Resetting Code
		{0xd5,   Password::Never, Password::PW3},   // AES-Key for PSO:ENC/DEC
		{0xf4,   Password::Never, Password::PW3},   // SM-Key-Container

		{0x7f66, Password::Any,   Password::Never}, // Extended length information

		{0xd6,   Password::Any,   Password::PW3},   // User Interaction Flag PSO:CDS
		{0xd7,   Password::Any,   Password::PW3},   // User Interaction Flag PSO:DEC
		{0xd8,   Password::Any,   Password::PW3},   // User Interaction Flag PSO:AUT

		{0xf9,   Password::Any,   Password::PW3},   // KDF-DO

		// read only
		{0x2f00, Password::Any,   Password::Never}, // EF.DIR
		{0x7f74, Password::Any,   Password::Never}, // General feature management
		{0x5f52, Password::Any,   Password::Never}, // Historical bytes
		{0x4f,   Password::Any,   Password::Never}, // AID

		// composed data
		{0x65,   Password::Any,   Password::PW3},   // 5b, 5f2d, 5f35
		{0x6e,   Password::Any,   Password::Never}, // 4f, 5f52, 73
		{0x73,   Password::Any,   Password::Never}, // c0-c7, cd
		{0xc5,   Password::Any,   Password::PW3},   // c7-c9 (Fingerprints)
		{0xc6,   Password::Any,   Password::PW3},   // ca-cc (CA-Fingerprints)
		{0xcd,   Password::Any,   Password::PW3},   // ce-d0 (Generation date/time of key pairs)

		// command's specific
		{0x3fff, Password::Any,   Password::Any},

		{0x00,   Password::Never, Password::Never}  // last record
}};


uint8_t Security::PasswdTryRemains(Password passwdId) {
	return pwstatus.PasswdTryRemains(passwdId);
}

Util::Error Security::DataObjectAccessCheck(
		uint16_t dataObjectID, bool writeAccess) {

    for(const auto& d: DOAccess) {
    	if (d.DO == dataObjectID) {
    		if (writeAccess) {
    			if (GetAuth(d.PasswdWrite))
    				return Util::Error::NoError;
    			else
    				return Util::Error::AccessDenied;
    		} else {
    			if (GetAuth(d.PasswdRead))
    				return Util::Error::NoError;
    			else
    				return Util::Error::AccessDenied;
    		}

    	}
    }

    // KDF DO can be changed only when no keys are registered.
    // from gnuk
    if (dataObjectID == 0xf9) {
    	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
    	Crypto::KeyStorage &key_storage = solo.GetKeyStorage();

    	if (key_storage.KeyExists(File::AppID::OpenPGP, OpenPGPKeyType::DigitalSignature) ||
    		key_storage.KeyExists(File::AppID::OpenPGP, OpenPGPKeyType::Confidentiality) ||
			key_storage.KeyExists(File::AppID::OpenPGP, OpenPGPKeyType::Authentication)
    		)
        	return Util::Error::AccessDenied;
    }

    if (PGPConst::ReadWriteOnlyAllowedFiles)
    	return Util::Error::AccessDenied;
    else
    	return Util::Error::NoError;
}

Util::Error OpenPGP::Security::DataObjectInAllowedList(uint16_t dataObjectID) {
    for(const auto& d: DOAccess) {
    	if (d.DO == dataObjectID)
    		return Util::Error::NoError;
    }
	return Util::Error::AccessDenied;
}

Util::Error Security::CommandAccessCheck(
		uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {

	// check init and terminated card states
	if (ins != Application::APDUcommands::ActivateFile &&
		ins != Application::APDUcommands::TerminateDF &&
		ins != Application::APDUcommands::SoloReboot ) {

		// check init state
		LifeCycleState lcstate = LifeCycleState::Init;
		auto err = GetLifeCycleState(lcstate);
		if (err != Util::Error::NoError)
			return err;

		if (lcstate != LifeCycleState::Operational)
			return Util::Error::ConditionsNotSatisfied;

		// application terminated
		if (isTerminated())
			return Util::Error::ConditionsNotSatisfied;
	}


	// DataObjectAccessCheck
	if (ins == Application::APDUcommands::GetData ||
		ins == Application::APDUcommands::GetData2 ||
		ins == Application::APDUcommands::PutData ||
		ins == Application::APDUcommands::PutData2
		) {

		uint16_t object_id = (p1 << 8) + p2;

		auto err = DataObjectAccessCheck(
				object_id,
				ins == Application::APDUcommands::PutData || ins == Application::APDUcommands::PutData2);
		if (err != Util::Error::NoError)
			return err;
	}

	// Perform Security Operation
	if (ins == Application::APDUcommands::PSO)
		switch (p1) {
		// signature
		case 0x9e:
			if (GetAuth(Password::PSOCDS)) // PW+81
				return Util::Error::NoError;
			else
				return Util::Error::AccessDenied;

		// decipher
		case 0x80:
			if (GetAuth(Password::PW1))   // PW+82
				return Util::Error::NoError;
			else
				return Util::Error::AccessDenied;

		// encipher
		case 0x86:
			if (GetAuth(Password::PW1))   // PW+82
				return Util::Error::NoError;
			else
				return Util::Error::AccessDenied;
		default:
			break;
		};

	// Internal authenticate
	if (ins == Application::APDUcommands::InternalAuthenticate) {
		if (GetAuth(Password::PW1)) {
			return Util::Error::NoError;
		} else {
			return Util::Error::AccessDenied;
		}
	}

	// Generate asymmetric key pair
	if (ins == Application::APDUcommands::GenerateAsymmKeyPair)
		switch (p1) {
		// 0x80 - Generation of key pair
		case 0x80:
			if (GetAuth(Password::PW3))
				return Util::Error::NoError;
			else
				return Util::Error::AccessDenied;

		// 0x81 - Reading of actual public key template
		case 0x81:
			return Util::Error::NoError;

		default:
			break;
		};

	return Util::Error::NoError;
}

bool Security::DataObjectInSecureArea(uint16_t dataObjectID) {
	if (dataObjectID == File::SecureFileID::AES)
		return true;

	return false;
}


void Security::ClearAllAuth() {
	applicationState.Clear();
}

void Security::Init() {
	ClearAllAuth();

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();
	applicationConfig.Load(filesystem);

	Reload();
}

void Security::Reload() {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	pwstatus.Load(filesystem);
	kdfDO.Load(filesystem);
}

void Security::intRESET() {
	applicationState.Init();  // clear `terminateExecuted` state
	Init();
    DoReset = true;
}

Util::Error Security::AfterSaveFileLogic(uint16_t objectID) {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	// PW status and KDF-DO
	// list of objects that need to refresh theirs state
	if (objectID == 0xc4 || objectID == 0xf9)
		Reload();

	// reset reseting password code try TODO: check in the datasheet if it correct!
	if (objectID == 0xd3) {
		auto err = ResetPasswdTryRemains(Password::RC);
		if (err != Util::Error::NoError)
			return err;
	}

	// KDF-DO. clear all the authentications and passwords
	// if KDF-DO contains default passwords - needs to save them
	if (objectID == 0xf9) {
		ClearAllAuth();
		ClearAllPasswd();

		kdfDO.Print();
		if (kdfDO.HaveInitPassword(Password::Any)) {
			auto err = kdfDO.SaveInitPasswordsToPWFiles(filesystem);
			if (err != Util::Error::NoError)
				return err;
		}
	}

	return Util::Error::NoError;
}

Util::Error Security::GetLifeCycleState(LifeCycleState &state) {
	state = applicationConfig.state;
	return Util::Error::NoError;
}

Util::Error Security::SetLifeCycleState(LifeCycleState state) {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	applicationConfig.state = state;
	return applicationConfig.Save(filesystem);
}

Util::Error Security::SetPasswd(Password passwdId, bstr password) {

	if (passwdId == Password::Any || passwdId == Password::Never)
		return Util::Error::NoError;

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	Util::Error err;

	// password check
	if (passwdId == Password::PW3 && password.length() == 0) {
		// empty PW3 for GNUK
	} else {
		if (password.length() < pwstatus.GetMinLength(passwdId) ||
			password.length() > GetMaxPWLength(passwdId) )
			return Util::Error::WrongAPDUDataLength;
	}

	switch (passwdId) {
	case Password::PSOCDS:
	case Password::PW1:
	case Password::PW3:
		err = filesystem.WriteFile(File::AppID::OpenPGP,
				(passwdId == Password::PW3) ? File::SecureFileID::PW3 : File::SecureFileID::PW1,
				File::Secure,
				password);
		if (err != Util::Error::NoError)
			return err;
		break;
	case Password::RC:
		err = filesystem.WriteFile(File::AppID::OpenPGP,
				0xd3,
				File::File,
				password);
		if (err != Util::Error::NoError)
			return err;
		break;
	default:
		break;
	}

	// clear pw1/pw3/rc access counter
	return ResetPasswdTryRemains(passwdId);
}

Util::Error Security::VerifyPasswd(Password passwdId, bstr data, bool passwdCheckFirstPart, size_t *passwdLen) {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	if (passwdId == Password::Any)
		return Util::Error::NoError;
	if (passwdId == Password::Never)
		return Util::Error::WrongPassword;

	if (passwdLen)
		*passwdLen = 0;

	size_t min_length = pwstatus.GetMinLength(passwdId);
	size_t max_length = GetMaxPWLength(passwdId);

	uint8_t _passwd[max_length] = {0};
	bstr passwd(_passwd, 0, max_length);

	if (passwdId != Password::RC) {
		auto file_err = filesystem.ReadFile(File::AppID::OpenPGP,
				(passwdId == Password::PW3) ? File::SecureFileID::PW3 : File::SecureFileID::PW1,
				File::Secure,
				passwd);
		if (file_err != Util::Error::NoError)
			return file_err;
	} else {
		auto file_err = filesystem.ReadFile(File::AppID::OpenPGP,
				0xd3,
				File::File,
				passwd);
		if (file_err != Util::Error::NoError)
			return file_err;
	}

	size_t passwd_length = passwd.length();

	if (passwdId == Password::PW3 && passwd_length == 0) {
		// gnuk PW3 may be empty.
		// If PW3 is null and PW1 = OK >> check with pw1
		// If PW3 is null and PW1 = default >> check with default pw3. Here may be default KDF-DO password if set!
		auto file_err = filesystem.ReadFile(File::AppID::OpenPGP,
				File::SecureFileID::PW1,
				File::Secure,
				passwd);
		if (file_err != Util::Error::NoError)
			return file_err;

		// PW3 is null and PW1 = default
		if (passwd == PGPConst::DefaultPW1) {
			passwd.set(PGPConst::DefaultPW3);
		}

		// PW3 is null and PW1 = default. if KDF-DO set
		if (kdfDO.HaveInitPassword(Password::Any) && passwd == kdfDO.InitialPW1) {
			passwd.set(kdfDO.InitialPW3);
		}
		passwd_length = passwd.length();
	} else {
		if (passwd_length < min_length || passwd_length > max_length)
			return Util::Error::InternalError;
	}

	// check allowing passwd check
	if (pwstatus.PasswdTryRemains(passwdId) == 0)
		return Util::Error::PasswordLocked;

	// check password
	bstr vdata = data;
	if (passwdCheckFirstPart)
		vdata = data.substr(0, passwd_length);

	// check password (first part or all)
	if (vdata != passwd) {
		pwstatus.DecErrorCounter(passwdId);
		pwstatus.Save(filesystem);
		// TODO: maybe here need to add 0x6100 error
		return Util::Error::WrongPassword;
	}

	// OpenPGP v3.3.1 page 44
	SetAuth(passwdId);
	ResetPasswdTryRemains(passwdId);

	if (passwdLen)
		*passwdLen = passwd_length;

	return Util::Error::NoError;
}

bool Security::PWIsEmpty(Password passwdId) {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	size_t max_length = GetMaxPWLength(passwdId);

	uint8_t _passwd[max_length] = {0};
	bstr passwd(_passwd, 0, max_length);

	auto file_err = filesystem.ReadFile(File::AppID::OpenPGP,
			(passwdId == Password::PW3) ? File::SecureFileID::PW3 : File::SecureFileID::PW1,
			File::Secure,
			passwd);
	if (file_err != Util::Error::NoError)
		return false;

	return passwd.length() == 0;
}

size_t Security::GetMaxPWLength(Password passwdId) {
	return MAX(pwstatus.GetMaxLength(passwdId), kdfDO.GetPWLength());
}


Util::Error Security::ResetPasswdTryRemains(Password passwdId) {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	pwstatus.PasswdSetRemains(passwdId, PGPConst::DefaultPWResetCounter);
	return pwstatus.Save(filesystem);
}

// from gnuk source
Util::Error Security::ClearAllPasswd() {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	auto file_err = filesystem.DeleteFile(File::AppID::OpenPGP,
			File::SecureFileID::PW1,
			File::Secure);
	if (file_err != Util::Error::NoError)
		return file_err;

	file_err = filesystem.DeleteFile(File::AppID::OpenPGP,
			File::SecureFileID::PW3,
			File::Secure);
	if (file_err != Util::Error::NoError)
		return file_err;

	// RC
	file_err = filesystem.DeleteFile(File::AppID::OpenPGP,
			0xd3,
			File::File);
	if (file_err != Util::Error::NoError)
		return file_err;

	return Util::Error::NoError;
}

void Security::ClearAuth(Password passwdId) {
	switch (passwdId){
	case Password::PW1:
		applicationState.pw1Authenticated = false;
		break;
	case Password::PW3:
		applicationState.pw3Authenticated = false;
		break;
	case Password::PSOCDS:
		applicationState.cdsAuthenticated = false;
		break;
	default:
		break;
	}
}

void Security::SetAuth(Password passwdId) {
	switch (passwdId){
	case Password::PW1:
		applicationState.pw1Authenticated = true;
		break;
	case Password::PW3:
		applicationState.pw3Authenticated = true;
		break;
	case Password::PSOCDS:
		applicationState.cdsAuthenticated = true;
		break;
	default:
		break;
	}
}

bool Security::GetAuth(Password passwdId) {
	switch (passwdId){
	case Password::PW1:
		return applicationState.pw1Authenticated;
	case Password::PW3:
		return applicationState.pw3Authenticated;
	case Password::PSOCDS:
		return applicationState.cdsAuthenticated;
	case Password::Any:
		return true;
	case Password::Never:
		return false;
	default:
		return false;
	}
}

Util::Error Security::IncDSCounter() {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	DSCounter dscounter;
	auto cntrerr = dscounter.Load(filesystem);
	if (cntrerr != Util::Error::NoError)
		return cntrerr;

	dscounter.Counter++;

	cntrerr = dscounter.Save(filesystem);
	if (cntrerr != Util::Error::NoError)
		return cntrerr;

	return Util::Error::NoError;
}

void Security::Terminate() {
	applicationState.terminateExecuted = true;
}

bool Security::isTerminated() {
	return applicationState.terminateExecuted;
}

} /* namespace OpenPGP */
