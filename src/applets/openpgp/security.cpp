/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#include <applets/openpgp/security.h>
#include "errors.h"
#include "applets/apduconst.h"
#include "solofactory.h"

namespace OpenPGP {

Util::Error Security::DataObjectAccessCheck(
		uint16_t dataObjectID, bool writeAccess) {

	return Util::Error::NoError;
}

Util::Error Security::CommandAccessCheck(
		uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {

	// DataObjectAccessCheck
	if (ins == Applet::APDUcommands::GetData ||
		ins == Applet::APDUcommands::GetData2 ||
		ins == Applet::APDUcommands::PutData ||
		ins == Applet::APDUcommands::PutData2
		) {

		uint16_t object_id = (p1 << 8) + p2;

		auto err = DataObjectAccessCheck(
				object_id,
				ins == Applet::APDUcommands::PutData || ins == Applet::APDUcommands::PutData2);
		if (err != Util::Error::NoError)
			return err;
	}

	return Util::Error::NoError;
}

void Security::ClearAllAuth() {
	appletState.Clear();
}

void Security::Init() {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	ClearAllAuth();
	appletConfig.state = LifeCycleState::Init; // TODO: load
	pwstatus.Load(filesystem);
}

Util::Error Security::SetPasswd(Password passwdId, bstr passwords) {
	return Util::Error::NoError;
}

bool Security::VerifyPasswd(Password passwdId, bstr passwd) {
	return false;
}

Util::Error Security::ResetPasswdTryRemains(Password passwdId) {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	pwstatus.PasswdSetRemains(Password::PW1, PGPConst::DefaultPWResetCounter);
	return pwstatus.Save(filesystem);
}

void Security::ClearAuth(Password passwdId) {
	switch (passwdId){
	case OpenPGP::Password::PW1:
		appletState.pw1Authenticated = false;
		break;
	case OpenPGP::Password::PW3:
		appletState.pw3Authenticated = false;
		break;
	case OpenPGP::Password::PSOCDS:
		appletState.cdsAuthenticated = false;
	default:
		break;
	}
}

void Security::SetAuth(Password passwdId) {
	switch (passwdId){
	case OpenPGP::Password::PW1:
		appletState.pw1Authenticated = true;
		break;
	case OpenPGP::Password::PW3:
		appletState.pw3Authenticated = true;
		break;
	case OpenPGP::Password::PSOCDS:
		appletState.cdsAuthenticated = true;
	default:
		break;
	}
}

bool Security::GetAuth(Password passwdId) {
	switch (passwdId){
	case OpenPGP::Password::PW1:
		return appletState.pw1Authenticated;
	case OpenPGP::Password::PW3:
		return appletState.pw3Authenticated;
	case OpenPGP::Password::PSOCDS:
		return appletState.cdsAuthenticated;
	default:
		return false;
	}
}

Util::Error Security::IncDSCounter() {
	return Util::Error::NoError;
}

} /* namespace OpenPGP */

