/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "openpgpapplet.h"
#include "apduconst.h"
#include "openpgp/apdusecuritycheck.h"
#include "solofactory.h"

namespace Applet {

OpenPGPApplet::OpenPGPApplet() : Applet() {
	config.state = OpenPGP::LifeCycleState::Init;
	state.pw1Authenticated = false;
	state.pw3Authenticated = false;
	state.CDSAuthenticated = false;
}

Util::Error OpenPGPApplet::Select(bstr &result) {
	auto err = Applet::Select(result);

	state.pw1Authenticated = false;
	state.pw3Authenticated = false;
	state.CDSAuthenticated = false;

	return err;
}

const bstr* OpenPGPApplet::GetAID() {
	return &aid;
}

Util::Error OpenPGPApplet::APDUExchange(bstr header, bstr data, bstr &result) {
	result.clear();

	if (!selected)
		return Util::Error::AppletNotSelected;

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::APDUSecurityCheck &securty = opgp_factory.GetAPDUSecurityCheck();


	printf("0>"); dump_hex(header); dump_hex(data);

	auto cla = header[0];
	auto ins = header[1];
	auto p1 = header[2];
	auto p2 = header[3];

	auto err = securty.CommandAccessCheck(cla, ins, p1, p2);
	if (err != Util::Error::NoError)
		return err;

	// TODO: move it to APDU
	if (ins == APDUcommands::GetData) {
		auto err = securty.DataObjectAccessCheck((p1 >> 8) + p2, false);
		if (err != Util::Error::NoError)
			return err;
	}

	auto cmd = opgp_factory.GetAPDUCommand(cla, ins, p1, p2);
	if (!cmd)
		return Util::Error::WrongCommand;

	auto cmderr = cmd->Process(cla, ins, p1, p2, data, result);
	if (cmderr != Util::Error::NoError)
		return cmderr;

	printf("0<"); dump_hex(result);

	return Util::Error::NoError;
}

void OpenPGPApplet::ClearAuth(OpenPGP::Password passwdId) {
	switch (passwdId){
	case OpenPGP::Password::PW1:
		state.pw1Authenticated = false;
		break;
	case OpenPGP::Password::PW3:
		state.pw3Authenticated = false;
		break;
	default:
		break;
	}
}

void OpenPGPApplet::SetAuth(OpenPGP::Password passwdId) {
	switch (passwdId){
	case OpenPGP::Password::PW1:
		state.pw1Authenticated = true;
		break;
	case OpenPGP::Password::PW3:
		state.pw3Authenticated = true;
		break;
	default:
		break;
	}
}

bool OpenPGPApplet::GetAuth(OpenPGP::Password passwdId) {
	switch (passwdId){
	case OpenPGP::Password::PW1:
		return state.pw1Authenticated;
	case OpenPGP::Password::PW3:
		return state.pw3Authenticated;
	default:
		break;
	}
	return false;
}

void OpenPGPApplet::ClearPSOCDSAccess() {
	state.CDSAuthenticated = false;
}

void OpenPGPApplet::SetPSOCDSAccess() {
	state.CDSAuthenticated = true;
}

bool OpenPGPApplet::GetPSOCDSAccess() {
	return state.CDSAuthenticated;
}

}

