/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "secureapdu.h"

#include <applets/openpgp/security.h>
#include "applets/apduconst.h"
#include "solofactory.h"
#include "applets/openpgp/openpgpfactory.h"
#include "applets/openpgpapplet.h"
#include "applets/openpgp/openpgpconst.h"
#include "applets/openpgp/openpgpstruct.h"
#include "device.h"

namespace OpenPGP {

Util::Error APDUActivateFile::Check(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2) {
	if (ins != Applet::APDUcommands::ActivateFile)
		return Util::Error::WrongCommand;

	if (cla != 0x00 && cla != 0x0c)
		return Util::Error::WrongAPDUCLA;

	if (p1 != 0x00 || p2 != 0x00)
		return Util::Error::WrongAPDUP1P2;

	return Util::Error::NoError;
}

Util::Error APDUActivateFile::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr& dataOut) {

	dataOut.clear();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

    Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();
    OpenPGP::ResetProvider &resetprovider = opgp_factory.GetResetProvider();

    LifeCycleState lcstate = LifeCycleState::Init;
    auto err = security.GetLifeCycleState(lcstate);
	if (err != Util::Error::NoError)
		return err;

	if (lcstate == LifeCycleState::Init && !security.isTerminated()) { // isTerminated==false: `terminate df` and then reset
	    resetprovider.ResetCard();
	    security.Init();
	    printf_device("Card was CLEARED\n");
	}

	err = security.SetLifeCycleState(LifeCycleState::Operational);
	if (err != Util::Error::NoError)
		return err;

	return Util::Error::NoError;
}

std::string_view APDUActivateFile::GetName() {
	using namespace std::literals;
	return "ActivateFile"sv;
}

Util::Error APDUTerminateDF::Check(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2) {
	if (ins != Applet::APDUcommands::TerminateDF)
		return Util::Error::WrongCommand;

	if (cla != 0x00 && cla != 0x0c)
		return Util::Error::WrongAPDUCLA;

	if (p1 != 0x00 || p2 != 0x00)
		return Util::Error::WrongAPDUP1P2;

	return Util::Error::NoError;
}

Util::Error APDUTerminateDF::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr& dataOut) {

	dataOut.clear();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

    Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	// TODO: if authenticated with PW3

	security.Terminate();

    auto err = security.SetLifeCycleState(LifeCycleState::Init);
	if (err != Util::Error::NoError)
		return err;

	return Util::Error::NoError;
}

std::string_view APDUTerminateDF::GetName() {
	using namespace std::literals;
	return "TerminateDF"sv;
}

Util::Error APDUManageSecurityEnvironment::Check(uint8_t cla,
		uint8_t ins, uint8_t p1, uint8_t p2) {
	if (ins != Applet::APDUcommands::ManageSecurityEnv)
		return Util::Error::WrongCommand;

	if (cla != 0x00)
		return Util::Error::WrongAPDUCLA;

	if (p1 != 0x41 || (p2 != 0xa4 && p2 != 0xb8))
		return Util::Error::WrongAPDUP1P2;

	return Util::Error::NoError;
}

Util::Error APDUManageSecurityEnvironment::Process(uint8_t cla,
		uint8_t ins, uint8_t p1, uint8_t p2, bstr data, uint8_t le,
		bstr& dataOut) {

	dataOut.clear();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	return Util::Error::WrongCommand;
}

std::string_view APDUManageSecurityEnvironment::GetName() {
	using namespace std::literals;
	return "ManageSecurityEnvironment"sv;
}

Util::Error APDUSoloReboot::Check(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2) {
	if (ins != Applet::APDUcommands::SoloReboot)
		return Util::Error::WrongCommand;

	if (cla != 0x00)
		return Util::Error::WrongAPDUCLA;

	if (p1 != 0x00 || p2 != 0x00)
		return Util::Error::WrongAPDUP1P2;

	return Util::Error::NoError;
}

Util::Error APDUSoloReboot::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr& dataOut) {
	dataOut.clear();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	if (data != "reboot"_bstr)
		return Util::Error::AccessDenied;

	// reset form pc only
    Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	security.intRESET();

	//reboot from hardware
	hwreboot();

	return Util::Error::NoError;
}

std::string_view APDUSoloReboot::GetName() {
	using namespace std::literals;
	return "SoloReboot"sv;
}

}
