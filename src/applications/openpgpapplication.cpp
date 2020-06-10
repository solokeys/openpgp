/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include <applications/openpgp/security.h>
#include "opgpdevice.h"
#include "openpgpapplication.h"
#include "apduconst.h"
#include "solofactory.h"

namespace Application {

OpenPGPApplication::OpenPGPApplication() : Application() {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	security.Init();
}

Util::Error OpenPGPApplication::Select(bstr &result) {
	auto err = Application::Select(result);

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	security.Init();

	using namespace OpenPGP;
    LifeCycleState lcstate = LifeCycleState::Init;
    auto errsec = security.GetLifeCycleState(lcstate);
	if (errsec != Util::Error::NoError)
		return errsec;

	if (lcstate != LifeCycleState::Operational)
		return Util::Error::ApplicationTerminated;

	return err;
}

const bstr* OpenPGPApplication::GetAID() {
	return &aid;
}

Util::Error OpenPGPApplication::APDUExchange(APDUStruct &apdu, bstr &result) {
	result.clear();

	if (!selected)
		return Util::Error::ApplicationNotSelected;

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();


	auto err = security.CommandAccessCheck(apdu.cla, apdu.ins, apdu.p1, apdu.p2);
	if (err != Util::Error::NoError) {
		printf_device("Security error. Access denied.\n");
		return err;
	}

	auto cmd = opgp_factory.GetAPDUCommand(apdu.cla, apdu.ins, apdu.p1, apdu.p2);
	if (!cmd)
		return Util::Error::WrongCommand;

	auto name = cmd->GetName();
	printf_device("======== %.*s\n", static_cast<int>(name.size()), name.data());

	auto cmderr = cmd->Process(apdu.cla, apdu.ins, apdu.p1, apdu.p2, apdu.data, apdu.le, result);
	if (cmderr != Util::Error::NoError)
		return cmderr;

	return Util::Error::NoError;
}

}

