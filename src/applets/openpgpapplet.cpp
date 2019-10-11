/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include <applets/openpgp/security.h>
#include "openpgpapplet.h"
#include "apduconst.h"
#include "solofactory.h"

namespace Applet {

OpenPGPApplet::OpenPGPApplet() : Applet() {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	security.Init();
}

Util::Error OpenPGPApplet::Select(bstr &result) {
	auto err = Applet::Select(result);

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();

	security.Init();

	if (security.isTerminated())
		return Util::Error::ApplicationTerminated;

	return err;
}

const bstr* OpenPGPApplet::GetAID() {
	return &aid;
}

Util::Error OpenPGPApplet::APDUExchange(bstr header, bstr data, uint8_t le, bstr &result) {
	result.clear();

	if (!selected)
		return Util::Error::AppletNotSelected;

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	OpenPGP::OpenPGPFactory &opgp_factory = solo.GetOpenPGPFactory();
	OpenPGP::Security &security = opgp_factory.GetSecurity();


	printf("0>"); dump_hex(header); dump_hex(data);

	auto cla = header[0];
	auto ins = header[1];
	auto p1 = header[2];
	auto p2 = header[3];

	auto err = security.CommandAccessCheck(cla, ins, p1, p2);
	if (err != Util::Error::NoError) {
		printf("Security error. Access denied.\n");
		return err;
	}

	auto cmd = opgp_factory.GetAPDUCommand(cla, ins, p1, p2);
	if (!cmd)
		return Util::Error::WrongCommand;

	auto cmderr = cmd->Process(cla, ins, p1, p2, data, le, result);
	if (cmderr != Util::Error::NoError)
		return cmderr;

	printf("0<"); dump_hex(result);

	return Util::Error::NoError;
}

}

