/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_APPLETS_OPENPGP_OPENPGPFACTORY_H_
#define SRC_APPLETS_OPENPGP_OPENPGPFACTORY_H_

#include "applets/apducommand.h"
#include "apdusecuritycheck.h"
#include "resetprovider.h"
#include "solofactory.h"

namespace OpenPGP {

	class OpenPGPFactory {
	private:
		Factory::SoloFactory &soloFactory;

		ResetProvider resetProvider;
		APDUSecurityCheck apduSecurityCheck;
	public:
		OpenPGPFactory(Factory::SoloFactory &solo_factory) : soloFactory(solo_factory){};
		Applet::APDUCommand *GetAPDUCommand(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2);

		APDUSecurityCheck &GetAPDUSecurityCheck();
		ResetProvider &GetResetProvider();
	};

} /* namespace OpenPGP */

#endif /* SRC_APPLETS_OPENPGP_OPENPGPFACTORY_H_ */
