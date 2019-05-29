/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_OPENPGP_OPENPGPFACTORY_H_
#define SRC_OPENPGP_OPENPGPFACTORY_H_

#include <array>

#include "applets/apducommand.h"
#include "apdusecuritycheck.h"
#include "resetprovider.h"
#include "userapdu.h"

namespace OpenPGP {

	class OpenPGPFactory {
	public:
		// userapdu
		APDUVerify apduVerify;
		APDUChangeReferenceData apduChangeReferenceData;
		APDUResetRetryCounter apduResetRetryCounter;
		APDUGetData apduGetData;
		APDUPutData apduPutData;


		std::array<Applet::APDUCommand*, 5> commands = {
			&apduVerify,
			&apduChangeReferenceData,
			&apduResetRetryCounter,
			&apduGetData,
			&apduPutData
		};

		ResetProvider resetProvider;
		APDUSecurityCheck apduSecurityCheck;
	public:
		Applet::APDUCommand *GetAPDUCommand(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2);

		APDUSecurityCheck &GetAPDUSecurityCheck();
		ResetProvider &GetResetProvider();
	};

} /* namespace OpenPGP */

#endif /* SRC_OPENPGP_OPENPGPFACTORY_H_ */
