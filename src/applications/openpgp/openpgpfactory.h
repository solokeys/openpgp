/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_OPENPGP_OPENPGPFACTORY_H_
#define SRC_OPENPGP_OPENPGPFACTORY_H_

#include <applications/openpgp/security.h>
#include <array>

#include "applications/apducommand.h"
#include "resetprovider.h"
#include "userapdu.h"
#include "cryptoapdu.h"
#include "secureapdu.h"

namespace OpenPGP {

	class OpenPGPFactory {
	public:
		// userapdu
		APDUVerify apduVerify;
		APDUChangeReferenceData apduChangeReferenceData;
		APDUResetRetryCounter apduResetRetryCounter;
		APDUGetData apduGetData;
		APDUPutData apduPutData;

		// cryptoapdu
		APDUGetChallenge apduGetChallenge;
		APDUInternalAuthenticate apduInternalAuthenticate;
		APDUGenerateAsymmetricKeyPair apduGenerateAsymmetricKeyPair;
		APDUPSO apduPSO;

		//secureapdu
		APDUActivateFile apduActivateFile;
		APDUTerminateDF apduTerminateDF;
		APDUManageSecurityEnvironment apduManageSecurityEnvironment;
		APDUSoloReboot apduSoloReboot;

		std::array<Application::APDUCommand*, 13> commands = {
			&apduVerify,
			&apduChangeReferenceData,
			&apduResetRetryCounter,
			&apduGetData,
			&apduPutData,

			&apduGetChallenge,
			&apduInternalAuthenticate,
			&apduGenerateAsymmetricKeyPair,
			&apduPSO,

			&apduActivateFile,
			&apduTerminateDF,
			&apduManageSecurityEnvironment,
			&apduSoloReboot,
		};

		ResetProvider resetProvider;
		Security security;
	public:
		Application::APDUCommand *GetAPDUCommand(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2);

		Security &GetSecurity();
		ResetProvider &GetResetProvider();
	};

} /* namespace OpenPGP */

#endif /* SRC_OPENPGP_OPENPGPFACTORY_H_ */
