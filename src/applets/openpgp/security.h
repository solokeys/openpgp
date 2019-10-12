/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_APPLETS_OPENPGP_SECURITY_H_
#define SRC_APPLETS_OPENPGP_SECURITY_H_

#include <cstdint>

#include "errors.h"
#include "util.h"
#include "openpgpconst.h"
#include "openpgpstruct.h"

namespace OpenPGP {

	// OpenPGP application v3.3.1 page 35
	class Security {
	private:
		AppletState appletState;
		AppletConfig appletConfig;
		PWStatusBytes pwstatus;
		KDFDO kdfDO;
	public:
		void Init();
		void Reload();
		Util::Error AfterSaveFileLogic(uint16_t objectID);

		Util::Error GetLifeCycleState(LifeCycleState &state);
		Util::Error SetLifeCycleState(LifeCycleState state);

		Util::Error SetPasswd(Password passwdId, bstr passwords);
		Util::Error VerifyPasswd(Password passwdId, bstr passwd, bool passwdCheckFirstPart, size_t *passwdLen);
		bool PWIsEmpty(Password passwdId);
		size_t GetMaxPWLength(Password passwdId);
		Util::Error ResetPasswdTryRemains(Password passwdId);
		uint8_t PasswdTryRemains(Password passwdId);
		Util::Error ClearAllPasswd();

		void ClearAllAuth();

		void ClearAuth(Password passwdId);
		void SetAuth(Password passwdId);
		bool GetAuth(Password passwdId);

		Util::Error IncDSCounter();

		Util::Error CommandAccessCheck(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2);
		Util::Error DataObjectAccessCheck(uint16_t dataObjectID, bool writeAccess);
		Util::Error DataObjectInAllowedList(uint16_t dataObjectID);

		void Terminate();
		bool isTerminated();
		void intRESET();
	};

} /* namespace OpenPGP */

#endif /* SRC_APPLETS_OPENPGP_SECURITY_H_ */
