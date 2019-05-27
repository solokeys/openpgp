/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef SRC_APPLETS_APDUCONST_H_
#define SRC_APPLETS_APDUCONST_H_

namespace Applet {

	enum APDUResponse {
		SelectInTerminationState 	= 0x6285,
		VerifyFailNoTryLeft 		= 0x63C0,
		MemoryWriteError			= 0x6501,
		MemoryFailure				= 0x6581,
		WrongLength					= 0x6700,
		LogicalChannelNotSupported	= 0x6881,
		SecureMessagingNotSupport	= 0x6882,
		LastCmdOfChainExpected		= 0x6883,
		CommandChainingNotSupported	= 0x6884,
		SecurityStatusNotSatisfied	= 0x6982,
		AuthenticationMethodBlocked	= 0x6983,
		ConditionsUseNotSatisfied	= 0x6985,
		ExpectedSMObjectsMissing	= 0x6987,
		SMdataObjectsIncorrect	 	= 0x6988,
		PermissionDenied			= 0x69f0,
		IncorrectParamInDataField	= 0x6a80,
		FileNotFound				= 0x6a82,
		WrongParametersP1orP2		= 0x6b00,
		INSnotSupported				= 0x6d00,
		CLAnotSupported				= 0x6e00,
		InternalException			= 0x6f00,
		OK 							= 0x9000,
	};

	enum APDUcommands {
		Select					= 0xa4,
		SelectData				= 0xa5,
		GetData					= 0xca,
		GetNextData				= 0xcc,
		Verify					= 0x20,
		ChangeReferenceData		= 0x24,
		ResetRetryCounter		= 0x2c,
		PutData					= 0xda,
		PutData2				= 0xdb,
		GenerateAsymmKeyPair	= 0x47,
		PSO						= 0x2a,
		Internalauthenticate	= 0x88,
		GetChallenge			= 0x84,
		ManageSecurityEnv		= 0x22,
		TerminateDF				= 0xe6,
		ActivateFile			= 0x44,
	};

}

#endif /* SRC_APPLETS_APDUCONST_H_ */
