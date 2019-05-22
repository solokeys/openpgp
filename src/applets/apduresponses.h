/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef SRC_APPLETS_APDURESPONSES_H_
#define SRC_APPLETS_APDURESPONSES_H_

namespace Applet {

	enum APDUResponse {
		VerifyFailNoTryLeft 	= 0x63C0,
		MemoryWriteError		= 0x6501,
		MemoryFailure			= 0x6581,
		WrongLength				= 0x6700,
		ConditionsNotSatisfied 	= 0x6985,
		PermissionDenied		= 0x69f0,
		FileNotFound			= 0x6a82,
		OK 						= 0x9000,
	};

}

#endif /* SRC_APPLETS_APDURESPONSES_H_ */
