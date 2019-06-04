/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef SRC_OPENPGP_OPENPGPSTRUCT_H_
#define SRC_OPENPGP_OPENPGPSTRUCT_H_

#include "filesystem.h"
#include "util.h"
#include "openpgpconst.h"

namespace OpenPGP {

struct AppletState {
	bool pw1Authenticated;
	bool pw3Authenticated;

	Util::Error Load();
	Util::Error Save();
};

struct AppletConfig {
	LifeCycleState state;
	bstr pw1;
	bstr pw3;

	Util::Error Load();
	Util::Error Save();
};

struct __attribute__ ((packed)) PWStatusBytes {
	uint8_t PW1ValidSeveralCDS;
	uint8_t MaxLengthAndFormatPW1;
	uint8_t MaxLengthRCforPW1;
	uint8_t MaxLengthAndFormatPW3;
	uint8_t ErrorCounterPW1;
	uint8_t ErrorCounterRC;
	uint8_t ErrorCounterPW3;

	Util::Error Load(File::FileSystem &fs);
	Util::Error Save(File::FileSystem &fs);
	void DecErrorCounter(Password passwdId);
	bool PasswdTryRemains(Password passwdId);
	void PasswdSetRemains(Password passwdId, uint8_t rem);
	void Print();
};

} // namespace OpenPGP

#endif /* SRC_OPENPGP_OPENPGPSTRUCT_H_ */
