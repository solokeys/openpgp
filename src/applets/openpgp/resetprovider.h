/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef SRC_APPLETS_OPENPGP_RESETPROVIDER_H_
#define SRC_APPLETS_OPENPGP_RESETPROVIDER_H_

#include "errors.h"

namespace OpenPGP {

	class ResetProvider {
	public:
		Util::Error ResetCard();
	};

}


#endif /* SRC_APPLETS_OPENPGP_RESETPROVIDER_H_ */
