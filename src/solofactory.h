/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef SRC_SOLOFACTORY_H_
#define SRC_SOLOFACTORY_H_

#include "cryptolib.h"
#include "applets/appletstorage.h"

namespace Factory {

	using namespace Crypto;
	using namespace Applet;

	class SoloFactory {
	private:
	public:
		Util::Error Init();

		AppletStorage *GetAppletStorage();

		CryptoEngine *GetCryptoEngine();
		CryptoLib *GetCryptoLib();
	};


}


#endif /* SRC_SOLOFACTORY_H_ */
