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
#include "apduexecutor.h"
#include "applets/appletstorage.h"
#include "applets/openpgp/openpgpfactory.h"

#include "sologlobal.h"

//namespace OpenPGP {class OpenPGPFactory;}

namespace Factory {

	using namespace Crypto;
	using namespace Applet;
	using namespace OpenPGP;

	class SoloFactory {
	private:
		AppletStorage appletStorage{*this};
		APDUExecutor apduExecutor{*this};
		CryptoEngine cryptoEngine;
		CryptoLib cryptoLib;

		OpenPGPFactory openPGPFactory{*this};
	public:
		Util::Error Init();

		APDUExecutor &GetAPDUExecutor();

		AppletStorage &GetAppletStorage();

		CryptoEngine &GetCryptoEngine();
		CryptoLib &GetCryptoLib();

		OpenPGPFactory &GetOpenPGPFactory();
	};


}

#endif /* SRC_SOLOFACTORY_H_ */
