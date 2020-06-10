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
#include "filesystem.h"

namespace Factory {

	using namespace Crypto;
    using namespace Application;
	using namespace OpenPGP;
	using namespace File;

	class SoloFactory {
    private:
        OpenPGPFactory *openPGPFactory;
        ApplicationStorage *applicationStorage;
        APDUExecutor *apduExecutor;
        CryptoEngine *cryptoEngine;
        FileSystem *fileSystem;
    public:
        SoloFactory();

		Util::Error Init();

		APDUExecutor &GetAPDUExecutor();

        ApplicationStorage &GetApplicationStorage();

		CryptoEngine &GetCryptoEngine();
		CryptoLib &GetCryptoLib();
		KeyStorage &GetKeyStorage();

		OpenPGPFactory &GetOpenPGPFactory();
		FileSystem &GetFileSystem();

		static SoloFactory &GetSoloFactory();
	};

}

#endif /* SRC_SOLOFACTORY_H_ */
