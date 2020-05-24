/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "solofactory.h"

namespace Factory {

using namespace Crypto;
using namespace Applet;
using namespace OpenPGP;
using namespace File;

SoloFactory &SoloFactory::GetSoloFactory() {
    PUT_TO_SRAM2 static SoloFactory soloFactory;
	return soloFactory;
}

SoloFactory::SoloFactory() {
}

Util::Error SoloFactory::Init() {
    static PUT_TO_SRAM2 OpenPGPFactory sopenPGPFactory;
    static PUT_TO_SRAM2 AppletStorage sappletStorage;
    static PUT_TO_SRAM2 APDUExecutor sapduExecutor;
    static PUT_TO_SRAM2 CryptoEngine scryptoEngine;
    static PUT_TO_SRAM2 FileSystem sfileSystem;

    openPGPFactory = &sopenPGPFactory;
    appletStorage = &sappletStorage;
    apduExecutor = &sapduExecutor;
    cryptoEngine = &scryptoEngine;
    fileSystem = &sfileSystem;

	return Util::NoError;
}

APDUExecutor& Factory::SoloFactory::GetAPDUExecutor() {
    return *apduExecutor;
}

AppletStorage& SoloFactory::GetAppletStorage() {
    return *appletStorage;
}

CryptoEngine& SoloFactory::GetCryptoEngine() {
    return *cryptoEngine;
}

CryptoLib& SoloFactory::GetCryptoLib() {
    return cryptoEngine->getCryptoLib();
}

KeyStorage& Factory::SoloFactory::GetKeyStorage() {
    return cryptoEngine->getKeyStorage();
}

OpenPGPFactory& SoloFactory::GetOpenPGPFactory() {
    return *openPGPFactory;
}

FileSystem& Factory::SoloFactory::GetFileSystem() {
    return *fileSystem;
}

}

