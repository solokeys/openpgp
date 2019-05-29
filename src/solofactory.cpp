/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "solofactory.h"

namespace Factory {

static SoloFactory soloFactory;

SoloFactory &SoloFactory::GetSoloFactory() {
	return soloFactory;
}

Util::Error SoloFactory::Init() {

	return Util::NoError;
}

APDUExecutor& Factory::SoloFactory::GetAPDUExecutor() {
	return apduExecutor;
}

AppletStorage& SoloFactory::GetAppletStorage() {
	return appletStorage;
}

CryptoEngine& SoloFactory::GetCryptoEngine() {
	return cryptoEngine;
}

CryptoLib& SoloFactory::GetCryptoLib() {
	return cryptoLib;
}

OpenPGPFactory& SoloFactory::GetOpenPGPFactory() {
	return openPGPFactory;
}

FileSystem& Factory::SoloFactory::GetFileSystem() {
	return fileSystem;
}

}
