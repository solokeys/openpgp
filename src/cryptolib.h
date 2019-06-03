/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_CRYPTOLIB_H_
#define SRC_CRYPTOLIB_H_

#include <util.h>
#include <errors.h>

namespace Crypto {

	enum KeyType {
		Symmetric,
		FullAsymmetric,
		Public,
		Private
	};

	class CryptoLib {
	private:

	public:
		Util::Error GenerateRandom(size_t length, bstr &dataOut);

		Util::Error AESEncrypt(bstr key, bstr dataIn, bstr &dataOut);
		Util::Error AESDecrypt(bstr key, bstr dataIn, bstr &dataOut);

		Util::Error RSAGenKey(bstr &keyOut);
		Util::Error RSASign(bstr key, bstr data, bstr &signature);
		Util::Error RSAVerify(bstr key, bstr data, bstr signature);

		Util::Error ECDSAGenKey(bstr &keyOut);
		Util::Error ECDSASign(bstr key, bstr data, bstr &signature);
		Util::Error ECDSAVerify(bstr key, bstr data, bstr signature);
	};

	class KeyStorage {
	private:
		uint8_t prvData[1024] = {0};
		bstr prvStr{prvData};
	public:
		KeyStorage() {prvStr.clear();};

		Util::Error GetKey(AppID_t appID, KeyID_t keyID, KeyType keyType, bstr &key);
		Util::Error SetKey(AppID_t appID, KeyID_t keyID, KeyType keyType, bstr key);
		Util::Error SetKeyExtHeader(AppID_t appID, bstr keyData, bool MorePacketsFollow);
	};

	class CryptoEngine {
	private:
		CryptoLib *cryptoLib;
		KeyStorage *keyStorage;
	public:
		Util::Error AESEncrypt(AppID_t appID, KeyID_t keyID, bstr dataIn, bstr &dataOut);
		Util::Error AESDecrypt(AppID_t appID, KeyID_t keyID, bstr dataIn, bstr &dataOut);

		Util::Error RSASign(AppID_t appID, KeyID_t keyID, bstr data, bstr &signature);
		Util::Error RSAVerify(AppID_t appID, KeyID_t keyID, bstr data, bstr signature);

		Util::Error ECDSASign(AppID_t appID, KeyID_t keyID, bstr data, bstr &signature);
		Util::Error ECDSAVerify(AppID_t appID, KeyID_t keyID, bstr data, bstr signature);
	};

}

#endif /* SRC_CRYPTOLIB_H_ */
