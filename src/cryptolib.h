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
#include "tlv.h"

namespace Crypto {

// OpenPGP 3.3.1 page 31. RFC 4880 and 6637
enum AlgoritmID {
	None                  = 0x00,
	RSA                   = 0x01,
	ECDSAforCDSandIntAuth = 0x13,
	ECDHforDEC            = 0x12
};

// OpenPGP 3.3.1 page 31.
enum RSAKeyImportFormat {
	StandardEPQ  = 0x00, // EPQ
	StandardEPQN = 0x01,
	Crt          = 0x02, // Chinese Remainder Theorem
	CrtWithN     = 0x03
};

// ECDSA OIDs. OpenPGP 3.3.1 pages 90-92.
// ansix9p256r1, OID = {1.2.840.10045.3.1.7} = ´2A8648CE3D030107´
// ansix9p384r1, OID = {1.3.132.0.34} = '2B81040022'
// ansix9p521r1, OID = {1.3.132.0.35} = '2B81040023'
// brainpoolP256r1, OID={1.3.36.3.3.2.8.1.1.7} = ´2B2403030208010107´
// brainpoolP384r1, OID={1.3.36.3.3.2.8.1.1.11} = ´2B240303020801010B´
// brainpoolP512r1, OID={1.3.36.3.3.2.8.1.1.13} = ´2B240303020801010D´
// max OID length 9 bytes
enum ECDSAaid {
	ansix9p256r1,
	ansix9p384r1,
	ansix9p521r1,
	brainpoolP256r1,
	brainpoolP384r1,
	brainpoolP512r1
};

enum KeyType {
	Symmetric,
	FullAsymmetric,
	Public,
	Private
};

enum KeyPartsRSA {
	PublicExponent = 0x91, // key format: standard and crt
	P              = 0x92, // standard and crt
	Q              = 0x93, // standard and crt
	PQ             = 0x94, // crt
	DP1            = 0x95, // crt
	DQ1            = 0x96, // crt
	N              = 0x97  // optional for standard and crt. Modulus.
};

enum KeyPartsECDSA {
	PrivateKey     = 0x92, // mandatory
	PublicKey      = 0x99  // optional
};

class CryptoEngine;

class CryptoLib {
private:
	CryptoEngine &cryptoEngine;

public:
	CryptoLib(CryptoEngine &_cryptoEngine): cryptoEngine(_cryptoEngine) {};

	Util::Error GenerateRandom(size_t length, bstr &dataOut);

	Util::Error AESEncrypt(bstr key, bstr dataIn, bstr &dataOut);
	Util::Error AESDecrypt(bstr key, bstr dataIn, bstr &dataOut);

	Util::Error RSAGenKey(bstr &keyOut);
	Util::Error RSAGetPublicKey(bstr strP, bstr strQ, bstr &strN);
	Util::Error RSASign(bstr key, bstr data, bstr &signature);
	Util::Error RSAVerify(bstr key, bstr data, bstr signature);

	Util::Error ECDSAGenKey(bstr &keyOut);
	Util::Error ECDSASign(bstr key, bstr data, bstr &signature);
	Util::Error ECDSAVerify(bstr key, bstr data, bstr signature);
};

class KeyStorage {
private:
	CryptoEngine &cryptoEngine;

	uint8_t prvData[1024] = {0};
	bstr prvStr{prvData};
public:
	KeyStorage(CryptoEngine &_cryptoEngine): cryptoEngine(_cryptoEngine) {prvStr.clear();};

	Util::Error GetKeyPart(bstr data, Util::tag_t keyPart, bstr &dataOut);
	Util::Error GetPublicKey(AppID_t appID, KeyID_t keyID, uint8_t AlgoritmID, bstr &pubKey);
	Util::Error GetPublicKey7F49(AppID_t appID, KeyID_t keyID, uint8_t AlgoritmID, bstr &tlvKey);
	Util::Error GetKey(AppID_t appID, KeyID_t keyID, KeyType keyType, bstr &key);
	Util::Error SetKey(AppID_t appID, KeyID_t keyID, KeyType keyType, bstr key);
	Util::Error SetKeyExtHeader(AppID_t appID, bstr keyData, bool MorePacketsFollow);
};

class CryptoEngine {
private:
	CryptoLib cryptoLib{*this};
	KeyStorage keyStorage{*this};
public:
	Util::Error AESEncrypt(AppID_t appID, KeyID_t keyID, bstr dataIn, bstr &dataOut);
	Util::Error AESDecrypt(AppID_t appID, KeyID_t keyID, bstr dataIn, bstr &dataOut);

	Util::Error Sign(AppID_t appID, KeyID_t keyID, bstr data, bstr &signature);
	Util::Error Verify(AppID_t appID, KeyID_t keyID, bstr data, bstr signature);

	CryptoLib &getCryptoLib() {
		return cryptoLib;
	}

	KeyStorage &getKeyStorage() {
		return keyStorage;
	}

};

} // namespace Crypto

#endif /* SRC_CRYPTOLIB_H_ */
