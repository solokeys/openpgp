/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_CRYPTOLIB_H_
#define SRC_CRYPTOLIB_H_

#include <opgputil.h>
#include <cstddef>
#include <cstdint>
#include <errors.h>
#include "tlv.h"

#include "bearssl.h"

namespace Crypto {

// OpenPGP 3.3.1 page 31. RFC 4880 and 6637
enum AlgoritmID {
	None                  = 0x00,
	RSA                   = 0x01,
    ECDHforDEC            = 0x12,  // ECDSA + Curve25519
    ECDSAforCDSandIntAuth = 0x13,
    EDDSA                 = 0x16,  // Ed25519
};

// OpenPGP 3.3.1 page 31.
enum RSAKeyImportFormat {
	StandardEPQ  = 0x00, // EPQ
	StandardEPQN = 0x01,
	Crt          = 0x02, // Chinese Remainder Theorem
	CrtWithN     = 0x03
};

// ECDSA OIDs. OpenPGP 3.3.1 pages 90-92.
// decoding https://docs.microsoft.com/ru-ru/windows/win32/seccertenroll/about-object-identifier
// curve Id http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
// ansix9p256r1, OID = {1.2.840.10045.3.1.7} = ´2A8648CE3D030107´       MBEDTLS_ECP_DP_SECP256R1  BR_EC_secp256r1       23
// ansix9p384r1, OID = {1.3.132.0.34} = '2B81040022'                    MBEDTLS_ECP_DP_SECP384R1  BR_EC_secp384r1       24
// ansix9p521r1, OID = {1.3.132.0.35} = '2B81040023'                    MBEDTLS_ECP_DP_SECP521R1  BR_EC_secp521r1       25
// brainpoolP256r1, OID={1.3.36.3.3.2.8.1.1.7} = ´2B2403030208010107´   MBEDTLS_ECP_DP_BP256R1    BR_EC_brainpoolP256r1 26
// brainpoolP384r1, OID={1.3.36.3.3.2.8.1.1.11} = ´2B240303020801010B´  MBEDTLS_ECP_DP_BP384R1    BR_EC_brainpoolP384r1 27
// brainpoolP512r1, OID={1.3.36.3.3.2.8.1.1.13} = ´2B240303020801010D´  MBEDTLS_ECP_DP_BP512R1    BR_EC_brainpoolP512r1 28
// secp256k1,       OID={1.3.132.0.10}  = '2B8104000a'                  MBEDTLS_ECP_DP_SECP256K1  BR_EC_secp256k1       22 (http://www.secg.org/sec2-v2.pdf)
// EdDSA: ed25519    1.3.6.1.4.1.11591.15.1  "\x06\x09\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01"
// ECDH:  curve25519 1.3.6.1.4.1.3029.1.5.1  "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01"   BR_EC_curve25519      29
// max OID length 9 bytes

enum ECCaid {
	none,
    ansix9p256r1,    // NIST P256
    ansix9p384r1,    // NIST P384
    ansix9p521r1,    // NIST P521
	brainpoolP256r1,
	brainpoolP384r1,
	brainpoolP512r1,
    secp256k1,       // bitcoin
    ed25519,         // sign
    curve25519,      // ecdh
};


constexpr static const char* const ECCaidStr[10] = {
	"none",
	"ansix9p256r1",
	"ansix9p384r1",
	"ansix9p521r1",
	"brainpoolP256r1",
	"brainpoolP384r1",
	"brainpoolP512r1",
	"secp256k1",
    "ed25519",
    "curve25519",
};

struct ECCalgParams {
    ECCaid aid;
	bstr oid;
    int tlsCurveId;
};

/*
 * Our ID, OID, Standard curve ID. Standard curve ID are equal to the numerical in TLS:
 * http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 */
static const uint8_t tls_ec_none            = 0;
static const uint8_t tls_ec_secp256k1       = 22;
static const uint8_t tls_ec_secp256r1       = 23;
static const uint8_t tls_ec_secp384r1       = 24;
static const uint8_t tls_ec_secp521r1       = 25;
static const uint8_t tls_ec_brainpoolP256r1 = 26;
static const uint8_t tls_ec_brainpoolP384r1 = 27;
static const uint8_t tls_ec_brainpoolP512r1 = 28;
static const uint8_t tls_ec_curve25519      = 29;
static const uint8_t tls_ec_ed25519         = 100; // undefined from tls

static const std::array<ECCalgParams, 10> ECDSAalgParamsList = {{
    {none,            ""_bstr,                                         tls_ec_none},
    {ansix9p256r1,    "\x2A\x86\x48\xCE\x3D\x03\x01\x07"_bstr,         tls_ec_secp256r1},
    {ansix9p384r1,    "\x2B\x81\x04\x00\x22"_bstr,                     tls_ec_secp384r1},
    {ansix9p521r1,    "\x2B\x81\x04\x00\x23"_bstr,                     tls_ec_secp521r1},
    {brainpoolP256r1, "\x2B\x24\x03\x03\x02\x08\x01\x01\x07"_bstr,     tls_ec_brainpoolP256r1},
    {brainpoolP384r1, "\x2B\x24\x03\x03\x02\x08\x01\x01\x0B"_bstr,     tls_ec_brainpoolP384r1},
    {brainpoolP512r1, "\x2B\x24\x03\x03\x02\x08\x01\x01\x0D"_bstr,     tls_ec_brainpoolP512r1},
    {secp256k1,       "\x2B\x81\x04\x00\x0a"_bstr,                     tls_ec_secp256k1},
    {ed25519,         "\x2B\x06\x01\x04\x01\xda\x47\x0f\x01"_bstr,     tls_ec_ed25519},     // EdDSA  Ed25519
    {curve25519,      "\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01"_bstr, tls_ec_curve25519}   // ECDH   Curve25519
}};

constexpr int curveIdFromAid(const ECCaid aid) {
	for(const auto& algp: ECDSAalgParamsList) {
    	if (algp.aid == aid) {
            return algp.tlsCurveId;
    	}
    }
    return 0;
}

constexpr int curveIdFromOID(const bstr oid) {
	for(const auto& algp: ECDSAalgParamsList) {
    	if (algp.oid == oid) {
            return algp.tlsCurveId;
    	}
    }
    return 0;
}

constexpr ECCaid AIDfromOID(const bstr oid) {
	for(const auto& algp: ECDSAalgParamsList) {
    	if (algp.oid == oid) {
    		return algp.aid;
    	}
    }
    return ECCaid::none;
}

enum KeyType {
	Symmetric,
	FullAsymmetric,
	Public,
	Private
};

// OpenPGP 3.3.1 page 33
enum KeyPartsRSA {
	PublicExponent = 0x91, // key format: standard and crt
	P              = 0x92, // standard and crt
	Q              = 0x93, // standard and crt
	PQ             = 0x94, // crt
	DP1            = 0x95, // crt
	DQ1            = 0x96, // crt
	N              = 0x97  // optional for standard and crt. Modulus.
};

enum KeyPartsECC {
	PrivateKey     = 0x92, // mandatory
	PublicKey      = 0x99  // optional
};

// OpenPGP 3.3.1 page 33
struct RSAKey {
	bstr Exp; // Public exponent: e  (key format: standard and crt)
	bstr P;   // Prime1: p           (standard and crt)
	bstr Q;   // Prime2: q           (standard and crt)
	bstr PQ;  // PQ: 1/q mod p       (crt)
	bstr DP1; // DP1: d mod (p - 1)  (crt)
	bstr DQ1; // DQ1: d mod (q - 1)  (crt)
	bstr N;   // Modulus: n          (optional for standard and crt)

	constexpr void clear(){
		Exp.set_length(0);
		P.set_length(0);
		Q.set_length(0);
		PQ.set_length(0);
		DP1.set_length(0);
		DQ1.set_length(0);
		N.set_length(0);
	}

	constexpr void Print() {
		printf_device("Exp [%lu] ", Exp.length()); dump_hex(Exp, 32);
		printf_device("P [%lu] ",   P.length());   dump_hex(P, 32);
		printf_device("Q [%lu] ",   Q.length());   dump_hex(Q, 32);
		printf_device("PQ [%lu] ",  PQ.length());  dump_hex(PQ, 32);
		printf_device("DP1 [%lu] ", DP1.length()); dump_hex(DP1, 32);
		printf_device("DQ1 [%lu] ", DQ1.length()); dump_hex(DQ1, 32);
		printf_device("N [%lu] ",   N.length());   dump_hex(N, 32);
	}
};

struct ECCKey {
    ECCaid CurveId;
	bstr Private;
	bstr Public;

	void clear(){
        CurveId = ECCaid::none;
		Private.set_length(0);
		Public.set_length(0);
	}
	constexpr void Print() {
        printf_device("Curve %s\n", ECCaidStr[CurveId]);
		printf_device("Public  [%lu] ", Public.length());  dump_hex(Public,  48);
		printf_device("Private [%lu] ", Private.length()); dump_hex(Private, 48);
	}
};

class CryptoEngine;

class CryptoLib {
private:
	CryptoEngine &cryptoEngine;

    Util::Error AppendKeyPart(bstr &buffer, bstr &keypart, uint8_t *mpi, size_t mpi_len);
public:
	CryptoLib(CryptoEngine &_cryptoEngine);
    
	void ClearKeyBuffer();

	Util::Error GenerateRandom(size_t length, bstr &dataOut);

	Util::Error AESEncrypt(bstr key, bstr dataIn, bstr &dataOut);
	Util::Error AESDecrypt(bstr key, bstr dataIn, bstr &dataOut);

	Util::Error RSAGenKey(RSAKey &keyOut, size_t keySize);
	Util::Error RSACalcPublicKey(bstr strP, bstr strQ, bstr &strN);
	Util::Error RSASign(RSAKey key, bstr data, bstr &signature);
	Util::Error RSADecipher(RSAKey key, bstr data, bstr &dataOut);
	Util::Error RSAVerify(bstr publicKey, bstr data, bstr signature);

    Util::Error ECCGenKey(ECCaid curveID, ECCKey &keyOut);
    Util::Error ECCCalcPublicKey(ECCaid curveID, bstr privateKey, bstr &publicKey);
    Util::Error ECCSign(ECCKey key, bstr data, bstr &signature);
    Util::Error ECCVerify(ECCKey key, bstr data, bstr signature);
    Util::Error ECDHComputeShared(ECCKey key, bstr anotherPublicKey, bstr &sharedSecret);
};

class KeyStorage {
private:
	CryptoEngine &cryptoEngine;
public:
	KeyStorage(CryptoEngine &_cryptoEngine);

	bool KeyExists(AppID_t appID, KeyID_t keyID);

	Util::Error GetKeyPart(bstr data, Util::tag_t keyPart, bstr &dataOut);
	Util::Error GetPublicKey(AppID_t appID, KeyID_t keyID, uint8_t AlgoritmID, bstr &pubKey);
	Util::Error GetPublicKey7F49(AppID_t appID, KeyID_t keyID, uint8_t AlgoritmID, bstr &tlvKey);

	Util::Error GetRSAKey(AppID_t appID, KeyID_t keyID, RSAKey &key);
    ECCaid GetECCCurveID(AppID_t appID, KeyID_t keyID);
    Util::Error GetECCKey(AppID_t appID, KeyID_t keyID, ECCKey &key);
	Util::Error GetAESKey(AppID_t appID, KeyID_t keyID, bstr &key);
	Util::Error PutRSAFullKey(AppID_t appID, KeyID_t keyID, RSAKey key);
    Util::Error PutECCFullKey(AppID_t appID, KeyID_t keyID, ECCKey key);

	Util::Error SetKey(AppID_t appID, KeyID_t keyID, KeyType keyType, bstr key);
	Util::Error SetKeyExtHeader(AppID_t appID, bstr keyData);
};

class CryptoEngine {
private:
	CryptoLib cryptoLib{*this};
	KeyStorage keyStorage{*this};
public:
	Util::Error AESEncrypt(AppID_t appID, KeyID_t keyID, bstr dataIn, bstr &dataOut);
	Util::Error AESDecrypt(AppID_t appID, KeyID_t keyID, bstr dataIn, bstr &dataOut);

	Util::Error RSASign(AppID_t appID, KeyID_t keyID, bstr data, bstr &signature);
	Util::Error RSADecipher(AppID_t appID, KeyID_t keyID, bstr data, bstr &dataOut);
	Util::Error RSAVerify(AppID_t appID, KeyID_t keyID, bstr data, bstr signature);

    Util::Error ECCSign(AppID_t appID, KeyID_t keyID, bstr data, bstr &signature);
    Util::Error ECCVerify(AppID_t appID, KeyID_t keyID, bstr data, bstr signature);
	Util::Error ECDHComputeShared(AppID_t appID, KeyID_t keyID, bstr anotherPublicKey, bstr &sharedSecret);

	CryptoLib &getCryptoLib() {
		return cryptoLib;
	}

	KeyStorage &getKeyStorage() {
		return keyStorage;
	}

};

} // namespace Crypto

#endif /* SRC_CRYPTOLIB_H_ */
