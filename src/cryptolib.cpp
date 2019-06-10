/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "cryptolib.h"

#include <mbedtls/config.h>
#include <mbedtls/rsa.h>
#include <mbedtls/aes.h>
#include <mbedtls/havege.h>

#include <string.h>

#include "tlv.h"
#include "solofactory.h"
#include "filesystem.h"
#include "applets/openpgp/openpgpconst.h"

namespace Crypto {

static const bstr RSADefaultExponent = "\x01\x00\x01"_bstr;

Util::Error CryptoLib::GenerateRandom(size_t length, bstr& dataOut) {
	if (length > dataOut.max_size())
		return Util::Error::OutOfMemory;

	mbedtls_havege_state state;
	mbedtls_havege_init(&state);
	mbedtls_havege_random(nullptr, dataOut.uint8Data(), length);
	mbedtls_havege_free(&state);

	dataOut.set_length(length);

	return Util::Error::NoError;
}

Util::Error CryptoLib::AESEncrypt(bstr key, bstr dataIn,
		bstr& dataOut) {
	return Util::Error::InternalError;
}

Util::Error CryptoLib::AESDecrypt(bstr key, bstr dataIn,
		bstr& dataOut) {
	return Util::Error::InternalError;
}

Util::Error CryptoLib::RSAGenKey(bstr& keyOut) {
	return Util::Error::InternalError;
}

Util::Error CryptoLib::RSASign(RSAKey key, bstr data, bstr& signature) {

	Util::Error ret = Util::Error::NoError;

	if (key.P.length() == 0 ||
		key.Q.length() == 0 ||
		key.Exp.length() == 0
		)
		return Util::Error::CryptoDataError;

	mbedtls_rsa_context rsa;
	mbedtls_mpi N, P, Q, E;

	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&E);

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

	while (true) {
		if (mbedtls_mpi_read_binary(&P, key.P.uint8Data(), key.P.length())) {
			ret = Util::Error::CryptoDataError;
			break;
		}
		if (mbedtls_mpi_read_binary(&Q, key.Q.uint8Data(), key.Q.length())) {
			ret = Util::Error::CryptoDataError;
			break;
		}
		if (mbedtls_mpi_read_binary(&E, key.Exp.uint8Data(), key.Exp.length())) {
			ret = Util::Error::CryptoDataError;
			break;
		}
		if (key.N.length()) {
			if (mbedtls_mpi_read_binary(&N, key.N.uint8Data(), key.N.length())) {
				ret = Util::Error::CryptoDataError;
				break;
			}

			if (mbedtls_rsa_import(&rsa, &N, &P, &Q, NULL, &E)) {
				ret = Util::Error::CryptoDataError;
				break;
			}
		} else {
			if (mbedtls_rsa_import(&rsa, NULL, &P, &Q, NULL, &E)) {
				ret = Util::Error::CryptoDataError;
				break;
			}
		}

		if (mbedtls_rsa_complete(&rsa)) {
			ret = Util::Error::CryptoDataError;
			break;
		}

		if (mbedtls_rsa_check_privkey(&rsa)) {
			ret = Util::Error::CryptoDataError;
			break;
		}

		size_t keylen = mbedtls_mpi_size(&rsa.N);
		printf("rsa key length: %lu bytes, data length: %lu\n", keylen, data.length());

		// OpenPGP 3.3.1 page 54. PKCS#1
		// command data field is not longer than 40% of the length of the modulus
		if (keylen * 0.4 < data.length()) {
			printf("pkcs#1 data length error!\n");
			ret = Util::Error::CryptoDataError;
			break;
		}

		// OpenPGP 3.3.1 page 53
		uint8_t vdata[keylen] = {0};
		vdata[1] = 0x01; // Block type
		memset(&vdata[2], 0xff, keylen - data.length() - 3);
		memcpy(&vdata[keylen - data.length()], data.uint8Data(), data.length());
		dump_hex(data);
		dump_hex(vdata, keylen, 0);

		int res = mbedtls_rsa_public(&rsa, vdata, signature.uint8Data());
		if (res) {
			printf("crypto oper error: %d\n", res);
			ret = Util::Error::CryptoOperationError;
			break;
		}
		signature.set_length(keylen);


		break;
	}

	mbedtls_rsa_free(&rsa);

	return ret;
}

Util::Error CryptoLib::RSAVerify(bstr publicKey, bstr data, bstr signature) {
	return Util::Error::InternalError;
}

Util::Error CryptoLib::ECDSAGenKey(bstr& keyOut) {
	return Util::Error::InternalError;
}

Util::Error CryptoLib::ECDSASign(bstr key, bstr data, bstr& signature) {
	return Util::Error::InternalError;
}

Util::Error CryptoLib::RSACalcPublicKey(bstr strP, bstr strQ, bstr &strN) {
	Util::Error ret = Util::Error::NoError;

	mbedtls_rsa_context rsa;
	mbedtls_mpi N, P, Q;

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&Q);

	while (true) {
		if (mbedtls_mpi_read_binary(&P, strP.uint8Data(), strP.length())) {
			ret = Util::Error::CryptoDataError;
			break;
		}
		if (mbedtls_mpi_read_binary(&Q, strQ.uint8Data(), strQ.length())) {
			ret = Util::Error::CryptoDataError;
			break;
		}

		if (mbedtls_mpi_mul_mpi(&N, &P, &Q)) {
			ret = Util::Error::CryptoOperationError;
			break;
		}

		size_t length = mbedtls_mpi_size(&N);
		if (mbedtls_mpi_write_binary(&N, strN.uint8Data(), length)) {
			ret = Util::Error::CryptoDataError;
			break;
		}
		strN.set_length(length);

		break;
	}

	mbedtls_rsa_free(&rsa);
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&P);
	mbedtls_mpi_free(&Q);

	return ret;
}

Util::Error CryptoLib::ECDSAVerify(bstr key, bstr data,
		bstr signature) {
	return Util::Error::InternalError;
}

Util::Error KeyStorage::GetECDSAPrivateKey(AppID_t appID, KeyID_t keyID, bstr& key) {
	return Util::Error::InternalError;
}

Util::Error KeyStorage::SetKey(AppID_t appID, KeyID_t keyID,
		KeyType keyType, bstr key) {
	return Util::Error::InternalError;
}

Util::Error KeyStorage::GetKeyPart(bstr dataIn, Util::tag_t keyPart,
		bstr& dataOut) {
	dataOut.set_length(0);

	Util::TLVTree tlv;
	auto err = tlv.Init(dataIn);
	if (err != Util::Error::NoError) {
		dataIn.clear();
		return err;
	}

	Util::TLVElm *eheader = tlv.Search(0x7f48);
	if (!eheader || eheader->Length() == 0)
		return Util::Error::StoredKeyError;

	bstr header = eheader->GetData();

	Util::DOL dol;
	err = dol.Init(header);
	if (err != Util::Error::NoError) {
		dataIn.clear();
		return err;
	}

	Util::TLVElm *edata = tlv.Search(0x5f48);
	if (!edata || edata->Length() == 0)
		return Util::Error::StoredKeyError;

	bstr data = edata->GetData();

	//printf("key %lu %lu\n ------------ dol --------------\n", header.length(), data.length());
	//dol.Print();

	size_t offset = 0;
	size_t length = 0;
	err = dol.Search(keyPart, offset, length);
	if (offset + length > data.length() || length == 0)
		return Util::Error::StoredKeyError;

	dataOut = data.substr(offset, length);
	return Util::Error::NoError;
}

Util::Error KeyStorage::GetPublicKey(AppID_t appID, KeyID_t keyID, uint8_t AlgoritmID,
		bstr& pubKey) {

	pubKey.clear();

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();
	CryptoLib &crypto = cryptoEngine.getCryptoLib();

	printf("GetPublicKey key %x [%lu] loaded.\n", keyID, prvStr.length());

	if (AlgoritmID == Crypto::AlgoritmID::RSA) {
		RSAKey rsa_key;
		auto err = GetRSAKey(appID, keyID, rsa_key);
		if (err != Util::Error::NoError)
			return err;

		if (rsa_key.P.length() != 0 &&
			rsa_key.Q.length() != 0 &&
			rsa_key.N.length() == 0){
			err = crypto.RSACalcPublicKey(rsa_key.P, rsa_key.Q, pubKey);
			if (err != Util::Error::NoError)
				return err;
		} else {
			pubKey = rsa_key.N;
		}
	} else {
		// TODO: move to GetECDSAKey

		// clear key storage
		prvStr.clear();
		auto err = filesystem.ReadFile(appID, keyID, File::Secure, prvStr);
		if (err != Util::Error::NoError)
			return err;

		err = GetKeyPart(prvStr, KeyPartsECDSA::PublicKey, pubKey);
		if (err != Util::Error::NoError || pubKey.length() == 0) {
			bstr privateKey;
			err = GetKeyPart(prvStr, KeyPartsECDSA::PrivateKey, privateKey);
			if (err != Util::Error::NoError)
				return err;

			printf("Private len: %lu", privateKey.length());
			dump_hex(privateKey);

			// TODO: add ECDSA calc public key from private!!!!

			return Util::Error::InternalError;
		}

	}

	return Util::Error::NoError;
}

Util::Error KeyStorage::GetPublicKey7F49(AppID_t appID, KeyID_t keyID,
		uint8_t AlgoritmID, bstr& tlvKey) {

	uint8_t _pubKey[1024] = {0};
	bstr pubKey{_pubKey, sizeof(_pubKey)};
	auto err = GetPublicKey(appID, keyID, AlgoritmID, pubKey);
	if (err != Util::Error::NoError)
		return err;

	printf("pubKey: %lu\n", pubKey.length());
	dump_hex(pubKey);

	Util::TLVTree tlv;
	tlv.Init(tlvKey);
	tlv.AddRoot(0x7f49);

	if (AlgoritmID == Crypto::AlgoritmID::RSA) {
		bstr strExp;
		// prvStr was filled by GetPublicKey
		err = GetKeyPart(prvStr, KeyPartsRSA::PublicExponent, strExp);
		if (err != Util::Error::NoError)
			return err;

		tlv.AddChild(0x81, &pubKey);
		tlv.AddNext(0x82, &strExp);
		tlv.PrintTree();

	} else {
		tlv.AddChild(0x86, &pubKey);
	}

	tlvKey = tlv.GetDataLink();
	return Util::Error::NoError;
}

Util::Error KeyStorage::GetRSAKey(AppID_t appID, KeyID_t keyID, RSAKey& key) {

	key.clear();

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	// clear key storage
	prvStr.clear();
	auto err = filesystem.ReadFile(appID, keyID, File::Secure, prvStr);
	if (err != Util::Error::NoError)
		return err;

	printf("key %x [%lu] loaded.\n", keyID, prvStr.length());

	GetKeyPart(prvStr, KeyPartsRSA::PublicExponent, key.Exp);
	GetKeyPart(prvStr, KeyPartsRSA::P, key.P);
	GetKeyPart(prvStr, KeyPartsRSA::Q, key.Q);
	GetKeyPart(prvStr, KeyPartsRSA::PQ, key.PQ);
	GetKeyPart(prvStr, KeyPartsRSA::DP1, key.DP1);
	GetKeyPart(prvStr, KeyPartsRSA::DQ1, key.DQ1);
	GetKeyPart(prvStr, KeyPartsRSA::N, key.N);

	if ((key.P.length() == 0 ||
		 key.Q.length() == 0) &&
		key.N.length() == 0)
		return Util::Error::CryptoDataError;

	if (key.Exp.length() == 0)
		key.Exp = RSADefaultExponent;

	return Util::Error::NoError;
}

Util::Error KeyStorage::SetKeyExtHeader(AppID_t appID, bstr keyData) {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	Util::TLVTree tlv;
	auto err = tlv.Init(keyData);
	if (err != Util::Error::NoError)
		return err;

	printf("-------------- tlv -----------------\n");
	tlv.PrintTree();

	// check wrong format
	if (tlv.CurrentElm().Tag() != 0x4d)
		return Util::Error::WrongData;

	using namespace OpenPGP;
	OpenPGPKeyType type = OpenPGPKeyType::Unknown;
	if (tlv.Search(OpenPGPKeyType::DigitalSignature) != nullptr)
		type = OpenPGPKeyType::DigitalSignature;
	if (tlv.Search(OpenPGPKeyType::Confidentiality) != nullptr)
		type = OpenPGPKeyType::Confidentiality;
	if (tlv.Search(OpenPGPKeyType::Authentication) != nullptr)
		type = OpenPGPKeyType::Authentication;

	if (type == OpenPGPKeyType::Unknown)
		return Util::Error::WrongData;

	printf("save key data [%02x] len:%lu\n", type, keyData.length());
	return filesystem.WriteFile(appID, type, File::Secure, keyData);
}

Util::Error CryptoEngine::AESEncrypt(AppID_t appID, KeyID_t keyID,
		bstr dataIn, bstr& dataOut) {
	return Util::Error::InternalError;
}

Util::Error CryptoEngine::AESDecrypt(AppID_t appID, KeyID_t keyID,
		bstr dataIn, bstr& dataOut) {
	return Util::Error::InternalError;
}

Util::Error CryptoEngine::RSASign(AppID_t appID, KeyID_t keyID,
		bstr data, bstr& signature) {

	RSAKey key;
	auto err = keyStorage.GetRSAKey(appID, keyID, key);
	if (err != Util::Error::NoError)
		return err;

	return cryptoLib.RSASign(key, data, signature);
}

Util::Error CryptoEngine::RSAVerify(AppID_t appID, KeyID_t keyID,
		bstr data, bstr signature) {
	return Util::Error::InternalError;
}

Util::Error CryptoEngine::ECDSASign(AppID_t appID, KeyID_t keyID,
		bstr data, bstr& signature) {

	uint8_t _key[520] = {0};
	bstr key(_key, 0, sizeof(_key));
	auto err = keyStorage.GetPublicKey(appID, keyID, AlgoritmID::ECDSAforCDSandIntAuth, key);
	if (err != Util::Error::NoError)
		return err;

	return Util::Error::InternalError;
}

Util::Error CryptoEngine::ECDSAVerify(AppID_t appID, KeyID_t keyID,
		bstr data, bstr signature) {
	return Util::Error::InternalError;
}

} // namespace Crypto

