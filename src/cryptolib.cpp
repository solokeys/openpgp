/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "cryptolib.h"
#include "solofactory.h"
#include "filesystem.h"
#include "tlv.h"
#include "applets/openpgp/openpgpconst.h"

namespace Crypto {

Util::Error CryptoLib::GenerateRandom(size_t length, bstr& dataOut) {
	return Util::Error::InternalError;
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

Util::Error CryptoLib::RSASign(bstr key, bstr data, bstr& signature) {
	return Util::Error::InternalError;
}

Util::Error CryptoLib::RSAVerify(bstr key, bstr data, bstr signature) {
	return Util::Error::InternalError;
}

Util::Error CryptoLib::ECDSAGenKey(bstr& keyOut) {
	return Util::Error::InternalError;
}

Util::Error CryptoLib::ECDSASign(bstr key, bstr data, bstr& signature) {
	return Util::Error::InternalError;
}

Util::Error CryptoLib::ECDSAVerify(bstr key, bstr data,
		bstr signature) {
	return Util::Error::InternalError;
}

Util::Error KeyStorage::GetKey(AppID_t appID, KeyID_t keyID,
		KeyType keyType, bstr& key) {
	return Util::Error::InternalError;
}

Util::Error KeyStorage::SetKey(AppID_t appID, KeyID_t keyID,
		KeyType keyType, bstr key) {
	return Util::Error::InternalError;
}

Util::Error KeyStorage::GetPublicKey(AppID_t appID, KeyID_t keyID,
		bstr& tlvKey) {

	tlvKey.clear();

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	// clear key storage
	prvStr.clear();
	auto err = filesystem.ReadFile(appID, keyID, File::Secure, prvStr);
	if (err != Util::Error::NoError)
		return err;

	printf("key %x [%lu] loaded.\n", keyID, prvStr.length());

	Util::TLVTree tlv;
	err = tlv.Init(prvStr);
	if (err != Util::Error::NoError) {
		prvStr.clear();
		return err;
	}

	Util::TLVElm *eheader = tlv.Search(0x7f48);
	if (!eheader || eheader->Length() == 0)
		return Util::Error::StoredKeyError;

	bstr header = eheader->GetData();

	Util::DOL dol;
	err = dol.Init(header);
	if (err != Util::Error::NoError) {
		prvStr.clear();
		return err;
	}

	Util::TLVElm *edata = tlv.Search(0x5f48);
	if (!edata || edata->Length() == 0)
		return Util::Error::StoredKeyError;

	bstr data = edata->GetData();

	printf("key %lu %lu. tag1: %x\n", header.length(), data.length(), dol.CurrentElm().Tag());
	// TODO: dataOut.append("\7f\49\00............"_bstr);

	return Util::Error::NoError;
}

Util::Error KeyStorage::SetKeyExtHeader(AppID_t appID, bstr keyData,
		bool MorePacketsFollow) {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	// TODO: not a good way to check first packet.
	if (keyData[0] == 0x4d)
		prvStr.clear();

	prvStr.append(keyData);

	if (!MorePacketsFollow) {
		Util::TLVTree tlv;
		auto err = tlv.Init(prvStr);
		if (err != Util::Error::NoError) {
			prvStr.clear();
			return err;
		}

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

		printf("save key data [%02x] len:%lu\n", type, prvStr.length());
		filesystem.WriteFile(appID, type, File::Secure, prvStr);
	}

	return Util::Error::InternalError;
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
	return Util::Error::InternalError;
}

Util::Error CryptoEngine::RSAVerify(AppID_t appID, KeyID_t keyID,
		bstr data, bstr signature) {
	return Util::Error::InternalError;
}

Util::Error CryptoEngine::ECDSASign(AppID_t appID, KeyID_t keyID,
		bstr data, bstr& signature) {
	return Util::Error::InternalError;
}

Util::Error CryptoEngine::ECDSAVerify(AppID_t appID, KeyID_t keyID,
		bstr data, bstr signature) {
	return Util::Error::InternalError;
}

} // namespace Crypto
