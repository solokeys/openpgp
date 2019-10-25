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
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <string.h>

#include "tlv.h"
#include "solofactory.h"
#include "filesystem.h"
#include "applets/openpgp/openpgpconst.h"

namespace Crypto {

static const bstr RSADefaultExponent = "\x01\x00\x01"_bstr;

void CryptoLib::ClearKeyBuffer() {
	memset(_KeyBuffer, 0x00, sizeof(_KeyBuffer));
	KeyBuffer.clear();
}


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
	dataOut.clear();
	uint8_t iv[64] = {0};

	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	if (mbedtls_aes_setkey_enc(&aes, key.uint8Data(), key.length() * 8))
		return Util::Error::StoredKeyError;
	if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, dataIn.length(), iv, dataIn.uint8Data(), dataOut.uint8Data()))
		return Util::Error::CryptoOperationError;
	mbedtls_aes_free(&aes);

	dataOut.set_length(dataIn.length());
	return Util::Error::NoError;
}

Util::Error CryptoLib::AESDecrypt(bstr key, bstr dataIn,
		bstr& dataOut) {
	dataOut.clear();
	uint8_t iv[64] = {0};

	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	if (mbedtls_aes_setkey_dec(&aes, key.uint8Data(), key.length() * 8))
		return Util::Error::StoredKeyError;
	if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, dataIn.length(), iv, dataIn.uint8Data(), dataOut.uint8Data()))
		return Util::Error::CryptoOperationError;
	mbedtls_aes_free(&aes);

	dataOut.set_length(dataIn.length());
	return Util::Error::NoError;
}

Util::Error CryptoLib::AppendKeyPart(bstr &buffer, bstr &keypart, mbedtls_mpi *mpi) {
	size_t mpi_len = mbedtls_mpi_size(mpi);
	if (mpi_len > 0) {
		if (mbedtls_mpi_write_binary(mpi, buffer.uint8Data() + buffer.length(), mpi_len))
			return Util::Error::CryptoDataError;

		keypart = bstr(buffer.uint8Data() + buffer.length(), mpi_len);
		buffer.set_length(buffer.length() + mpi_len);
	}
	return Util::Error::NoError;
}

Util::Error CryptoLib::AppendKeyPartEcpPoint(bstr &buffer, bstr &keypart,  mbedtls_ecp_group *grp, mbedtls_ecp_point  *point) {
	size_t mpi_len = 0;
	if (mbedtls_ecp_point_write_binary(
			grp,
			point,
			MBEDTLS_ECP_PF_UNCOMPRESSED,
			&mpi_len,
			buffer.uint8Data() + buffer.length(),
			buffer.free_space()) )
		return Util::Error::CryptoDataError;

	keypart = bstr(buffer.uint8Data() + buffer.length(), mpi_len);
	buffer.set_length(buffer.length() + mpi_len);

	return Util::Error::NoError;
}

Util::Error CryptoLib::RSAGenKey(RSAKey& keyOut, size_t keySize) {

	Util::Error ret = Util::Error::NoError;
	ClearKeyBuffer();

	mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_mpi N, P, Q, D, E;

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);

	while (true) {
	    const char *pers = "solokey_openpgp";
	    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
	    		(const unsigned char *)pers, strlen(pers))) {
			ret = Util::Error::CryptoOperationError;
			break;
	    }

		// OpenPGP 3.3.1 pages 33,34
		if (mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, keySize, 65537)) {
			ret = Util::Error::CryptoOperationError;
			break;
		}

        // crt: mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP)
	    if (mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E)) {
			ret = Util::Error::CryptoOperationError;
			break;
	    }

	    KeyBuffer.clear();

	    AppendKeyPart(KeyBuffer, keyOut.Exp, &E);
	    AppendKeyPart(KeyBuffer, keyOut.P, &P);
	    AppendKeyPart(KeyBuffer, keyOut.Q, &Q);
	    AppendKeyPart(KeyBuffer, keyOut.N, &N);

		// check
		if (keyOut.P.length() == 0 || keyOut.Q.length() == 0 || keyOut.Exp.length() == 0) {
			ret = Util::Error::CryptoDataError;
			break;
		}

		break;
	}

    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
	mbedtls_rsa_free(&rsa);

	return ret;
}

Util::Error CryptoLib::RSAFillPrivateKey(mbedtls_rsa_context *context,
		RSAKey key) {

	Util::Error ret = Util::Error::NoError;

	mbedtls_mpi N, P, Q, E;

	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&E);

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
		if (mbedtls_rsa_import(context, NULL, &P, &Q, NULL, &E)) {
			ret = Util::Error::CryptoDataError;
			break;
		}
		if (key.N.length()) {
			if (mbedtls_mpi_read_binary(&N, key.N.uint8Data(), key.N.length())) {
				ret = Util::Error::CryptoDataError;
				break;
			}

			if (mbedtls_rsa_import(context, &N, NULL, NULL, NULL, NULL)) {
				ret = Util::Error::CryptoDataError;
				break;
			}
		}

		if (int res=mbedtls_rsa_complete(context)) {
			printf("error: cant complete key %d %x\n",res,-res);
			ret = Util::Error::CryptoDataError;
			break;
		}

		if (mbedtls_rsa_check_privkey(context)) {
			printf("error: cant check key\n");
			ret = Util::Error::CryptoDataError;
			break;
		}

		break;
	}

	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&P);
	mbedtls_mpi_free(&Q);
	mbedtls_mpi_free(&E);

	return ret;
}

Util::Error CryptoLib::RSASign(RSAKey key, bstr data, bstr& signature) {

	Util::Error ret = Util::Error::NoError;

	if (key.P.length() == 0 ||
		key.Q.length() == 0 ||
		key.Exp.length() == 0
		)
		return Util::Error::CryptoDataError;

	mbedtls_rsa_context rsa;

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

	while (true) {
		ret = RSAFillPrivateKey(&rsa, key);
		if (ret != Util::Error::NoError)
			break;

		size_t keylen = mbedtls_mpi_size(&rsa.N);

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

		memset(signature.uint8Data(), 0x00, keylen);

		int res = mbedtls_rsa_private(&rsa, nullptr, nullptr, vdata, signature.uint8Data());
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

Util::Error CryptoLib::RSADecipher(RSAKey key, bstr data, bstr &dataOut) {
	Util::Error ret = Util::Error::NoError;

	if (key.P.length() == 0 ||
		key.Q.length() == 0 ||
		key.Exp.length() == 0
		)
		return Util::Error::CryptoDataError;

	mbedtls_rsa_context rsa;

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

	while (true) {
		ret = RSAFillPrivateKey(&rsa, key);
		if (ret != Util::Error::NoError)
			break;

		size_t keylen = mbedtls_mpi_size(&rsa.N);

		if (keylen != data.length()) {
			ret = Util::Error::CryptoDataError;
			break;
		}

		int res = mbedtls_rsa_private(&rsa, nullptr, nullptr, data.uint8Data(), dataOut.uint8Data());
		if (res) {
			printf("crypto oper error: %d\n", res);
			ret = Util::Error::CryptoOperationError;
			break;
		}
		dataOut.set_length(keylen);
		break;
	}

	mbedtls_rsa_free(&rsa);

	// check and get rid of PKCS#1 header
	// OpenPGP 3.3.1 page 57
	if (dataOut[0] != 0x00 || dataOut[1] != 0x02) {
		dataOut.clear();
		return Util::Error::CryptoResultError;
	}

	size_t ptr = 2;
	for (size_t i = 2; i < dataOut.length(); i++)
		if (dataOut[i] == 0x00) {
			ptr = i;
			break;
		}

	// The length of PS shall be at least 8 bytes. OpenPGP 3.3.1 page 57
	if (ptr < 10) {
		dataOut.clear();
		return Util::Error::CryptoResultError;
	}

	dataOut.del(0, ptr + 1);

	return ret;
}

Util::Error CryptoLib::RSAVerify(bstr publicKey, bstr data, bstr signature) {
	return Util::Error::InternalError;
}

static int ecdsa_init(mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id curveID, uint8_t *key_d, uint8_t *key_xy) {
	if (!ctx)
		return 1;

	int res;

	mbedtls_ecdsa_init(ctx);
	res = mbedtls_ecp_group_load(&ctx->grp, curveID);
	if (res)
		return res;

	size_t keylen = (ctx->grp.nbits + 7 ) / 8;
	if (key_d) {
		res = mbedtls_mpi_read_binary(&ctx->d, key_d, keylen);
		if (res)
			return res;
	}

	if (key_xy) {
		res = mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->Q, key_xy, keylen * 2 + 1);
		if (res)
			return res;
	}

	return 0;
};

Util::Error CryptoLib::ECDSAGenKey(ECDSAaid curveID, ECDSAKey& keyOut) {
	ClearKeyBuffer();
	keyOut.clear();

	if (curveID == ECDSAaid::none)
		return  Util::Error::StoredKeyParamsError;

	mbedtls_ecdsa_context ctx;

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "ecdsa solokeys generate";

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	Util::Error err = Util::Error::InternalError;
	mbedtls_ecp_group_id groupid = MbedtlsCurvefromAid(curveID);

	while (true) {
		if (ecdsa_init(&ctx, groupid, NULL, NULL))
			break;

		if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)))
			break;

		if (mbedtls_ecdsa_genkey(&ctx, groupid, mbedtls_ctr_drbg_random, &ctr_drbg))
			break;

		keyOut.CurveId = curveID;
	    AppendKeyPart(KeyBuffer, keyOut.Private, &ctx.d);
	    AppendKeyPartEcpPoint(KeyBuffer, keyOut.Public,  &ctx.grp, &ctx.Q);

		err =  Util::Error::NoError;
		break;
	}

	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_ecdsa_free(&ctx);
	return err;

}

Util::Error CryptoLib::ECDSASign(ECDSAKey key, bstr data, bstr& signature) {
	signature.clear();

	mbedtls_mpi r, s;
	mbedtls_ecdsa_context ctx;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);


	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "ecdsa solokeys signature";

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	Util::Error ret = Util::Error::InternalError;

	while (true) {
		if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) {
			ret =  Util::Error::CryptoOperationError;
			break;
		}

		if (ecdsa_init(&ctx, MbedtlsCurvefromAid(key.CurveId), key.Private.uint8Data(), key.Public.uint8Data())) {
			ret = Util::Error::CryptoDataError;
			break;
		}

		if (mbedtls_ecdsa_sign(
				&ctx.grp,
				&r,
				&s,
				&ctx.d,
				data.uint8Data(),
				data.length(),
				mbedtls_ctr_drbg_random,
				&ctr_drbg)) {
			ret =  Util::Error::CryptoOperationError;
			break;
		}

		size_t mpi_len = mbedtls_mpi_size(&r);
		if (mbedtls_mpi_write_binary(&r, signature.uint8Data(), mpi_len)) {
			ret = Util::Error::CryptoDataError;
			break;
		}
		signature.set_length(mpi_len);

		mpi_len = mbedtls_mpi_size(&s);
		if (mbedtls_mpi_write_binary(&s, signature.uint8Data() + signature.length(), mpi_len)) {
			ret = Util::Error::CryptoDataError;
			break;
		}
		signature.set_length(signature.length() + mpi_len);

		ret =  Util::Error::NoError;
		break;
	}


	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_ecdsa_free(&ctx);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return ret;
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

Util::Error CryptoLib::ECDSACalcPublicKey(ECDSAaid curveID, bstr privateKey, bstr &publicKey) {
	Util::Error ret = Util::Error::NoError;

	mbedtls_ecdsa_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "ecdsa solokeys public key";

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	while (true) {
		if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) {
			ret = Util::Error::CryptoOperationError;
			break;
		}

		if (ecdsa_init(&ctx, MbedtlsCurvefromAid(curveID), privateKey.uint8Data(), NULL)) {
			ret = Util::Error::CryptoDataError;
			break;
		}

		// Q = d * P
		if (mbedtls_ecp_mul( &ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, mbedtls_ctr_drbg_random, &ctr_drbg)) {
			ret = Util::Error::CryptoOperationError;
			break;
		}

		if (mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Q)) {
			ret = Util::Error::CryptoDataError;
			break;
		}

		size_t point_len = 0;
		if (mbedtls_ecp_point_write_binary(
				&ctx.grp,
				&ctx.Q,
				MBEDTLS_ECP_PF_UNCOMPRESSED,
				&point_len,
				publicKey.uint8Data(),
				publicKey.free_space()) ) {
			ret = Util::Error::CryptoDataError;
			break;
		}
		publicKey.set_length(point_len);
		break;
	}

	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_ecdsa_free(&ctx);
	return ret;
}

Util::Error CryptoLib::ECDSAVerify(ECDSAKey key, bstr data,
		bstr signature) {
	return Util::Error::InternalError;
}

bool KeyStorage::KeyExists(AppID_t appID, KeyID_t keyID) {
	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();
	File::GenericFileSystem &gf = filesystem.getGenFiles();

	return gf.FileExist(appID, keyID, File::FileType::Secure);
}

Util::Error LoadKeyParameters(AppID_t appID, KeyID_t keyID, OpenPGP::AlgoritmAttr& keyParams) {

	keyParams.Clear();

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	return keyParams.Load(filesystem, keyID);
}

ECDSAaid KeyStorage::GetECDSACurveID(AppID_t appID, KeyID_t keyID) {
	OpenPGP::AlgoritmAttr keyParams;
	auto err = LoadKeyParameters(appID, keyID, keyParams);
	if (err != Util::Error::NoError)
		return ECDSAaid::none;

	if (keyParams.AlgorithmID != AlgoritmID::ECDSAforCDSandIntAuth &&
		keyParams.AlgorithmID != AlgoritmID::ECDHforDEC)
		return ECDSAaid::none;

	return AIDfromOID(keyParams.ECDSAa.OID);
}

Util::Error KeyStorage::GetECDSAKey(AppID_t appID, KeyID_t keyID, ECDSAKey& key) {

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();
	CryptoLib &cryptolib = cryptoEngine.getCryptoLib();

	// clear key storage
	prvStr.clear();
	auto err = filesystem.ReadFile(appID, keyID, File::Secure, prvStr);
	if (err != Util::Error::NoError)
		return err;

	KeyID_t fileID = 0;
	if (keyID == OpenPGP::OpenPGPKeyType::DigitalSignature)
		fileID = 0xc1;
	if (keyID == OpenPGP::OpenPGPKeyType::Confidentiality)
		fileID = 0xc2;
	if (keyID == OpenPGP::OpenPGPKeyType::Authentication)
		fileID = 0xc3;

	if (fileID == 0x00)
		return Util::Error::StoredKeyParamsError;

	key.CurveId = GetECDSACurveID(appID, fileID);
	if (key.CurveId == ECDSAaid::none)
		return Util::Error::StoredKeyParamsError;

	GetKeyPart(prvStr, KeyPartsECDSA::PublicKey, key.Public);
	GetKeyPart(prvStr, KeyPartsECDSA::PrivateKey, key.Private);

	if (key.Public.length() == 0 && key.Private.length() > 0) {

		key.Public = bstr(prvStr.uint8Data() + prvStr.length(), 0, prvStr.free_space());
		auto err = cryptolib.ECDSACalcPublicKey(key.CurveId, key.Private, key.Public);
		if (err != Util::Error::NoError)
			return err;
	}

	return Util::Error::NoError;
}

Util::Error KeyStorage::GetAESKey(AppID_t appID, KeyID_t keyID, bstr &key) {
	key.clear();

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();

	// clear key storage
	prvStr.clear();

	auto err = filesystem.ReadFile(appID, keyID, File::Secure, prvStr);
	if (err != Util::Error::NoError)
		return err;

	if (prvStr.length() == 0 || (prvStr.length() != 16 && prvStr.length() != 24 && prvStr.length() != 32))
		return Util::Error::StoredKeyError;

	key = prvStr;

	return Util::Error::NoError;
}

Util::Error KeyStorage::SetKey(AppID_t appID, KeyID_t keyID,
		KeyType keyType, bstr key) {
	return Util::Error::InternalError;
}

Util::Error KeyStorage::PutRSAFullKey(AppID_t appID, KeyID_t keyID, RSAKey key) {

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();
	using namespace Util;

	prvStr.clear();

	TLVTree tlv;
	tlv.Init(prvStr);
	tlv.AddRoot(0x7f49);
	tlv.AddChild(keyID);

	uint8_t _dol[100] = {0};
	bstr sdol(_dol, 0, sizeof(_dol));
	DOL dol;
	dol.Init(sdol);

	dol.AddNextWithData(KeyPartsRSA::PublicExponent, key.Exp.length());
	dol.AddNextWithData(KeyPartsRSA::P, key.P.length());
	dol.AddNextWithData(KeyPartsRSA::Q, key.Q.length());
	dol.AddNextWithData(KeyPartsRSA::PQ, key.PQ.length());
	dol.AddNextWithData(KeyPartsRSA::DP1, key.DP1.length());
	dol.AddNextWithData(KeyPartsRSA::DQ1, key.DQ1.length());
	dol.AddNextWithData(KeyPartsRSA::N, key.N.length());

	// insert dol
	sdol = dol.GetData();
	tlv.AddNext(0x7f48, &sdol);

	// make tlv data element
	tlv.AddNext(0x5f48);

	// insert data
	tlv.Search(0x5f48);
	tlv.AppendCurrentData(key.Exp);
	tlv.AppendCurrentData(key.P);
	tlv.AppendCurrentData(key.Q);
	tlv.AppendCurrentData(key.PQ);
	tlv.AppendCurrentData(key.DP1);
	tlv.AppendCurrentData(key.DQ1);
	tlv.AppendCurrentData(key.N);

	//printf("---------- key ------------\n");
	//tlv.PrintTree();


	auto err = filesystem.WriteFile(appID, keyID, File::Secure, tlv.GetDataLink());
	if (err != Util::Error::NoError)
		return err;

	printf("key %x [%lu] saved.\n", keyID, tlv.GetDataLink().length());

	return Util::Error::NoError;
}

Util::Error KeyStorage::PutECDSAFullKey(AppID_t appID, KeyID_t keyID, ECDSAKey key) {

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();
	using namespace Util;

	prvStr.clear();

	TLVTree tlv;
	tlv.Init(prvStr);
	tlv.AddRoot(0x7f49);
	tlv.AddChild(keyID);

	uint8_t _dol[100] = {0};
	bstr sdol(_dol, 0, sizeof(_dol));
	DOL dol;
	dol.Init(sdol);

	dol.AddNextWithData(KeyPartsECDSA::PublicKey, key.Public.length());
	dol.AddNextWithData(KeyPartsECDSA::PrivateKey, key.Private.length());

	// insert dol
	sdol = dol.GetData();
	tlv.AddNext(0x7f48, &sdol);

	// make tlv data element
	tlv.AddNext(0x5f48);

	// insert data
	tlv.Search(0x5f48);
	tlv.AppendCurrentData(key.Public);
	tlv.AppendCurrentData(key.Private);

	//printf("---------- ecdsa key ------------\n");
	//tlv.PrintTree();

	auto err = filesystem.WriteFile(appID, keyID, File::Secure, tlv.GetDataLink());
	if (err != Util::Error::NoError)
		return err;

	printf("key %x [%lu] saved.\n", keyID, tlv.GetDataLink().length());

	return Util::Error::NoError;
}

Util::Error KeyStorage::GetKeyPart(bstr dataIn, Util::tag_t keyPart,
		bstr& dataOut) {
	dataOut.set_length(0);

	using namespace Util;

	TLVTree tlv;
	auto err = tlv.Init(dataIn);
	if (err != Util::Error::NoError) {
		dataIn.clear();
		return err;
	}

	TLVElm *eheader = tlv.Search(0x7f48);
	if (!eheader || eheader->Length() == 0)
		return Util::Error::StoredKeyError;

	bstr header = eheader->GetData();

	DOL dol;
	err = dol.Init(header);
	if (err != Util::Error::NoError) {
		dataIn.clear();
		return err;
	}

	TLVElm *edata = tlv.Search(0x5f48);
	if (!edata || edata->Length() == 0)
		return Util::Error::StoredKeyError;

	bstr data = edata->GetData();

	//printf("key %lu %lu\n ------------ dol --------------\n", header.length(), data.length());
	//dol.Print();

	size_t offset = 0;
	size_t length = 0;
	err = dol.Search(keyPart, offset, length);
	if (offset + length > data.length() || length == 0)
		return Error::StoredKeyError;

	dataOut = data.substr(offset, length);
	return Error::NoError;
}

Util::Error KeyStorage::GetPublicKey(AppID_t appID, KeyID_t keyID, uint8_t AlgoritmID,
		bstr& pubKey) {

	pubKey.clear();

	CryptoLib &crypto = cryptoEngine.getCryptoLib();

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
		ECDSAKey ecdsa_key;
		auto err = GetECDSAKey(appID, keyID, ecdsa_key);
		if (err != Util::Error::NoError)
			return err;

		pubKey = ecdsa_key.Public;
	}

	printf("GetPublicKey key %x [%lu] loaded.\n", keyID, prvStr.length());

	return Util::Error::NoError;
}

Util::Error KeyStorage::GetPublicKey7F49(AppID_t appID, KeyID_t keyID,
		uint8_t AlgoritmID, bstr& tlvKey) {

	uint8_t _pubKey[1024] = {0};
	bstr pubKey{_pubKey, 0, sizeof(_pubKey)};
	auto err = GetPublicKey(appID, keyID, AlgoritmID, pubKey);
	if (err != Util::Error::NoError)
		return err;

	printf("pubKey: %lu\n", pubKey.length());
	dump_hex(pubKey);

	using namespace Util;

	TLVTree tlv;
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
	return Error::NoError;
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

	using namespace Util;

	TLVTree tlv;
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

	// Security support template
	// 93 03 xx xx xx -- DS-Counter
	// needs to set to 0 after import or generation
	if (type == OpenPGPKeyType::DigitalSignature)
		filesystem.DeleteFile(appID, 0x7a, File::File);

	printf("save key data [%02x] len:%lu\n", type, keyData.length());
	return filesystem.WriteFile(appID, type, File::Secure, keyData);
}

Util::Error CryptoEngine::AESEncrypt(AppID_t appID, KeyID_t keyID,
		bstr dataIn, bstr& dataOut) {
	bstr key;
	auto err = keyStorage.GetAESKey(appID, keyID, key);
	if (err != Util::Error::NoError)
		return err;

	return cryptoLib.AESEncrypt(key, dataIn, dataOut);
}

Util::Error CryptoEngine::AESDecrypt(AppID_t appID, KeyID_t keyID,
		bstr dataIn, bstr& dataOut) {
	bstr key;
	auto err = keyStorage.GetAESKey(appID, keyID, key);
	if (err != Util::Error::NoError)
		return err;

	return cryptoLib.AESDecrypt(key, dataIn, dataOut);
}

Util::Error CryptoEngine::RSASign(AppID_t appID, KeyID_t keyID,
		bstr data, bstr& signature) {

	RSAKey key;
	auto err = keyStorage.GetRSAKey(appID, keyID, key);
	if (err != Util::Error::NoError)
		return err;

	printf("------------ key ------------\n");
	key.Print();

	return cryptoLib.RSASign(key, data, signature);
}

Util::Error CryptoEngine::RSADecipher(AppID_t appID, KeyID_t keyID,
		bstr data, bstr& dataOut) {

	RSAKey key;
	auto err = keyStorage.GetRSAKey(appID, keyID, key);
	if (err != Util::Error::NoError)
		return err;

	return cryptoLib.RSADecipher(key, data, dataOut);
}

Util::Error CryptoEngine::RSAVerify(AppID_t appID, KeyID_t keyID,
		bstr data, bstr signature) {
	return Util::Error::InternalError;
}

Util::Error CryptoEngine::ECDSASign(AppID_t appID, KeyID_t keyID,
		bstr data, bstr& signature) {

	ECDSAKey key;
	auto err = keyStorage.GetECDSAKey(appID, keyID, key);
	if (err != Util::Error::NoError)
		return err;

	printf("------------ key ------------\n");
	key.Print();

	return cryptoLib.ECDSASign(key, data, signature);
}

Util::Error CryptoEngine::ECDSAVerify(AppID_t appID, KeyID_t keyID,
		bstr data, bstr signature) {
	return Util::Error::InternalError;
}

} // namespace Crypto

