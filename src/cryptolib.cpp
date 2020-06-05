/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "cryptolib.h"

#include <string.h>
#include <stdlib.h>

#include "device.h"
#include "opgpdevice.h"
#include "tlv.h"
#include "solofactory.h"
#include "filesystem.h"
#include "applets/openpgp/openpgpconst.h"

#include "i15_addon.h"

namespace Crypto {

static const bstr RSADefaultExponent = "\x01\x00\x01"_bstr;
static const size_t MaxRsaLengthBit = 4096;

PUT_TO_SRAM2 uint8_t _KeyBuffer[2049] = {0}; // needs for placing RSA 4096 key
PUT_TO_SRAM2 bstr KeyBuffer;

PUT_TO_SRAM2 uint8_t prvData[2049] = {0}; // needs for placing RSA 4096 key
PUT_TO_SRAM2 bstr prvStr;

CryptoLib::CryptoLib(CryptoEngine &_cryptoEngine): cryptoEngine(_cryptoEngine) {
    KeyBuffer = bstr(_KeyBuffer, 0, sizeof(_KeyBuffer));
    ClearKeyBuffer();
};

void CryptoLib::ClearKeyBuffer() {
	memset(_KeyBuffer, 0x00, sizeof(_KeyBuffer));
	KeyBuffer.clear();
}

Util::Error CryptoLib::GenerateRandom(size_t length, bstr& dataOut) {
	if (length > dataOut.max_size())
		return Util::Error::OutOfMemory;

    gen_random_device(dataOut.uint8Data(), length);
	dataOut.set_length(length);

	return Util::Error::NoError;
}

Util::Error CryptoLib::AESEncrypt(bstr key, bstr dataIn,
		bstr& dataOut) {
	dataOut.clear();



    return Util::Error::NoError;
}

Util::Error CryptoLib::AESDecrypt(bstr key, bstr dataIn,
		bstr& dataOut) {
	dataOut.clear();
    //uint8_t iv[64] = {0};



    return Util::Error::NoError;
}

Util::Error CryptoLib::AppendKeyPart(bstr &buffer, bstr &keypart, uint8_t *mpi, size_t mpi_len) {
	if (mpi_len > 0) {
        memcpy(buffer.uint8Data() + buffer.length(), mpi, mpi_len);

		keypart = bstr(buffer.uint8Data() + buffer.length(), mpi_len);
		buffer.set_length(buffer.length() + mpi_len);
    }
	return Util::Error::NoError;
}
/*
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
*/

size_t RSAKeyLenFromPQ(size_t PQlen) {
    return PQlen * 2 * 8;
}

// from inner.h of bearssl
uint32_t br_dec32be(const unsigned char *buf) {
    return ((uint32_t)buf[0] << 24)
        | ((uint32_t)buf[1] << 16)
        | ((uint32_t)buf[2] << 8)
        | (uint32_t)buf[3];
}

size_t RSAKeyLenFromBitlen(size_t bitlen) {
    return (bitlen + 7) >> 3;
}

void br_hw_drbg_init(void *ctx,
    const void *params, const void *seed, size_t len) {
}

void br_hw_drbg_generate(void *ctx, void *out, size_t len) {
    gen_random_device((uint8_t *)out, len);
}

void br_hw_drbg_update(void *ctx, const void *seed, size_t len) {
}

const br_prng_class br_hw_drbg_vtable = {
    sizeof(br_hmac_drbg_context),
    (void (*)(const br_prng_class **, const void *, const void *, size_t))
        &br_hw_drbg_init,
    (void (*)(const br_prng_class **, void *, size_t))
        &br_hw_drbg_generate,
    (void (*)(const br_prng_class **, const void *, size_t))
        &br_hw_drbg_update
};

Util::Error CryptoLib::RSAGenKey(RSAKey& keyOut, size_t keySize) {

	Util::Error ret = Util::Error::NoError;
	ClearKeyBuffer();

    uint8_t keybufsk[2048]; // TODO
    std::memset(keybufsk, 0, sizeof(keybufsk));
    uint8_t keybufpk[1024]; // TODO
    std::memset(keybufpk, 0, sizeof(keybufpk));

    br_rsa_private_key sk = {};
    br_rsa_public_key pk = {};

    while (true) {
        // OpenPGP 3.3.1 pages 33,34
        const br_prng_class *rng = &br_hw_drbg_vtable;
        device_led(COLOR_MAGENTA);
        if (br_rsa_i15_keygen(&rng, &sk, keybufsk, &pk, keybufpk, keySize, 65537) == 0) {
            device_led(COLOR_RED);
            ret = Util::Error::CryptoOperationError;
            break;
        }
        device_led(COLOR_GREEN);

        KeyBuffer.clear();

        AppendKeyPart(KeyBuffer, keyOut.Exp, pk.e, pk.elen);
        AppendKeyPart(KeyBuffer, keyOut.P, sk.p, sk.plen);
        AppendKeyPart(KeyBuffer, keyOut.Q, sk.q, sk.qlen);
        AppendKeyPart(KeyBuffer, keyOut.N, pk.n, pk.nlen);

        // check
        if (keyOut.P.length() == 0 || keyOut.Q.length() == 0 || keyOut.Exp.length() == 0) {
            ret = Util::Error::CryptoDataError;
            break;
        }

        break;
    }
	return ret;
}

Util::Error RSAFillPrivateKey(uint8_t *keybuf, br_rsa_private_key &sk, RSAKey &key) {
    Util::Error ret = Util::Error::NoError;

    if (key.P.length() == 0 ||
        key.Q.length() == 0 ||
        key.Exp.length() == 0
       )
        return Util::Error::CryptoDataError;

    sk.n_bitlen = RSAKeyLenFromPQ(MAX(key.P.length(), key.Q.length()));
    sk.p = key.P.uint8Data();
    sk.plen = key.P.length();
    sk.q = key.Q.uint8Data();
    sk.qlen = key.Q.length();

    if (key.DP1.length() != 0) {
        sk.dp = key.DP1.uint8Data();
        sk.dplen = key.DP1.length();
    }
    if (key.DQ1.length() != 0) {
        sk.dq = key.DQ1.uint8Data();
        sk.dqlen = key.DQ1.length();
    }
    if (key.PQ.length() != 0) {
        sk.iq = key.PQ.uint8Data();
        sk.iqlen = key.PQ.length();
    }

    if (sk.dplen == 0 || sk.dqlen == 0 || sk.iqlen == 0)
        if(!br_rsa_deduce_crt(keybuf, &sk, key.Exp.uint8Data()))
            return Util::Error::StoredKeyError;

    return ret;
}

Util::Error CryptoLib::RSASign(RSAKey key, bstr data, bstr& signature) {

	Util::Error ret = Util::Error::NoError;

    uint8_t keybuf[RSAKeyLenFromBitlen(MaxRsaLengthBit) * 3];
    std::memset(keybuf, 0, sizeof(keybuf));

    br_rsa_private_key sk = {};
	while (true) {
        ret = RSAFillPrivateKey(keybuf, sk, key);
		if (ret != Util::Error::NoError)
			break;

        size_t keylen = RSAKeyLenFromBitlen(sk.n_bitlen);

		// OpenPGP 3.3.1 page 54. PKCS#1
		// command data field is not longer than 40% of the length of the modulus
		if (keylen * 0.4 < data.length()) {
			printf_device("pkcs#1 data length error!\n");
			ret = Util::Error::CryptoDataError;
			break;
		}

		// OpenPGP 3.3.1 page 53
        uint8_t vdata[keylen];
        std::memset(vdata, 0, keylen);
		vdata[1] = 0x01; // Block type
		memset(&vdata[2], 0xff, keylen - data.length() - 3);
		memcpy(&vdata[keylen - data.length()], data.uint8Data(), data.length());

		memset(signature.uint8Data(), 0x00, keylen);

        int res = br_rsa_i15_private(vdata, &sk);
        if (res == 0) {
            printf_device("crypto oper error: %d\n", res);
            ret = Util::Error::CryptoOperationError;
            break;
        }
        std::memcpy(signature.uint8Data(), vdata, keylen);
		signature.set_length(keylen);

		break;
	}

	return ret;
}

Util::Error CryptoLib::RSADecipher(RSAKey key, bstr data, bstr &dataOut) {
	Util::Error ret = Util::Error::NoError;
    dataOut.set_length(0);

    if (key.P.length() == 0 ||
		key.Q.length() == 0 ||
		key.Exp.length() == 0
		)
		return Util::Error::CryptoDataError;

    uint8_t keybuf[RSAKeyLenFromBitlen(MaxRsaLengthBit) * 3];
    std::memset(keybuf, 0, sizeof(keybuf));

    br_rsa_private_key sk = {};
    while (true) {
        ret = RSAFillPrivateKey(keybuf, sk, key);
		if (ret != Util::Error::NoError)
			break;

        size_t keylen = RSAKeyLenFromBitlen(sk.n_bitlen);

		if (keylen != data.length()) {
			ret = Util::Error::CryptoDataError;
			break;
		}

        uint8_t vdata[keylen];
        memcpy(vdata, data.uint8Data(), data.length());

        int res = br_rsa_i15_private(vdata, &sk);
        if (res == 0) {
            printf_device("crypto oper error: %d\n", res);
            ret = Util::Error::CryptoOperationError;
            break;
        }

        std::memcpy(dataOut.uint8Data(), vdata, keylen);
        dataOut.set_length(keylen);

		break;
	}

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

/*static int ecdsa_init(mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id curveID, bstr *key_d, bstr *key_xy) {
	if (!ctx)
		return 1;

	int res;

	mbedtls_ecdsa_init(ctx);
	res = mbedtls_ecp_group_load(&ctx->grp, curveID);

	if (res)
		return res;

	if (key_d && key_d->length() > 0) {
		res = mbedtls_mpi_read_binary(&ctx->d, key_d->uint8Data(), key_d->length());
		if (res)
			return res;
	}

	if (key_xy && key_xy->length() > 0) {
		res = mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->Q, key_xy->uint8Data(), key_xy->length());
		if (res)
			return res;
	}

	return 0;
};
*/
Util::Error CryptoLib::ECDSAGenKey(ECDSAaid curveID, ECDSAKey& keyOut) {
	ClearKeyBuffer();
	keyOut.clear();
    Util::Error err = Util::Error::InternalError;

    if (curveID == ECDSAaid::none)
		return  Util::Error::StoredKeyParamsError;

    int tlsCurveId = curveIdFromAid(curveID);

    uint8_t keybuf[BR_EC_KBUF_PUB_MAX_SIZE + 10];
    std::memset(keybuf, 0, sizeof(keybuf));
    br_ec_private_key sk = {};
    br_ec_public_key pk = {};

    while (true) {
        const br_prng_class *rng = &br_hw_drbg_vtable;
        const br_ec_impl *impl = nullptr;
        impl = &br_ec_all_m15;

        device_led(COLOR_MAGENTA);
        if (br_ec_keygen(&rng, impl, &sk, keybuf, tlsCurveId) == 0){
            device_led(COLOR_RED);
            err = Util::Error::CryptoOperationError;
            break;
        }

        AppendKeyPart(KeyBuffer, keyOut.Private, sk.x, sk.xlen);

        if (br_ec_compute_pub(impl, &pk, keybuf, &sk) == 0) {
            device_led(COLOR_RED);
            err = Util::Error::CryptoOperationError;
            break;
        }
        device_led(COLOR_GREEN);

        // was AppendKeyPartEcpPoint!!!
        AppendKeyPart(KeyBuffer, keyOut.Public, pk.q, pk.qlen);
        keyOut.CurveId = curveID;

        keyOut.Print();

        err =  Util::Error::NoError;
		break;
	}

	return err;
}

Util::Error ECDSAFillPrivateKey(br_ec_private_key &sk, ECDSAKey &key) {

    if (key.Private.length() == 0 ||
        key.CurveId == ECDSAaid::none )
        return Util::Error::StoredKeyError;

    sk.curve = curveIdFromAid(key.CurveId);
    if (sk.curve == tls_ec_none)
        return Util::Error::StoredKeyError;

    sk.x = key.Private.uint8Data();
    sk.xlen = key.Private.length();

    return Util::Error::NoError;
}


Util::Error CryptoLib::ECDSASign(ECDSAKey key, bstr data, bstr& signature) {
	signature.clear();

    Util::Error ret = Util::Error::InternalError;

    br_ec_private_key sk = {};

    while (true) {
        ret = ECDSAFillPrivateKey(sk, key);
        if (ret != Util::Error::NoError)
            break;

        size_t len = br_ecdsa_i15_sign_raw(&br_ec_all_m15, &br_sha256_vtable, data.data(), &sk, signature.uint8Data());
        if (len == 0) {
            ret = Util::Error::CryptoOperationError;
            break;
        }
        signature.set_length(len);

        ret = Util::Error::NoError;
		break;
	}


	return ret;
}

Util::Error CryptoLib::RSACalcPublicKey(bstr strP, bstr strQ, bstr &strN) {
	Util::Error ret = Util::Error::NoError;

    if (strP.length() == 0 ||
        strQ.length() == 0
        )
        return Util::Error::CryptoDataError;

    br_rsa_private_key sk = {};
    sk.n_bitlen = RSAKeyLenFromPQ(MAX(strP.length(), strQ.length()));
    sk.p = strP.uint8Data();
    sk.plen = strP.length();
    sk.q = strQ.uint8Data();
    sk.qlen = strQ.length();


    size_t length = br_rsa_i15_compute_modulus((void *)strN.data(), &sk);
    strN.set_length(length);

	return ret;
}

Util::Error CryptoLib::ECDSACalcPublicKey(ECDSAaid curveID, bstr privateKey, bstr &publicKey) {
    publicKey.clear();

    uint8_t keybuf[BR_EC_KBUF_PUB_MAX_SIZE + 10];
    std::memset(keybuf, 0, sizeof(keybuf));
    br_ec_private_key sk = {};
    br_ec_public_key pk = {};

    ECDSAKey key;
    key.clear();
    key.CurveId = curveID;
    key.Private = privateKey;

    auto err = ECDSAFillPrivateKey(sk, key);
    if (err != Util::Error::NoError)
        return err;

    if (br_ec_compute_pub(&br_ec_all_m15, &pk, keybuf, &sk) == 0)
        return Util::Error::CryptoOperationError;

    if (pk.qlen == 0)
        return Util::Error::CryptoOperationError;

    std::memcpy(publicKey.uint8Data(), pk.q, pk.qlen);
    publicKey.set_length(pk.qlen);

    return Util::Error::NoError;
}

Util::Error CryptoLib::ECDSAVerify(ECDSAKey key, bstr data,
		bstr signature) {
	return Util::Error::InternalError;
}

Util::Error CryptoLib::ECDHComputeShared(ECDSAKey key, bstr anotherPublicKey, bstr &sharedSecret) {

    sharedSecret.clear(); // == anotherPublicKey * key.Private

    br_ec_private_key sk = {};
    auto err = ECDSAFillPrivateKey(sk, key);
    if (err != Util::Error::NoError)
        return err;

    br_ec_public_key pk = {};
    pk.curve = sk.curve;
    pk.q = anotherPublicKey.uint8Data();
    pk.qlen = anotherPublicKey.length();

    size_t len = ecdh_shared_secret(&br_ec_all_m15, &sk, &pk, sharedSecret.uint8Data());
    printf("===len %d xlen %d\n", len, sk.xlen);
    if (len == 0)
        return Util::Error::CryptoOperationError;

    sharedSecret.set_length(len);

    return Util::Error::NoError;
}

KeyStorage::KeyStorage(CryptoEngine &_cryptoEngine): cryptoEngine(_cryptoEngine) {
    prvStr = bstr(prvData, 0, sizeof(prvData));
    prvStr.clear();
};

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
		printf_device("Generate public key from private.\n");
		key.Public = bstr(prvStr.uint8Data() + prvStr.length(), 0, prvStr.free_space());
		auto err = cryptolib.ECDSACalcPublicKey(key.CurveId, key.Private, key.Public);
		if (err != Util::Error::NoError)
			return err;
		prvStr.set_length(prvStr.length() + key.Public.length());
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

	//printf_device("---------- key ------------\n");
	//tlv.PrintTree();


	auto err = filesystem.WriteFile(appID, keyID, File::Secure, tlv.GetDataLink());
	if (err != Util::Error::NoError)
		return err;

	printf_device("key %x [%lu] saved.\n", keyID, tlv.GetDataLink().length());

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

	//printf_device("---------- ecdsa key ------------\n");
	//tlv.PrintTree();

	auto err = filesystem.WriteFile(appID, keyID, File::Secure, tlv.GetDataLink());
	if (err != Util::Error::NoError)
		return err;

	printf_device("key %x [%lu] saved.\n", keyID, tlv.GetDataLink().length());

	return Util::Error::NoError;
}

Util::Error KeyStorage::GetKeyPart(bstr dataIn, Util::tag_t keyPart,
		bstr& dataOut) {
	dataOut.clear();

	using namespace Util;

	TLVTree tlv;
	auto err = tlv.Init(dataIn);
	if (err != Util::Error::NoError)
		return err;

	TLVElm *eheader = tlv.Search(0x7f48);
	if (!eheader || eheader->Length() == 0)
		return Util::Error::StoredKeyError;

	bstr header = eheader->GetData();

	DOL dol;
	err = dol.Init(header);
	if (err != Util::Error::NoError)
		return err;

	TLVElm *edata = tlv.Search(0x5f48);
	if (!edata || edata->Length() == 0)
		return Util::Error::StoredKeyError;

	bstr data = edata->GetData();

	//printf_device("key %lu %lu\n ------------ dol --------------\n", header.length(), data.length());
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

	printf_device("GetPublicKey key %x [%lu] loaded.\n", keyID, prvStr.length());

	return Util::Error::NoError;
}

Util::Error KeyStorage::GetPublicKey7F49(AppID_t appID, KeyID_t keyID,
		uint8_t AlgoritmID, bstr& tlvKey) {

	uint8_t _pubKey[1024] = {0};
	bstr pubKey{_pubKey, 0, sizeof(_pubKey)};
	auto err = GetPublicKey(appID, keyID, AlgoritmID, pubKey);
	if (err != Util::Error::NoError)
		return err;

	printf_device("pubKey: %lu\n", pubKey.length());
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

	printf_device("key %x [%lu] loaded.\n", keyID, prvStr.length());

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

	printf_device("-------------- tlv -----------------\n");
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

	printf_device("save key data [%02x] len:%lu\n", type, keyData.length());
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

	printf_device("------------ key ------------\n");
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

	printf_device("------------ key ------------\n");
	key.Print();

	return cryptoLib.ECDSASign(key, data, signature);
}

Util::Error CryptoEngine::ECDSAVerify(AppID_t appID, KeyID_t keyID,
		bstr data, bstr signature) {
	return Util::Error::InternalError;
}

Util::Error CryptoEngine::ECDHComputeShared(AppID_t appID, KeyID_t keyID, bstr anotherPublicKey, bstr &sharedSecret) {
	ECDSAKey key;
	auto err = keyStorage.GetECDSAKey(appID, keyID, key);
	if (err != Util::Error::NoError)
		return err;

	printf_device("------------ key ------------\n");
	key.Print();

	return cryptoLib.ECDHComputeShared(key, anotherPublicKey, sharedSecret);
}


} // namespace Crypto

