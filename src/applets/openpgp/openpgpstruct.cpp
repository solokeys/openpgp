/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "openpgpstruct.h"

namespace OpenPGP {

Util::Error AppletConfig::Load(File::FileSystem &fs) {
	bstr data(reinterpret_cast<uint8_t *>(this), 1, 1);
	auto err = fs.ReadFile(File::AppletID::OpenPGP, File::SecureFileID::State, File::Secure, data);
	if (err != Util::Error::NoError)
		return err;

	return Util::Error::NoError;
}

Util::Error AppletConfig::Save(File::FileSystem &fs) {
	bstr data(reinterpret_cast<uint8_t *>(this), 1, 1);

	auto err = fs.WriteFile(File::AppletID::OpenPGP, File::SecureFileID::State, File::Secure, data);
	if (err != Util::Error::NoError)
		return err;
	return Util::Error::NoError;
}

Util::Error PWStatusBytes::Load(File::FileSystem &fs) {
	bstr data(reinterpret_cast<uint8_t *>(this), 7, 7);
	auto err = fs.ReadFile(File::AppletID::OpenPGP, 0xc4, File::FileType::File, data);
	if (err != Util::Error::NoError)
		return err;
	if (data.length() != 7)
		return Util::Error::InternalError;

	Print(); // for debug!
	return Util::Error::NoError;
}
Util::Error PWStatusBytes::Save(File::FileSystem &fs) {
	bstr data(reinterpret_cast<uint8_t *>(this), 7, 7);
	return fs.WriteFile(File::AppletID::OpenPGP, 0xc4, File::FileType::File, data, true);
}

uint8_t PWStatusBytes::GetMinLength(Password passwdId) {
	return PGPConst::PWMinLength(passwdId);
}

uint8_t OpenPGP::PWStatusBytes::GetMaxLength(Password passwdId) {
	switch (passwdId) {
	case Password::PSOCDS:
	case Password::PW1:
		return MaxLengthAndFormatPW1 & 0x7f;
	case Password::RC:
		return MaxLengthRCforPW1;
	case Password::PW3:
		return MaxLengthAndFormatPW3 & 0x7f;
	default:
		break;
	}
	return 0;
}

bool OpenPGP::PWStatusBytes::IsPINBlockFormat2(Password passwdId) {
	switch (passwdId) {
	case Password::PSOCDS:
	case Password::PW1:
		return MaxLengthAndFormatPW1 & 0x80;
	case Password::PW3:
		return MaxLengthAndFormatPW1 & 0x80;
	default:
		break;
	}
	return false;
}

void PWStatusBytes::DecErrorCounter(Password passwdId) {
	switch (passwdId) {
	case Password::PSOCDS:
	case Password::PW1:
		if (ErrorCounterPW1 > 0)
			ErrorCounterPW1--;
		break;
	case Password::RC:
		if (ErrorCounterRC > 0)
			ErrorCounterRC--;
		break;
	case Password::PW3:
		if (ErrorCounterPW3 > 0)
			ErrorCounterPW3--;
		break;
	default:
		break;
	}
}

uint8_t PWStatusBytes::PasswdTryRemains(Password passwdId) {
	switch (passwdId) {
	case Password::PSOCDS:
	case Password::PW1:
		return ErrorCounterPW1;
	case Password::RC:
		return ErrorCounterRC;
	case Password::PW3:
		return ErrorCounterPW3;
	default:
		break;
	}

	return false;
}

void PWStatusBytes::PasswdSetRemains(Password passwdId, uint8_t rem) {
	switch (passwdId) {
	case Password::PSOCDS:
	case Password::PW1:
		ErrorCounterPW1 = rem;
		break;
	case Password::RC:
		ErrorCounterRC = rem;
		break;
	case Password::PW3:
		ErrorCounterPW3 = rem;
		break;
	default:
		break;
	}
}

void PWStatusBytes::Print() {
	printf("-------------- PW status Bytes --------------\n"\
			"valid several CDS: %s maxlen PW1: %d format pw1: %s \n"\
			"maxlen RC: %d maxlen PW3: %d format pw3: %s \n"\
			"Error counters: PW1: %d RC: %d PW3: %d\n",
			PW1ValidSeveralCDS?"yes":"no",
			MaxLengthAndFormatPW1 & 0x7f,
			(MaxLengthAndFormatPW1 & 0x80)?"pin block 2":"utf-8",
			MaxLengthRCforPW1,
			MaxLengthAndFormatPW3 & 0x7f,
			(MaxLengthAndFormatPW3 & 0x80)?"pin block 2":"utf-8",
			ErrorCounterPW1,
			ErrorCounterRC,
			ErrorCounterPW3
	);
}

Util::Error AlgoritmAttr::Decode(bstr &data, KeyID_t key_id) {
	if ((data.length() < 2) ||
		(data[0] == Crypto::AlgoritmID::RSA && data.length() != 6))
		return Util::Error::InternalError;

	AlgorithmID = data[0];
	if (AlgorithmID == Crypto::AlgoritmID::RSA) {
		RSAa.NLen = (data[1] << 8) + data[2];
		RSAa.PubExpLen = (data[3] << 8) + data[4];
		RSAa.KeyFormat = data[5];

		if (RSAa.KeyFormat > 0x03)
			return Util::Error::WrongData;

		return Util::Error::NoError;
	}

	if (AlgorithmID == Crypto::AlgoritmID::ECDSAforCDSandIntAuth) {
		bool keyFormatLen = 0;
		ECDSAa.KeyFormat = 0x00; // by default - standard (private key only)
		// high bit can't be used in the last OID byte. In the OID it needs to mark 2-byte value
		if (data[data.length() - 1] & 0x10) {
			ECDSAa.KeyFormat = data[data.length() - 1];
			keyFormatLen = 1;
		}
		ECDSAa.OID = data.substr(1, data.length() - 1 - keyFormatLen);

		if (Crypto::MbedtlsCurvefromOID(ECDSAa.OID) == MBEDTLS_ECP_DP_NONE ||
			key_id == 0xc2)
			return Util::Error::WrongData;

		return Util::Error::NoError;
	}

	if (AlgorithmID == Crypto::AlgoritmID::ECDHforDEC) {
		if (key_id != 0xc2)
		return Util::Error::WrongData;

		return Util::Error::NoError;
	}

	return Util::Error::WrongData;
}

Util::Error AlgoritmAttr::Load(File::FileSystem& fs, KeyID_t file_id) {
	auto err = fs.ReadFile(File::AppletID::OpenPGP, file_id, File::FileType::File, data);
	if (err != Util::Error::NoError)
		return err;

	return Decode(data, file_id);
}

Util::Error DSCounter::Load(File::FileSystem& fs) {
	auto err = fs.ReadFile(File::AppletID::OpenPGP, 0x7a, File::File, dsdata);
	if (err != Util::Error::NoError)
		return err;

	if (dsdata.length() > 2 &&
		dsdata[0] == 0x93 &&
		dsdata[1] > 0 && dsdata[1] <= 4
		) {
		Counter = dsdata.get_uint_be(2, dsdata[1]);
	} else {
		return Util::Error::InternalError;
	}

	return Util::Error::NoError;
}

Util::Error DSCounter::Save(File::FileSystem& fs) {
	dsdata.set_uint_be(2, dsdata[1], Counter);
	return fs.WriteFile(File::AppletID::OpenPGP, 0x7a, File::File, dsdata);
}

Util::Error DSCounter::DeleteFile(File::FileSystem& fs) {
	return fs.DeleteFile(File::AppletID::OpenPGP, 0x7a, File::File);
}

void KDFDO::Clear() {
	memset(_kdfdata, 0, sizeof(_kdfdata));

	bKDFAlgorithm = 0;
	bHashAlgorithm = 0;
	IterationCount = 0;

	SaltPW1.clear();
	SaltRC.clear();
	SaltPW3.clear();
	InitialPW1.clear();
	InitialPW3.clear();
};

size_t KDFDO::GetPWLength() {
	if (bKDFAlgorithm == static_cast<uint8_t>(KDFAlgorithm::KDF_ITERSALTED_S2K)) {
		if (bHashAlgorithm == static_cast<uint8_t>(HashAlgorithm::SHA256))
			return 0x20;

		if (bHashAlgorithm == static_cast<uint8_t>(HashAlgorithm::SHA512))
			return 0x40;
	}

	return 0;
}

bool KDFDO::HaveInitPassword(Password passwdId) {
	switch (passwdId) {
	case Password::Any:
		return InitialPW1.length() > 0 || InitialPW3.length() > 0;
	case Password::PSOCDS:
	case Password::PW1:
		return InitialPW1.length() > 0;
	case Password::PW3:
		return InitialPW3.length() > 0;
	default:
		break;
	}

	return false;
}

Util::Error KDFDO::Load(File::FileSystem& fs) {

	Clear();

	auto err = fs.ReadFile(File::AppletID::OpenPGP, 0xf9, File::File, kdfdata);
	if (err != Util::Error::NoError)
		return err;

	Util::TLVTree tlv;
	err = tlv.Init(kdfdata);
	if (err != Util::Error::NoError)
		return Util::Error::CryptoDataError;

	// KDFAlgorithm
	if (tlv.Search(0x81) && tlv.CurrentElm().Length() == 1)
		bKDFAlgorithm = tlv.CurrentElm().GetData()[0];

	// no KDF-DO found
	if (bKDFAlgorithm != static_cast<uint8_t>(KDFAlgorithm::KDF_ITERSALTED_S2K)) {
		bKDFAlgorithm = static_cast<uint8_t>(KDFAlgorithm::None);

		return Util::Error::NoError;
	}

	// HashAlgorithm
	if (tlv.Search(0x82) && tlv.CurrentElm().Length() == 1)
		bHashAlgorithm = tlv.CurrentElm().GetData()[0];

	// IterationCount
	if (tlv.Search(0x83) && tlv.CurrentElm().Length() <= 4)
		IterationCount = tlv.CurrentElm().GetData().get_uint_le(0, 4);

	// SaltPW1
	if (tlv.Search(0x84) && tlv.CurrentElm().Length() > 0)
		SaltPW1 = tlv.CurrentElm().GetData();

	// SaltRC;
	if (tlv.Search(0x85) && tlv.CurrentElm().Length() > 0)
		SaltRC = tlv.CurrentElm().GetData();

	// SaltPW3;
	if (tlv.Search(0x86) && tlv.CurrentElm().Length() > 0)
		SaltPW3 = tlv.CurrentElm().GetData();

	// InitialPW1;
	if (tlv.Search(0x87) && tlv.CurrentElm().Length() > 0)
		InitialPW1 = tlv.CurrentElm().GetData();

	// InitialPW3;
	if (tlv.Search(0x88) && tlv.CurrentElm().Length() > 0)
		InitialPW3 = tlv.CurrentElm().GetData();

	return Util::Error::NoError;
}

Util::Error KDFDO::SaveInitPasswordsToPWFiles(File::FileSystem& fs) {
	if (InitialPW1.length() > 0) {
		auto err = fs.WriteFile(File::AppletID::OpenPGP, File::SecureFileID::PW1, File::Secure, InitialPW1);
		if (err != Util::Error::NoError)
			return err;
	}

	if (InitialPW3.length() > 0) {
		auto err = fs.WriteFile(File::AppletID::OpenPGP, File::SecureFileID::PW3, File::Secure, InitialPW3);
		if (err != Util::Error::NoError)
			return err;
	}

	return Util::Error::NoError;
}

void KDFDO::Print() {
	printf("-------------- KDF-DO --------------\n");
	printf("Algorithm:        0x%02x\n", bKDFAlgorithm);
	if (bKDFAlgorithm != 0x03)
		return;

	printf("Hash alg:         0x%02x\n", bHashAlgorithm);
	printf("Iteration count:  %d\n", IterationCount);
	printf("SaltPW1:    "); dump_hex(SaltPW1, 16);
	printf("SaltRC:     "); dump_hex(SaltRC, 16);
	printf("SaltPW3:    "); dump_hex(SaltPW3, 16);
	printf("InitialPW1: "); dump_hex(InitialPW1, 16);
	printf("InitialPW3: "); dump_hex(InitialPW3, 16);
}


} // namespace OpenPGP
