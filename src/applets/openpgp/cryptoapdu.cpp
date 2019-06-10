/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "cryptoapdu.h"
#include "applets/apduconst.h"
#include "solofactory.h"
#include "applets/openpgp/openpgpfactory.h"
#include "applets/openpgpapplet.h"
#include "applets/openpgp/apdusecuritycheck.h"
#include "applets/openpgp/openpgpconst.h"
#include "applets/openpgp/openpgpstruct.h"

namespace OpenPGP {

Util::Error APDUGetChallenge::Check(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2) {
	if (ins != Applet::APDUcommands::GetChallenge)
		return Util::Error::WrongCommand;

	if (cla != 0x00)
		return Util::Error::WrongAPDUCLA;

	if ((p1 != 0x00 && p2 != 0x00))   // encipher
		return Util::Error::WrongAPDUP1P2;

	return Util::Error::NoError;
}

Util::Error APDUGetChallenge::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr& dataOut) {

	dataOut.clear();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	if (data.length() > 0)
		return Util::Error::WrongAPDUDataLength;


	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	Crypto::CryptoLib &crypto = solo.GetCryptoLib();

	if (le == 0)
		le = 0xff;

	return crypto.GenerateRandom(le, dataOut);
}

Util::Error APDUInternalAuthenticate::Check(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2) {
	return Util::Error::WrongCommand;
}

Util::Error APDUInternalAuthenticate::Process(uint8_t cla, uint8_t ins,
		uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr& dataOut) {
	return Util::Error::WrongCommand;
}

Util::Error APDUGenerateAsymmetricKeyPair::Check(uint8_t cla,
		uint8_t ins, uint8_t p1, uint8_t p2) {

	if (ins != Applet::APDUcommands::GenerateAsymmKeyPair)
		return Util::Error::WrongCommand;

	if (cla != 0x00 && cla != 0x0c)
		return Util::Error::WrongAPDUCLA;

	if ((p1 != 0x80 && p1 != 0x81) ||
		(p2 != 0x00))
		return Util::Error::WrongAPDUP1P2;

	return Util::Error::NoError;
}

Util::Error APDUGenerateAsymmetricKeyPair::Process(uint8_t cla,
		uint8_t ins, uint8_t p1, uint8_t p2, bstr data, uint8_t le, bstr& dataOut) {

	dataOut.clear();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	printf("as key p - %lu\n", data.length());
	if (data.length() != 2)
		return Util::Error::WrongAPDUDataLength;

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();
	Crypto::KeyStorage &key_storage = solo.GetKeyStorage();

	OpenPGPKeyType key_type = OpenPGPKeyType::Unknown;
	if (data[0] == OpenPGPKeyType::DigitalSignature ||
		data[0] == OpenPGPKeyType::Confidentiality ||
		data[0] == OpenPGPKeyType::Authentication
		)
		key_type = static_cast<OpenPGPKeyType>(data[0]);

	// OpenPGP v3.3.1 page 64
	// 0x80 - Generation of key pair
	// 0x81 - Reading of actual public key template
	if (p1 == 0x80) {
		(void)key_type;

		return Util::Error::DataNotFound;
	} else {
		OpenPGP::AlgoritmAttr alg;
		KeyID_t file_id = 0;
		switch (key_type) {
		case OpenPGPKeyType::DigitalSignature:
			file_id = 0xc1;
			break;
		case OpenPGPKeyType::Confidentiality:
			file_id = 0xc2;
			break;
		case OpenPGPKeyType::Authentication:
			file_id = 0xc3;
			break;
		default:
			break;
		};
		if (file_id == 0)
			return Util::Error::DataNotFound;

		auto err = alg.Load(filesystem, file_id);
		if (err != Util::Error::NoError || alg.AlgorithmID == 0)
			return Util::Error::DataNotFound;

		err = key_storage.GetPublicKey7F49(
				File::AppletID::OpenPGP,
				key_type,
				alg.AlgorithmID,
				dataOut);
		if (err != Util::Error::NoError || dataOut.length() == 0)
			return Util::Error::DataNotFound;

		return Util::Error::NoError;
	}

	return Util::Error::NoError;
}

Util::Error APDUPSO::Check(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2) {
	if (ins != Applet::APDUcommands::PSO)
		return Util::Error::WrongCommand;

	if (cla != 0x00)
		return Util::Error::WrongAPDUCLA;

	if (!((p1 == 0x9e && p2 == 0x9a) ||  // compute digital signature
		  (p1 == 0x80 && p2 == 0x86) ||  // decipher
		  (p1 == 0x86 && p2 == 0x80)))   // encipher
		return Util::Error::WrongAPDUP1P2;

	return Util::Error::NoError;
}

// OpenPGP v3.3.1. page 53
Util::Error APDUPSO::Process(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, bstr data, uint8_t le, bstr& dataOut) {

	Factory::SoloFactory &solo = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = solo.GetFileSystem();
	Applet::OpenPGPApplet &applet = solo.GetAppletStorage().GetOpenPGPApplet();
	Crypto::CryptoEngine &crypto_e = solo.GetCryptoEngine();

	auto err_check = Check(cla, ins, p1, p2);
	if (err_check != Util::Error::NoError)
		return err_check;

	if (!applet.GetPSOCDSAccess())
		return Util::Error::AccessDenied;

	PWStatusBytes pwstatus;
	pwstatus.Load(filesystem);

	//PSO:CDS OpenPGP 3.3.1 page 53. iso 7816-8:2004 page 6-8
	if (p1 == 0x9e && p2 == 0x9a) {
		OpenPGP::AlgoritmAttr alg;
		auto err = alg.Load(filesystem, 0xc1);
		if (err != Util::Error::NoError || alg.AlgorithmID == 0)
			return Util::Error::DataNotFound;

		if (alg.AlgorithmID == Crypto::AlgoritmID::RSA)
			err = crypto_e.RSASign(File::AppletID::OpenPGP, OpenPGPKeyType::DigitalSignature, data, dataOut);
		else
			err = crypto_e.ECDSASign(File::AppletID::OpenPGP, OpenPGPKeyType::DigitalSignature, data, dataOut);

		if (!pwstatus.PW1ValidSeveralCDS)
			applet.ClearPSOCDSAccess();

		// clear CDS flag if sign cant be done too
		if (err != Util::Error::NoError)
			return err;
	}

	// 	PSO:DECIPHER OpenPGP 3.3.1 page 57. iso 7816-8:2004 page 6-8
	if (p1 == 0x80 && p2 == 0x86) {

	}

	// 	PSO:ENCIPHER OpenPGP 3.3.1 page 60. iso 7816-8:2004 page 6-8
	if (p1 == 0x86 && p2 == 0x80) {

	}

	return Util::Error::NoError;
}

} // namespace OpenPGP
