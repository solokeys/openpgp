/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "openpgpstruct.h"

namespace OpenPGP {

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
	return fs.WriteFile(File::AppletID::OpenPGP, 0xc4, File::FileType::File, data);
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

Util::Error OpenPGP::AlgoritmAttr::Load(File::FileSystem& fs, KeyID_t file_id) {
	auto err = fs.ReadFile(File::AppletID::OpenPGP, file_id, File::FileType::File, data);
	if (err != Util::Error::NoError)
		return err;

	if ((data.length() < 2) ||
		(data[0] == Crypto::AlgoritmID::RSA && data.length() != 6))
		return Util::Error::InternalError;

	AlgorithmID = data[0];
	if (AlgorithmID == Crypto::AlgoritmID::RSA) {
		RSAa.NLen = (data[1] << 8) + data[2];
		RSAa.PubExpLen = (data[3] << 8) + data[4];
		RSAa.KeyFormat = data[5];
	} else {
		ECDSAa.KeyFormat = 0xff; // default!!!
		ECDSAa.OID = data.substr(1, data.length() - 1);
	}

	return Util::Error::NoError;
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

} // namespace OpenPGP
