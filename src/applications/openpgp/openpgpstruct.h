/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef SRC_OPENPGP_OPENPGPSTRUCT_H_
#define SRC_OPENPGP_OPENPGPSTRUCT_H_

#include "filesystem.h"
#include "opgputil.h"
#include "openpgpconst.h"
#include "cryptolib.h"

namespace OpenPGP {

struct ApplicationState {
	bool pw1Authenticated = false;
	bool cdsAuthenticated = false;
	bool pw3Authenticated = false;

	bool terminateExecuted = false;

	void Clear() {
		pw1Authenticated = false;
		cdsAuthenticated = false;
		pw3Authenticated = false;
	}
	void Init() {
		Clear();
		terminateExecuted = false;
	}
};

struct ApplicationConfig {
	LifeCycleState state;

	Util::Error Load(File::FileSystem &fs);
	Util::Error Save(File::FileSystem &fs);
};

struct __attribute__ ((packed)) PWStatusBytes {
	uint8_t PW1ValidSeveralCDS;
	uint8_t MaxLengthAndFormatPW1;
	uint8_t MaxLengthRCforPW1;
	uint8_t MaxLengthAndFormatPW3;
	uint8_t ErrorCounterPW1;
	uint8_t ErrorCounterRC;
	uint8_t ErrorCounterPW3;

	void DecErrorCounter(Password passwdId);
	uint8_t PasswdTryRemains(Password passwdId);
	void PasswdSetRemains(Password passwdId, uint8_t rem);

	uint8_t GetMaxLength(Password passwdId);
	uint8_t GetMinLength(Password passwdId);
	bool IsPINBlockFormat2(Password passwdId);

	Util::Error Load(File::FileSystem &fs);
	Util::Error Save(File::FileSystem &fs);
	void Print();
};

// Open PGP 3.3.1 page 31
struct  RSAAlgorithmAttr {
	uint16_t NLen;      // modulus length in bit
	uint16_t PubExpLen; // public exponent length in bits
	uint8_t KeyFormat;  // Crypto::RSAKeyImportFormat. Import-Format of private key

	void clear() {
		NLen = 0x0000;
		PubExpLen = 0x0000;
		KeyFormat = 0x00;
	}
};

// Open PGP 3.3.1 page 31
struct  ECDSAAlgorithmAttr {
	uint8_t bOID[PGPConst::AlgoritmAttrMaxOIDSize] = {0};
	bstr OID{bOID, sizeof(bOID)};
	uint8_t KeyFormat = 0; // Import-Format of private key, optional. if Format byte is not present `FF` = standard with public key

	void clear() {
		OID.clear();
		KeyFormat = 0x00;
	}
};

// Open PGP 3.3.1 page 31
struct  AlgoritmAttr {
	uint8_t _data[PGPConst::AlgoritmAttrMaxFileSize] = {0};
	bstr data{_data, sizeof(_data)};

	uint8_t AlgorithmID = 0; // Crypto::AlgoritmID
	RSAAlgorithmAttr RSAa = {0};
	ECDSAAlgorithmAttr ECDSAa = {0};

	void Clear();
	Util::Error DecodeData(bstr &vdata, KeyID_t key_id);
	Util::Error Decode(KeyID_t key_id);
	Util::Error Load(File::FileSystem &fs, KeyID_t file_id);
};

// DS-Counter
struct DSCounter {
private:
	uint8_t _dsdata[PGPConst::DSCounterMaxFileSize] = {0};
	bstr dsdata{_dsdata, 0, sizeof(_dsdata)};
public:
	uint32_t Counter = 0;

	Util::Error Load(File::FileSystem &fs);
	Util::Error Save(File::FileSystem &fs);
	Util::Error DeleteFile(File::FileSystem &fs);
};

// KDF-DO
// OpenPGP 3.3.1 pages 18-20, 29
enum class KDFAlgorithm {
	None = 0x00,
	KDF_ITERSALTED_S2K = 0x03
};

enum class HashAlgorithm {
	None   = 0x00,
	SHA256 = 0x08,
	SHA512 = 0x0a
};

struct KDFDO {
private:
	uint8_t _kdfdata[PGPConst::KDFDOMaxFileSize] = {0};
	bstr kdfdata{_kdfdata, 0, sizeof(_kdfdata)};
public:
	uint8_t bKDFAlgorithm = 0;
	uint8_t bHashAlgorithm = 0;
	uint32_t IterationCount = 0;

	bstr SaltPW1;
	bstr SaltRC;
	bstr SaltPW3;
	bstr InitialPW1;
	bstr InitialPW3;

	void Clear();
	size_t GetPWLength();
	bool HaveInitPassword(Password passwdId);

	Util::Error Load(File::FileSystem &fs);
	Util::Error SaveInitPasswordsToPWFiles(File::FileSystem &fs);

	void Print();
};


} // namespace OpenPGP

#endif /* SRC_OPENPGP_OPENPGPSTRUCT_H_ */
