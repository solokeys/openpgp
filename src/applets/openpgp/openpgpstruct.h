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
#include "util.h"
#include "openpgpconst.h"
#include "cryptolib.h"

namespace OpenPGP {

struct AppletState {
	bool pw1Authenticated;
	bool cdsAuthenticated;
	bool pw3Authenticated;

	void Clear() {
		pw1Authenticated = false;
		cdsAuthenticated = false;
		pw3Authenticated = false;
	}
};

struct AppletConfig {
	LifeCycleState state;

	Util::Error Load();
	Util::Error Save();
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
};

// Open PGP 3.3.1 page 31
struct  ECDSAAlgorithmAttr {
	uint8_t bOID[10];
	bstr OID{bOID, sizeof(bOID)};
	uint8_t KeyFormat; // Import-Format of private key, optional. if Format byte is not present `FF` = standard with public key
};

// Open PGP 3.3.1 page 31
struct  AlgoritmAttr {
	uint8_t _data[50];
	bstr data{_data, sizeof(_data)};

	uint8_t AlgorithmID; // Crypto::AlgoritmID
	RSAAlgorithmAttr RSAa;
	ECDSAAlgorithmAttr ECDSAa;

	Util::Error Load(File::FileSystem &fs, KeyID_t file_id);
};

// DS-Counter
struct DSCounter {
private:
	uint8_t _dsdata[20] = {0};
	bstr dsdata{_dsdata, 0, sizeof(_dsdata)};
public:
	uint32_t Counter;

	Util::Error Load(File::FileSystem &fs);
	Util::Error Save(File::FileSystem &fs);
	Util::Error DeleteFile(File::FileSystem &fs);
};

} // namespace OpenPGP

#endif /* SRC_OPENPGP_OPENPGPSTRUCT_H_ */
