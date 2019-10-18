/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_APPLETS_OPENPGP_OPENPGPCONST_H_
#define SRC_APPLETS_OPENPGP_OPENPGPCONST_H_

#include <cstdint>
#include "util.h"

namespace OpenPGP {

enum Password {
	PW1,
	PW3,
	RC,
	PSOCDS,
	Any,
	Never
};

class PGPConst {
private:
	PGPConst(){};
public:
	static const bool ReadWriteOnlyAllowedFiles = true; // read and write files with known DSO only (if true)
	static const uint8_t PWValidPSOCDSCommand = 0x00U;  // PW1 (no. 81) only valid for one PSO:CDS command by default
	static const uint8_t PW1MinLength = 6U;
	static const uint8_t PW3MinLength = 8U;
	static constexpr uint8_t PWMinLength(Password pwd) {
		if (pwd == Password::PW3)
			return PW3MinLength;
		else
			return PW1MinLength;
	}
	// look DO`c4`
	static const uint8_t RCMaxLength = 0x20U; // resetting code
	static const uint8_t PW1MaxLength = 0x20U;
	static const uint8_t PW3MaxLength = 0x20U;
	static constexpr uint8_t PWMaxLength(Password pwd) {
		if (pwd == Password::PW3)
			return PW3MaxLength;
		else
			return PW1MaxLength;
	}
	static const uint8_t DefaultPWResetCounter = 0x03U; // OpenPGP v 3.3.1 page 23
	static const uint8_t DefaultRCResetCounter = 0x00U; // OpenPGP v 3.3.1 page 23

	static const bstr DefaultPW1; // default password PW1 (123456)
	static const bstr DefaultPW3; // default password PW3 (12345678)

	// maximum file sizes for structures in bytes
	static const size_t AlgoritmAttrMaxFileSize = 50U;
	static const size_t AlgoritmAttrMaxOIDSize = 10U;
	static const size_t DSCounterMaxFileSize = 20U;
	static const size_t KDFDOMaxFileSize = 200U;
	static const size_t MaxGetChallengeLen = 128U;
	static const size_t MaxCardholderCertificateLen = 2048U;
	static const size_t MaxSpecialDOLen = 240U;
};

enum OpenPGPKeyType {
	Unknown          = 0x00,
	DigitalSignature = 0xb6,
	Confidentiality  = 0xb8,
	Authentication   = 0xa4,
	AES              = 0xd5,
};

// OpenPGP v3.3.1 page 38 and 78
enum LifeCycleState {
	NoInfo		= 0x00,
	Init		= 0x03,
	Operational = 0x05,
};

} // namespace OpenPGP

#endif /* SRC_APPLETS_OPENPGP_OPENPGPCONST_H_ */
