/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef SRC_APPLETS_APDUCONST_H_
#define SRC_APPLETS_APDUCONST_H_

#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include "util.h"
#include "error.h"

namespace Applet {

	enum APDUResponse {
		SelectInTerminationState 	= 0x6285,
		VerifyFailNoTryLeft 		= 0x63C0,
		MemoryWriteError			= 0x6501,
		MemoryFailure				= 0x6581,
		WrongLength					= 0x6700,
		LogicalChannelNotSupported	= 0x6881,
		SecureMessagingNotSupport	= 0x6882,
		LastCmdOfChainExpected		= 0x6883,
		CommandChainingNotSupported	= 0x6884,
		SecurityStatusNotSatisfied	= 0x6982,
		AuthenticationMethodBlocked	= 0x6983,
		ConditionsUseNotSatisfied	= 0x6985,
		ExpectedSMObjectsMissing	= 0x6987,
		SMdataObjectsIncorrect	 	= 0x6988,
		PermissionDenied			= 0x69f0,
		IncorrectParamInDataField	= 0x6a80,
		FileNotFound				= 0x6a82,
		ReferencedDataNotFound		= 0x6a88,
		WrongParametersP1orP2		= 0x6b00,
		INSnotSupported				= 0x6d00,
		CLAnotSupported				= 0x6e00,
		InternalException			= 0x6f00,
		OK 							= 0x9000,
	};

	enum APDUcommands {
		Select					= 0xa4,
		SelectData				= 0xa5,
		GetData					= 0xca,
		GetData2				= 0xcb,
		GetNextData				= 0xcc,
		Verify					= 0x20,
		ChangeReferenceData		= 0x24,
		ResetRetryCounter		= 0x2c,
		PutData					= 0xda,
		PutData2				= 0xdb,
		GenerateAsymmKeyPair	= 0x47,
		PSO						= 0x2a,
		Internalauthenticate	= 0x88,
		GetChallenge			= 0x84,
		ManageSecurityEnv		= 0x22,
		TerminateDF				= 0xe6,
		ActivateFile			= 0x44,
		SoloReboot				= 0xee,
	};

	class APDUStruct {
	public:
	    uint8_t cla;
	    uint8_t ins;
	    uint8_t p1;
	    uint8_t p2;
	    uint16_t lc;
	    bstr data;
	    uint32_t le;
	    bool extended_apdu;
	    uint8_t case_type;

	    constexpr void clear() {
	    	cla = 0;
	    	ins = 0;
	    	p1 = 0;
	    	p2 = 0;
	    	lc = 0;
	    	data.clear();
	    	le = 0;
	    	extended_apdu = false;
	    	case_type = 0;
	    }

	    // iso7816:2013. 5.3.2 Decoding conventions for command bodies
	    constexpr Util::Error decode(const bstr idata) {
	    	clear();

	    	cla = idata[0];
	    	ins = idata[1];
	    	p1 = idata[2];
	    	p2 = idata[3];

	    	uint8_t b0 = idata[4];

	    	// case 1
	    	if (idata.length() == 4) {
	    		case_type = 0x01;
	    	}

	    	 // case 2S (Le)
	    	if (idata.length() == 5) {
	    		case_type = 0x02;
	    		le = b0;
	    		if (!le)
	    			le = 0x100;
	    	}

	    	// case 3S (Lc + data)
	    	if (idata.length() == 5U + b0 && b0 != 0) {
	    		case_type = 0x03;
	    		lc = b0;
	    	}

	    	// case 4S (Lc + data + Le)
	    	if (idata.length() == 5U + b0 + 1U && b0 != 0) {
	    		case_type = 0x04;
	    		lc = b0;
	    		le = idata[idata.length() - 1];
	    		if (!le)
	    			le = 0x100;
	    	}

	    	// extended length apdu
	    	if (idata.length() >= 7 && b0 == 0) {
	    		uint16_t extlen = (idata[5] << 8) + idata[6];

	    		if (idata.length() - 7 < extlen) {
	    			return Util::Error::WrongAPDULength;
	    		}

	    		 // case 2E (Le) - extended
	    		if (idata.length() == 7) {
	    			case_type = 0x12;
	    			extended_apdu = true;
	    			le = extlen;
	    			if (!le)
	    				le = 0x10000;
	    		}

	    	   // case 3E (Lc + data) - extended
	    	   if (idata.length() == 7U + extlen) {
	    			case_type = 0x13;
	    			extended_apdu = true;
	    			lc = extlen;
	    		}

	    	   // case 4E (Lc + data + Le) - extended 2-byte Le
	    	   if (idata.length() == 7U + extlen + 2U) {
	    			case_type = 0x14;
	    			extended_apdu = true;
	    			lc = extlen;
	    			le = (idata[idata.length() - 2] << 8) + idata[idata.length() - 1];
	    		if (!le)
	    			le = 0x10000;
	    		}

	    	   // case 4E (Lc + data + Le) - extended 3-byte Le
	    	   if (idata.length() == 7U + extlen + 3U && idata[idata.length() - 3] == 0) {
	    			case_type = 0x24;
	    			extended_apdu = true;
	    			lc = extlen;
	    			le = (idata[idata.length() - 2] << 8) + idata[idata.length() - 1];
	    		if (!le)
	    			le = 0x10000;
	    		}
	    	} else {
	    		if ((idata.length() > 5) && (idata.length() - 5 < b0)) {
	    			return Util::Error::WrongAPDULength;
	    		}
	    	}

	    	if (!case_type) {
	    		return Util::Error::ConditionsNotSatisfied;
	    	}

	    	if (lc) {
	    		if (extended_apdu) {
	    			data = idata.substr(7, lc);
	    		} else {
	    			data = idata.substr(5, lc);
	    		}

	    	}

	    	return Util::Error::NoError;
	    }

	    constexpr void print() {
	    	printEx(0);
	    }

	    constexpr void printEx(const size_t maxdatalen) {
	        printf("APDU: %scase=0x%02x cla=0x%02x ins=0x%02x p1=0x%02x p2=0x%02x Lc=0x%02x(%d) Le=0x%02x(%d)",
	               extended_apdu ? "[e]" : "", case_type, cla, ins, p1, p2, lc, lc, le, le);
	        if (maxdatalen > 0) {
	        	if (lc > 0) {
	        		printf(" data: ");
	        		dump_hex(data, maxdatalen);
	        	} else {
	        		printf("\n");
	        	}
	        } else {
	        	printf("\n");
	        }
	    }
	};

}

#endif /* SRC_APPLETS_APDUCONST_H_ */
