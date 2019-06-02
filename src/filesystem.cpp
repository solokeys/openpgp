/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "filesystem.h"
#include <array>
#include "device.h"

namespace File {

struct CompositeTag_t {
	Util::tag_t TagGroup;
	Util::tag_t TagElm;
	bool WithTag;
	size_t TagLength; // If WithTag=false here must be constant length
};

std::array<CompositeTag_t, 24> CompositeTag = {{
//CompositeTag_t CompositeTag[] = {
	// Cardholder Related Data
	{0x65, 0x5b,   true,  0},  // name
	{0x65, 0x5f2d, true,  0},  // language
	{0x65, 0x5f35, true,  0},  // sex  1 male 2 female 9(n/a)

	// Application Related Data
	{0x6e, 0x4f,   true,  0},  // Full Application identifier (AID), ISO 7816-4
	{0x6e, 0x5f52, true,  0},  // Historical bytes (page 38)
	{0x6e, 0x73,   true,  0},  // Discretionary data objects

	// Discretionary data objects
	{0x73, 0xc0,   true,  0},  // Extended Capabilities
	{0x73, 0xc1,   true,  0},  // Algorithm attributes signature
	{0x73, 0xc2,   true,  0},  // Algorithm attributes decryption
	{0x73, 0xc3,   true,  0},  // Algorithm attributes authentication
	{0x73, 0xc4,   true,  0},  // PW status Bytes
	{0x73, 0xc5,   true,  0},  // List of Fingerprints 20b per key. order: Sig, Dec, Auth
	{0x73, 0xc6,   true,  0},  // List of CA-Fingerprints 20b per key. order: Sig, Dec, Auth
	{0x73, 0xcd,   true,  0},  // List of generation dates/times of public key pairs,
                               // 4 bytes each, order: Sig, Dec, Auth, seconds since Jan 1, 1970,

	// individual Fingerprints
	{0xc5, 0xc7,   false, 20}, // Sig
	{0xc5, 0xc8,   false, 20}, // Dec
	{0xc5, 0xc9,   false, 20}, // Auth

	// individual CA-Fingerprints
	{0xc6, 0xca,   false, 20}, // Sig
	{0xc6, 0xcb,   false, 20}, // Dec
	{0xc6, 0xcc,   false, 20}, // Auth

// List of generation dates/times
	{0xcd, 0xce,   false, 4}, // Sig
	{0xcd, 0xcf,   false, 4}, // Dec
	{0xcd, 0xd0,   false, 4}, // Auth
}};

/*  Application Related Data
 *  4F 10 D2 76 00 01 24 01 02 01 00 05 00 00 31 88 00 00 Full Application identifier (AID), ISO 7816-4
 *  5F 52 0A 00 31 C5 73 C0 01 40 05 90 00  Historical bytes (page 38) 00 - iso format ....  05 - operational state 90 00 - ok
 *  Discretionary data objects
 *  73 81 B7
 *  C0 0A 7C 00 08 00 08 00 08 00 08 00 Extended Capabilities
 *  C1 06 01 08 00 00 20 00             Algorithm attributes signature
 *  C2 06 01 08 00 00 20 00             Algorithm attributes decryption
 *  C3 06 01 08 00 00 20 00             Algorithm attributes authentication
 *  C4 07 00 20 20 20 03 00 03          PW status Bytes
 *  C5 3C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Fingerprints 20b per key. order: Sig, Dec, Auth
 *        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 *        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 *        00 00 00 00 00 00 00 00 00 00 00 00
 *  C6 3C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 List of CA-Fingerprints
 *        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 *        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 *        00 00 00 00 00 00 00 00 00 00 00 00
 *  CD 0C 00 00 00 00 00 00 00 00 00 00 00 00             List of generation dates/times of public key pairs,
 *                                                        4 bytes each, order: Sig, Dec, Auth, seconds since Jan 1, 1970,
 *
 *	0x65 Cardholder Related Data
 *	5B 00  5F 2D 02 65 6e  5F 35 01 39    5b name, 5f2d language = en, 5f35 sex = 9(n/a)
*/

Util::Error FileSystem::SetFileName(AppID_t AppId, KeyID_t FileID,
		FileType FileType, char* name) {
	name[0] = '\0';

	sprintf(name, "%d_%d_%d", AppId, FileID, FileType);

	return Util::Error::NoError;
}

Util::Error ConfigFileSystem::ReadFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data) {

	// secure objects
	if (FileType == FileType::Key)
		switch (FileID) {
		case KeyFileID::PW1:
			data.set("123456"_bstr);
			return Util::Error::NoError;
		case KeyFileID::PW3:
			data.set("12345678"_bstr);
			return Util::Error::NoError;
		default:
			break;
		}


	// files
	switch (FileID) {
	// EF.DIR. OpenPGP v 3.3.1 page 12.
	case 0x2f00:
		data.set("\x61\x11\x4F\x06\xD2\x76\x00\x01\x24\x01\x50\x07OpenPGP"_bstr);
		return Util::Error::NoError;

	// General feature management. OpenPGP v 3.3.1 page 14
	case 0x7f74:
		data.set("\x81\x01\x28"_bstr); // Button and LED
		return Util::Error::NoError;

	// AID
	case 0x4f:
		data.set("\xD2\x76\x00\x01\x24\x01\x02\x01\x00\x05\x00\x00\x31\x88\x00\x00"_bstr); // from 0x6e
		return Util::Error::NoError;

	// Historical bytes
	case 0x5f52:
		data.set("\x00\x31\xC5\x73\xC0\x01\x40\x05\x90\x00"_bstr); // from 0x6e
		return Util::Error::NoError;

	// Extended Capabilities
	case 0xc0:
		data.set("\x74\x00\x00\x20\x08\x00\x00\xff\x01\x00"_bstr); // from 0x6e
		return Util::Error::NoError;

	// Algorithm Attributes
	case 0xc1:  // Sig
	case 0xc2:  // Dec
	case 0xc3:  // Auth
		data.set("\x01\x08\x00\x00\x20\x00"_bstr); // from 0x6e
		return Util::Error::NoError;

	// PW Status Bytes (binary)
	case 0xc4:
		data.set("\x00\x20\x20\x20\x03\x00\x03"_bstr); // from 0x6e
		return Util::Error::NoError;

	// Security support template
	case 0x7a:
		data.set("\x93\x03\x00\x00\x00"_bstr); // 93 - Digital signature counter (counts usage of Compute	Digital Signature command), binary, ISO 7816-4

		return Util::Error::NoError;

	// Sex
	case 0x5f35:
		data.set("\x39"_bstr); // sex = 9(n/a)
		return Util::Error::NoError;

	// empty files
	case 0x5b:   // name
	case 0x5f2d: // language
	case 0x5e:   // Login data
	case 0x5f50: //  URL with Link to a set of public keys

	// individual list of dates/times. from 0xcd
	case 0xce: // Sig
	case 0xcf: // Dec
	case 0xd0: // Auth

	// individual Fingerprints. from 0xc5
	case 0xc7: // Sig
	case 0xc8: // Dec
	case 0xc9: // Auth

	// individual CA-Fingerprints. from 0xc6
	case 0xca: // Sig
	case 0xcb: // Dec
	case 0xcc: // Auth
		data.clear();
		return Util::Error::NoError;

	default:
		break;
	}


	return Util::Error::FileNotFound;
}

bool FileSystem::isTagComposite(Util::tag_t tag) {
	for(const auto& ctag: CompositeTag) {
    	if (ctag.TagGroup == tag) {
    		return true;
    	}
    }
	return false;
}

Util::Error FileSystem::ReadFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data) {

	data.clear();

	// check if it needs to compose file
	if (isTagComposite(FileID)) {
		uint8_t _vdata[1024] = {0};
		bstr vdata(_vdata);
		for(const auto& ctag: CompositeTag) {
	    	if (ctag.TagGroup == FileID) {
	    		vdata.clear();

	    		ReadFile(AppId, ctag.TagElm, FileType, vdata);

	    		if (ctag.WithTag) {
					if (ctag.TagElm > 0xff)
						data.appendAPDUres(ctag.TagElm);
					else
						data.append(ctag.TagElm);
					data.append(vdata.length());
					data.append(vdata);
	    		} else {
	    			if (ctag.TagLength == vdata.length()) {
	    				data.append(vdata);
	    			} else {
	    				for (size_t i = 0; i < ctag.TagLength; i++)
	    					data.append(0x00);
	    			}
	    		}
	    	}
	    }
		return Util::Error::NoError;
	}

	// try to read file
	char file_name[100] = {0};
	SetFileName(AppId, FileID, FileType, file_name);

	size_t len = 0;
	int res = readfile(file_name, data.uint8Data(), 1024, &len); // TODO: change 1024 to `data` max length
	if (res == 0) {
		data.set_length(len);
		return Util::Error::NoError;
	}

	// try to read file from tlv config
	// TODO:

	// check if we can read file from config area. here always a lowest priority
	auto err = cfgFiles.ReadFile(AppId, FileID, FileType, data);
	if (err == Util::Error::NoError)
		return err;

	return Util::Error::NoError;
}

Util::Error FileSystem::WriteFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data) {

	char file_name[100] = {0};
	SetFileName(AppId, FileID, FileType, file_name);

	int res = writefile(file_name, data.uint8Data(), data.length());
	if (res != 0)
		return Util::Error::FileWriteError;

	return Util::Error::NoError;
}


Util::Error FileSystem::DeleteFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType) {

	char file_name[100] = {0};
	SetFileName(AppId, FileID, FileType, file_name);

	deletefile(file_name);

	return Util::Error::FileNotFound;
}

Util::Error FileSystem::DeleteFiles(AppID_t AppId) {

	char file_name[100] = {0};
	sprintf(file_name, "%d_*", AppId);
	deletefiles(file_name);

	return Util::Error::NoError;
}

} // namespace File
