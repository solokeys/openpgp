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
#include "tlv.h"
#include "applets/openpgp/openpgpconst.h"

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

void ConfigFileSystem::FillExtendedCapatibilities(bstr &data) {
	uint8_t *bdata = data.uint8Data();
	data.clear();
	// was "\x74\x00\x00\x20\x08\x00\x00\xff\x01\x00"
	bdata[0] =
			0x00 |  // Secure Messaging supported
			0x40 |  // Support for GET CHALLENGE
			0x20 |  // Support for Key Import
			0x10 |  // PW Status changeable (DO C4 available for PUT DATA)
			0x08 |  // Support for Private use DOs (0101-0104)
			0x04 |  // Algorithm attributes changeable with PUT DATA
			0x02 |  // PSO:DEC/ENC with AES
			0x01;   // KDF-DO (F9) and related functionality available
	// Secure Messaging Algorithm (SM)
	// 00 = no SM or proprietary implementation
	// 01 = AES 128 bit
	// 02 = AES 256 bit
	// 03 = SCP11b
	bdata[1] = 0x00;
	// Maximum length of a challenge supported by the command GET CHALLENGE (unsigned integer, Most Significant Bit ... Least Significant Bit)
	bdata[2] = OpenPGP::PGPConst::MaxGetChallengeLen >> 8;
	bdata[3] = OpenPGP::PGPConst::MaxGetChallengeLen & 0xff;
	// Maximum length of Cardholder Certificates (DO 7F21, each for AUT, DEC and SIG)
	bdata[4] = OpenPGP::PGPConst::MaxCardholderCertificateLen >> 8;
	bdata[5] = OpenPGP::PGPConst::MaxCardholderCertificateLen & 0xff;
	// Maximum length of special DOs with no precise length information given in the definition (Private Use, Login data, URL,
	// Algorithm attributes, KDF etc.)
	bdata[6] = OpenPGP::PGPConst::MaxSpecialDOLen >> 8;
	bdata[7] = OpenPGP::PGPConst::MaxSpecialDOLen & 0xff;
	// PIN block 2 format
	// 0 = not supported, 1 = supported
	bdata[8] = 0x01;
	// MSE command for key numbers 2 (DEC) and 3 (AUT)
	// 0 = not supported, 1 = supported
	bdata[9] = 0x00;

	data.set_length(10);
}

void ConfigFileSystem::FillFeatures(bstr &data) {
	// was "\x81\x01\x28"
	data.set("\x81\x01\x00"_bstr); // Button and LED
	data.uint8Data()[2] =
			0x00 | // Display (defined by ISO/IEC 7816-4)
			0x00 | // Biometric input sensor (defined by ISO/IEC 7816-4)
			0x20 | // Button
			0x00 | // Keypad
			0x08 | // LED
			0x00 | // Loudspeaker
			0x00 | // Microphone
			0x00;  // Touchscreen
}

Util::Error ConfigFileSystem::ReadFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data) {

	// secure objects
	if (FileType == FileType::Secure)
		switch (FileID) {
		case SecureFileID::PW1:
			data.set("123456"_bstr);
			return Util::Error::NoError;
		case SecureFileID::PW3:
			data.set("12345678"_bstr);
			return Util::Error::NoError;
		case SecureFileID::State:
			data.set("\x05"_bstr);  // State - Operational by default
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
		FillFeatures(data);
		return Util::Error::NoError;

	// AID
	case 0x4f:
		data.set("\xD2\x76\x00\x01\x24\x01\x02\x01\x00\x05\x00\x00\x31\x88\x00\x00"_bstr); // group (0x6e) Application Related Data
		return Util::Error::NoError;

	// Historical bytes
	case 0x5f52:
		data.set("\x00\x31\xC5\x73\xC0\x01\x40\x05\x90\x00"_bstr); // group (0x6e)
		return Util::Error::NoError;

	// Extended Capabilities. Group (0x6e) Application Related Data
	case 0xc0:
		FillExtendedCapatibilities(data);
		return Util::Error::NoError;

	// Algorithm Attributes
	case 0xc1:  // Sig
	case 0xc2:  // Dec
	case 0xc3:  // Auth
		data.set("\x01\x08\x00\x00\x20\x00"_bstr); // group (0x6e)
		return Util::Error::NoError;

	// PW Status Bytes (binary)
	case 0xc4:
		uint8_t PWStatusBytesDefault[7];

		PWStatusBytesDefault[0] = OpenPGP::PGPConst::PWValidPSOCDSCommand;
		PWStatusBytesDefault[1] = OpenPGP::PGPConst::PW1MaxLength;
		PWStatusBytesDefault[2] = OpenPGP::PGPConst::RCMaxLength;
		PWStatusBytesDefault[3] = OpenPGP::PGPConst::PW3MaxLength;
		PWStatusBytesDefault[4] = OpenPGP::PGPConst::DefaultPWResetCounter;
		PWStatusBytesDefault[5] = OpenPGP::PGPConst::DefaultRCResetCounter;
		PWStatusBytesDefault[6] = OpenPGP::PGPConst::DefaultPWResetCounter;

		data.set(bstr(PWStatusBytesDefault, sizeof(PWStatusBytesDefault)));
		return Util::Error::NoError;

	// Security support template
	case 0x7a:
		data.set("\x93\x03\x00\x00\x00"_bstr); // 93 - Digital signature counter (counts usage of Compute Digital Signature command), binary, ISO 7816-4

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

Util::Error GenericFileSystem::SetFileName(AppID_t AppId, KeyID_t FileID,
		FileType FileType, char* name) {
	name[0] = '\0';

	sprintf(name, "%d_%d_%d", AppId, FileID, FileType);

	return Util::Error::NoError;
}

bool GenericFileSystem::FileExist(AppID_t AppId, KeyID_t FileID, FileType FileType) {
	char file_name[100] = {0};
	SetFileName(AppId, FileID, FileType, file_name);

	return fileexist(file_name);
}

Util::Error GenericFileSystem::ReadFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data) {

	// try to read file
	char file_name[100] = {0};
	SetFileName(AppId, FileID, FileType, file_name);

	size_t len = 0;
	int res = readfile(file_name, data.uint8Data(), data.max_length(), &len);
	if (res == 0) {
		data.set_length(len);
		return Util::Error::NoError;
	}

	return Util::Error::FileNotFound;
}

Util::Error GenericFileSystem::WriteFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data) {

	char file_name[100] = {0};
	SetFileName(AppId, FileID, FileType, file_name);

	int res = writefile(file_name, data.uint8Data(), data.length());
	if (res != 0)
		return Util::Error::FileWriteError;

	return Util::Error::NoError;
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
		bstr vdata(_vdata, 0, sizeof(_vdata));
		Util::TLVTree tlv;
		for(const auto& ctag: CompositeTag) {
	    	if (ctag.TagGroup == FileID) {
	    		vdata.clear();

	    		auto rerr = ReadFile(AppId, ctag.TagElm, FileType, vdata);
	    		if (rerr != Util::Error::NoError){
	    			data.clear();
	    			return rerr;
	    		}

	    		if (ctag.WithTag) {
	    			if (data.length() == 0) {
	    				tlv.Init(data);
	    				if (WRAP_GROUP_TAGS) {
		    				tlv.AddRoot(FileID);
		    				tlv.AddChild(ctag.TagElm, &vdata);
	    				} else {
		    				tlv.AddRoot(ctag.TagElm, &vdata);
	    				}
	    			} else {
	    				tlv.AddNext(ctag.TagElm, &vdata);
	    			}
	    			data.set_length(tlv.GetDataLink().length());
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

	// from settings file system
	auto err = settingsFiles.ReadFile(AppId, FileID, FileType, data);
	if (err == Util::Error::NoError)
		return err;

	// from general file system
	err = genFiles.ReadFile(AppId, FileID, FileType, data);
	if (err == Util::Error::NoError)
		return err;

	// check if we can read file from config area. here always a lowest priority
	err = cfgFiles.ReadFile(AppId, FileID, FileType, data);
	if (err == Util::Error::NoError)
		return err;

	return Util::Error::FileNotFound;
}

Util::Error FileSystem::WriteFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data, bool adminMode) {
printf("* Os error here\n");
	// to settings file system
	auto err = settingsFiles.WriteFile(AppId, FileID, FileType, data, adminMode);
	if (err != Util::Error::FileNotFound)
		return err;

	// main write to filesystem
	err = genFiles.WriteFile(AppId, FileID, FileType, data);
	if (err != Util::Error::FileNotFound)
		return err;

	return Util::Error::FileNotFound;
}


Util::Error FileSystem::DeleteFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType) {

	char file_name[100] = {0};
	genFiles.SetFileName(AppId, FileID, FileType, file_name);

	deletefile(file_name);

	return Util::Error::NoError;
}

Util::Error FileSystem::DeleteFiles(AppID_t AppId) {

	char file_name[100] = {0};
	sprintf(file_name, "%d_*", AppId);
	deletefiles(file_name);

	return Util::Error::NoError;
}

Util::Error SettingsFileSystem::ReadFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data) {

	return Util::Error::FileNotFound;
}

Util::Error SettingsFileSystem::WriteFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data, bool adminMode) {

	// PW status Bytes
	if (FileID == 0xc4 && !(adminMode && data.length() == 7)) {
		if ((data.length() != 1) && (data.length() != 4))
			return Util::Error::WrongAPDUDataLength;

		uint8_t _vdata[50] = {0};
		bstr vdata(_vdata);

		// read from generic filesystem
		auto err = fs.ReadFile(AppId, FileID, FileType, vdata);
		if (err != Util::Error::NoError)
			return err;

		if (vdata.length() != 7)
			return Util::Error::InternalError;

		uint8_t *d = vdata.uint8Data();
		d[0] = data[0];
		if (data.length() == 4) {
			d[1] = data[1];
			d[2] = data[2];
			d[3] = data[3];
		}

		// write to generic filesystem
		err = fs.getGenFiles().WriteFile(AppId, FileID, FileType, vdata);
		return err;

	}

	return Util::Error::FileNotFound;
}

} // namespace File


