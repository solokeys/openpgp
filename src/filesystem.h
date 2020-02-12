/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef SRC_FILESYSTEM_H_
#define SRC_FILESYSTEM_H_

#include <opgputil.h>
#include <errors.h>
#include <tlv.h>

namespace File {

enum FileType {
	File,
	TLVFile,
	Secure
};

enum SecureFileID {
	PW1   = 0x80,
	PW3   = 0x81,
	RC    = 0x82,

	State = 0x90,

	DigitalSignature = 0xb6,
	Confidentiality  = 0xb8,
	Authentication   = 0xa4,

	AES              = 0xd5,
};

enum AppletID {
	All     = 0,
	Test    = 1,
	OpenPGP = 2,
};

// settings for wrapping multiple tlv tags with tag itself in response.
constexpr bool WRAP_GROUP_TAGS = false;

class FileSystem;

class SettingsFileSystem {
private:
	FileSystem &fs;
public:
	SettingsFileSystem(FileSystem &_fs) : fs(_fs){};

	Util::Error ReadFile(AppID_t AppId, KeyID_t FileID, FileType FileType, bstr &data);
	Util::Error WriteFile(AppID_t AppId, KeyID_t FileID, FileType FileType, bstr &data, bool adminMode = false);
};

// Read only file system for system files. files lays in program flash.
class ConfigFileSystem {
private:
	void FillExtendedCapatibilities(bstr &data);
	void FillFeatures(bstr &data);
public:
	Util::Error ReadFile(AppID_t AppId, KeyID_t FileID, FileType FileType, bstr &data);
};

class GenericFileSystem {
private:
public:
	Util::Error SetFileName(AppID_t AppId, KeyID_t FileID, FileType FileType, char *name);

	bool FileExist(AppID_t AppId, KeyID_t FileID, FileType FileType);
	Util::Error ReadFile(AppID_t AppId, KeyID_t FileID, FileType FileType, bstr &data);
	Util::Error WriteFile(AppID_t AppId, KeyID_t FileID, FileType FileType, bstr &data);
};

class FileSystem {
private:
	ConfigFileSystem cfgFiles;
	GenericFileSystem genFiles;
	SettingsFileSystem settingsFiles{*this};

	bool isTagComposite(Util::tag_t tag);

public:
	Util::Error ReadFile(AppID_t AppId, KeyID_t FileID, FileType FileType, bstr &data);
	Util::Error WriteFile(AppID_t AppId, KeyID_t FileID, FileType FileType, bstr &data, bool adminMode = false);

	Util::Error DeleteFile(AppID_t AppId, KeyID_t FileID, FileType FileType);
	Util::Error DeleteFiles(AppID_t AppId);

	ConfigFileSystem &getCfgFiles() {
		return cfgFiles;
	}

	GenericFileSystem &getGenFiles() {
		return genFiles;
	}

	SettingsFileSystem &getSettingsFiles() {
		return settingsFiles;
	}
};

}

#endif /* SRC_FILESYSTEM_H_ */
