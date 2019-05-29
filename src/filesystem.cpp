/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "filesystem.h"

namespace File {

Util::Error ConfigFileSystem::ReadFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data) {

	switch (FileID) {
	// EF.DIR. OpenPGP v 3.3.1 page 12.
	case 0x2f00:
		data.set("\x61\x11\x4F\x06\xD2\x76\x00\x01\x24\x01\x50\x07OpenPGP"_bstr);
		return Util::Error::NoError;

	default:
		break;
	}


	return Util::Error::FileNotFound;
}


Util::Error FileSystem::ReadFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data) {

	data.clear();




	// check if we can read file from config area. here always a lowest priority
	auto err = cfgFiles.ReadFile(AppId, FileID, FileType, data);
	if (err == Util::Error::NoError)
		return err;

	return Util::Error::NoError;
}

Util::Error FileSystem::WriteFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType, bstr& data) {

	return Util::Error::FileWriteError;
}


Util::Error FileSystem::DeleteFile(AppID_t AppId, KeyID_t FileID,
		FileType FileType) {

	return Util::Error::FileNotFound;
}

Util::Error FileSystem::DeleteFiles(AppID_t AppId) {

	return Util::Error::NoError;
}

} // namespace File
