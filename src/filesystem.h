/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef SRC_FILESYSTEM_H_
#define SRC_FILESYSTEM_H_

#include <util.h>
#include <errors.h>

namespace File {

enum FileType {
	File,
	Key
};

// Read only file system for system files. files lays in program flash.
class ConfigFileSystem {
private:
public:
	Util::Error ReadFile(AppID_t AppId, KeyID_t FileID, FileType FileType, bstr &data);
};

class FileSystem {
private:
	ConfigFileSystem cfgFiles;
public:
	Util::Error ReadFile(AppID_t AppId, KeyID_t FileID, FileType FileType, bstr &data);
	Util::Error WriteFile(AppID_t AppId, KeyID_t FileID, FileType FileType, bstr &data);

	Util::Error DeleteFile(AppID_t AppId, KeyID_t FileID, FileType FileType);
	Util::Error DeleteFiles(AppID_t AppId);
};

}

#endif /* SRC_FILESYSTEM_H_ */
