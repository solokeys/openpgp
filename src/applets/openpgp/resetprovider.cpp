/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "resetprovider.h"

#include "device.h"
#include "solofactory.h"
#include "util.h"

namespace OpenPGP {

Util::Error ResetProvider::ResetCard() {
    Factory::SoloFactory &factory = Factory::SoloFactory::GetSoloFactory();
	File::FileSystem &filesystem = factory.GetFileSystem();

	return filesystem.DeleteFiles(File::AppletID::OpenPGP);
}

}
