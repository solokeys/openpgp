/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_APPLET_H_
#define SRC_APPLET_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "errors.h"

namespace Applet {

	class Applet {
	private:
		bool selected;

	public:
		Util::Error Init();

		Util::Error Select();
		Util::Error DeSelect();

		Util::Error APDUExchange(uint8_t *apdu, size_t length, uint8_t *result, size_t *resultLength);
	};


}

#endif /* SRC_APPLET_H_ */
