/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_APPLET_H_
#define SRC_APPLET_H_

#include <cstdint>
#include <util.h>

#include "errors.h"

namespace Applet {

	class Applet {
	protected:
		bool selected;
		const bstr aid = {0x00};

		// TODO: applet config load/save

	public:
		virtual ~Applet();

		virtual Util::Error Init();

		virtual Util::Error Select();
		virtual Util::Error DeSelect();

		virtual const bstr *GetAID();

		virtual Util::Error APDUExchange(bstr* apdu, bstr* result);
	};


}

#endif /* SRC_APPLET_H_ */
