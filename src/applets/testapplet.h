/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_APPLETS_TESTAPPLET_H_
#define SRC_APPLETS_TESTAPPLET_H_

#include "applet.h"

namespace Application {

	class TestApplication: public Application {
	private:
		const bstr aid = "\xfa\xfa\xfa\xfa"_bstr;
	public:
		virtual const bstr *GetAID();

		virtual Util::Error APDUExchange(APDUStruct &apdu, bstr &result);
	};

}

#endif /* SRC_APPLETS_TESTAPPLET_H_ */
