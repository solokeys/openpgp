/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_TLVELM_H_
#define SRC_TLVELM_H_

#include "util.h"
#include "errors.h"

namespace Util {

using tag_t = uint32_t;

class TLVElm {
private:
	bstr &byteStr;

	tag_t tag = 0;
	tag_t length = 0;
	uint8_t *dataptr = nullptr;

	Error Deserialize();
	Error Serialize();
public:
	TLVElm(bstr &_bytestr) : byteStr(_bytestr) {};

	void constexpr Clear() {
		length = 0;
	}
	void constexpr Delete() { // maybe not here...
		tag = 0;
		length = 0;
	}
	void constexpr Append(bstr &data) {
		;
	}
	void constexpr Set(bstr &data) {
		length = 0;
		Append(data);
	}

};

} /* namespace Util */

#endif /* SRC_TLVELM_H_ */
