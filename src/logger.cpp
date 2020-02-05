/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include <stdarg.h>
#include "logger.h"

#define OPGP_DEBUG

namespace Logger {

	const char* LogPrefixStr[lpLast + 1] {
		"APDU",
		"File",
		"Logic",
		"Crypto",

		""
	};

	void printflog(LogPrefix prefix, const char *fmt, ...) {
	#ifdef OPGP_DEBUG
		printf_device("[%s] ", LogPrefixStr[prefix]);
		va_list vl;
		va_start(vl, fmt);
		printf_device(fmt, vl);
		va_end(vl);
	#endif
	}

	void printflogAPDU(const char *fmt, ...) {
		va_list vl;
		va_start(vl, fmt);
		printflog(LogPrefix::lpAPDU, fmt, vl);
		va_end(vl);
	}
}

