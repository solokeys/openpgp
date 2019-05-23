// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _UTIL_H
#define _UTIL_H

#include <cstdint>
#include <vector>

typedef std::vector<uint8_t> bstr;
typedef uint16_t KeyID_t;
typedef uint16_t AppID_t;

void dump_hex(uint8_t * buf, int size);

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#endif


#endif
