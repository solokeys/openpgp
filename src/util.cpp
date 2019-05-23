// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#include "util.h"

void dump_hex(uint8_t * buf, int size)
{
    while(size--)
    {
        printf("%02x ", *buf++);
    }
    printf("\n");
}

void dump_hex(bstr data) {
	dump_hex(const_cast<uint8_t*>(&data.front()), data.length());
}

