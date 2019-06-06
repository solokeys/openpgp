/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#include <tlv.h>

namespace Util {


/*
 * TLV test
 * 		bstr test = "1234"_bstr;
		tlv.AddChild(0xf4, &test);
		tlv.AddNext(0x82, &strExp);
		tlv.Search(0xf4);
		printf("tlv currtag %x\n", tlv.CurrentElm().Tag());
		tlv.AddChild(0x83, &test);
		tlv.AddNext(0x84, &test);
		tlv.AddNext(0x85, &test);
		tlv.PrintTree();
		tlv.Search(0x84);
		printf("tlv currtag %x\n", tlv.CurrentElm().Tag());
		tlv.DeleteCurrent();
		printf("tlv currtag %x\n", tlv.CurrentElm().Tag());
		tlv.PrintTree();
 *
 */



} /* namespace Util */
