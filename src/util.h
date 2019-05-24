// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <cstdint>
#include <string_view>

namespace std {
	template<typename _CharT, typename _Traits = std::char_traits<_CharT>>
    class w_basic_string_view : public basic_string_view<_CharT, _Traits> {
    public:
		using basic_string_view<_CharT, _Traits>::basic_string_view;

		constexpr size_t vsize() const {
			return sizeof(this->value_type);
		};

		constexpr void clear() {
			this->remove_suffix(this->length());
		}

		constexpr void append(uint8_t b) {
			append(&b, 1);
		}

		constexpr void append(const uint8_t *data, size_t len) {
			uint8_t *dst = const_cast<uint8_t*>(this->data());
			w_basic_string_view<_CharT, _Traits> newsv(dst, this->length() + len);

			dst += this->length();
			for (size_t i = 0; i < len; i++)
			  *dst++ = *data++;

			*this = newsv;
		}

		constexpr void append(std::basic_string_view<_CharT, _Traits> sv) {
			append(sv.data(), sv.length());
		}
   };
}

using bstr = std::w_basic_string_view<uint8_t>;
constexpr bstr operator "" _bstr(const char* data, size_t len){
	return bstr(reinterpret_cast<const uint8_t *>(data), len);
};

using KeyID_t = uint16_t;
using AppID_t = uint16_t;

void dump_hex(uint8_t * buf, int size);
void dump_hex(bstr data);

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#endif


#endif
