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

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#endif

namespace std {
	template<typename _CharT, typename _Traits = std::char_traits<_CharT>>
    class w_basic_string_view : public basic_string_view<_CharT, _Traits> {
    private:
		size_t _max_length;
    public:
		using basic_string_view<_CharT, _Traits>::basic_string_view;

		constexpr w_basic_string_view(std::basic_string_view<_CharT, _Traits> sv, size_t maxLength = 0)
							:basic_string_view<_CharT, _Traits>(sv) {
			_max_length = MAX(sv.length(), maxLength);
		}
		constexpr w_basic_string_view(const _CharT* __str, size_t __len, size_t maxLength = 0)
							:basic_string_view<_CharT, _Traits>(__str, __len) {
			_max_length = MAX(__len, maxLength);
		}


		constexpr uint8_t *uint8Data() {
			return const_cast<uint8_t *>(this->data());
		}

		constexpr void clear() {
			this->remove_suffix(this->length());
		}

		constexpr void append(const uint8_t *data, size_t len) {
			uint8_t *dst = const_cast<uint8_t*>(this->data());
			w_basic_string_view<_CharT, _Traits> newsv(dst, this->length() + len);

			dst += this->length();
			for (size_t i = 0; i < len; i++)
			  *dst++ = *data++;

			*this = newsv;
		}

		constexpr void append(uint8_t b) {
			append(&b, 1);
		}

		constexpr void appendAPDUres(uint16_t w) {
			uint8_t b[2];
			b[0] = (w >> 8) & 0xff;
			b[1] = w & 0xff;
			append(b, 2);
		}

		constexpr void append(std::basic_string_view<_CharT, _Traits> sv) {
			append(sv.data(), sv.length());
		}

		constexpr void set(std::basic_string_view<_CharT, _Traits> sv) {
			clear();
			append(sv.data(), sv.length());
		}

		constexpr void setAPDURes(uint16_t w) {
			clear();
			appendAPDUres(w);
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

#endif
