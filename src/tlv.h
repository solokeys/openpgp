/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#ifndef SRC_TLV_H_
#define SRC_TLV_H_

#include "util.h"
#include "errors.h"

namespace Util {

using tag_t = uint32_t;

class TLVElm {
private:
	bstr byteStr;

	tag_t tag = 0;
	tag_t length = 0;
	uint8_t *dataptr = nullptr;
	tag_t elm_length = 0;

	constexpr Error Deserialize() {
		if (byteStr.length() < 2)
			return Error::TLVDecodeLengthError;

		size_t ptr = 0;
		tag = byteStr[ptr];
		if ((tag & 0x1f) == 0x1f) {
			// maximum 4-byte type length
			for (uint8_t i = 0; i < 3; i ++) {
				ptr++; if (ptr >= byteStr.length()) return Error::TLVDecodeTagError;
				tag = (tag << 8) + byteStr[ptr];
				if ((byteStr[ptr] & 0x80) == 0)
					break;
			}
		}

		ptr++; if (ptr >= byteStr.length()) return Error::TLVDecodeLengthError;
		uint8_t len1 = byteStr[ptr];
		length = len1;
		if (len1 == 0x81) {
			ptr++; if (ptr >= byteStr.length()) return Error::TLVDecodeLengthError;
			length = byteStr[ptr];
		}
		if (len1 == 0x82) {
			ptr++; if (ptr >= byteStr.length()) return Error::TLVDecodeLengthError;
			length = (byteStr[ptr] << 8) + byteStr[ptr + 1];
			ptr++; if (ptr >= byteStr.length()) return Error::TLVDecodeLengthError;
		}
		if (len1 > 0x82)
			return Error::TLVDecodeLengthError;

		ptr++; if (ptr >= byteStr.length()) return Error::TLVDecodeLengthError;
		elm_length = ptr + length;
		// length check
		if (elm_length > byteStr.length())
			return Error::TLVDecodeValueError;

		printf("----ptr %lu elmlen %d len %d\n", ptr, elm_length, length);

		if (length > 0)
			dataptr = byteStr.uint8Data() + ptr;
		else
			dataptr = nullptr;


		return Error::NoError;
	}
	constexpr Error Serialize() {
		return Error::NoError;
	}
public:
	constexpr Util::Error Init (bstr &_bytestr) {
		byteStr = _bytestr;
		return Deserialize();
	}

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
	constexpr Util::Error Set(bstr &data) {
		length = 0;
		Append(data);
		return Error::NoError;
	}

	constexpr tag_t Tag() {
		return tag;
	}

	constexpr tag_t Length() {
		return length;
	}

	constexpr tag_t ElmLength() {
		return elm_length;
	}

	constexpr bstr GetData() {
		return bstr(byteStr.substr(elm_length - length, length));
	}
};

const static size_t MaxTreeLevel = 10U;

class TLVTree {
private:
	bstr _data;
	TLVElm _elm[MaxTreeLevel];
	uint8_t currLevel = 0;
public:
	constexpr Util::Error Init(bstr data) {
		_data = data;
		currLevel = 0;
		return _elm[0].Init(_data);
	};

	constexpr void GoFirst() {
		Init(_data);
	}

	constexpr TLVElm &CurrentElm() {
		return _elm[currLevel];
	}

	constexpr bool GoParent() {
		printf("goparent\n");
		if (currLevel == 0)
			return false;
		currLevel--;
		return true;
	}

	constexpr bool GoChild() {
		printf("gochild %x\n", _elm[currLevel].Tag());
		if (currLevel >= MaxTreeLevel - 1)
			return false;

		bstr data = _elm[currLevel].GetData();
		printf("--- %lu\n", data.length());
		if (data.length() == 0 || _elm[currLevel + 1].Init(data) != Util::Error::NoError)
			return false;

		currLevel++;
		printf("gochild ok lvl:%d\n", currLevel);
		return true;
	}

	constexpr bool GoNext() {
		printf("gonext %x\n", _elm[currLevel].Tag());
		return false;
	}

	constexpr TLVElm *Search(tag_t tag) {
		GoFirst();
		while (true) {
			if (CurrentElm().Tag() == tag)
				return &CurrentElm();

			if (GoChild())
				continue;

			if (GoNext()) {
				continue;
			} else {
				// return condition
				if (currLevel == 0)
					return nullptr;
			}

			while (true) {
				if (GoNext()) {
					continue;
				} else {
					// exit condition
					if (!GoParent())
						return nullptr;
				}
			}
		}

		return nullptr;
	}
};

} /* namespace Util */

#endif /* SRC_TLV_H_ */
