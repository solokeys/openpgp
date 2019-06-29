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
#include <array>
#include <string.h>

namespace Util {

using tag_t = uint32_t;

static const std::array<tag_t, 10> ConstructedTagsList = {
	0x65,
	0x6e,
	0x73,
	0x7a,
	//0x7f21, // Cardholder certificate
	0x7f66,
	0x7f74,
	0xf4,
	0xf9,

	0x4d,

	0x7f49  // key structure response
};

constexpr bool isTagConstructed(tag_t tag) {
	for(const auto& ctag: ConstructedTagsList) {
    	if (ctag == tag) {
    		return true;
    	}
    }
	return false;
}

constexpr Error ExtractTag(bstr &str, size_t &pos, tag_t &tag) {
	if (str.length() < 2)
		return Error::TLVDecodeLengthError;

	tag = str[pos];
	if ((tag & 0x1f) == 0x1f) {
		// maximum 4-byte type length
		for (uint8_t i = 0; i < 3; i ++) {
			pos++; if (pos >= str.length()) return Error::TLVDecodeTagError;
			tag = (tag << 8) + str[pos];
			if ((str[pos] & 0x80) == 0)
				break;
		}
	}

	return Error::NoError;
}

constexpr Error ExtractLength(bstr &str, size_t &pos, tag_t &length) {
	if (str.length() < 2)
		return Error::TLVDecodeLengthError;

	uint8_t len1 = str[pos];
	length = len1;
	if (len1 == 0x81) {
		pos++; if (pos >= str.length()) return Error::TLVDecodeLengthError;
		length = str[pos];
	}
	if (len1 == 0x82) {
		pos++; if (pos >= str.length()) return Error::TLVDecodeLengthError;
		length = (str[pos] << 8) + str[pos + 1];
		pos++; if (pos >= str.length()) return Error::TLVDecodeLengthError;
	}
	if (len1 > 0x82)
		return Error::TLVDecodeLengthError;

	return Error::NoError;
}

constexpr Error EncodeTag(bstr &str, size_t &size, tag_t tag) {

	if (tag > 0xffffff) {
		str.append((tag & 0xff000000) >> 24);
		size++;
	}
	if (tag > 0xffff) {
		str.append((tag & 0xff0000) >> 16);
		size++;
	}
	if (tag > 0xff) {
		str.append((tag & 0xff00) >> 8);
		size++;
	}
	str.append(tag & 0xff);
	size++;

	return Error::NoError;
}

constexpr Error EncodeLength(bstr &str, size_t &size, tag_t length) {

	if (length < 0x80) {
		str.append(length);
		size++;
		return Error::NoError;
	}
	if (length < 0x100) {
		str.append(0x81);
		str.append(length);
		size += 2;
		return Error::NoError;
	}
	if (length < 0x10000) {
		str.append(0x82);
		str.append((length >> 8) & 0xff);
		str.append(length & 0xff);
		size += 3;
		return Error::NoError;
	}
	if (length < 0x1000000) {
		str.append(0x83);
		str.append((length >> 16) & 0xff);
		str.append((length >> 8) & 0xff);
		str.append(length & 0xff);
		size += 4;
		return Error::NoError;
	}

	return Error::NoError;
}


class TLVElm {
private:
	bstr byteStr;

	tag_t tag = 0;
	tag_t length = 0;
	uint8_t *dataptr = nullptr;
	tag_t elm_length = 0;
	tag_t rest_length = 0;

	constexpr Error Deserialize() {
		tag = 0;
		length = 0;
		dataptr = nullptr;
		elm_length = 0;
		rest_length = 0;

		size_t ptr = 0;
		auto err = ExtractTag(byteStr, ptr, tag);
		if (err != Error::NoError)
			return err;

		ptr++; if (ptr >= byteStr.length()) return Error::TLVDecodeLengthError;
		err = ExtractLength(byteStr, ptr, length);
		if (err != Error::NoError)
			return err;

		// ptr can be out of range if length of elm = 0
		ptr++; if (ptr > byteStr.length()) return Error::TLVDecodeLengthError;
		elm_length = ptr + length;
		rest_length = byteStr.length() - elm_length;
		// length check
		if (elm_length > byteStr.length())
			return Error::TLVDecodeValueError;

		if (length > 0)
			dataptr = byteStr.uint8Data() + ptr;
		else
			dataptr = nullptr;

		return Error::NoError;
	}
public:
	constexpr Util::Error Init (bstr &_bytestr) {
		byteStr = _bytestr;
		return Deserialize();
	}

	constexpr Util::Error InitRest () {
		if (rest_length == 0)
			return Util::Error::TLVDecodeLengthError;

		byteStr = byteStr.substr(elm_length, rest_length);
		return Deserialize();
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

	constexpr tag_t HeaderLength() {
		return elm_length - length;
	}

	constexpr tag_t RestLength() {
		return rest_length;
	}

	constexpr bstr GetData() {
		return bstr(byteStr.substr(elm_length - length, length));
	}
	constexpr uint8_t *GetPtr() {
		return byteStr.uint8Data();
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

	constexpr bool GoFirst() {
		return Init(_data) == Error::NoError;
	}

	constexpr TLVElm &CurrentElm() {
		return _elm[currLevel];
	}

	constexpr bool GoParent() {
		if (currLevel == 0)
			return false;
		currLevel--;
		return true;
	}

	constexpr bool GoChild() {
		if (!isTagConstructed(_elm[currLevel].Tag()) || currLevel >= MaxTreeLevel - 1)
			return false;

		bstr data = _elm[currLevel].GetData();
		if (data.length() == 0 || _elm[currLevel + 1].Init(data) != Util::Error::NoError)
			return false;

		currLevel++;
		return true;
	}

	constexpr bool GoNext() {
		if (_elm[currLevel].RestLength() == 0)
			return false;

		return _elm[currLevel].InitRest() == Util::Error::NoError;
	}

	constexpr bool GoNextTreeElm() {
		if (GoChild())
			return true;

		if (GoNext()) {
			return true;
		} else {
			// return condition
			if (currLevel == 0)
				return false;
		}

		while (true) {
			if (GoNext()) {
				return true;
			} else {
				// exit condition
				if (!GoParent())
					return false;
			}
		}
	}

	constexpr TLVElm *Search(tag_t tag) {
		GoFirst();
		while (true) {
			if (CurrentElm().Tag() == tag)
				return &CurrentElm();

			if (!GoNextTreeElm())
				return nullptr;
		}

		return nullptr;
	}

	constexpr bstr &GetDataLink() {
		return _data;
	}

	constexpr void AddRoot(tag_t tag, bstr *data = nullptr) {
		_data.clear();
		size_t size = 0;
		EncodeTag(_data, size, tag);
		if (data) {
			EncodeLength(_data, size, data->length());
			_data.append(*data);
		} else {
			EncodeLength(_data, size, 0);
		}
		Init(_data);
	}
	constexpr void NormalizeParents(int offset) {
		if (offset == 0 || currLevel == 0)
			return;

		currLevel--;
		for (int lvl = currLevel; lvl >= 0; lvl--) {
			uint8_t _strdata[8] = {0};
			bstr strdata(_strdata, 0, 8);

			tag_t tag = _elm[lvl].Tag();
			tag_t len = _elm[lvl].Length() + offset;
			size_t header_length = _elm[lvl].HeaderLength();

			size_t new_len = 0;
			EncodeTag(strdata, new_len, tag);
			EncodeLength(strdata, new_len, len);

			// needs to move string's tail
			if (header_length != new_len) {
				uint8_t *elm_end = _elm[lvl].GetPtr() + header_length;
				size_t elm_end_offset = _elm[lvl].GetPtr() - _data.uint8Data();
				size_t move_data_len = _data.length() - elm_end_offset;
				int delta_size = new_len - header_length;
				//printf("elm_length %lu, new_len %lu, delta_size %d, move_data_len %lu\n",header_length, new_len, delta_size, move_data_len);
				_data.set_length(_data.length() + delta_size);
				memmove(elm_end + delta_size, elm_end, move_data_len);
			};
			memmove(_elm[lvl].GetPtr(), _strdata, new_len);
		}
	}
	constexpr void AddChild(tag_t tag, bstr *data = nullptr) {
		size_t datalen = 0;
		if (data)
			datalen = data->length();

		//_data.append(0xaa); // test

		tag_t old_parent_tag = CurrentElm().Tag();
		size_t need_buf_len = 8 + 8 + datalen; // maxT = 4, maxL = 4. parent tag + child tag
		size_t old_elm_len = CurrentElm().ElmLength();
		size_t old_data_len = _data.length();
		uint8_t *current_ptr = CurrentElm().GetPtr();
		size_t current_offset = current_ptr - _data.uint8Data();

		// needs to move memory
		size_t move_data_len = old_data_len - current_offset - old_elm_len;
		uint8_t *move_data_ptr = current_ptr + old_elm_len;
		memmove(current_ptr + need_buf_len, move_data_ptr, move_data_len);

		if (old_elm_len < need_buf_len) { // test only!!!!
			_data.set_length(old_data_len + need_buf_len - old_elm_len);
		}

		bstr child_place(_data.uint8Data() + current_offset + 8, 0, 8 + datalen); // base address + current elm start offset + 4T + 4L
		size_t child_size = 0;
		EncodeTag(child_place, child_size, tag);
		EncodeLength(child_place, child_size, datalen);
		if (data) {
			child_place.append(*data);
			child_size += datalen;
		}

		bstr parent_place(_data.substr(current_offset, 0), 8); // base address + current elm start offset
		size_t parent_size = 0;
		EncodeTag(parent_place, parent_size, CurrentElm().Tag());
		EncodeLength(parent_place, parent_size, child_size);
		//dump_hex(_data);

		// memmove child
		memmove(current_ptr + parent_size, current_ptr + 8, child_size);
		// memmove rest
		memmove(current_ptr + parent_size + child_size, current_ptr + need_buf_len, move_data_len);
		// set real length
		_data.set_length(old_data_len - old_elm_len + parent_size + child_size);

		// normalize parent lengths
		NormalizeParents(child_size - CurrentElm().Length());

		Init(_data);

		// because the tag is unique.
		if (Search(old_parent_tag))
			GoChild();
	}
	constexpr void AddNext(tag_t tag, bstr *data = nullptr) {
		size_t datalen = 0;
		if (data)
			datalen = data->length();

		size_t need_buf_len = 8 + 8 + datalen; // maxT = 4, maxL = 4. parent tag + child tag

		// current element params
		uint8_t *start_ptr = _data.uint8Data();
		uint8_t *current_ptr = CurrentElm().GetPtr();
		size_t cur_elm_offset = current_ptr - start_ptr;
		size_t cur_elm_len = CurrentElm().ElmLength();
		size_t cur_elm_end_offset = cur_elm_offset + cur_elm_len;

		size_t old_data_len = _data.length();

		// needs to move memory
		size_t move_data_len = old_data_len - cur_elm_end_offset;
		memmove(start_ptr + cur_elm_end_offset + need_buf_len, start_ptr + cur_elm_end_offset, move_data_len);

		_data.set_length(old_data_len + need_buf_len + 4); // 4-test

		bstr elm_place(_data.uint8Data() + cur_elm_end_offset, 0, 8 + datalen); // base address + current elm end offset + 4T + 4L
		size_t elm_size = 0;
		EncodeTag(elm_place, elm_size, tag);
		EncodeLength(elm_place, elm_size, datalen);
		if (data) {
			elm_place.append(*data);
			elm_size += datalen;
		}

		memmove(start_ptr + cur_elm_end_offset + elm_size, start_ptr + cur_elm_end_offset + need_buf_len, move_data_len);
		_data.set_length(old_data_len + elm_size);
		//dump_hex(_data);

		// normalize parent lengths
		NormalizeParents(elm_size);

		Init(_data);

		// because the tag is unique.
		Search(tag);
	}
	constexpr void DeleteCurrent() {
		// current element params
		uint8_t *start_ptr = _data.uint8Data();
		uint8_t *current_ptr = CurrentElm().GetPtr();
		size_t cur_elm_offset = current_ptr - start_ptr;
		size_t cur_elm_len = CurrentElm().ElmLength();
		size_t cur_elm_end_offset = cur_elm_offset + cur_elm_len;
		size_t move_data_len = _data.length() - cur_elm_end_offset;

		memmove(current_ptr, current_ptr + cur_elm_len, move_data_len);
		_data.set_length(_data.length() - cur_elm_len);

		// normalize parent lengths
		dump_hex(_data);
		NormalizeParents(-cur_elm_len);
		dump_hex(_data);

		Init(_data);
	}

	constexpr void ClearCurrentData() {
		if (CurrentElm().Length() == 0)
			return;

		uint8_t *start_ptr = _data.uint8Data();
		uint8_t *current_ptr = CurrentElm().GetPtr();
		size_t cur_elm_offset = current_ptr - start_ptr;
		size_t cur_elm_data_len = CurrentElm().Length();
		size_t cur_elm_header_len = CurrentElm().HeaderLength();

		// length of `length` will be the same length or less. so it is safe to encode direct to tag's place
		size_t size = 0;
		bstr elm_place(current_ptr, 0, 8);
		EncodeTag(elm_place, size, CurrentElm().Tag());
		EncodeLength(elm_place, size, 0); // zero length

		size_t delta_len = cur_elm_header_len - size;
		_data.del(cur_elm_offset + size, delta_len + cur_elm_data_len);

		NormalizeParents(-(delta_len + cur_elm_data_len));

		Init(_data);
		Search(CurrentElm().Tag());
	}

	constexpr void AppendCurrentData(bstr cdata) {
		if (cdata.length() == 0)
			return;

		uint8_t *start_ptr = _data.uint8Data();
		uint8_t *current_ptr = CurrentElm().GetPtr();
		size_t cur_elm_offset = current_ptr - start_ptr;
		tag_t cur_elm_tag = CurrentElm().Tag();
		size_t cur_elm_len = CurrentElm().ElmLength();
		size_t cur_elm_header_len = CurrentElm().HeaderLength();
		size_t cur_elm_end_offset = cur_elm_offset + cur_elm_len;

		// encode new tag
		size_t new_header_len = 0;
		uint8_t _header[8] = {0};
		bstr header(_header, 0, sizeof(_header));
		EncodeTag(header, new_header_len, cur_elm_tag);
		size_t new_elm_data_len = CurrentElm().Length() + cdata.length();
		EncodeLength(header, new_header_len, new_elm_data_len);

		// place new header
		int delta_header_len = new_header_len - cur_elm_header_len;
		_data.moveTail(cur_elm_offset + cur_elm_header_len, delta_header_len);
		memmove(current_ptr, _header, new_header_len);

		// place new data
		_data.moveTail(cur_elm_end_offset + delta_header_len, cdata.length());
		memmove(start_ptr + cur_elm_end_offset + delta_header_len, cdata.uint8Data(), cdata.length());

		NormalizeParents(delta_header_len + cdata.length());

		Init(_data);
		Search(cur_elm_tag);
	}

	constexpr void PrintTree() {
		GoFirst();
		while (true) {
			printf("%.*s [%03d] %x [%d] ",
					(currLevel + 1) * 2, "------------",
					CurrentElm().ElmLength(),
					CurrentElm().Tag(),
					CurrentElm().Length());
			dump_hex(CurrentElm().GetData(), 16);

			if (!GoNextTreeElm())
				break;
		}

	}
};

// Data Object List
class DOLElm {
private:
	bstr byteStr;

	tag_t tag = 0;
	tag_t length = 0;
	tag_t elm_length = 0;
	tag_t rest_length = 0;

	constexpr Error Deserialize() {
		tag = 0;
		length = 0;
		elm_length = 0;
		rest_length = 0;

		size_t ptr = 0;
		auto err = ExtractTag(byteStr, ptr, tag);
		if (err != Error::NoError)
			return err;

		ptr++; if (ptr >= byteStr.length()) return Error::TLVDecodeLengthError;
		err = ExtractLength(byteStr, ptr, length);
		if (err != Error::NoError)
			return err;

		// ptr out of range
		ptr++; if (ptr > byteStr.length()) return Error::TLVDecodeLengthError;
		elm_length = ptr;
		rest_length = byteStr.length() - elm_length;
		// length check
		if (elm_length > byteStr.length())
			return Error::TLVDecodeValueError;

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
	constexpr Util::Error InitRest () {
		if (rest_length == 0)
			return Util::Error::TLVDecodeLengthError;

		byteStr = byteStr.substr(elm_length, rest_length);
		return Deserialize();
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
	constexpr tag_t RestLength() {
		return rest_length;
	}

	void constexpr Clear() {
		length = 0;
	}
};

class DOL {
private:
	bstr _data;
	DOLElm _dolElm;
	size_t _elmptr;
public:
	constexpr Util::Error Init(bstr data) {
		_data = data;
		_elmptr = 0;
		return _dolElm.Init(_data);
	};
	constexpr DOLElm &CurrentElm() {
		return _dolElm;
	}
	constexpr void GoFirst() {
		Init(_data);
	}
	constexpr bool GoNext() {
		if (_dolElm.RestLength() == 0)
			return false;

		_elmptr += _dolElm.Length();
		return _dolElm.InitRest() == Util::Error::NoError;
	}
	constexpr Error Search(tag_t tag, size_t &offset, size_t &length) {
		GoFirst();
		while (true) {
			if (CurrentElm().Tag() == tag) {
				offset = _elmptr;
				length = CurrentElm().Length();
				return Error::NoError;
			}

			if (!GoNext())
				return Error::DataNotFound;
		}

		return Error::DataNotFound;
	}

	constexpr void Print() {
		GoFirst();
		while (true) {
			printf("== [%03d] %x [%d] \n",
					CurrentElm().ElmLength(),
					CurrentElm().Tag(),
					CurrentElm().Length());

			if (!GoNext())
				break;
		}

	}

	constexpr void AddNext(tag_t tag, tag_t len = 0) {
		size_t size = 0;
		EncodeTag(_data, size, tag);
		EncodeLength(_data, size, len);
	}
	constexpr void AddNextWithData(tag_t tag, tag_t len) {
		if (len > 0)
			AddNext(tag, len);
	}

	constexpr bstr GetData() {
		return _data;
	}

};

} /* namespace Util */

#endif /* SRC_TLV_H_ */
