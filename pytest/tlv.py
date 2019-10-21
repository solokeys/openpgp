#!/usr/bin/python

#
#    Python TLV (as part of EMV Framework)
#    Copyrigh 2012 Albert Puigsech Galicia <albert@puigsech.com>
#
#    This code is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License
#    as published by the Free Software Foundation; either version 2
#    of the License, or (at your option) any later version.
#

TAG_CLASS_UNIVERSAL = 0x0
TAG_CLASS_APLICATION = 0x1
TAG_CLASS_CONTEXT_SPECIFIC = 0x2
TAG_CLASS_PRIVATE = 0x3

TAG_TYPE_PRIMITIVE = 0x0
TAG_TYPE_CONSTRUCTED = 0x1

TAG_SIZE_BIG_1 = 0x81
TAG_SIZE_BIG_2 = 0x82


def encode_tag(tag):
    res = b""
    if tag > 0xffffff:
        res += bytes([(tag & 0xff000000) >> 24])

    if tag > 0xffff:
        res += bytes([(tag & 0xff0000) >> 16])

    if tag > 0xff:
        res += bytes([(tag &0xff00) >> 8])

    res += bytes([tag & 0xff])
    return res


def encode_len(length):
    if length < 0x80:
        return bytes([length])

    if length < 0x100:
        return bytes([0x81, length])

    if length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xff, length & 0xff])

    if length < 0x1000000:
        return bytes([0x83, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff])

    return None

def encode_taglen(tag, length):
    return encode_tag(tag) + encode_len(length)


ConstructedTagList = [
    0x65,
    0x6e,
    0x73,
    0x7a,
    # 0x7f21, # Cardholder certificate
    0x7f66,
    0x7f74,
    0xf4,
    0xf9,

    0x4d,

    0x7f49 # key structure response
]


class TAG:
    def __init__(self, data=None, tags_db=None, content=True):
        self.childs = []
        self.root = False
        self.code = None
        self.name = None
        self.type = None
        self._class = None
        self.extended = None
        self.size = None
        self.total_size = None
        self.data = None
        self.parsed_data = None
        self.human_data = None
        self.parse(data, tags_db, content)

    def parse(self, data, tags_db, content):
        if data == None:
            return

        size = len(data)

        i = 0
        if data[i] & 0b00011111 == 0b00011111:
            self.extended = True
        else:
            self.extended = False
        self._class = (data[i] & 0b11000000) >> 6
        self.type = (data[i] & 0b00100000) >> 5

        if self.extended:
            self.code = 256 * data[i] + data[i + 1]
            i += 2
        else:
            self.code = data[i]
            i += 1

        # Recursive extended size
        if data[i] == TAG_SIZE_BIG_1:
            self.size = data[i + 1]
            i += 2
        elif data[i] == TAG_SIZE_BIG_2:
            self.size = 256 * data[i + 1] + data[i + 2]
            i += 3
        else:
            self.size = data[i]
            i += 1

        if content == True:
            self.data = data[i:i + self.size]
            i += self.size

            #if self.type == TAG_TYPE_CONSTRUCTED:
            if self.code in ConstructedTagList:
                self.type = TAG_TYPE_CONSTRUCTED
                j = 0
                while j < self.size:
                    tag = TAG(self.data[j:], tags_db)
                    self.childs.append(tag)
                    j += tag.total_size
            else:
                self.type = TAG_TYPE_PRIMITIVE

        key = '%x' % self.code
        if tags_db != None and tags_db.has_key(key):
            self.name = tags_db[key]['name']
            if tags_db[key].has_key('parser') and tags_db[key]['parser'] != None:
                d = tags_db[key]['parser'].split('.')
                m = __import__(d[0])
                func = getattr(m, d[1])
                func(self)

        self.total_size = i

    def encode(self):
        if len(self.childs) == 0:
            self.size = len(self.data)
            return encode_tag(self.code) + encode_len(len(self.data)) + self.data
        else:
            total_elm = b""
            for elm in self.childs:
                total_elm += elm.encode()

            self.total_size = len(total_elm)
            self.data = total_elm
            return encode_tag(self.code) + encode_len(len(total_elm)) + total_elm



    def list_childs(self, code=None):
        if code == None:
            return self.childs
        ret = []
        for c in self.childs:
            if c.code == code:
                ret.append(c)
        return ret

    def show(self, deep=0):
        if self.root:
            for c in self.childs:
                c.show(deep)
        else:
            deep_str = deep * '   '
            print('%s%.2x [%.2x] - %s' % (deep_str, self.code, self.size, self.name), end = '')
            if self.type == TAG_TYPE_PRIMITIVE and self.data != None:
                print('%s  ' % (deep_str), end = '')
                for i in self.data:
                    print('%.2x' % (i), end = '')
                print(' ', end = '')
                if self.human_data != None:
                    print('%s  ' % (deep_str), end = '')
                    print('( {0:s} )'.format(self.human_data), end = '')
            print('')

            deep += 1
            for tag in self.childs:
                tag.show(deep)

    def append(self, tag, value):
        vstr = encode_tag(tag) + encode_len(len(value)) + value
        elm = TAG(encode_tag(tag) + encode_len(len(value)) + value)
        self.childs.append(elm)
        return elm

class TLV(TAG):
    def parse(self, data, tags_db=None, content=True):
        size = len(data)
        self.root = True
        self.type = TAG_TYPE_CONSTRUCTED
        i = 0
        while i < size:
            tag = TAG(data[i:], tags_db, content)
            self.childs.append(tag)
            i += tag.total_size

    def encode(self):
        ret = b""
        for c in self.childs:
            ret += c.encode()
        return ret

    def node_search(self, tag, node):
        if node is None:
            return None

        for c in node.childs:
            if c.code == tag:
                return c
            if not (c.childs is None):
                res = self.node_search(tag, c)
                if not (res is None):
                    return res

    def search(self, tag):
        if self.code == tag:
            return self

        return self.node_search(tag, self)


