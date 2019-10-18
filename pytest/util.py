from tlv import *
from re import match, DOTALL


def get_data_object(card, tag):
    tagh = tag >> 8
    tagl = tag & 0xff
    return card.cmd_get_data(tagh, tagl)


def check_null(data_object):
    return data_object == None or len(data_object) == 0


def check_zeroes(data_object):
    for c in data_object:
        if c != 0x00:
            return False
    return True


def get_pk_info(pk):
    pktlv = TLV(pk)
    #pktlv.show()
    tag81 = pktlv.search(0x81)
    tag82 = pktlv.search(0x82)
    tag86 = pktlv.search(0x86) # format `04 || x || y`
    if tag86 is None:
        assert not (tag81 is None)
        assert not (tag82 is None)
        return tag81.data, tag82.data
    else:
        return tag86.data, None


def check_extended_capabilities(data):
    return match(b'[\x70\x74\x75\x7f]\x00\x00[\x20\x40\x80][\x00\x04\x08\x10]\x00[\x00\x01]\xff\x01\x00', data)


def check_pw_status(data):
    return match(b'\x00...\x03[\x00\x03]\x03', data, DOTALL)
