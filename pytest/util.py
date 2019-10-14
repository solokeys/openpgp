from tlv import *


def get_data_object(card, tag):
    tagh = tag >> 8
    tagl = tag & 0xff
    return card.cmd_get_data(tagh, tagl)


def check_null(data_object):
    return data_object == None or len(data_object) == 0


def get_pk_info(pk):
    pktlv = TLV(pk)
    #pktlv.show()
    tag81 = pktlv.search(0x81)
    tag82 = pktlv.search(0x82)
    assert not (tag81 is None)
    assert not (tag82 is None)
    return tag81.data, tag82.data
