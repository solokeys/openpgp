def get_data_object(card, tag):
    tagh = tag >> 8
    tagl = tag & 0xff
    return card.cmd_get_data(tagh, tagl)

def check_null(data_object):
    return data_object == None or len(data_object) == 0
