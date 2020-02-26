import struct
from smartcard import System
from smartcard.pcsc.PCSCExceptions import ListReadersException
from smartcard.pcsc.PCSCContext import PCSCContext

def _list_readers():
    try:
        return System.readers()
    except ListReadersException:
        # If the PCSC system has restarted the context might be stale, try
        # forcing a new context (This happens on Windows if the last reader is
        # removed):
        PCSCContext.instance = None
        return System.readers()

class CardReader(object):
    def __init__(self, dev):
        self.__dev = dev
        self.__conn = dev.createConnection()
        self.__conn.connect()

    def get_string(self, num):
        if num == 1:
            return self.__dev.name
        return ""

    def increment_seq(self):
        print("increment_seq")

    def reset_device(self):
        print("reset_device")

    def is_tpdu_reader(self):
        print("is_tpdu_reader")
        return False

    def ccid_get_result(self):
        print("ccid_get_result")

    def ccid_get_status(self):
        # always power on
        return 1

    def ccid_power_on(self):
        if self.__conn is None:
            self.__conn = self.__dev.createConnection()
            self.__conn.connect()
        return self.__conn.getATR()

    def ccid_power_off(self):
        pass

    def ccid_send_data_block(self, data):
        print("ccid_send_data_block")

    def ccid_send_cmd(self, data):
        print("ccid_send_cmd")

    def send_tpdu(self, info=None, more=0, response_time_ext=0,
                  edc_error=0, no_error=0):
        print("send_tpdu")

    def recv_tpdu(self):
        print("recv_tpdu")

    def apdu_exchange(self, apdu, protocol=None):
        """Exchange data with smart card.

        :param apdu: byte string. data to exchange with card
        :return: byte string. response from card
        """

        print(">> " + apdu.hex())
        resp, sw1, sw2 = self.__conn.transmit(list(apdu), protocol)
        response = bytes(bytearray(resp))
        print('<< [' + bytes(bytearray([sw1, sw2])).hex() + ']' + response.hex())

        return response, sw1, sw2

    def _select(self, aid):
        apdu = b"\x00\xa4\x04\x00" + struct.pack("!B", len(aid)) + aid
        return self.apdu_exchange(apdu)  # resp, sw1, sw2

    def send_cmd(self, cmd):
        resp, sw1, sw2 = self.apdu_exchange(cmd)
        return resp + bytes(bytearray([sw1, sw2]))


def get_pcsc_device():
    readers = _list_readers()
    if len(readers) > 0:
        return CardReader(readers[0])
    else:
        return None
