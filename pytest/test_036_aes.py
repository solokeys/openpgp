"""
test_036_aes.py - test working with AES encrypt/decrypt and keys

Copyright (C) 2019  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from skip_gnuk_only_tests import *

from card_const import *
from constants_for_test import *


class Test_AES(object):
    def test_setup_AES(self, card):
        assert card.verify(3, FACTORY_PASSPHRASE_PW3)

        assert card.cmd_put_data(0x00, 0xd5, AES256key)
        try:
            card.cmd_get_data(0x00, 0xd5)
            assert False
        except ValueError:
            pass

        assert card.cmd_verify_reset(3)

    def test_AES_encode(self, card):
        assert card.verify(2, FACTORY_PASSPHRASE_PW1)

        v = card.cmd_pso(0x86, 0x80, AESPlainText)
        assert v[0] == 0x02
        print(v.hex())
        assert v[1:] == AESCipherText

    def test_AES_decode(self, card):
        v = card.cmd_pso(0x80, 0x86, b"\x02" + AESCipherText)
        assert v == AESPlainText

    def test_AES_cbc(self, card):
        ct = card.cmd_pso(0x86, 0x80, AESPlainTextLong)
        assert ct[0] == 0x02

        v = card.cmd_pso(0x80, 0x86, ct)
        assert v == AESPlainTextLong

    def test_verify_reset(self, card):
        assert card.cmd_verify_reset(3)
