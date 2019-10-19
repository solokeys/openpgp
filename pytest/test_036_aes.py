"""
test_036_aes.py - test working with AES encrypt/decrypt and keys

Copyright (C) 2019  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from skip_gnuk_only_tests import *
from pytest import *

from card_const import *
from constants_for_test import *
from Crypto.Cipher import AES


@pytest.fixture(params=[AES128key, AES192key, AES256key],
                ids=["AES128", "AES192", "AES256"], scope="class")
def fAES(request):
    return request.param

class Test_AES(object):
    def test_setup_AES(self, card, fAES):
        assert card.verify(3, FACTORY_PASSPHRASE_PW3)

        assert card.cmd_put_data(0x00, 0xd5, fAES)
        try:
            card.cmd_get_data(0x00, 0xd5)
            assert False
        except ValueError:
            pass

        assert card.cmd_verify_reset(3)

    def test_AES_encode(self, card, fAES):
        assert card.verify(2, FACTORY_PASSPHRASE_PW1)

        v = card.cmd_pso(0x86, 0x80, AESPlainText)
        assert v[0] == 0x02
        aes = AES.new(fAES, AES.MODE_CBC, AESiv)
        assert v[1:] == aes.encrypt(AESPlainText)

    def test_AES_decode(self, card, fAES):
        aes = AES.new(fAES, AES.MODE_CBC, AESiv)
        v = card.cmd_pso(0x80, 0x86, b"\x02" + aes.encrypt(AESPlainText))
        assert v == AESPlainText

    def test_AES_cbc(self, card, fAES):
        ct = card.cmd_pso(0x86, 0x80, AESPlainTextLong)
        assert ct[0] == 0x02

        aes = AES.new(fAES, AES.MODE_CBC, AESiv)
        assert ct[1:] == aes.encrypt(AESPlainTextLong)

        v = card.cmd_pso(0x80, 0x86, ct)
        assert v == AESPlainTextLong

    def test_verify_reset(self, card):
        assert card.cmd_verify_reset(2)
