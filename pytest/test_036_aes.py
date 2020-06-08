"""
test_036_aes.py - test working with AES encrypt/decrypt and keys

Copyright (C) 2019  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from skip_gnuk_only_tests import *
from pytest import *

from card_const import *
from constants_for_test import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


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
        cipher = Cipher(algorithms.AES(fAES), modes.CBC(AESiv), backend=default_backend())
        encryptor = cipher.encryptor()
        assert v[1:] == encryptor.update(AESPlainText) + encryptor.finalize()

    def test_AES_decode(self, card, fAES):
        cipher = Cipher(algorithms.AES(fAES), modes.CBC(AESiv), backend=default_backend())
        encryptor = cipher.encryptor()
        v = card.cmd_pso(0x80, 0x86, b"\x02" + encryptor.update(AESPlainText) + encryptor.finalize())
        assert v == AESPlainText

    def test_AES_cbc(self, card, fAES):
        ct = card.cmd_pso(0x86, 0x80, AESPlainTextLong)
        assert ct[0] == 0x02

        cipher = Cipher(algorithms.AES(fAES), modes.CBC(AESiv), backend=default_backend())
        encryptor = cipher.encryptor()
        assert ct[1:] == encryptor.update(AESPlainTextLong) + encryptor.finalize()

        v = card.cmd_pso(0x80, 0x86, ct)
        assert v == AESPlainTextLong

    def test_verify_reset(self, card):
        assert card.cmd_verify_reset(2)
