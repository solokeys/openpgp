"""
test_035_ecdsa.py - test setting ecdsa keys

Copyright (C) 2019  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from skip_gnuk_only_tests import *

from card_const import *
from constants_for_test import *
from openpgp_card import *


class Test_ECDSA(object):
    def test_setup_rsa4096(self, card):
        assert card.verify(3, FACTORY_PASSPHRASE_PW3)

        assert card.set_ecdsa_algorithm_attributes(
            CryptoAlg.Signature.value, CryptoAlgType.ECDSA.value, ECDSACurves.ansix9p256r1.value)
        assert card.set_ecdsa_algorithm_attributes(
            CryptoAlg.Decryption.value, CryptoAlgType.ECDSA.value, ECDSACurves.ansix9p256r1.value)
        assert card.set_ecdsa_algorithm_attributes(
            CryptoAlg.Authentication.value, CryptoAlgType.ECDSA.value, ECDSACurves.ansix9p256r1.value)

    def test_keygen_1(self, card):
        pk = card.cmd_genkey(1)
        print(pk)
        #fpr_date = rsa_keys.calc_fpr(pk[0], pk[1])
        #r = card.cmd_put_data(0x00, 0xc7, fpr_date[0])
        #if r:
        #    r = card.cmd_put_data(0x00, 0xce, fpr_date[1])
        #assert r


