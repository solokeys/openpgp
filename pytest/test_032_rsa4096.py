"""
test_031_user_do.py - test user data objects (0101, 0102, 0103, 0104)

Copyright (C) 2019  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from skip_gnuk_only_tests import *

from card_const import *
from constants_for_test import *
from openpgp_card import *


def test_setup_rsa4096(card):
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)

    assert card.set_rsa_algorithm_attributes(
        CryptoAlg.Signature.value, CryptoAlgType.RSA.value, 4096, 32, CryptoAlgImportFormat.RSAStandard.value)
    assert card.set_rsa_algorithm_attributes(
        CryptoAlg.Decryption.value, CryptoAlgType.RSA.value, 4096, 32, CryptoAlgImportFormat.RSAStandard.value)
    assert card.set_rsa_algorithm_attributes(
        CryptoAlg.Authentication.value, CryptoAlgType.RSA.value, 4096, 32, CryptoAlgImportFormat.RSAStandard.value)



