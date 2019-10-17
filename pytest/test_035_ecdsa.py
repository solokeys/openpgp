"""
test_035_ecdsa.py - test setting ecdsa keys

Copyright (C) 2019  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from skip_gnuk_only_tests import *

from card_const import *
from constants_for_test import *
from openpgp_card import *
import ecdsa_keys
from binascii import hexlify


class Test_ECDSA(object):
    def test_setup_ecdsa(self, card):
        assert card.verify(3, FACTORY_PASSPHRASE_PW3)

        assert card.set_ecdsa_algorithm_attributes(
            CryptoAlg.Signature.value, CryptoAlgType.ECDSA.value, ECDSACurves.ansix9p384r1.value)
        #assert card.set_ecdsa_algorithm_attributes(
        #    CryptoAlg.Decryption.value, CryptoAlgType.ECDSA.value, ECDSACurves.ansix9p384r1.value)
        #assert card.set_ecdsa_algorithm_attributes(
        #    CryptoAlg.Authentication.value, CryptoAlgType.ECDSA.value, ECDSACurves.ansix9p384r1.value)

    def test_keygen_1(self, card):
        pk = card.cmd_genkey(1)
        fpr_date = ecdsa_keys.calc_fpr_ecdsa(pk[0])
        r = card.cmd_put_data(0x00, 0xc7, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xce, fpr_date[1])
        assert r

    def test_keygen_2(self, card):
        pk = card.cmd_genkey(2)
        fpr_date = ecdsa_keys.calc_fpr_ecdsa(pk[0])
        r = card.cmd_put_data(0x00, 0xc7, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xce, fpr_date[1])
        assert r

    def test_keygen_3(self, card):
        pk = card.cmd_genkey(3)
        fpr_date = ecdsa_keys.calc_fpr_ecdsa(pk[0])
        r = card.cmd_put_data(0x00, 0xc7, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xce, fpr_date[1])
        assert r

    def test_verify_pw1(self, card):
        v = card.cmd_verify(1, FACTORY_PASSPHRASE_PW1)
        assert v

    def test_signature_sigkey(self, card):
        msg = b"Sign me please"
        pk = card.cmd_get_public_key(1)
        pk_info = get_pk_info(pk)
        digest = ecdsa_keys.compute_digestinfo_ecdsa(msg)
        sig = (card.cmd_pso(0x9e, 0x9a, digest))
        r = ecdsa_keys.verify_signature_ecdsa(pk_info[0], digest, sig)
        assert r

    def test_verify_pw1_2(self, card):
        v = card.cmd_verify(2, FACTORY_PASSPHRASE_PW1)
        assert v

    #def test_decryption(self, card):
    #    msg = b"encrypt me please"
    #    pk = card.cmd_get_public_key(2)
    #    pk_info = get_pk_info(pk)
    #    ciphertext = rsa_keys.encrypt_with_pubkey(pk_info, msg)
    #    r = card.cmd_pso(0x80, 0x86, ciphertext)
    #    assert r == msg

    #def test_signature_authkey(self, card):
    #    msg = b"Sign me please to authenticate"
    #    pk = card.cmd_get_public_key(3)
    #    pk_info = get_pk_info(pk)
    #    digest = rsa_keys.compute_digestinfo(msg)
    #    sig = int(hexlify(card.cmd_internal_authenticate(digest)),16)
    #    r = rsa_keys.verify_signature(pk_info, digest, sig)
    #    assert r
