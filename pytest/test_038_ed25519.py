"""
test_038_ed25519.py - test setup of ed25519 keys and crypto operations with them

Copyright (C) 2019  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from skip_gnuk_only_tests import *

from card_const import *
from constants_for_test import *
from openpgp_card import *
import ecdsa_keys
from ecdsa.util import string_to_number
from binascii import hexlify
from cryptography.hazmat.primitives.asymmetric import ed25519


def Ed25519CheckPublicKey(public_key):
    assert len(public_key) == 32

    PublicKey = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    assert not (PublicKey is None)
    return True


class Test_EdDSA(object):
    def test_setup_ed25519(self, card):
        assert card.verify(3, FACTORY_PASSPHRASE_PW3)
        #  PW1 valid for several PSO:CDS commands
        assert card.cmd_put_data(0x00, 0xc4, b"\x01")

        assert card.set_eddsa_algorithm_attributes(CryptoAlg.Signature.value, ECDSACurves.ed25519.value)
        assert card.set_eddsa_algorithm_attributes(CryptoAlg.Decryption.value, ECDSACurves.curve25519.value)  # ECDH
        assert card.set_eddsa_algorithm_attributes(CryptoAlg.Authentication.value, ECDSACurves.ed25519.value)

    def test_keygen_1(self, card):
        pk = card.cmd_genkey(1)
        assert Ed25519CheckPublicKey(pk[0])
        fpr_date = ecdsa_keys.calc_fpr_ecdsa(pk[0])
        r = card.cmd_put_data(0x00, 0xc7, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xce, fpr_date[1])
        assert r

    def test_keygen_2(self, card):
        pk = card.cmd_genkey(2)
        assert Ed25519CheckPublicKey(pk[0])
        fpr_date = ecdsa_keys.calc_fpr_ecdsa(pk[0])
        r = card.cmd_put_data(0x00, 0xc8, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xcf, fpr_date[1])
        assert r

    def test_keygen_3(self, card):
        pk = card.cmd_genkey(3)
        assert Ed25519CheckPublicKey(pk[0])
        fpr_date = ecdsa_keys.calc_fpr_ecdsa(pk[0])
        r = card.cmd_put_data(0x00, 0xc9, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xd0, fpr_date[1])
        assert r

    def test_verify_pw1(self, card):
        assert card.verify(1, FACTORY_PASSPHRASE_PW1)

    def test_signature_sigkey(self, card):
        msg = b"Sign me please"
        digest = ecdsa_keys.compute_digestinfo_ecdsa(msg)

        pk = card.cmd_get_public_key(1)
        pk_info = get_pk_info(pk)
        sig = card.cmd_pso(0x9e, 0x9a, digest)

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pk_info[0])
        # return error cryptography.exceptions.InvalidSignature
        public_key.verify(sig, digest)

    def yubikeyfail_test_verify_reset(self, card):
        assert card.cmd_verify_reset(1)
        assert card.cmd_verify_reset(2)
        assert card.cmd_verify_reset(3)
