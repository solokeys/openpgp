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
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey


def Ed25519CheckPublicKey(public_key):
    assert len(public_key) == 32

    PublicKey = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    assert not (PublicKey is None)
    return True


def check_signature(card, key_num, msg=b"Sign me please"):
    digest = ecdsa_keys.compute_digestinfo_ecdsa(msg)

    pk = card.cmd_get_public_key(key_num)
    pk_info = get_pk_info(pk)
    sig = card.cmd_pso(0x9e, 0x9a, digest)

    public_key = ed25519.Ed25519PublicKey.from_public_bytes(pk_info[0])
    # return error cryptography.exceptions.InvalidSignature
    public_key.verify(sig, digest)
    return True


def check_ecdh(card, key_num=2):
    myPublicKey, myPrivateKey = ecdsa_keys.generate_key_eddsa_ecdh()
    myPublicKeyTLV = ecdh_public_key_encode(ecdsa_keys.ecc_to_string(myPublicKey))

    pk = card.cmd_get_public_key(key_num)
    pk_info = get_pk_info(pk)
    sharedSecret = card.cmd_pso(0x80, 0x86, myPublicKeyTLV)

    peer_pk = X25519PublicKey.from_public_bytes(pk_info[0])
    mySharedSecret = myPrivateKey.exchange(peer_pk)

    return sharedSecret == mySharedSecret


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
        assert check_signature(card, 1)

    def test_verify_pw1_82(self, card):
        assert card.verify(2, FACTORY_PASSPHRASE_PW1)

    def test_ecdh(self, card):
        assert check_ecdh(card)

    def test_signature_authkey(self, card):
        assert check_signature(card, 1, b"Sign me please to authenticate")

    def test_import_key_1(self, card):
        t = ecdsa_keys.build_privkey_template_eddsa(1)
        r = card.cmd_put_data_odd(0x3f, 0xff, t)
        assert r

    def test_signature_sigkey_uploaded(self, card):
        assert check_signature(card, 1)

    def test_import_key_1_wo0x04(self, card):
        t = ecdsa_keys.build_privkey_template_eddsa(1, True)
        r = card.cmd_put_data_odd(0x3f, 0xff, t)
        assert r

    def test_signature_sigkey_uploaded_wo0x04(self, card):
        assert check_signature(card, 1)

    def test_import_key_2(self, card):
        t = ecdsa_keys.build_privkey_template_eddsa(2)
        r = card.cmd_put_data_odd(0x3f, 0xff, t)
        assert r

    def test_ecdh_uploaded(self, card):
        assert check_ecdh(card)

    def test_import_key_3(self, card):
        t = ecdsa_keys.build_privkey_template_eddsa(3)
        r = card.cmd_put_data_odd(0x3f, 0xff, t)
        assert r

    def test_signature_authkey_uploaded(self, card):
        assert check_signature(card, 1, b"Sign me please to authenticate")

    def yubikeyfail_test_verify_reset(self, card):
        assert card.cmd_verify_reset(1)
        assert card.cmd_verify_reset(2)
        assert card.cmd_verify_reset(3)
