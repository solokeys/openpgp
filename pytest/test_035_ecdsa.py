"""
test_035_ecdsa.py - test setting ecdsa keys and crypto operations with them

Copyright (C) 2019, 2020  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from skip_gnuk_only_tests import *

from card_const import *
from constants_for_test import *
from openpgp_card import *
import ecdsa_keys
from ecdsa.util import string_to_number
from binascii import hexlify
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils


@pytest.fixture(
    params=[
        ECDSACurves.ansix9p256r1,
        ECDSACurves.ansix9p384r1,
        ECDSACurves.ansix9p521r1,
        # ECDSACurves.brainpoolP256r1,
        # ECDSACurves.brainpoolP384r1,
        # ECDSACurves.brainpoolP512r1,
        ECDSACurves.secp256k1],
    ids=[
        "ansix9p256r1",
        "ansix9p384r1",
        "ansix9p521r1",
        # "brainpoolP256r1",
        # "brainpoolP384r1",
        # "brainpoolP512r1",
        "secp256k1"],
    scope="class")
def ECDSAcurve(request):
    return request.param.value


def ECDSACheckPublicKey(curve_oid, public_key):
    assert len(public_key) > 2
    assert public_key[0] == 0x04

    curve = ecdsa_keys.find_curve_oid_hex(curve_oid)
    assert not (curve is None)
    assert curve.verifying_key_length + 1 == len(public_key)

    length = (len(public_key) - 1) // 2
    x = public_key[1:length + 1]
    y = public_key[length + 1:]
    assert len(x) == len(y)
    curve.curve.contains_point(string_to_number(x), string_to_number(y))
    return True


def check_ecdh(card, ECDSAcurve, key_num=2):
    myPublicKey, myPrivateKey = ecdsa_keys.generate_key_ecdsa(ECDSAcurve)
    myPublicKeyTLV = ecdh_public_key_encode(b"\x04" + myPublicKey.to_string())

    pk = card.cmd_get_public_key(2)
    pk_info = get_pk_info(pk)

    mySharedSecret = ecdsa_keys.ecdh(ECDSAcurve, myPrivateKey.to_string(),
                                     pk_info[0])

    sharedSecret = card.cmd_pso(0x80, 0x86, myPublicKeyTLV)

    return sharedSecret == mySharedSecret


class Test_ECDSA(object):
    def test_setup_ecdsa(self, card, ECDSAcurve):
        assert card.verify(3, FACTORY_PASSPHRASE_PW3)
        #  PW1 valid for several PSO:CDS commands
        assert card.cmd_put_data(0x00, 0xc4, b"\x01")

        assert card.set_ecdsa_algorithm_attributes(CryptoAlg.Signature.value, ECDSAcurve)
        assert card.set_ecdsa_algorithm_attributes(CryptoAlg.Decryption.value, ECDSAcurve) # ECDH
        assert card.set_ecdsa_algorithm_attributes(CryptoAlg.Authentication.value, ECDSAcurve)

    def test_keygen_1(self, card, ECDSAcurve):
        pk = card.cmd_genkey(1)
        assert ECDSACheckPublicKey(ECDSAcurve, pk[0])
        fpr_date = ecdsa_keys.calc_fpr_ecdsa(pk[0])
        r = card.cmd_put_data(0x00, 0xc7, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xce, fpr_date[1])
        assert r

    def test_keygen_2(self, card, ECDSAcurve):
        pk = card.cmd_genkey(2)
        assert ECDSACheckPublicKey(ECDSAcurve, pk[0])
        fpr_date = ecdsa_keys.calc_fpr_ecdsa(pk[0])
        r = card.cmd_put_data(0x00, 0xc8, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xcf, fpr_date[1])
        assert r

    def test_keygen_3(self, card, ECDSAcurve):
        pk = card.cmd_genkey(3)
        assert ECDSACheckPublicKey(ECDSAcurve, pk[0])
        fpr_date = ecdsa_keys.calc_fpr_ecdsa(pk[0])
        r = card.cmd_put_data(0x00, 0xc9, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xd0, fpr_date[1])
        assert r

    def test_verify_pw1(self, card, ECDSAcurve):
        assert card.verify(1, FACTORY_PASSPHRASE_PW1)

    def test_signature_sigkey(self, card, ECDSAcurve):
        msg = b"Sign me please"
        pk = card.cmd_get_public_key(1)
        pk_info = get_pk_info(pk)
        digest = ecdsa_keys.compute_digestinfo_ecdsa(msg)
        sig = card.cmd_pso(0x9e, 0x9a, digest)
        assert ecdsa_keys.verify_signature_ecdsa(pk_info[0], digest, sig, ECDSAcurve)

    def test_verify_pw1_82(self, card, ECDSAcurve):
        assert card.verify(2, FACTORY_PASSPHRASE_PW1)

    def test_authkey_ecdh(self, card, ECDSAcurve):
        assert check_ecdh(card, ECDSAcurve)

    def test_signature_authkey(self, card, ECDSAcurve):
        msg = b"Sign me please to authenticate"
        pk = card.cmd_get_public_key(3)
        pk_info = get_pk_info(pk)
        digest = ecdsa_keys.compute_digestinfo_ecdsa(msg)
        sig = card.cmd_internal_authenticate(digest)
        r = ecdsa_keys.verify_signature_ecdsa(pk_info[0], digest, sig, ECDSAcurve)
        assert r

    def test_ecdsa_import_key_1(self, card, ECDSAcurve):
        t = ecdsa_keys.build_privkey_template_ecdsa(1, ECDSAcurve)
        r = card.cmd_put_data_odd(0x3f, 0xff, t)
        assert r

    def test_signature_sigkey_uploaded(self, card, ECDSAcurve):
        msg = b"Sign me please"
        pk = card.cmd_get_public_key(1)
        pk_info = get_pk_info(pk)
        digest = ecdsa_keys.compute_digestinfo_ecdsa(msg)
        sig = card.cmd_pso(0x9e, 0x9a, digest)
        r = ecdsa_keys.verify_signature_ecdsa(pk_info[0], digest, sig, ECDSAcurve)
        assert r

    def test_ecdsa_import_key_2(self, card, ECDSAcurve):
        t = ecdsa_keys.build_privkey_template_ecdsa(2, ECDSAcurve)
        r = card.cmd_put_data_odd(0x3f, 0xff, t)
        assert r

    def test_authkey_ecdh_uploaded(self, card, ECDSAcurve):
        myPublicKey, myPrivateKey = ecdsa_keys.generate_key_ecdsa(ECDSAcurve)
        myPublicKeyTLV = ecdh_public_key_encode(b"\x04" + myPublicKey.to_string())

        pk = card.cmd_get_public_key(2)
        pk_info = get_pk_info(pk)

        mySharedSecret = ecdsa_keys.ecdh(ECDSAcurve, myPrivateKey.to_string(), pk_info[0])

        sharedSecret = card.cmd_pso(0x80, 0x86, myPublicKeyTLV)

        assert sharedSecret == mySharedSecret

    def test_ecdsa_import_key_3(self, card, ECDSAcurve):
        t = ecdsa_keys.build_privkey_template_ecdsa(3, ECDSAcurve)
        r = card.cmd_put_data_odd(0x3f, 0xff, t)
        assert r

    def test_signature_authkey_uploaded(self, card, ECDSAcurve):
        msg = b"Sign me please to authenticate"
        pk = card.cmd_get_public_key(3)
        pk_info = get_pk_info(pk)
        digest = ecdsa_keys.compute_digestinfo_ecdsa(msg)
        sig = card.cmd_internal_authenticate(digest)
        r = ecdsa_keys.verify_signature_ecdsa(pk_info[0], digest, sig, ECDSAcurve)
        assert r

    def yubikeyfail_test_verify_reset(self, card, ECDSAcurve):
        assert card.cmd_verify_reset(1)
        assert card.cmd_verify_reset(2)
        assert card.cmd_verify_reset(3)
