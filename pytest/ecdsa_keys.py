"""
ecdsa_keys.py - ecdsa functions

Copyright (C) 2019  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from time import time
from struct import pack
from hashlib import sha1, sha256
from util import *
from binascii import hexlify, unhexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def hex_oid_to_string(oid):
    if len(oid) < 3:
        return ""

    o1 = int(oid[0] / 40)
    o2 = int(oid[0] % 40)
    if o1 > 2:
        o2 += (o1 - 2) * 40
        o1 = 2
    soid = str(o1) + "." + str(o2)

    val = 0
    for c in oid[1:]:
        val = ((val << 7) | (c & 0x7F))
        if c < 0x80:
            soid += "." + str(val)
            val = 0
    return soid


def get_curve_by_oid(oid):
    mtd = [a for a in dir(ec.EllipticCurveOID) \
           if not a.startswith('__') and \
              not callable(getattr(ec.EllipticCurveOID, a))]

    for m in mtd:
        crv = getattr(ec.EllipticCurveOID, m)
        if crv.dotted_string == oid:
            return crv

    return None


def get_curve_by_hex_oid(oid_hex):
    return get_curve_by_oid(hex_oid_to_string(oid_hex))


def calc_fpr_ecdsa(n):
    timestamp = int(time())
    timestamp_data = pack('>I', timestamp)
    m_len = 6 + 2 + 256 + 2 + 4
    m = b'\x99' + pack('>H', m_len) + b'\x04' + timestamp_data + b'\x01' + \
        pack('>H', len(n) * 8) + n
    fpr = sha1(m).digest()
    return fpr, timestamp_data


def generate_key_ecdsa(ecdsa_curve):
    curve = ec.get_curve_for_oid(get_curve_by_hex_oid(ecdsa_curve))
    assert not(curve is None)

    PrivateKey = ec.generate_private_key(curve(), default_backend())
    PublicKey = PrivateKey.public_key()
    return PublicKey, PrivateKey


def generate_key_eddsa():
    PrivateKey = Ed25519PrivateKey.generate()
    PublicKey = PrivateKey.public_key()
    return PublicKey, PrivateKey

def generate_key_eddsa_ecdh():
    PrivateKey = X25519PrivateKey.generate()
    PublicKey = PrivateKey.public_key()
    return PublicKey, PrivateKey


def build_privkey_template_ecdsa(openpgp_keyno, ecdsa_curve):
    if openpgp_keyno == 1:
        keyspec = 0xb6
    elif openpgp_keyno == 2:
        keyspec = 0xb8
    else:
        keyspec = 0xa4

    PublicKey, PrivateKey = generate_key_ecdsa(ecdsa_curve)
    return create_ecdsa_4D_key(keyspec, ecc_to_string(PrivateKey),
                               ecc_to_string(PublicKey))


def int_to_binstr(vint, size=None):
    hint = hex(vint)
    if hint[:2] == "0x":
        hint = hint[2:]
    if len(hint) % 2 != 0:
        hint = "0" + hint
    bstr = unhexlify(hint)
    while size > len(bstr):
        bstr = b"\x00" + bstr
    return bstr


def binstr_to_int(string):
    return int(hexlify(string), 16)


def curve_keysize_bytes(curve):
    return curve.key_size // 8 + (1 if curve.key_size % 8 else 0)


def ecc_to_string(key):
    if isinstance(key, Ed25519PrivateKey):
        return key.private_bytes(
                  serialization.Encoding.Raw,
                  serialization.PrivateFormat.Raw,
                  serialization.NoEncryption())

    if isinstance(key, Ed25519PublicKey):
        return key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)

    if isinstance(key, X25519PrivateKey):
        return key.private_bytes(
                  serialization.Encoding.Raw,
                  serialization.PrivateFormat.Raw,
                  serialization.NoEncryption())

    if isinstance(key, X25519PublicKey):
        return key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)

    if isinstance(key, ec.EllipticCurvePrivateKey):
        numbers = key.private_numbers()
        keysize = curve_keysize_bytes(numbers.public_numbers.curve)
        print(numbers.private_value, keysize, int_to_binstr(numbers.private_value, keysize).hex())
        return int_to_binstr(numbers.private_value, keysize)

    if isinstance(key, ec.EllipticCurvePublicKey):
        numbers = key.public_numbers()
        keysize = curve_keysize_bytes(numbers.curve)
        return b"\x04" + int_to_binstr(numbers.x, keysize) + \
               int_to_binstr(numbers.y, keysize)

    return None


def build_privkey_template_eddsa(openpgp_keyno, wo0x04=False):
    if openpgp_keyno == 1:
        keyspec = 0xb6
    elif openpgp_keyno == 2:
        keyspec = 0xb8
    else:
        keyspec = 0xa4

    if openpgp_keyno == 2:
        PublicKey, PrivateKey = generate_key_eddsa_ecdh()
    else:
        PublicKey, PrivateKey = generate_key_eddsa()
    return create_ecdsa_4D_key(keyspec, ecc_to_string(PrivateKey),
                               (b"" if wo0x04 else b"\x04") + ecc_to_string(PublicKey))


def compute_digestinfo_ecdsa(msg):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(msg)
    return digest.finalize()


def fill_sign(sig):
    siglen = len(sig)
    if siglen < 3:
        return sig
    if sig[0] == 0x30 and sig[1] == siglen - 2:
        return sig

    r = sig[:siglen // 2]
    if r[0] & 0x80 != 0:
        r = b"\x00" + r
    while len(r) > 1 and r[0] == 0x00 and r[1] & 0x80 == 0:
        r = r[1:]

    s = sig[siglen // 2:]
    if s[0] & 0x80 != 0:
        s = b"\x00" + s
    while len(s) > 1 and s[0] == 0x00 and s[1] & 0x80 == 0:
        s = s[1:]

    return create_ecdsa_signature(r, s)


def verify_signature_ecdsa(pk_info, digest, sig, ecdsa_curve):
    curve = ec.get_curve_for_oid(get_curve_by_hex_oid(ecdsa_curve))
    assert not(curve is None)

    pub = ec.EllipticCurvePublicKey.from_encoded_point(curve(), pk_info)
    sig = fill_sign(sig)

    try:
        pub.verify(sig, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


def ecdh(ecdsa_curve, PrivateKey, PublicKey):
    curve = ec.get_curve_for_oid(get_curve_by_hex_oid(ecdsa_curve))
    assert not(curve is None)

    pub = ec.EllipticCurvePublicKey.from_encoded_point(curve(), PublicKey)
    prv = ec.derive_private_key(int(hexlify(PrivateKey), 16), curve(), default_backend())

    shared_secret = prv.exchange(ec.ECDH(), pub)
    return shared_secret


