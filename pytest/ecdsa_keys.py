"""
ecdsa_keys.py - ecdsa functions

Copyright (C) 2019  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from time import time
from struct import pack
from hashlib import sha1, sha256
import ecdsa


def calc_fpr_ecdsa(n):
    timestamp = int(time())
    timestamp_data = pack('>I', timestamp)
    m_len = 6 + 2 + 256 + 2 + 4
    m = b'\x99' + pack('>H', m_len) + b'\x04' + timestamp_data + b'\x01' + \
        pack('>H', len(n) * 8) + n
    fpr = sha1(m).digest()
    return fpr, timestamp_data

def compute_digestinfo_ecdsa(msg):
    digest = sha256(msg).digest()
    return digest

def verify_signature_ecdsa(pk_info, digest, sig):
    vk = ecdsa.VerifyingKey.from_string(pk_info[1:], curve=ecdsa.NIST384p, hashfunc=sha256)
    return vk.verify_digest(sig, digest)

