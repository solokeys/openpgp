"""
ecdsa_keys.py - ecdsa functions

Copyright (C) 2019  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from time import time
from struct import pack
from hashlib import sha1, sha256
from util import *
import ecdsa


# Brainpool P-256-r1
_a = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
_b = 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
_p = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
_Gx = 0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262
_Gy = 0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997
_q = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7

curve_brainpoolp256r1 = ecdsa.ellipticcurve.CurveFp( _p, _a, _b)
generator_brainpoolp256r1 = ecdsa.ellipticcurve.Point( curve_brainpoolp256r1, _Gx, _Gy, _q)

# Brainpool P-384-r1
_a = 0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826
_b = 0x04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11
_p = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53
_Gx = 0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E
_Gy = 0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315
_q = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565

curve_brainpoolp384r1 = ecdsa.ellipticcurve.CurveFp( _p, _a, _b)
generator_brainpoolp384r1 = ecdsa.ellipticcurve.Point( curve_brainpoolp384r1, _Gx, _Gy, _q)

# Brainpool P-512-r1
_a = 0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA
_b = 0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723
_p = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3
_Gx = 0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822
_Gy = 0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892
_q = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069

curve_brainpoolp512r1 = ecdsa.ellipticcurve.CurveFp( _p, _a, _b)
generator_brainpoolp512r1 = ecdsa.ellipticcurve.Point( curve_brainpoolp512r1, _Gx, _Gy, _q)

BRAINPOOLP256r1 = ecdsa.curves.Curve("BRAINPOOLP256r1",
                        curve_brainpoolp256r1,
                        generator_brainpoolp256r1,
                        (1, 3, 36, 3, 3, 2, 8, 1, 1, 7),
                        "brainpoolP256r1")
BRAINPOOLP384r1 = ecdsa.curves.Curve("BRAINPOOLP384r1",
                        curve_brainpoolp384r1,
                        generator_brainpoolp384r1,
                        (1, 3, 36, 3, 3, 2, 8, 1, 1, 11),
                        "brainpoolP384r1")
BRAINPOOLP512r1 = ecdsa.curves.Curve("BRAINPOOLP512r1",
                        curve_brainpoolp512r1,
                        generator_brainpoolp512r1,
                        (1, 3, 36, 3, 3, 2, 8, 1, 1, 13),
                        "brainpoolP512r1")

ecdsa.curves.curves.extend([BRAINPOOLP256r1, BRAINPOOLP384r1, BRAINPOOLP512r1])


def find_curve_oid_hex(oid_curve_hex):
    for c in ecdsa.curves.curves:
        if c.encoded_oid[2:] == oid_curve_hex:
            return c
    return None

def calc_fpr_ecdsa(n):
    timestamp = int(time())
    timestamp_data = pack('>I', timestamp)
    m_len = 6 + 2 + 256 + 2 + 4
    m = b'\x99' + pack('>H', m_len) + b'\x04' + timestamp_data + b'\x01' + \
        pack('>H', len(n) * 8) + n
    fpr = sha1(m).digest()
    return fpr, timestamp_data

def generate_key_ecdsa(ecdsa_curve):
    curve = find_curve_oid_hex(ecdsa_curve)
    assert not(curve is None)
    PrivateKey = ecdsa.SigningKey.generate(curve, hashfunc=sha256)
    PublicKey = PrivateKey.get_verifying_key()
    return PublicKey, PrivateKey

def build_privkey_template_ecdsa(openpgp_keyno, ecdsa_curve):
    if openpgp_keyno == 1:
        keyspec = 0xb6
    elif openpgp_keyno == 2:
        keyspec = 0xb8
    else:
        keyspec = 0xa4

    PublicKey, PrivateKey = generate_key_ecdsa(ecdsa_curve)
    return create_ecdsa_4D_key(keyspec, PrivateKey.to_string(), b"\x04" + PublicKey.to_string())

def compute_digestinfo_ecdsa(msg):
    digest = sha256(msg).digest()
    return digest

def verify_signature_ecdsa(pk_info, digest, sig, ecdsa_curve):
    curve = find_curve_oid_hex(ecdsa_curve)
    assert not(curve is None)
    vk = ecdsa.VerifyingKey.from_string(pk_info[1:], curve=curve, hashfunc=sha256)
    return vk.verify_digest(sig, digest)

def ecdh(ecdsa_curve, PrivateKey, PublicKey):
    curve = find_curve_oid_hex(ecdsa_curve)
    assert not(curve is None)

    pub = ecdsa.VerifyingKey.from_string(PublicKey[1:], curve=curve, hashfunc=sha256)
    prv = ecdsa.SigningKey.from_string(PrivateKey, curve=curve, hashfunc=sha256)

    result = None
    acc = pub.pubkey.point
    pk_mul = prv.privkey.secret_multiplier

    while pk_mul:
        if pk_mul & 1:
            # add
            if result is None:
                result = acc
            else:
                result = acc.__add__(result)
        # double
        acc = acc.double()
        pk_mul >>= 1
    return ecdsa.ecdsa.int_to_string(result.x())


