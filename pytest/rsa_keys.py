from binascii import hexlify, unhexlify
from time import time
from struct import pack
from hashlib import sha1, sha256
import string
from os import urandom

def read_key_from_file(file):
    f = open(file)
    n_str = f.readline()[:-1]
    e_str = f.readline()[:-1]
    p_str = f.readline()[:-1]
    q_str = f.readline()[:-1]
    f.close()
    e = int(e_str, 16)
    p = int(p_str, 16)
    q = int(q_str, 16)
    n = int(n_str, 16)
    if n != p * q:
        raise ValueError("wrong key", p, q, n)
    return (unhexlify(n_str), unhexlify(e_str), unhexlify(p_str), unhexlify(q_str), e, p, q, n)

def calc_fpr(n,e):
    timestamp = int(time())
    timestamp_data = pack('>I', timestamp)
    m_len = 6 + 2 + 256 + 2 + 4
    m = b'\x99' + pack('>H', m_len) + b'\x04' + timestamp_data + b'\x01' + \
        pack('>H', 2048) + n + pack('>H', 17) + e
    fpr = sha1(m).digest()
    return (fpr, timestamp_data)

key = [ None, None, None ]
fpr = [ None, None, None ]
timestamp = [ None, None, None ]

key[0] = read_key_from_file('rsa-sig.key')
key[1] = read_key_from_file('rsa-dec.key')
key[2] = read_key_from_file('rsa-aut.key')

(fpr[0], timestamp[0]) = calc_fpr(key[0][0], key[0][1])
(fpr[1], timestamp[1]) = calc_fpr(key[1][0], key[1][1])
(fpr[2], timestamp[2]) = calc_fpr(key[2][0], key[2][1])

def build_privkey_template(openpgp_keyno, keyno):
    n_bytes = key[keyno][0]
    e_bytes = b'\x00' + key[keyno][1]
    p_bytes = key[keyno][2]
    q_bytes = key[keyno][3]

    if openpgp_keyno == 1:
        keyspec = b'\xb6'
    elif openpgp_keyno == 2:
        keyspec = b'\xb8'
    else:
        keyspec = b'\xa4'

    key_template = b'\x91\x04'+ b'\x92\x81\x80' + b'\x93\x81\x80' 

    exthdr = keyspec + b'\x00' + b'\x7f\x48' + b'\x08' + key_template

    suffix = b'\x5f\x48' + b'\x82\x01\x04'

    t = b'\x4d' + b'\x82\x01\x16' + exthdr + suffix + e_bytes + p_bytes + q_bytes
    return t

def build_privkey_template_for_remove(openpgp_keyno):
    if openpgp_keyno == 1:
        keyspec = b'\xb6'
    elif openpgp_keyno == 2:
        keyspec = b'\xb8'
    else:
        keyspec = b'\xa4'
    return b'\x4d\02' + keyspec + b'\0x00'

def compute_digestinfo(msg):
    digest = sha256(msg).digest()
    prefix = b'\x30\31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    return prefix + digest

# egcd and modinv are from wikibooks
# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def pkcs1_pad_for_sign(digestinfo):
    byte_repr = b'\x00' + b'\x01' + bytes.ljust(b'', 256 - 19 - 32 - 3, b'\xff') \
        + b'\x00' + digestinfo
    return int(hexlify(byte_repr), 16)

def pkcs1_pad_for_crypt(msg):
    padlen = 256 - 3 - len(msg)
    byte_repr = b'\x00' + b'\x02' \
        + bytes.replace(urandom(padlen), b'\x00', b'\x01') + b'\x00' + msg
    return int(hexlify(byte_repr), 16)

def compute_signature(keyno, digestinfo):
    e = key[keyno][4]
    p = key[keyno][5]
    q = key[keyno][6]
    n = key[keyno][7]
    p1 = p - 1
    q1 = q - 1
    h = p1 * q1
    d = modinv(e, h)
    dp = d % p1
    dq = d % q1
    qp = modinv(q, p)

    input = pkcs1_pad_for_sign(digestinfo)
    t1 = pow(input, dp, p)
    t2 = pow(input, dq, q)
    t = ((t1 - t2) * qp) % p
    sig = t2 + t * q
    return sig

def integer_to_bytes_256(i):
    return i.to_bytes(256, byteorder='big')

def encrypt(keyno, plaintext):
    e = key[keyno][4]
    n = key[keyno][7]
    m = pkcs1_pad_for_crypt(plaintext)
    return b'\x00' + integer_to_bytes_256(pow(m, e, n))

def encrypt_with_pubkey(pubkey_info, plaintext):
    n = int(hexlify(pubkey_info[0]), 16)
    e = int(hexlify(pubkey_info[1]), 16)
    m = pkcs1_pad_for_crypt(plaintext)
    return b'\x00' + integer_to_bytes_256(pow(m, e, n))

def verify_signature(pubkey_info, digestinfo, sig):
    n = int(hexlify(pubkey_info[0]), 16)
    e = int(hexlify(pubkey_info[1]), 16)
    di_pkcs1 = pow(sig,e,n)
    m = pkcs1_pad_for_sign(digestinfo)
    return di_pkcs1 == m
