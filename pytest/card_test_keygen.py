"""
card_test_keygen.py - test key generation

Copyright (C) 2018, 2019  g10 Code GmbH
Author: NIIBE Yutaka <gniibe@fsij.org>

This file is a part of Gnuk, a GnuPG USB Token implementation.

Gnuk is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Gnuk is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from binascii import hexlify
import rsa_keys
from card_const import *

class Test_Card_Keygen(object):
    def test_keygen_1(self, card):
        pk = card.cmd_genkey(1)
        fpr_date = rsa_keys.calc_fpr(pk[0], pk[1])
        r = card.cmd_put_data(0x00, 0xc7, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xce, fpr_date[1])
        assert r

    def test_keygen_2(self, card):
        pk = card.cmd_genkey(2)
        fpr_date = rsa_keys.calc_fpr(pk[0], pk[1])
        r = card.cmd_put_data(0x00, 0xc8, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xcf, fpr_date[1])
        assert r

    def test_keygen_3(self, card):
        pk = card.cmd_genkey(3)
        fpr_date = rsa_keys.calc_fpr(pk[0], pk[1])
        r = card.cmd_put_data(0x00, 0xc9, fpr_date[0])
        if r:
            r = card.cmd_put_data(0x00, 0xd0, fpr_date[1])
        assert r

    def test_verify_pw1(self, card):
        v = card.cmd_verify(1, FACTORY_PASSPHRASE_PW1)
        assert v

    def test_signature_sigkey(self, card):
        msg = b"Sign me please"
        pk = card.cmd_get_public_key(1)
        pk_info = (pk[9:9+256], pk[9+256+2:])
        digest = rsa_keys.compute_digestinfo(msg)
        sig = int(hexlify(card.cmd_pso(0x9e, 0x9a, digest)),16)
        r = rsa_keys.verify_signature(pk_info, digest, sig)
        assert r

    def test_verify_pw1_2(self, card):
        v = card.cmd_verify(2, FACTORY_PASSPHRASE_PW1)
        assert v

    def test_decryption(self, card):
        msg = b"encrypt me please"
        pk = card.cmd_get_public_key(2)
        pk_info = (pk[9:9+256], pk[9+256+2:])
        ciphertext = rsa_keys.encrypt_with_pubkey(pk_info, msg)
        r = card.cmd_pso(0x80, 0x86, ciphertext)
        assert r == msg

    def test_signature_authkey(self, card):
        msg = b"Sign me please to authenticate"
        pk = card.cmd_get_public_key(3)
        pk_info = (pk[9:9+256], pk[9+256+2:])
        digest = rsa_keys.compute_digestinfo(msg)
        sig = int(hexlify(card.cmd_internal_authenticate(digest)),16)
        r = rsa_keys.verify_signature(pk_info, digest, sig)
        assert r
