"""
card_test_personalize_card.py - test personalizing card

Copyright (C) 2016, 2018, 2019  g10 Code GmbH
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

from struct import pack
from re import match, DOTALL
from util import *
import rsa_keys
from card_const import *
from constants_for_test import *

class Test_Card_Personalize_Card(object):
    def test_setup_pw3_0(self, card):
        r = card.change_passwd(3, FACTORY_PASSPHRASE_PW3, PW3_TEST0)
        assert r

    def test_verify_pw3_0(self, card):
        v = card.verify(3, PW3_TEST0)
        assert v

    def test_login_put(self, card):
        r = card.cmd_put_data(0x00, 0x5e, b"gpg_user")
        assert r

    def test_name_put(self, card):
        r = card.cmd_put_data(0x00, 0x5b, b"GnuPG User")
        assert r

    def test_lang_put(self, card):
        r = card.cmd_put_data(0x5f, 0x2d, b"ja")
        assert r

    def test_sex_put(self, card):
        r = card.cmd_put_data(0x5f, 0x35, b"1")
        assert r

    def test_url_put(self, card):
        r = card.cmd_put_data(0x5f, 0x50, b"https://www.fsij.org/gnuk/")
        assert r

    def test_pw1_status_put(self, card):
        r = card.cmd_put_data(0x00, 0xc4, b"\x01")
        assert r

    def test_login(self, card):
        login = get_data_object(card, 0x5e)
        assert login == b"gpg_user"

    def test_name_lang_sex(self, card):
        name = b"GnuPG User"
        lang = b"ja"
        sex = b"1"
        expected = b'\x5b' + pack('B', len(name)) + name \
                   +  b'\x5f\x2d' + pack('B', len(lang)) + lang \
                   + b'\x5f\x35' + pack('B', len(sex)) + sex
        name_lang_sex = get_data_object(card, 0x65)
        assert name_lang_sex == expected

    def test_url(self, card):
        url = get_data_object(card, 0x5f50)
        assert url == b"https://www.fsij.org/gnuk/"

    def test_pw1_status(self, card):
        s = get_data_object(card, 0xc4)
        assert match(b'\x01...\x03[\x00\x03]\x03', s, DOTALL)

    def test_rsa_import_key_1(self, card):
        t = rsa_keys.build_privkey_template(1, 0)
        r = card.cmd_put_data_odd(0x3f, 0xff, t)
        assert r

    def test_rsa_import_key_2(self, card):
        t = rsa_keys.build_privkey_template(2, 1)
        r = card.cmd_put_data_odd(0x3f, 0xff, t)
        assert r

    def test_rsa_import_key_3(self, card):
        t = rsa_keys.build_privkey_template(3, 2)
        r = card.cmd_put_data_odd(0x3f, 0xff, t)
        assert r

    def test_fingerprint_1_put(self, card):
        fpr1 = rsa_keys.fpr[0]
        r = card.cmd_put_data(0x00, 0xc7, fpr1)
        assert r

    def test_fingerprint_2_put(self, card):
        fpr2 = rsa_keys.fpr[1]
        r = card.cmd_put_data(0x00, 0xc8, fpr2)
        assert r

    def test_fingerprint_3_put(self, card):
        fpr3 = rsa_keys.fpr[2]
        r = card.cmd_put_data(0x00, 0xc9, fpr3)
        assert r

    def test_timestamp_1_put(self, card):
        timestamp1 = rsa_keys.timestamp[0]
        r = card.cmd_put_data(0x00, 0xce, timestamp1)
        assert r

    def test_timestamp_2_put(self, card):
        timestamp2 = rsa_keys.timestamp[1]
        r = card.cmd_put_data(0x00, 0xcf, timestamp2)
        assert r

    def test_timestamp_3_put(self, card):
        timestamp3 = rsa_keys.timestamp[2]
        r = card.cmd_put_data(0x00, 0xd0, timestamp3)
        assert r

    def test_ds_counter_0(self, card):
        c = get_data_object(card, 0x7a)
        assert c == b'\x93\x03\x00\x00\x00'

    def test_pw1_status(self, card):
        s = get_data_object(card, 0xc4)
        assert match(b'\x01...\x03[\x00\x03]\x03', s, DOTALL)

    def test_app_data(self, card):
        app_data = get_data_object(card, 0x6e)
        hist_len = app_data[20]
        # FIXME: parse and check DO of C0, C1, C2, C3, C4, and C6
        assert app_data[0:8] == b"\x4f\x10\xd2\x76\x00\x01\x24\x01" and \
               app_data[18:18+2] == b"\x5f\x52"

    def test_public_key_1(self, card):
        pk = card.cmd_get_public_key(1)
        assert rsa_keys.key[0][0] == pk[9:9+256]

    def test_public_key_2(self, card):
        pk = card.cmd_get_public_key(2)
        assert rsa_keys.key[1][0] == pk[9:9+256]

    def test_public_key_3(self, card):
        pk = card.cmd_get_public_key(3)
        assert rsa_keys.key[2][0] == pk[9:9+256]

    def test_setup_pw1_0(self, card):
        r = card.change_passwd(1, FACTORY_PASSPHRASE_PW1, PW1_TEST0)
        assert r

    def test_verify_pw1_0(self, card):
        v = card.verify(1, PW1_TEST0)
        assert v

    def test_verify_pw1_0_2(self, card):
        v = card.verify(2, PW1_TEST0)
        assert v

    def test_setup_pw1_1(self, card):
        r = card.change_passwd(1, PW1_TEST0, PW1_TEST1)
        assert r

    def test_verify_pw1_1(self, card):
        v = card.verify(1, PW1_TEST1)
        assert v

    def test_verify_pw1_1_2(self, card):
        v = card.verify(2, PW1_TEST1)
        assert v

    def test_setup_reset_code(self, card):
        r = card.setup_reset_code(RESETCODE_TEST)
        assert r

    def test_reset_code(self, card):
        r = card.reset_passwd_by_resetcode(RESETCODE_TEST, PW1_TEST2)
        assert r

    def test_verify_pw1_2(self, card):
        v = card.verify(1, PW1_TEST2)
        assert v

    def test_verify_pw1_2_2(self, card):
        v = card.verify(2, PW1_TEST2)
        assert v

    def test_setup_pw3_1(self, card):
        r = card.change_passwd(3, PW3_TEST0, PW3_TEST1)
        assert r

    def test_verify_pw3_1(self, card):
        v = card.verify(3, PW3_TEST1)
        assert v

    def test_reset_userpass_admin(self, card):
        r = card.reset_passwd_by_admin(PW1_TEST3)
        assert r

    def test_verify_pw1_3(self, card):
        v = card.verify(1, PW1_TEST3)
        assert v

    def test_verify_pw1_3_2(self, card):
        v = card.verify(2, PW1_TEST3)
        assert v

    def test_setup_pw1_4(self, card):
        r = card.change_passwd(1, PW1_TEST3, PW1_TEST4)
        assert r

    def test_verify_pw1_4(self, card):
        v = card.verify(1, PW1_TEST4)
        assert v

    def test_verify_pw1_4_2(self, card):
        v = card.verify(2, PW1_TEST4)
        assert v

    def test_setup_pw3_2(self, card):
        r = card.change_passwd(3, PW3_TEST1, PW3_TEST0)
        assert r

    def test_verify_pw3_2(self, card):
        v = card.verify(3, PW3_TEST0)
        assert v

    def test_sign_0(self, card):
        digestinfo = rsa_keys.compute_digestinfo(PLAIN_TEXT0)
        r = card.cmd_pso(0x9e, 0x9a, digestinfo)
        sig = rsa_keys.compute_signature(0, digestinfo)
        sig_bytes = sig.to_bytes(int((sig.bit_length()+7)/8), byteorder='big')
        assert r == sig_bytes

    def test_sign_1(self, card):
        digestinfo = rsa_keys.compute_digestinfo(PLAIN_TEXT1)
        r = card.cmd_pso(0x9e, 0x9a, digestinfo)
        sig = rsa_keys.compute_signature(0, digestinfo)
        sig_bytes = sig.to_bytes(int((sig.bit_length()+7)/8), byteorder='big')
        assert r == sig_bytes

    def test_ds_counter_1(self, card):
        c = get_data_object(card, 0x7a)
        assert c == b'\x93\x03\x00\x00\x02'

    def test_sign_auth_0(self, card):
        digestinfo = rsa_keys.compute_digestinfo(PLAIN_TEXT0)
        r = card.cmd_internal_authenticate(digestinfo)
        sig = rsa_keys.compute_signature(2, digestinfo)
        sig_bytes = sig.to_bytes(int((sig.bit_length()+7)/8), byteorder='big')
        assert r == sig_bytes

    def test_sign_auth_1(self, card):
        digestinfo = rsa_keys.compute_digestinfo(PLAIN_TEXT1)
        r = card.cmd_internal_authenticate(digestinfo)
        sig = rsa_keys.compute_signature(2, digestinfo)
        sig_bytes = sig.to_bytes(int((sig.bit_length()+7)/8), byteorder='big')
        assert r == sig_bytes

    def test_decrypt_0(self, card):
        ciphertext = rsa_keys.encrypt(1, PLAIN_TEXT0)
        r = card.cmd_pso(0x80, 0x86, ciphertext)
        assert r == PLAIN_TEXT0

    def test_decrypt_1(self, card):
        ciphertext = rsa_keys.encrypt(1, PLAIN_TEXT1)
        r = card.cmd_pso(0x80, 0x86, ciphertext)
        assert r == PLAIN_TEXT1
