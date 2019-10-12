"""
test_031_user_do.py - test user data objects (0101, 0102, 0103, 0104)

Copyright (C) 2019  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from skip_gnuk_only_tests import *

from card_const import *
from constants_for_test import *

str_test0101 = b"test_do0101"
str_test0102 = b"test_do0102"
str_test0103 = b"test_do0103"
str_test0104 = b"test_do0104"


# access:
# 0101 any       pwd1(82)
# 0102 any       pwd3
# 0103 pwd1(02)  pwd1(82)
# 0104 pwd3      pwd3

def test_verify_pw1_2(card):
    v = card.verify(2, FACTORY_PASSPHRASE_PW1)
    assert v


def test_verify_pw3(card):
    v = card.verify(3, FACTORY_PASSPHRASE_PW3)
    assert v


def test_verify_reset(card):
    assert card.cmd_verify_reset(2)
    assert card.cmd_verify_reset(3)


def test_0101(card):
    assert card.verify(2, FACTORY_PASSPHRASE_PW1)
    assert card.cmd_put_data(0x01, 0x01, str_test0101)
    v = card.cmd_get_data(0x01, 0x01)
    assert v == str_test0101
    assert card.cmd_verify_reset(2)


def test_0102(card):
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)
    assert card.cmd_put_data(0x01, 0x02, str_test0102)
    v = card.cmd_get_data(0x01, 0x02)
    assert v == str_test0102
    assert card.cmd_verify_reset(3)


def test_0103(card):
    assert card.verify(2, FACTORY_PASSPHRASE_PW1)
    assert card.cmd_put_data(0x01, 0x03, str_test0103)
    v = card.cmd_get_data(0x01, 0x03)
    assert v == str_test0103
    assert card.cmd_verify_reset(2)


def test_0104(card):
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)
    assert card.cmd_put_data(0x01, 0x04, str_test0104)
    v = card.cmd_get_data(0x01, 0x04)
    assert v == str_test0104
    assert card.cmd_verify_reset(3)


def test_verify_reset2(card):
    assert card.cmd_verify_reset(2)
    assert card.cmd_verify_reset(3)


def test_0101_access_deny(card):
    # get wo rights
    v = card.cmd_get_data(0x01, 0x01)
    assert v == str_test0101

    # cant put wo rights
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)
    try:
        assert not card.cmd_put_data(0x01, 0x01, str_test0101)
    except ValueError:
        pass
    assert card.cmd_verify_reset(3)


def test_0102_access_deny(card):
    # get wo rights
    v = card.cmd_get_data(0x01, 0x02)
    assert v == str_test0102

    # cant put wo rights
    assert card.verify(1, FACTORY_PASSPHRASE_PW1)
    assert card.verify(2, FACTORY_PASSPHRASE_PW1)
    try:
        assert not card.cmd_put_data(0x01, 0x02, str_test0102)
    except ValueError:
        pass
    assert card.cmd_verify_reset(1)
    assert card.cmd_verify_reset(2)


def test_0103_access_deny(card):
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)

    # get wo rights
    try:
        v = card.cmd_get_data(0x01, 0x03)
        assert v == str_test0103
    except ValueError:
        pass

    # cant put wo rights
    try:
        assert not card.cmd_put_data(0x01, 0x03, str_test0103)
    except ValueError:
        pass
    assert card.cmd_verify_reset(3)


def test_0104_access_deny(card):
    assert card.verify(1, FACTORY_PASSPHRASE_PW1)
    assert card.verify(2, FACTORY_PASSPHRASE_PW1)

    # get wo rights
    try:
        v = card.cmd_get_data(0x01, 0x04)
        assert v == str_test0104
    except ValueError:
        pass

    # cant put wo rights
    try:
        assert not card.cmd_put_data(0x01, 0x04, str_test0104)
    except ValueError:
        pass

    assert card.cmd_verify_reset(1)
    assert card.cmd_verify_reset(2)

