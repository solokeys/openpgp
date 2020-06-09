"""
test_037_challenge.py - test setting rsa 4096

Copyright (C) 2020  SoloKeys
Author: Oleg Moiseenko (merlokk)

"""

from skip_gnuk_only_tests import *

from card_const import *
from constants_for_test import *
from openpgp_card import *


def test_challenge(card):
    rndval = card.cmd_get_challenge(10)
    assert len(rndval) == 10
    assert rndval[0] != rndval[1] and rndval[1] != rndval[2] and \
           rndval[3] != rndval[4] and rndval[4] != rndval[5]

def test_challenge_long(card):
    rndval = card.cmd_get_challenge(255)
    assert len(rndval) == 255

