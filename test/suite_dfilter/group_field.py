# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_exists(unittest.TestCase):

    def test_exists_1(self, checkDFilterSucceed):
        dfilter = "frame"
        checkDFilterSucceed(dfilter)
