# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2014, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###

import os


# Set the timezone in tests to United States Central Time
# UTC-6 in winter and UTC-5 in summer
os.environ['TZ'] = 'America/Chicago'
os.environ['PGTZ'] = 'America/Chicago'

here = os.path.abspath(os.path.dirname(__file__))
TEST_DATA_DIRECTORY = os.path.join(here, 'data')

def test_data(filename):
    return os.path.join(TEST_DATA_DIRECTORY, filename)
