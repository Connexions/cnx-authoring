# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import os

from pyramid.paster import get_appsettings


__all__ = (
    'TEST_DATA_DIRECTORY',
    'integration_test_settings', 'test_data',
    )


# Set the timezone in tests to United States Central Time
# UTC-6 in winter and UTC-5 in summer
os.environ['TZ'] = 'America/Chicago'
os.environ['PGTZ'] = 'America/Chicago'

here = os.path.abspath(os.path.dirname(__file__))
TEST_DATA_DIRECTORY = os.path.join(here, 'data')


def test_data(filename):
    """Get the path to a test data file."""
    return os.path.join(TEST_DATA_DIRECTORY, filename)


def integration_test_settings():
    """Integration settings initializer"""
    config_uri = os.environ.get('TESTING_CONFIG', None)
    if config_uri is None:
        config_uri = os.path.join(here, 'testing.ini')
    settings = get_appsettings(config_uri)
    return settings
