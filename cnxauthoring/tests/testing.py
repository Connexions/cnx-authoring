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


_LICENSE_VALUES = (
  ('Creative Commons Attribution License',
   'by', '3.0',
   'http://creativecommons.org/licenses/by/3.0/'),
  ('Creative Commons Attribution License',
   'by', '4.0',
   'http://creativecommons.org/licenses/by/4.0/'),
  ('Creative Commons Attribution-NonCommercial-ShareAlike License',
   'by-nc-sa', '3.0',
   'http://creativecommons.org/licenses/by-nc-sa/3.0/'),
  ('Creative Commons Attribution-NonCommercial-ShareAlike License',
   'by-nc-sa', '4.0',
   'http://creativecommons.org/licenses/by-nc-sa/4.0/'),
  )
_LICENSE_KEYS = ('name', 'code', 'version', 'url',)


def _setup_licenses():
    """This sets up a limited set of licenses for tests.
    This is necessary because licenses are normally initiallized from
    a request made to an archive instance. Since, unittests won't
    have access to an archive instance.
    """
    from .. import models
    models.LICENSES = [
        models.License(**dict(args))
        for args in [zip(_LICENSE_KEYS, v) for v in _LICENSE_VALUES]
        ]
    models.CURRENT_LICENSES = (models.LICENSES[1], models.LICENSES[3],)
    models.DEFAULT_LICENSE = models.CURRENT_LICENSES[0]
    assert models.DEFAULT_LICENSE.code == 'by'
    assert models.DEFAULT_LICENSE.version == '4.0'
    assert models.CURRENT_LICENSES[1].code == 'by-nc-sa'
    assert models.CURRENT_LICENSES[1].version == '4.0'


_setup_licenses()
