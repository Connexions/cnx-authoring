# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2014, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import os
import unittest
try:
    from urllib.parse import urljoin, urlparse
except ImportError:
    from urlparse import urljoin, urlparse

import psycopg2
import requests
from pyramid.paster import get_appsettings
from wsgi_intercept import (
    requests_intercept,
    add_wsgi_intercept, remove_wsgi_intercept,
    )

from .testing import integration_test_settings


__all__ = (
    'publishing_settings', 'intercept_publishing',
    )

here = os.path.abspath(os.path.dirname(__file__))

# global apps
_archive_app = None
_publishing_app = None


def publishing_settings():
    """Integration settings initializer"""
    config_uri = os.environ.get('PUB_N_ARC_CONFIG', None)
    if config_uri is None:
        config_uri = os.path.join(here, 'pub_n_arc.ini')
    settings = get_appsettings(config_uri)
    return settings


def _parse_url_from_settings(settings, url_key):
    """This parses a url from ``settings`` into host and port.
    These can then be used as arguments to ``add_wsgi_intercept``.
    """
    parsed_url = urlparse(settings[url_key])
    try:
        host, port = parsed_url.netloc.split(':')
    except ValueError:
        host = parsed_url.netloc
        port = 80
    port = int(port)
    return host, port


def install_intercept():
    """Initializes both the archive and publishing applications.
    Then this will register intercepts for both applications using
    the configuration setting found in the authoring config file.
    This sets up the example data found in cnx-archive.
    Any previously initialized data will be lost.
    Therefore, it is a good idea to only initialize the applications
    during testcase class setup (i.e. setUpClass).
    """
    from cnxarchive import config
    settings = publishing_settings()
    authoring_settings = integration_test_settings()

    connection_string = settings[config.CONNECTION_STRING]
    # Wipe out any previous attempts.
    with psycopg2.connect(connection_string) as db_connection:
        with db_connection.cursor() as cursor:
            cursor.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        
    # Initialize the archive database.
    from cnxarchive.database import initdb
    initdb(settings)
    # Initialize the publishing database.
    from cnxpublishing.db import initdb
    initdb(connection_string)
    with psycopg2.connect(connection_string) as db_connection:
        with db_connection.cursor() as cursor:
            filepath = config.TEST_DATA_SQL_FILE
            with open(filepath, 'r') as fb:
                cursor.execute(fb.read())
    # Initialize the openstax accounts database.
    connection_string = settings[config.ACCOUNTS_CONNECTION_STRING]
    with psycopg2.connect(connection_string) as db_connection:
        with db_connection.cursor() as cursor:
            cursor.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            data_dir = config.TEST_DATA_DIRECTORY
            filepaths = (
                os.path.join(data_dir, 'osc-accounts.schema.sql'),
                os.path.join(data_dir, 'osc-accounts.data.sql'),
                )
            for filepath in filepaths:
                with open(filepath, 'r') as fb:
                    cursor.execute(fb.read())

    # Set up the intercept for archive
    from cnxarchive import main
    global _archive_app
    if not _archive_app:
        _archive_app = main({}, **publishing_settings())
    make_app = lambda : _archive_app
    # Grab the configured archive url from the authoring config.
    host, port = _parse_url_from_settings(authoring_settings,
                                          'archive.url')
    add_wsgi_intercept(host, port, make_app)

    # Set up the intercept for publishing
    from cnxpublishing.main import main
    global _publishing_app
    if not _publishing_app:
        _publishing_app = main({}, **publishing_settings())
    make_app = lambda : _publishing_app
    # Grab the configured publishing url from the authoring config.
    host, port = _parse_url_from_settings(authoring_settings,
                                          'publishing.url')
    add_wsgi_intercept(host, port, make_app)


def uninstall_intercept():
    """Uninstalls intercepts added by ``install_intercept``"""
    authoring_settings = integration_test_settings()

    # Grab the configured urls from the authoring config.
    loc = _parse_url_from_settings(authoring_settings, 'archive.url')
    remove_wsgi_intercept(*loc)
    loc = _parse_url_from_settings(authoring_settings, 'publishing.url')
    remove_wsgi_intercept(*loc)


class TestSingluarRunIntercept(unittest.TestCase):
    """This installs and uninstalls the intercept and sets up
    the applications during each test run.
    """

    def setUp(self):
        # Install the requests library intercept.
        requests_intercept.install()
        # Initialize the intercepts for archive and publishing.
        install_intercept()

    def tearDown(self):
        # Uninstall the requests library intercept.
        requests_intercept.uninstall()
        # Initialize the intercepts for archive and publishing.
        uninstall_intercept()

    def test_archive(self):
        """Check the intercept for communications with archive."""
        archive_url = integration_test_settings()['archive.url']
        uuid = 'c8bdbabc-62b1-4a5f-b291-982ab25756d7'
        url = urljoin(archive_url, 'contents/{}'.format(uuid))
        resp = requests.get(url)

        data = resp.json()
        self.assertEqual(data['legacy_id'], 'm42091')
        self.assertIn('cnxcap', [r['id'] for r in data['maintainers']])

    def test_publishing(self):
        """Check the intercept for communications with publishing."""
        publishing_url = integration_test_settings()['publishing.url']
        uuid = 'c8bdbabc-62b1-4a5f-b291-982ab25756d7'
        url = urljoin(publishing_url, 'contents/{}/permissions'.format(uuid))
        resp = requests.get(url)

        expected = [
            {u'uid': u'OpenStaxCollege',
             u'uuid': u'c8bdbabc-62b1-4a5f-b291-982ab25756d7',
             u'permission': u'publish'},
            {u'uid': u'cnxcap',
             u'uuid': u'c8bdbabc-62b1-4a5f-b291-982ab25756d7',
             u'permission': u'publish'}]
        self.assertEqual(sorted(resp.json(), key=lambda v: v['uid']),
                         expected)
