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

from cnxarchive import config
from cnxarchive.database import initdb as archive_initdb
from cnxarchive import main as archive_main
from cnxpublishing.db import initdb as publishing_initdb
from cnxpublishing.main import main as publishing_main

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


def _amend_archive_data():
    """This contains data modifications to archive that are specific to
    the authoring tests.
    """
    # **Only add to this function if you really really must.**
    # The idea is to utilize as much of the archive data as possible.
    # We do this because that data has been tested and adding things here
    # may unintentionally insert an assumption about the data in archive.

    conn_str = publishing_settings()[config.CONNECTION_STRING]

    with psycopg2.connect(conn_str) as db_connection:
        with db_connection.cursor() as cursor:
            cursor.execute("""\
INSERT INTO document_controls (uuid, licenseid) VALUES
  ('a3f7c934-2a89-4baf-a9a9-a89d957586d2', 11);
INSERT INTO abstracts (abstractid, abstract, html) VALUES
  (9000, '', '');
INSERT INTO modules
  (module_ident, portal_type, uuid,
   name, abstractid, licenseid, doctype, stateid,
   submitter, submitlog,
   authors)
  VALUES
  (9000, 'Module', 'a3f7c934-2a89-4baf-a9a9-a89d957586d2',
   'missing resource', 9000, 12, '', null,
   'cnxcap', 'tests derive-from with missing resource',
   '{cnxcap}');
INSERT INTO files
  (fileid, file)
  VALUES
  (9000, '<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><p>module with a missing resource</p><img src="/resources/aca93d69479e75244b01272902968d8349a548f4/python"/></body></html>');
INSERT INTO module_files
  (module_ident, fileid, filename, mimetype)
  VALUES
  (9000, 9000, 'index.cnxml.html', 'text/html');""")


def _amend_publishing_data():
    """This contains data modifications of the publishing/archive data
    that are specific to the authoring tests.
    """
    conn_str = publishing_settings()[config.CONNECTION_STRING]

    with psycopg2.connect(conn_str) as db_connection:
        with db_connection.cursor() as cursor:
            cursor.execute("""\
INSERT INTO role_acceptances (uuid, user_id, role_type, accepted)
  SELECT uuid, unnest(authors), 'Author', TRUE FROM modules
  UNION
  SELECT uuid, unnest(maintainers), 'Publisher'::role_types, TRUE FROM modules
  UNION
  SELECT uuid, unnest(licensors), 'Copyright Holder'::role_types, TRUE
  FROM modules
  UNION
  SELECT m.uuid, unnest(personids), 'Author'::role_types, TRUE
  FROM moduleoptionalroles NATURAL JOIN latest_modules AS m
  WHERE roleid = 1
  UNION
  SELECT m.uuid, unnest(personids), 'Copyright Holder'::role_types, TRUE
  FROM moduleoptionalroles NATURAL JOIN latest_modules AS m
  WHERE roleid = 2
  UNION
  SELECT m.uuid, unnest(personids), 'Publisher'::role_types, TRUE
  FROM moduleoptionalroles NATURAL JOIN latest_modules AS m
  WHERE roleid = 3
  UNION
  SELECT m.uuid, unnest(personids), 'Translator'::role_types, TRUE
  FROM moduleoptionalroles NATURAL JOIN latest_modules AS m
  WHERE roleid = 4
  UNION
  SELECT m.uuid, unnest(personids), 'Editor'::role_types, TRUE
  FROM moduleoptionalroles NATURAL JOIN latest_modules AS m
  WHERE roleid = 5
  -- Note, no legacy mapping for Illustrator
;

INSERT INTO license_acceptances (uuid, user_id, accepted)
  SELECT uuid, unnest(authors), TRUE FROM modules
  UNION
  SELECT uuid, unnest(maintainers), TRUE FROM modules
  UNION
  SELECT uuid, unnest(licensors), TRUE
  FROM modules
  UNION
  SELECT m.uuid, unnest(personids), TRUE
  FROM moduleoptionalroles NATURAL JOIN latest_modules AS m
  WHERE roleid = 1
  UNION
  SELECT m.uuid, unnest(personids), TRUE
  FROM moduleoptionalroles NATURAL JOIN latest_modules AS m
  WHERE roleid = 2
  UNION
  SELECT m.uuid, unnest(personids), TRUE
  FROM moduleoptionalroles NATURAL JOIN latest_modules AS m
  WHERE roleid = 3
  UNION
  SELECT m.uuid, unnest(personids), TRUE
  FROM moduleoptionalroles NATURAL JOIN latest_modules AS m
  WHERE roleid = 4
  UNION
  SELECT m.uuid, unnest(personids), TRUE
  FROM moduleoptionalroles NATURAL JOIN latest_modules AS m
  WHERE roleid = 5
;""")


def install_intercept():
    """Initializes both the archive and publishing applications.
    Then this will register intercepts for both applications using
    the configuration setting found in the authoring config file.
    This sets up the example data found in cnx-archive.
    Any previously initialized data will be lost.
    Therefore, it is a good idea to only initialize the applications
    during testcase class setup (i.e. setUpClass).
    """
    settings = publishing_settings()
    authoring_settings = integration_test_settings()

    connection_string = settings[config.CONNECTION_STRING]
    # Wipe out any previous attempts.
    with psycopg2.connect(connection_string) as db_connection:
        with db_connection.cursor() as cursor:
            cursor.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")

    # Initialize the archive database.
    archive_initdb(settings)
    # Initialize the publishing database.
    publishing_initdb(connection_string)
    with psycopg2.connect(connection_string) as db_connection:
        with db_connection.cursor() as cursor:
            filepath = config.TEST_DATA_SQL_FILE
            with open(filepath, 'r') as fb:
                cursor.execute(fb.read())

    # Make amendments to the data that are specific to the authoring tests.
    _amend_archive_data()
    _amend_publishing_data()

    # Set up the intercept for archive
    global _archive_app
    if not _archive_app:
        _archive_app = archive_main({}, **publishing_settings())

    def make_app():
        return _archive_app
    # Grab the configured archive url from the authoring config.
    host, port = _parse_url_from_settings(authoring_settings,
                                          'archive.url')
    add_wsgi_intercept(host, port, make_app)

    # Set up the intercept for publishing
    global _publishing_app
    if not _publishing_app:
        _publishing_app = publishing_main({}, **publishing_settings())

    def make_app():
        return _publishing_app
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
        self.assertIn('cnxcap', [r['id'] for r in data['publishers']])

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
