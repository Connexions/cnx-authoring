# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import datetime
import json
import io
import mimetypes
import os
import sys
import re
import unittest
try:
    from unittest import mock  # python 3
except ImportError:
    import mock  # python 2
try:
    import urllib2  # python2
except ImportError:
    import urllib.request as urllib2  # renamed in python3

import cnxepub
import pytz
from webtest import Upload
from wsgi_intercept import requests_intercept

from .intercept import install_intercept, uninstall_intercept
from .testing import integration_test_settings, test_data
from ..models import DEFAULT_LICENSE, TZINFO


USER_PROFILE = {
        u'username': u'user1',
        u'id': 1,
        u'first_name': u'User',
        u'last_name': u'One',
        u'contact_infos': [
            {
                u'type': u'EmailAddress',
                u'verified': True,
                u'id': 1,
                u'value': u'user1@example.com',
                },
            ],
        }

SUBMITTER = {
        u'id': u'user1',
        u'email': u'user1@example.com',
        u'firstname': u'User',
        u'surname': u'One',
        u'fullname': u'User One',
        u'type': u'cnx-id',
        }

SUBMITTER_WITH_ACCEPTANCE = SUBMITTER.copy()
SUBMITTER_WITH_ACCEPTANCE[u'hasAccepted'] = True
SUBMITTER_WITH_ACCEPTANCE[u'requester'] = SUBMITTER['id']


class BaseFunctionalTestCase(unittest.TestCase):
    accounts_request_return = ''
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.settings = settings = integration_test_settings()
        # only run once for all the tests

        # make sure storage is set correctly in cnxauthoring.views by reloading
        # cnxauthoring.views
        if 'cnxauthoring.views' in sys.modules:
            del sys.modules['cnxauthoring.views']

        from .. import main
        app = main({}, **settings)

        from webtest import TestApp
        cls.testapp = TestApp(app)

        # Install the intercept for archive and publishing.
        install_intercept()
        requests_intercept.install()

    @classmethod
    def tearDownClass(cls):
        from ..storage import storage
        if hasattr(storage, 'conn'):
            storage.conn.close()
        # Uninstall the intercept for archive and publishing.
        requests_intercept.uninstall()
        uninstall_intercept()

    def setUp(self):
        # All tests start with a login.
        self.login()
        self.addCleanup(self.logout)

    def login(self, username='user1', password='password', login_url='/login',
              headers=None):
        headers = headers or {}
        response = self.testapp.get(login_url, headers=headers, status=302)
        response = self.testapp.post(response.headers['Location'], {
            'username': username,
            'password': password,
            })
        return self.testapp.get(response.headers['Location'])

    def logout(self):
        self.testapp.get('/logout', status=302)

    def assert_cors_headers(self, response):
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'http://localhost:8000')
        self.assertEqual(response.headers['Access-Control-Allow-Headers'],
                'Origin, Content-Type')
        self.assertEqual(response.headers['Access-Control-Allow-Methods'],
                'GET, OPTIONS, PUT, POST')


class FunctionalTests(BaseFunctionalTestCase):
    def test_login(self):
        self.logout()
        response = self.login()
        self.assertEqual(response.headers['Location'], 'http://localhost/')
        self.assert_cors_headers(response)

    def test_login_redirect_already_logged_in(self):
        response = self.testapp.get(
            '/login?redirect=http://example.com/logged_in', status=302)
        self.assertEqual(response.headers['Location'],
                'http://example.com/logged_in')
        self.assert_cors_headers(response)

    def test_login_redirect_loop(self):
        self.logout()
        response = self.login(headers={'REFERER': 'http://localhost/login'})
        self.assertEqual(response.headers['Location'], 'http://localhost/')
        self.assert_cors_headers(response)

    def test_login_redirect_referer(self):
        self.logout()
        response = self.login(headers={'REFERER': 'http://example.com/'})
        self.assertEqual(response.headers['Location'], 'http://example.com/')
        self.assert_cors_headers(response)

    def test_login_redirect(self):
        self.logout()
        response = self.login(
            login_url='/login?redirect=http://example.com/logged_in')
        self.assertEqual(response.headers['Location'],
                         'http://example.com/logged_in')
        self.assert_cors_headers(response)

    def test_logout_redirect_loop(self):
        response = self.testapp.get('/logout',
                headers={'REFERER': 'http://localhost/logout'},
                status=302)
        self.assertEqual(response.headers['Location'], 'http://localhost/')
        self.testapp.get('/users/profile', status=401)
        self.assert_cors_headers(response)

    def test_logout_redirect_referer(self):
        response = self.testapp.get('/logout',
                headers={'REFERER': 'http://example.com/logged_out'},
                status=302)
        self.assertEqual(response.headers['Location'],
                'http://example.com/logged_out')
        self.testapp.get('/users/profile', status=401)
        self.assert_cors_headers(response)

    def test_logout_redirect(self):
        response = self.testapp.get(
                '/logout?redirect=http://example.com/logged_out',
                headers={'REFERER': 'http://example.com/'},
                status=302)
        self.assertEqual(response.headers['Location'],
                'http://example.com/logged_out')
        self.testapp.get('/users/profile', status=401)
        self.assert_cors_headers(response)

    def test_options(self):
        self.testapp.options('/', status=404)
        self.testapp.options('/some-random.html', status=404)

        urls = ['/*', '/login', '/logout', '/callback', '/search',
                '/contents/uuid@draft.json', '/resources/hash',
                '/contents', '/resources', '/users/search',
                '/users/profile', '/users/contents']

        for url in urls:
            response = self.testapp.options(url, status=200)
            self.assert_cors_headers(response)
            self.assertEqual(response.headers['Content-Length'], '0')

    def test_get_content_401(self):
        self.logout()
        response = self.testapp.get('/contents/1234abcde@draft.json',
                                    status=401)
        self.assert_cors_headers(response)

    def test_get_content_404(self):
        response = self.testapp.get('/contents/1234abcde@draft.json',
                                    status=404)
        self.assert_cors_headers(response)

    def test_get_content_403(self):
        response = self.testapp.post_json('/users/contents',
                {'title': 'My New Document'}, status=201)
        content = response.json
        with mock.patch('cnxauthoring.models.Document.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.get('/contents/{}@draft.json'
                    .format(content['id']), status=403)
        self.assertTrue('You do not have permission to view'
                in response.body.decode('utf-8'))

        response = self.testapp.post_json('/users/contents', {
                    'title': 'My New Binder',
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'tree': {
                        'contents': [],
                        },
                    }, status=201)
        content = response.json
        with mock.patch('cnxauthoring.models.Binder.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.get('/contents/{}@draft.json'
                    .format(content['id']), status=403)
        self.assertTrue('You do not have permission to view'
                in response.body.decode('utf-8'))

    def test_get_content_for_document(self):
        now = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.post_json(
                '/users/contents', {
                    'title': 'My New Document',
                    'created': u'2014-03-13T15:21:15-05:00',
                    'revised': u'2014-03-13T15:21:15-05:00',
                    }, status=201)
        put_result = response.json
        response = self.testapp.get('/contents/{}@draft.json'.format(
            put_result['id']), status=200)
        get_result = response.json
        submitter_w_assign_date = SUBMITTER_WITH_ACCEPTANCE.copy()
        submitter_w_assign_date['assignmentDate'] = now.astimezone(
            TZINFO).isoformat()
        self.assertEqual(get_result, {
            u'id': get_result['id'],
            u'title': u'My New Document',
            u'containedIn': [],
            u'content': u'',
            u'created': get_result['created'],
            u'derivedFrom': None,
            u'derivedFromTitle': None,
            u'derivedFromUri': None,
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0',
                },
            u'revised': get_result['revised'],
            u'mediaType': u'application/vnd.org.cnx.module',
            u'language': u'en',
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'abstract': u'',
            u'version': u'draft',
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'publication': None,
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'translators': [],
            u'editors': [],
            u'illustrators': [],
            })
        self.assertEqual(put_result, get_result)
        self.assert_cors_headers(response)

    def test_post_content_401(self):
        self.logout()
        response = self.testapp.post('/users/contents', status=401)
        self.assert_cors_headers(response)

    def test_post_content_403(self):
        with mock.patch('cnxauthoring.models.Document.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.post_json('/users/contents',
                {'title': u'My document タイトル'}, status=403)
        self.assert_cors_headers(response)

        with mock.patch('cnxauthoring.models.Binder.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.post_json('/users/contents', {
                    'title': u'My book タイトル',
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'tree': {
                        'contents': [],
                        },
                    }, status=403)
        self.assert_cors_headers(response)

    def test_post_content_invalid_json(self):
        response = self.testapp.post('/users/contents',
                'invalid json', status=400)
        self.assertTrue('Invalid JSON' in response.body.decode('utf-8'))
        self.assert_cors_headers(response)

    def test_post_content_empty(self):
        response = self.testapp.post_json(
                '/users/contents', {}, status=400)
        self.assertEqual(response.json, {
            u'title': u'Required',
            })
        self.assert_cors_headers(response)

    def test_post_content_empty_binder(self):
        response = self.testapp.post_json('/users/contents', {
                    'mediaType': 'application/vnd.org.cnx.collection',
                    }, status=400)
        self.assertEqual(response.json, {
            u'title': u'Required',
            u'tree': u'Required',
            })
        self.assert_cors_headers(response)

    def test_post_content_unknown_media_type(self):
        response = self.testapp.post_json('/users/contents', {
                    'mediaType': 'unknown-media-type',
                    }, status=400)
        self.assertEqual(response.json, {
            u'media_type': u'"unknown-media-type" is not one of '
                           u'application/vnd.org.cnx.module, '
                           u'application/vnd.org.cnx.collection',
            u'title': u'Required',
            })
        self.assert_cors_headers(response)

    def test_post_content_minimal(self):
        response = self.testapp.post_json('/users/contents',
                {'title': u'My document タイトル'}, status=201)
        result = response.json
        self.assertEqual(result['title'], u'My document タイトル')
        self.assertEqual(result['language'], u'en')
        self.assert_cors_headers(response)

        response = self.testapp.get('/contents/{}@draft.json'.format(
            result['id']), status=200)
        self.assert_cors_headers(response)

    def test_post_content_minimal_binder(self):
        response = self.testapp.post_json('/users/contents', {
                    'title': u'My book タイトル',
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'tree': {
                        'contents': [],
                        },
                    }, status=201)
        result = response.json
        self.assertEqual(result['title'], u'My book タイトル')
        self.assertEqual(result['language'], u'en')
        self.assertEqual(result['tree'], {
            u'contents': [],
            u'id': '{}@draft'.format(result['id']),
            u'title': result['title'],
            })

        self.assert_cors_headers(response)

        response = self.testapp.get(
                '/contents/{}@draft.json'.format(result['id']), status=200)
        result = response.json
        self.assertEqual(result['title'], u'My book タイトル')
        self.assertEqual(result['language'], u'en')
        self.assertEqual(result['tree'], {
            u'contents': [],
            u'id': '{}@draft'.format(result['id']),
            u'title': result['title'],
            })
        self.assert_cors_headers(response)

    def test_post_content_binder_document_not_found(self):
        response = self.testapp.post_json('/users/contents', {
                    'title': 'Book',
                    'abstract': 'Book abstract',
                    'language': 'de',
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'tree': {
                        'contents': [
                            {
                                'id': 'page@draft',
                                'title': 'Page one',
                                },
                            ],
                        },
                    }, status=400)
        self.assert_cors_headers(response)
        self.assertTrue('Document Not Found: page@draft' in
                response.body.decode('utf-8'))

    def test_post_content_multiple(self):
        post_data = [
                {'title': u'My document タイトル 1'},
                {'title': u'My document タイトル 2'},
                ]
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        result = response.json
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['title'], u'My document タイトル 1')
        self.assertEqual(result[1]['title'], u'My document タイトル 2')
        self.assert_cors_headers(response)

        response = self.testapp.get('/contents/{}@draft.json'.format(
            result[0]['id']), status=200)
        self.assert_cors_headers(response)
        response = self.testapp.get('/contents/{}@draft.json'.format(
            result[1]['id']), status=200)
        self.assert_cors_headers(response)

    def test_post_content_derived_from_not_found(self):
        post_data = {'derivedFrom': u'notfound@1'}
        response = self.testapp.post_json(
                '/users/contents', post_data, status=400)
        self.assertTrue(b'Derive failed' in response.body)
        self.assert_cors_headers(response)

    def test_post_content_derived_from_no_version(self):
        post_data = {
            'derivedFrom': u'91cb5f28-2b8a-4324-9373-dac1d617bc24',
            }

        now = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.post_json('/users/contents',
                post_data, status=201)
        result = response.json
        content = result.pop('content')
        self.assertTrue(content.startswith('<html'))
        self.assertTrue(u'Lav en madplan for den kommende uge' in content)
        self.assertNotIn('2011-10-05', result.pop('created'))
        self.assertNotIn('2011-10-12', result.pop('revised'))
        submitter_w_assign_date = SUBMITTER_WITH_ACCEPTANCE.copy()
        submitter_w_assign_date['assignmentDate'] = now.astimezone(
            TZINFO).isoformat()
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'id': result['id'],
            u'derivedFrom': '{}@1'.format(post_data['derivedFrom']),
            u'derivedFromTitle': u'Indkøb',
            u'derivedFromUri': u'http://cnx.org/contents/{}@1'.format(
                post_data['derivedFrom']),
            u'title': u'Copy of Indkøb',
            u'abstract': u'',
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'illustrators': [],
            })
        self.assert_cors_headers(response)

        response = self.testapp.get('/contents/{}@draft.json'.format(
            result['id']), status=200)
        result = response.json
        content = result.pop('content')
        self.assertTrue(u'Lav en madplan for den kommende uge' in content)
        self.assertTrue(content.startswith('<html'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'id': result['id'],
            u'derivedFrom': '{}@1'.format(post_data['derivedFrom']),
            u'derivedFromTitle': u'Indkøb',
            u'derivedFromUri': u'http://cnx.org/contents/{}@1'.format(
                post_data['derivedFrom']),
            u'title': u'Copy of Indkøb',
            u'abstract': u'',
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'illustrators': [],
            })
        self.assert_cors_headers(response)

        # Check that resources are saved
        resource_path = re.search('(/resources/[^"]*)"', content).group(1)
        response = self.testapp.get(resource_path, status=200)
        self.assertEqual(response.content_type, 'image/jpeg')
        self.assert_cors_headers(response)

    def test_post_content_derived_from(self):
        post_data = {
                'derivedFrom': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
            }

        # Create the derived content
        now = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.post_json('/users/contents',
                post_data, status=201)
        result = response.json

        content = result.pop('content')
        self.assertTrue(content.startswith('<html'))
        self.assertTrue(u'Lav en madplan for den kommende uge' in content)
        self.assertNotIn('2011-10-05', result.pop('created'))
        self.assertNotIn('2011-10-12', result.pop('revised'))
        submitter_w_assign_date = SUBMITTER_WITH_ACCEPTANCE.copy()
        submitter_w_assign_date['assignmentDate'] = now.astimezone(
            TZINFO).isoformat()
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Indkøb',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(
                post_data['derivedFrom']),
            u'title': u'Copy of Indkøb',
            u'abstract': u'',
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'illustrators': [],
            })
        self.assert_cors_headers(response)

        response = self.testapp.get('/contents/{}@draft.json'.format(
            result['id']), status=200)
        result = response.json
        content = result.pop('content')
        self.assertTrue(u'Lav en madplan for den kommende uge' in content)
        self.assertTrue(content.startswith('<html'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Indkøb',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(
                post_data['derivedFrom']),
            u'title': u'Copy of Indkøb',
            u'abstract': u'',
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'illustrators': [],
            })
        self.assert_cors_headers(response)

        # Check that resources are saved
        resource_path = re.search('(/resources/[^"]*)"', content).group(1)
        response = self.testapp.get(resource_path, status=200)
        self.assertEqual(response.content_type, 'image/jpeg')
        self.assert_cors_headers(response)

    def test_post_content_derived_from_w_missing_resource(self):
        post_data = {
            'derivedFrom': u'a3f7c934-2a89-4baf-a9a9-a89d957586d2@1',
            }

        now = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.post_json('/users/contents',
                    post_data, status=201)
        result = response.json
        content = result.pop('content')
        self.assertTrue(u'missing resource' in content)
        self.assertTrue(content.startswith('<html'))
        self.assertFalse('2011-10-12' in result.pop('created'))
        self.assertTrue(result.pop('revised') is not None)
        submitter_w_assign_date = SUBMITTER_WITH_ACCEPTANCE.copy()
        submitter_w_assign_date['assignmentDate'] = now.astimezone(
            TZINFO).isoformat()
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'missing resource',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(
                post_data['derivedFrom']),
            u'title': u'Copy of missing resource',
            u'abstract': u'',
            u'language': u'en',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'illustrators': [],
            })
        self.assert_cors_headers(response)

        response = self.testapp.get('/contents/{}@draft.json'.format(
            result['id']), status=200)
        result = response.json
        content = result.pop('content')
        self.assertTrue(u'missing resource' in content)
        self.assertTrue(content.startswith('<html'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'missing resource',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(
                post_data['derivedFrom']),
            u'title': u'Copy of missing resource',
            u'abstract': u'',
            u'language': u'en',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'illustrators': [],
            })
        self.assert_cors_headers(response)

    def test_post_content_derived_from_binder(self):
        post_data = {
            'derivedFrom': u'a733d0d2-de9b-43f9-8aa9-f0895036899e@1.1',
            }

        now = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.post_json('/users/contents',
                post_data, status=201)
        result = response.json
        self.assertTrue(result.pop('revised') is not None)
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('abstract') is not None)
        submitter_w_assign_date = SUBMITTER_WITH_ACCEPTANCE.copy()
        submitter_w_assign_date[u'assignmentDate'] = unicode(
            now.astimezone(TZINFO).isoformat())
        expected = {
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Derived Copy of College Physics',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(
                post_data['derivedFrom']),
            u'title': u'Copy of Derived Copy of College Physics',
            u'content': u'',
            u'language': u'en',
            u'mediaType': u'application/vnd.org.cnx.collection',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'illustrators': [],
            u'tree': {
                u'id': u'{}@draft'.format(result['id']),
                u'title': u'Copy of Derived Copy of College Physics',
                u'contents': [
                    {u'id': u'209deb1f-1a46-4369-9e0d-18674cf58a3e@7',
                     u'title': u'Preface'},
                    {u'id': u'subcol',
                     u'title': u'Introduction: The Nature of Science and Physics',
                     u'contents': [
                         {u'id': u'f3c9ab70-a916-4d8c-9256-42953287b4e9@3',
                          u'title': u'Introduction to Science and the Realm of Physics, Physical Quantities, and Units'},
                         {u'id': u'd395b566-5fe3-4428-bcb2-19016e3aa3ce@4',
                          u'title': u'Physics: An Introduction'},
                         {u'id': u'c8bdbabc-62b1-4a5f-b291-982ab25756d7@6',
                          u'title': u'Physical Quantities and Units'},
                         {u'id': u'5152cea8-829a-4aaf-bcc5-c58a416ecb66@7',
                          u'title': u'Accuracy, Precision, and Significant Figures'},
                         {u'id': u'5838b105-41cd-4c3d-a957-3ac004a48af3@5',
                          u'title': u'Approximation'}]},
                    {u'id': u'subcol',
                     u'title': u"Further Applications of Newton's Laws: Friction, Drag, and Elasticity",
                     u'contents': [
                         {u'id': u'24a2ed13-22a6-47d6-97a3-c8aa8d54ac6d@2',
                          u'title': u'Introduction: Further Applications of Newton\u2019s Laws'},
                         {u'id': u'ea271306-f7f2-46ac-b2ec-1d80ff186a59@5',
                          u'title': u'Friction'},
                         {u'id': u'26346a42-84b9-48ad-9f6a-62303c16ad41@6',
                          u'title': u'Drag Forces'},
                         {u'id': u'56f1c5c1-4014-450d-a477-2121e276beca@8',
                          u'title': u'Elasticity: Stress and Strain'}]},
                    {u'id': u'f6024d8a-1868-44c7-ab65-45419ef54881@3',
                     u'title': u'Atomic Masses'},
                    {u'id': u'7250386b-14a7-41a2-b8bf-9e9ab872f0dc@2',
                     u'title': u'Selected Radioactive Isotopes'},
                    {u'id': u'c0a76659-c311-405f-9a99-15c71af39325@5',
                     u'title': u'Useful Inf\xf8rmation'},
                    {u'id': u'ae3e18de-638d-4738-b804-dc69cd4db3a3@4',
                     u'title': u'Glossary of Key Symbols and Notation'}]},
            }
        self.assertEqual(result, expected)
        self.assert_cors_headers(response)

        response = self.testapp.get(
                '/contents/{}@draft.json'.format(result['id']), status=200)
        result = response.json
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertTrue(result.pop('abstract') is not None)        
        self.assertEqual(result, expected)
        self.assert_cors_headers(response)

    def test_post_content_revision_403(self):
        self.logout()
        self.login('user2')
        post_data = {
            'id': '91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
            'title': u"Turning DNA through resonance",
            'abstract': u"Theories on turning DNA structures",
            'language': u'en',
            'content': u"Ding dong the switch is flipped.",
            'subjects': [u'Science and Technology'],
            'keywords': [u'DNA', u'resonance'],
            }

        response = self.testapp.post_json('/users/contents',
                post_data, status=403)

    def test_post_content_revision_404(self):
        post_data = {
            'id': 'edf794be-28bc-4242-8ae2-b043e4dd32ef@1',
            'title': u"Turning DNA through resonance",
            'abstract': u"Theories on turning DNA structures",
            'language': u'en',
            'content': u"Ding dong the switch is flipped.",
            'subjects': [u'Science and Technology'],
            'keywords': [u'DNA', u'resonance'],
            }

        response = self.testapp.post_json('/users/contents',
                post_data, status=404)

    def test_post_content_revision(self):
        self.logout()
        self.login('Rasmus1975')
        post_data = {
            'id': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
            'title': u'Turning DNA through resonance',
            'abstract': u'Theories on turning DNA structures',
            'language': u'en',
            'subjects': [u'Science and Technology'],
            'keywords': [u'DNA', u'resonance'],
            }

        now = datetime.datetime.now(TZINFO)
        formatted_now = now.astimezone(TZINFO).isoformat()
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        result = response.json
        license = result.pop('license')
        self.assertEqual(license['url'], DEFAULT_LICENSE.url)
        created = result.pop('created')
        self.assertTrue(created.startswith('2011-10-05'))
        revised = result.pop('revised')
        self.assertEqual(revised, now.astimezone(TZINFO).isoformat())
        content = result.pop('content')
        self.assertTrue(u'Lav en madplan for den kommende uge' in content)

        # FIXME the user info we have in archive differs from
        #       that here in authoring.
        rasmus_user_info = {
            u'email': u'rasmus@example.com',
            u'firstname': u'Rasmus',
            u'fullname': u'Rasmus Ruby',
            u'id': u'Rasmus1975',
            u'surname': u'Ruby',
            u'type': u'cnx-id',
            }
        rasmus_role = rasmus_user_info.copy()
        rasmus_role.update({
            u'assignmentDate': formatted_now,
            u'hasAccepted': True,
            u'requester': rasmus_user_info['id'],
            u'email': u'',
            u'emails': [u'rasmus@example.org'],
            u'suffix': None,
            u'surname': u'',
            u'title': None,
            u'website': None,
            u'fullname': u'Rasmus de 1975',
        })

        self.assertEqual(result, {
            u'abstract': u'Theories on turning DNA structures',
            u'authors': [rasmus_role],
            u'cnx-archive-uri': post_data['id'],
            u'containedIn': [],
            u'copyrightHolders': [rasmus_role],
            u'derivedFrom': None,
            u'derivedFromTitle': None,
            u'derivedFromUri': None,
            u'editors': [],
            u'id': post_data['id'].split('@')[0],
            u'illustrators': [],
            u'keywords': [u'DNA', u'resonance'],
            u'language': u'en',
            u'licensors': [rasmus_role],
            u'mediaType': u'application/vnd.org.cnx.module',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'publishers': [rasmus_role],
            u'state': u'Draft',
            u'subjects': [u'Science and Technology'],
            u'submitter': rasmus_user_info,
            u'title': u'Turning DNA through resonance',
            u'translators': [],
            u'version': u'draft'})
        self.assert_cors_headers(response)

        response = self.testapp.get(
            '/contents/{}@draft.json'.format(result['id']), status=200)
        result = response.json
        content = result.pop('content')
        self.assertTrue(u'Lav en madplan for den kommende uge' in content)
        self.assertTrue(content.startswith('<html'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': rasmus_user_info,
            u'authors': [rasmus_role],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [rasmus_role],
            u'id': result['id'],
            u'derivedFrom': None,
            u'derivedFromTitle': None,
            u'derivedFromUri': None,
            u'title': u'Turning DNA through resonance',
            u'abstract': u'Theories on turning DNA structures',
            u'language': u'en',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0',
                },
            u'subjects': [u'Science and Technology'],
            u'keywords': [u'DNA', u'resonance'],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'cnx-archive-uri': post_data['id'],
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [rasmus_role],
            u'copyrightHolders': [rasmus_role],
            u'illustrators': [],
            })
        self.assert_cors_headers(response)

        # Check that resources are saved
        resource_path = re.search('(/resources/[^"]*)"', content).group(1)
        response = self.testapp.get(resource_path, status=200)
        self.assertEqual(response.content_type, 'image/jpeg')
        self.assert_cors_headers(response)

    def test_post_content(self):
        post_data = {
            'title': u"Turning DNA through resonance",
            'abstract': u"Theories on turning DNA structures",
            'created': u'2014-03-13T15:21:15.677617',
            'revised': u'2014-03-13T15:21:15.677617',
            'license': {'url': DEFAULT_LICENSE.url},
            'language': u'en',
            'content': u"Ding dong the switch is flipped.",
            'subjects': [u'Science and Technology'],
            'keywords': [u'DNA', u'resonance'],
            'editors': [SUBMITTER],
            }

        now = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.post_json('/users/contents',
                post_data, status=201)
        result = response.json
        license = result.pop('license')
        self.assertEqual(license['url'], post_data['license']['url'])
        created = result.pop('created')
        self.assertTrue(created.startswith('2014-03-13T15:21:15.677617'))
        revised = result.pop('revised')
        self.assertTrue(revised.startswith('2014-03-13T15:21:15.677617'))
        submitter_w_assign_date = SUBMITTER_WITH_ACCEPTANCE.copy()
        submitter_w_assign_date['assignmentDate'] = now.astimezone(
            TZINFO).isoformat()
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'id': result['id'],
            u'derivedFrom': None,
            u'derivedFromTitle': None,
            u'derivedFromUri': None,
            u'title': post_data['title'],
            u'abstract': post_data['abstract'],
            u'language': post_data['language'],
            u'containedIn': [],
            u'content': post_data['content'],
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'subjects': post_data['subjects'],
            u'keywords': post_data['keywords'],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'editors': [submitter_w_assign_date],
            u'translators': [],
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'illustrators': [],
            })
        self.assert_cors_headers(response)

    def test_post_content_binder(self):
        now = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.post_json('/users/contents',
                {'title': 'Page one'}, status=201)
        page1 = response.json
        self.assert_cors_headers(response)

        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.post_json('/users/contents',
                {'title': 'Page two'}, status=201)
        page2 = response.json
        self.assert_cors_headers(response)

        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.post_json('/users/contents', {
                    'title': 'Book',
                    'abstract': 'Book abstract',
                    'language': 'de',
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'tree': {
                        'contents': [
                            {
                                'id': '{}@draft'.format(page1['id']),
                                'title': 'Page one',
                                },
                            {
                                'id': 'subcol',
                                'title': 'New section',
                                'contents': [
                                    {
                                        'id': '{}@draft'.format(page2['id']),
                                        'title': 'Page two',
                                        },
                                    ],
                                },
                            ],
                        },
                    }, status=201)
        book = response.json
        self.assert_cors_headers(response)

        response = self.testapp.get(
                '/contents/{}@draft.json'.format(book['id']), status=200)
        result = response.json
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        submitter_w_assign_date = SUBMITTER_WITH_ACCEPTANCE.copy()
        submitter_w_assign_date['assignmentDate'] = now.astimezone(
            TZINFO).isoformat()
        self.assertEqual(result, {
            u'id': book['id'],
            u'title': u'Book',
            u'abstract': u'Book abstract',
            u'containedIn': [],
            u'content': u'',
            u'mediaType': u'application/vnd.org.cnx.collection',
            u'derivedFrom': None,
            u'derivedFromTitle': None,
            u'derivedFromUri': None,
            u'language': u'de',
            u'version': u'draft',
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'tree': {
                u'id': u'{}@draft'.format(book['id']),
                u'title': u'Book',
                u'contents': [
                    {
                        u'id': u'{}@draft'.format(page1['id']),
                        u'title': u'Page one',
                        },
                    {
                        u'id': u'subcol',
                        u'title': u'New section',
                        u'contents': [
                            {
                                u'id': u'{}@draft'.format(page2['id']),
                                u'title': u'Page two',
                                },
                            ],
                        },
                    ],
                },
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'editors': [],
            u'translators': [],
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'illustrators': [],
            })
        self.assert_cors_headers(response)

    def test_put_content_401(self):
        self.logout()
        response = self.testapp.put_json(
                '/contents/1234abcde@draft.json', {}, status=401)
        self.assert_cors_headers(response)

    def test_put_content_not_found(self):
        response = self.testapp.put_json('/contents/1234abcde@draft.json',
                {'title': u'Update document title'}, status=404)
        self.assert_cors_headers(response)

    def test_put_content_403(self):
        response = self.testapp.post_json('/users/contents', {
                    'title': u'My document タイトル',
                    'abstract': u'My document abstract',
                    'language': u'en'}, status=201)
        document = response.json

        with mock.patch('cnxauthoring.models.Document.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.put_json(
                '/contents/{}@draft.json'.format(document['id']),
                {'title': 'new title'}, status=403)
        self.assertTrue('You do not have permission to edit'
                in response.body.decode('utf-8'))

        response = self.testapp.post_json('/users/contents', {
                    'title': u'My binder タイトル',
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'tree': {
                        'contents': [],
                        },
                    'language': u'en'}, status=201)
        binder = response.json

        with mock.patch('cnxauthoring.models.Binder.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.put_json(
                '/contents/{}@draft.json'.format(binder['id']),
                {'title': 'new title'}, status=403)
        self.assertTrue('You do not have permission to edit'
                in response.body.decode('utf-8'))

    def test_put_content_invalid_json(self):
        response = self.testapp.post_json('/users/contents', {
                    'title': u'My document タイトル',
                    'abstract': u'My document abstract',
                    'language': u'en'}, status=201)
        document = response.json
        self.assert_cors_headers(response)

        response = self.testapp.put(
                '/contents/{}@draft.json'.format(document['id']),
                'invalid json', content_type='application/json', status=400)
        self.assertTrue('Invalid JSON' in response.body.decode('utf-8'))
        self.assert_cors_headers(response)

    def test_put_content_derived_from(self):
        post_data = {
            'derivedFrom': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
            }

        response = self.testapp.post_json(
            '/users/contents', post_data, status=201)
        page = response.json
        self.assert_cors_headers(response)

        post_data = {
            'content': '<html><body><p>Page content</p></body></html>',
            }
        now = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.put_json(
                '/contents/{}@draft.json'.format(page['id']),
                post_data, status=200)
        result = response.json
        self.assertEqual(result['content'], post_data['content'])
        self.assertEqual(result['revised'], now.astimezone(TZINFO).isoformat())
        self.assert_cors_headers(response)

    def test_put_content_binder_document_not_found(self):
        response = self.testapp.post_json('/users/contents', {
                    'title': u'My book タイトル',
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'tree': {
                        'contents': [],
                        },
                    }, status=201)
        self.assert_cors_headers(response)
        binder = response.json
        update_data = {
                'title': u'...',
                'tree': {
                    'contents': [{
                        u'id': u'7d089006-5a95-4e24-8e04-8168b5c41aa3@draft',
                        u'title': u'Hygiene',
                        }],
                    },
                }
        response = self.testapp.put_json(
                '/contents/{}@draft.json'.format(binder['id']),
                update_data, status=400)
        self.assertTrue(
            'Document Not Found: 7d089006-5a95-4e24-8e04-8168b5c41aa3@draft'
            in response.body.decode('utf-8'))

    def test_put_content_binder(self):
        # Create a derived binder
        post_data = {
            'derivedFrom': u'a733d0d2-de9b-43f9-8aa9-f0895036899e@1.1',
            }
        created = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = created
            response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        binder = response.json
        self.assert_cors_headers(response)

        update_data = {
            'title': u'...',
            'abstract': u'...',
            'tree': {
                'contents': [{
                    u'id': u'7d089006-5a95-4e24-8e04-8168b5c41aa3@1',
                    u'title': u'Hygiene',
                    }],
                },
            }

        revised = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = revised
            response = self.testapp.put_json(
                '/contents/{}@draft.json'.format(binder['id']),
                update_data, status=200)
        binder = response.json
        submitter_w_assign_date = SUBMITTER_WITH_ACCEPTANCE.copy()
        submitter_w_assign_date[u'assignmentDate'] = unicode(
            created.astimezone(TZINFO).isoformat())
        self.assertEqual(binder, {
            u'created': unicode(created.astimezone(TZINFO).isoformat()),
            u'revised': unicode(revised.astimezone(TZINFO).isoformat()),
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'id': binder['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Derived Copy of College Physics',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(
                post_data['derivedFrom']),
            u'abstract': u'...',
            u'containedIn': [],
            u'content': u'',
            u'language': u'en',
            u'mediaType': u'application/vnd.org.cnx.collection',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'title': u'...',
            u'tree': {
                u'id': u'{}@draft'.format(binder['id']),
                u'title': u'...',
                u'contents': [{
                    u'id': u'7d089006-5a95-4e24-8e04-8168b5c41aa3@1',
                    u'title': u'Hygiene',
                    }],
                },
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'editors': [],
            u'translators': [],
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'illustrators': [],
            })
        self.assert_cors_headers(response)

        response = self.testapp.get(
            '/contents/{}@draft.json'.format(binder['id']), status=200)
        binder = response.json
        self.assertEqual(binder, {
            u'created': created.astimezone(TZINFO).isoformat(),
            u'revised': revised.astimezone(TZINFO).isoformat(),
            u'submitter': SUBMITTER,
            u'authors': [submitter_w_assign_date],
            u'permissions': [u'edit', u'publish', u'view'],
            u'publishers': [submitter_w_assign_date],
            u'id': binder['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Derived Copy of College Physics',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(
                post_data['derivedFrom']),
            u'abstract': u'...',
            u'containedIn': [],
            u'content': u'',
            u'language': u'en',
            u'mediaType': u'application/vnd.org.cnx.collection',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'title': u'...',
            u'tree': {
                u'id': u'{}@draft'.format(binder['id']),
                u'title': u'...',
                u'contents': [{
                    u'id': u'7d089006-5a95-4e24-8e04-8168b5c41aa3@1',
                    u'title': u'Hygiene',
                    }],
                },
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'permissions': [u'edit', u'publish', u'view'],
            u'publication': None,
            u'editors': [],
            u'translators': [],
            u'licensors': [submitter_w_assign_date],
            u'copyrightHolders': [submitter_w_assign_date],
            u'illustrators': [],
            })
        self.assert_cors_headers(response)

    def test_put_content_binder2(self):
        response = self.testapp.post_json('/users/contents', {
            'title': 'Empty book',
            'mediaType': 'application/vnd.org.cnx.collection',
            'tree': {
                'contents': [],
                },
            }, status=201)
        binder = response.json
        created = binder['created']

        response = self.testapp.post_json(
            '/users/contents', {'title': 'Empty page'}, status=201)
        page = response.json

        revised = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = revised
            response = self.testapp.put_json(
                '/contents/{}@draft.json'.format(binder['id']), {
                    'id': '{}@draft'.format(binder['id']),
                    'downloads': [],
                    'isLatest': True,
                    'derivedFrom': None,
                    'abstract': '',
                    'revised': '2014-05-02T12:42:09.490860-04:00',
                    'keywords': [],
                    'subjects': [],
                    'publication': None,
                    'license': {
                        'url': 'http://creativecommons.org/licenses/by/4.0/',
                        'version': '4.0',
                        'name': 'Attribution',
                        'abbr': 'by'
                        },
                    'language': 'en',
                    'title': 'etst book',
                    'created': '2014-05-02T12:42:09.490738-04:00',
                    'tree': {
                        'id': '{}@draft'.format(binder['id']),
                        'title': 'etst book',
                        'contents': [
                            {'id': 'f309a0f9-63fb-46ca-9585-d1e1dc96a142@3',
                             'title':
                                'Introduction to Two-Dimensional Kinematics'},
                            {'id': 'e12329e4-8d6c-49cf-aa45-6a05b26ebcba@2',
                             'title':
                                'Introduction to One-Dimensional Kinematics'},
                            {'id': '{}@draft'.format(page['id']),
                             'title': 'test page'}
                            ]
                        },
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'content': '',
                    'state': 'Draft',
                    'version': 'draft',
                    'submitter': SUBMITTER,
                    'authors': [SUBMITTER_WITH_ACCEPTANCE],
                    'publishers': [SUBMITTER_WITH_ACCEPTANCE],
                    'error': False,
                    }, status=200)

        response = self.testapp.get(
            '/contents/{}@draft.json'.format(binder['id']), status=200)
        result = response.json
        self.assertEqual(result['created'], created)
        self.assertEqual(
            result['revised'], revised.astimezone(TZINFO).isoformat())
        self.assertEqual(result['tree'], {
            'id': '{}@draft'.format(binder['id']),
            'title': 'etst book',
            'contents': [
                {
                    'id': 'f309a0f9-63fb-46ca-9585-d1e1dc96a142@3',
                    'title': 'Introduction to Two-Dimensional Kinematics'
                    },
                {
                    'id': 'e12329e4-8d6c-49cf-aa45-6a05b26ebcba@2',
                    'title': 'Introduction to One-Dimensional Kinematics'
                    },
                {
                    'id': '{}@draft'.format(page['id']),
                    'title': 'test page'
                    }
                ]
            })

    def test_put_content(self):
        created = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = created
            response = self.testapp.post_json('/users/contents', {
                'title': u'My document タイトル',
                'abstract': u'My document abstract',
                'language': u'en'}, status=201)
        document = response.json
        self.assert_cors_headers(response)

        update_data = {
            'title': u"Turning DNA through resonance",
            'abstract': u"Theories on turning DNA structures",
            'content': u"Ding dong the switch is flipped.",
            'keywords': ['DNA', 'resonance'],
            'subjects': ['Science and Technology'],
            }

        revised = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = revised
            response = self.testapp.put_json(
                '/contents/{}@draft.json'.format(document['id']),
                update_data, status=200)
        result = response.json
        self.assertEqual(result['id'], document['id'])
        self.assertEqual(result['title'], update_data['title'])
        self.assertEqual(result['abstract'], update_data['abstract'])
        self.assertEqual(result['language'], document['language'])
        self.assertEqual(result['content'], update_data['content'])
        self.assertEqual(result['keywords'], update_data['keywords'])
        self.assertEqual(result['subjects'], update_data['subjects'])
        self.assertEqual(result['created'],
                         created.astimezone(TZINFO).isoformat())
        self.assertEqual(result['revised'],
                         revised.astimezone(TZINFO).isoformat())

        response = self.testapp.get(
            '/contents/{}@draft.json'.format(document['id']))
        result = response.json
        self.assertEqual(result['id'], document['id'])
        self.assertEqual(result['title'], update_data['title'])
        self.assertEqual(result['abstract'], update_data['abstract'])
        self.assertEqual(result['language'], document['language'])
        self.assertEqual(result['content'], update_data['content'])
        self.assertEqual(result['keywords'], update_data['keywords'])
        self.assertEqual(result['subjects'], update_data['subjects'])
        self.assertEqual(result['created'],
                         created.astimezone(TZINFO).isoformat())
        self.assertEqual(result['revised'],
                         revised.astimezone(TZINFO).isoformat())
        self.assert_cors_headers(response)

    def test_delete_content_401(self):
        self.logout()
        response = self.testapp.delete('/contents/{}@draft'.format(id),
                                       status=401)
        self.assert_cors_headers(response)

    def test_delete_content_403(self):
        response = self.testapp.post_json(
            '/users/contents', {'title': 'My page'}, status=201)
        page = response.json
        self.assert_cors_headers(response)

        self.logout()
        self.login('you')
        response = self.testapp.delete(
            '/contents/{}@draft'.format(page['id']), status=403)
        self.assert_cors_headers(response)

    def test_delete_content(self):
        response = self.testapp.post_json(
            '/users/contents', {'title': 'My page'}, status=201)
        page = response.json
        self.assert_cors_headers(response)

        # test that it's possible to get the content we just created
        response = self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']), status=200)

        # delete the content
        response = self.testapp.delete(
            '/contents/{}@draft'.format(page['id']), status=200)
        self.assert_cors_headers(response)

        response = self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']), status=404)

    def test_delete_content_multiple(self):
        # create two pages
        response = self.testapp.post_json('/users/contents', {
            'title': 'Page one',
            'editors': [{'id': 'user2'}]}, status=201)
        page_one = response.json

        response = self.testapp.post_json('/users/contents', {
            'title': 'Page two'}, status=201)
        page_two = response.json

        # create a book, put the two pages inside the book, plus
        # one page from archive
        response = self.testapp.post_json('/users/contents', {
            'title': 'My book',
            'mediaType': 'application/vnd.org.cnx.collection',
            'tree': {
                'contents': [
                    {'id': '{}@draft'.format(page_one['id']),
                     'title': 'Page one'},
                    {'id': '{}@draft'.format(page_two['id']),
                     'title': 'Page two'},
                    {'id': '91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
                     'title': 'Page three'}],
                },
            }, status=201)
        book = response.json

        # login as user2
        self.logout()
        self.login('user2')

        # create another book, put only page one in it
        response = self.testapp.post_json('/users/contents', {
            'title': "User2's book",
            'mediaType': 'application/vnd.org.cnx.collection',
            'tree': {
                'contents': [
                    {'id': '{}@draft'.format(page_one['id']),
                     'title': 'Page one'}],
                },
            }, status=201)

        # log back in as user1
        self.logout()
        self.login('user1')

        # delete the book and all the pages inside it
        response = self.testapp.put_json('/contents/delete', [
            book['id'], page_one['id'], page_two['id'],
            '91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
            ], status=200)
        # only the book and page_two should be deleted
        deleted = response.json
        self.assertEqual(deleted, [book['id'], page_two['id']])

        self.testapp.get('/contents/{}@draft.json'.format(book['id']),
                         status=404)
        self.testapp.get('/contents/{}@draft.json'.format(page_one['id']),
                         status=200)
        self.testapp.get('/contents/{}@draft.json'.format(page_two['id']),
                         status=404)

    def test_delete_content_binder(self):
        # Create a page first
        response = self.testapp.post_json('/users/contents', {
            'title': 'My page',
            }, status=201)
        page = response.json
        self.assert_cors_headers(response)

        # Create a book with the page inside
        response = self.testapp.post_json('/users/contents', {
            'title': 'My book',
            'mediaType': 'application/vnd.org.cnx.collection',
            'tree': {
                'contents': [
                    {
                        'id': '{}@draft'.format(page['id']),
                        'title': 'My page',
                        },
                    ],
                },
            }, status=201)
        book_one = response.json
        self.assert_cors_headers(response)

        # Create another book with the same page inside
        response = self.testapp.post_json('/users/contents', {
            'title': 'My different book',
            'mediaType': 'application/vnd.org.cnx.collection',
            'tree': {
                'contents': [
                    {
                        'id': '{}@draft'.format(page['id']),
                        'title': 'My page',
                        },
                    ],
                },
            }, status=201)
        book_two = response.json
        self.assert_cors_headers(response)

        # Assert that the page is contained in two books
        response = self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']))
        result = response.json
        self.assertEqual(sorted(result['containedIn']),
                         sorted([book_one['id'], book_two['id']]))

        # Delete book one
        self.testapp.delete('/contents/{}@draft'.format(book_one['id']),
                            status=200)
        self.testapp.get('/contents/{}@draft.json'.format(book_one['id']),
                         status=404)

        # Assert that the page is now only contained in book two
        response = self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']))
        result = response.json
        self.assertEqual(result['containedIn'], [book_two['id']])

    def test_delete_content_multiple_users(self):
        response = self.testapp.post_json('/users/contents', {
            'title': 'Multiple users test',
            'editors': [{'id': 'you'}],
            }, status=201)
        page = response.json
        self.assert_cors_headers(response)

        self.testapp.get('/contents/{}@draft.json'.format(page['id']),
                         status=200)

        self.logout()
        self.login('you')

        # editor should get the content in their workspace
        response = self.testapp.get('/users/contents', status=200)
        workspace = response.json
        items = [i['id'] for i in workspace['results']['items']]
        self.assertIn('{}@draft'.format(page['id']), items)
        # make sure the editor can also view the content
        self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']), status=200)

        # make sure the editor can also edit the content after accepting their
        # role
        self.testapp.post_json(
            '/contents/{}@draft/acceptance'.format(page['id']),
            {'license': True,
             'roles': [{'role': 'editors', 'hasAccepted': True}]},
            status=200)
        response = self.testapp.put_json(
            '/contents/{}@draft.json'.format(page['id']),
            {'title': 'Multiple users test edited by you'}, status=200)

        self.logout()
        self.login('user2')

        # someone not in acl should not be able to view the content
        self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']), status=403)
        self.logout()

        # log back in as the submitter and check that the title has been
        # changed
        self.login('user1')
        response = self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']), status=200)
        self.assertEqual(response.json['title'],
                         'Multiple users test edited by you')
        response = self.testapp.get('/users/contents', status=200)
        workspace = response.json
        items = [i['id'] for i in workspace['results']['items']]
        self.assertIn('{}@draft'.format(page['id']), items)

        # try to delete the content should return an error
        self.testapp.delete('/contents/{}@draft'.format(page['id']),
                            status=403)
        self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']), status=200)

        # delete user1 from the content
        self.testapp.delete(
            '/contents/{}@draft/users/me'.format(page['id']), status=200)
        # content should not appear in user1's workspace
        response = self.testapp.get('/users/contents', status=200)
        workspace = response.json
        items = [i['id'] for i in workspace['results']['items']]
        self.assertNotIn('{}@draft'.format(page['id']), items)
        self.logout()

        # content should still be accessible by "you"
        self.login('you')
        response = self.testapp.get('/users/contents', status=200)
        workspace = response.json
        items = [i['id'] for i in workspace['results']['items']]
        self.assertIn('{}@draft'.format(page['id']), items)
        self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']), status=200)
        response = self.testapp.put_json(
            '/contents/{}@draft.json'.format(page['id']),
            {'title': 'Multiple users test edited again by you'}, status=200)
        self.logout()

        # content should not appear in user1's workspace
        self.login('user1')
        response = self.testapp.get('/users/contents', status=200)
        workspace = response.json
        items = [i['id'] for i in workspace['results']['items']]
        self.assertNotIn('{}@draft'.format(page['id']), items)

        # re-add user1 to the document
        post_data = {
            'id': '{}@draft'.format(page['id']),
            }
        response = self.testapp.post_json(
            '/users/contents', post_data, status=201)
        response = self.testapp.get('/users/contents', status=200)
        workspace = response.json
        items = [i['id'] for i in workspace['results']['items']]
        self.assertIn('{}@draft'.format(page['id']), items)

    def test_search_content_401(self):
        self.logout()
        response = self.testapp.get('/search', status=401)
        self.assert_cors_headers(response)

    def test_search_content_no_q(self):
        response = self.testapp.get('/search', status=200)
        result = response.json
        self.assertEqual(result, {
            'query': {'limits': []},
            'results': {
                'items': [],
                'total': 0,
                'limits': [],
                }
            })
        self.assert_cors_headers(response)

    def test_search_content_q_empty(self):
        response = self.testapp.get('/search?q=', status=200)
        result = response.json
        self.assertEqual(result, {
            'query': {'limits': []},
            'results': {
                'items': [],
                'total': 0,
                'limits': [],
                }
            })
        self.assert_cors_headers(response)

    def test_search_unbalanced_quotes(self):
        self.logout()
        self.login('user2')
        post_data = {'title': u'Document'}
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        self.assert_cors_headers(response)

        response = self.testapp.get('/search?q="Document', status=200)
        result = response.json
        self.assertEqual(result['query']['limits'],
                [{'tag': 'text', 'value': 'Document'}])
        self.assertEqual(result['results']['total'], 1)
        self.assert_cors_headers(response)

    def test_search_content(self):
        post_data = {'title': u"Document"}
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)

        self.logout()
        self.login('user2')
        post_data = {
            'title': u"Turning DNA through resonance",
            'abstract': u"Theories on turning DNA structures",
            'created': u'2014-03-13T15:21:15.677617',
            'revised': u'2014-03-13T15:21:15.677617',
            'license': {'url': DEFAULT_LICENSE.url},
            'language': u'en',
            'contents': u"Ding dong the switch is flipped.",
            }
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        result = response.json
        doc_id = result['id']
        self.assert_cors_headers(response)

        post_data = {'title': u'New stuff'}
        response = self.testapp.post_json(
            '/users/contents', post_data, status=201)
        result = response.json
        new_doc_id = result['id']
        self.assert_cors_headers(response)

        # should not be able to get other user's documents
        response = self.testapp.get('/search?q=document', status=200)
        result = response.json
        self.assertDictEqual(result, {
            'query': {
                'limits': [{'tag': 'text', 'value': 'document'}]},
            'results': {
                'items': [],
                'total': 0,
                'limits': []}})
        self.assert_cors_headers(response)

        # should be able to search user's own documents
        response = self.testapp.get('/search?q=DNA', status=200)
        result = response.json
        self.assertEqual(result['results']['total'], 1)
        self.assertEqual(result['results']['items'][0]['id'],
                '{}@draft'.format(doc_id))
        self.assert_cors_headers(response)

        # should be able to search multiple terms
        response = self.testapp.get('/search?q=new+resonance', status=200)
        result = response.json
        self.assertEqual(result['query']['limits'], [
            {'tag': 'text', 'value': 'new'},
            {'tag': 'text', 'value': 'resonance'}])
        self.assertEqual(result['results']['total'], 2)
        self.assertEqual(sorted([i['id'] for i in result['results']['items']]),
                sorted(['{}@draft'.format(doc_id),
                    '{}@draft'.format(new_doc_id)]))
        self.assert_cors_headers(response)

        # should be able to search with double quotes
        response = self.testapp.get('/search?q="through resonance"',
                status=200)
        result = response.json
        self.assertEqual(result['query']['limits'], [
            {'tag': 'text', 'value': 'through resonance'}])
        self.assertEqual(result['results']['total'], 1)
        self.assertEqual(result['results']['items'][0]['id'],
                '{}@draft'.format(doc_id))

        self.assert_cors_headers(response)

    def test_get_resource_401(self):
        self.logout()
        response = self.testapp.get('/resources/1234abcde', status=401)
        self.assert_cors_headers(response)

    def test_get_resource_403(self):
        with open(test_data('1x1.png'), 'rb') as data:
            upload_data = data.read()

        response = self.testapp.post('/resources',
                {'file': Upload('1x1.png', upload_data, 'image/png')},
                status=201)
        self.assert_cors_headers(response)
        redirect_url = response.headers['Location']

        with mock.patch('cnxauthoring.models.Resource.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.get(redirect_url, status=403)
        self.assert_cors_headers(response)

    def test_get_resource_404(self):
        response = self.testapp.get('/resources/1234abcde', status=404)
        self.assert_cors_headers(response)

    def test_get_resource_html(self):
        """Test that a html resource file will get downloaded as a binary file
        to avoid people using it to steal cookies etc

        See https://github.com/Connexions/cnx-authoring/issues/64
        """
        upload_data = b'<html><body><h1>title</h1></body></html>'
        response = self.testapp.post('/resources', {
            'file': Upload('a.html', upload_data,
                'text/html')}, status=201)
        redirect_url = response.headers['Location']
        self.assert_cors_headers(response)

        response = self.testapp.get(redirect_url, status=200)
        self.assertEqual(response.body, upload_data)
        self.assertEqual(response.content_type, 'application/octet-stream')
        self.assert_cors_headers(response)

    def test_get_resource(self):
        with open(test_data('1x1.png'), 'rb') as data:
            upload_data = data.read()

        response = self.testapp.post('/resources',
                {'file': Upload('1x1.png', upload_data, 'image/png')},
                status=201)
        redirect_url = response.headers['Location']
        response = self.testapp.get(redirect_url, status=200)
        self.assertEqual(response.body, upload_data)
        self.assertEqual(response.content_type, 'image/png')
        self.assert_cors_headers(response)

        # any logged in user can retrieve any resource files
        self.logout()
        self.login('user3')
        response = self.testapp.get(redirect_url, status=200)
        self.assertEqual(response.body, upload_data)
        self.assertEqual(response.content_type, 'image/png')
        self.assert_cors_headers(response)

    def test_post_resource_401(self):
        self.logout()
        response = self.testapp.post('/resources',
                {'file': Upload('a.txt', b'hello\n', 'text/plain')},
                status=401)
        self.assert_cors_headers(response)

    def test_post_resource_403(self):
        with mock.patch('cnxauthoring.models.Resource.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.post('/resources',
                {'file': Upload('a.txt', b'hello\n', 'text/plain')},
                status=403)
        self.assert_cors_headers(response)

    def test_post_resource(self):
        response = self.testapp.post('/resources',
                {'file': Upload('a.txt', b'hello\n', 'text/plain')},
                status=201)
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.headers['Location'],
                'http://localhost/resources/'
                'f572d396fae9206628714fb2ce00f72e94f2258f')
        self.assertEqual(response.body,
                b'/resources/'
                b'f572d396fae9206628714fb2ce00f72e94f2258f')
        self.assert_cors_headers(response)

    def test_post_duplicate_resource(self):
        response = self.testapp.post('/resources',
                {'file': Upload('a.txt', b'hello\n', 'text/plain')},
                status=201)
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.headers['Location'],
                'http://localhost/resources/'
                'f572d396fae9206628714fb2ce00f72e94f2258f')
        self.assertEqual(response.body,
                b'/resources/'
                b'f572d396fae9206628714fb2ce00f72e94f2258f')
        response = self.testapp.post('/resources',
                {'file': Upload('a.txt', b'hello\n', 'text/plain')},
                status=201)
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.headers['Location'],
                'http://localhost/resources/'
                'f572d396fae9206628714fb2ce00f72e94f2258f')
        self.assertEqual(response.body,
                b'/resources/'
                b'f572d396fae9206628714fb2ce00f72e94f2258f')
        self.assert_cors_headers(response)

    def test_post_resource_exceed_size_limit(self):
        two_mb = b'x' * 2 * 1024 * 1024
        response = self.testapp.post('/resources',
                # a 2MB file, size limit for tests is 1MB
                {'file': Upload('a.txt', two_mb, 'text/plain')},
                status=400)
        self.assertIn(b'File uploaded has exceeded limit 1MB', response.body)

    def test_user_search_no_q(self):
        response = self.testapp.get('/users/search')
        result = response.json
        self.assertEqual(result, {
            u'num_matching_users': 0,
            u'per_page': 10,
            u'users': [],
            u'order_by': u'username ASC',
            u'page': 0,
            })
        self.assert_cors_headers(response)

    def test_user_search_q_empty(self):
        response = self.testapp.get('/users/search?q=')
        result = response.json
        self.assertEqual(result, {
            u'num_matching_users': 0,
            u'per_page': 10,
            u'users': [],
            u'order_by': u'username ASC',
            u'page': 0,
            })
        self.assert_cors_headers(response)

    def test_user_search(self):
        mock_accounts_search_results = {
                u'application_users': [
                    {
                        u'unread_updates': 1,
                        u'application_id': 9,
                        u'id': 14,
                        u'user': {u'username': u'admin', u'id': 1}},
                    {
                        u'unread_updates': 1,
                        u'application_id': 9,
                        u'id': 15,
                        u'user': {u'username': u'karenc', u'id': 6}},
                    {
                        u'unread_updates': 1,
                        u'application_id': 9,
                        u'id': 13,
                        u'user': {u'username': u'karenchan', u'id': 4}},
                    {
                        u'unread_updates': 1,
                        u'application_id': 9,
                        u'id': 12,
                        u'user': {
                            u'username': u'karenchan2014',
                            u'first_name': u'Karen', u'last_name': u'Chan',
                            u'id': 10, u'full_name': u'Karen Chan'}},
                    {
                        u'unread_updates': 1,
                        u'application_id': 9,
                        u'id': 11,
                        u'user': {u'username': u'user_30187', u'id': 9}}
                    ],
                u'order_by': u'username ASC',
                u'users': [
                    {u'username': u'admin', u'id': 1},
                    {u'username': u'karenc', u'id': 6},
                    {u'username': u'karenchan', u'id': 4},
                    {u'username': u'karenchan2014',
                        u'first_name': u'Karen',
                        u'last_name': u'Chan',
                        u'id': 10,
                        u'full_name': u'Karen Chan'},
                    {u'username': u'user_30187', u'id': 9}
                    ],
                u'num_matching_users': 5,
                u'per_page': 10,
                u'page': 0}
        with mock.patch('openstax_accounts.stub.OpenstaxAccounts.search'
                        ) as accounts_search:
            accounts_search.return_value = mock_accounts_search_results
            response = self.testapp.get('/users/search?q=admin')
            args, kwargs = accounts_search.call_args
            self.assertEqual(args, ('admin',))
            self.assertEqual(kwargs, {
                'per_page': 10, 'order_by': 'last_name,first_name'})
        result = response.json
        self.assertEqual(result, {
            u'users': [
                {
                    u'id': u'admin',
                    u'email': u'',
                    u'firstname': u'',
                    u'surname': u'',
                    u'fullname': u'',
                    },
                {
                    u'id': u'karenc',
                    u'email': u'',
                    u'firstname': u'',
                    u'surname': u'',
                    u'fullname': u'',
                    },
                {
                    u'id': u'karenchan',
                    u'email': u'',
                    u'firstname': u'',
                    u'surname': u'',
                    u'fullname': u'',
                    },
                {
                    u'id': u'karenchan2014',
                    u'email': u'',
                    u'firstname': u'Karen',
                    u'surname': u'Chan',
                    u'fullname': u'Karen Chan',
                    },
                {
                    u'id': u'user_30187',
                    u'email': u'',
                    u'firstname': u'',
                    u'surname': u'',
                    u'fullname': u'',
                    },
                ],
            u'order_by': u'username ASC',
            u'num_matching_users': 5,
            u'per_page': 10,
            u'page': 0,
            })
        self.assert_cors_headers(response)

    def test_profile_401(self):
        self.logout()
        response = self.testapp.get('/users/profile', status=401)
        self.assert_cors_headers(response)

    def test_profile(self):
        response = self.testapp.get('/users/profile', status=200)
        result = response.json
        self.assertEqual(result, SUBMITTER)
        self.assert_cors_headers(response)

    def test_user_contents_401(self):
        self.logout()
        response = self.testapp.get('/users/contents', status=401)
        self.assert_cors_headers(response)

    def test_user_contents(self):
        # user1 adds a document
        response = self.testapp.post_json(
            '/users/contents',
            {'title': 'document by default user',
             'editors': [{"id": "user2"}],
             }, status=201)
        page = response.json

        # user1 adds user3 as an author, editor, licensor and publisher
        # and adds user4 as a translator
        response = self.testapp.put_json(
            '/contents/{}@draft.json'.format(page['id']),
            {'authors': page['authors'] + [{'id': 'user3'}],
             'editors': page['editors'] + [{'id': 'user3'}],
             'translators': [{'id': 'user4'}],
             'licensors': page['licensors'] + [{'id': 'user3'}],
             'publishers': page['publishers'] + [{'id': 'user3'}]},
            status=200)
        page = response.json

        # user1 removes user4 as a translator
        response = self.testapp.put_json(
            '/contents/{}@draft.json'.format(page['id']),
            {'translators': []}, status=200)
        page = json.loads(response.body.decode('utf-8'))

        # the document should show up in user1's workspace
        response = self.testapp.get('/users/contents', status=200)
        result = response.json
        content_ids = [(i['id'], i['rolesToAccept'])
            for i in result['results']['items']]
        self.assertIn(('{}@draft'.format(page['id']), []), content_ids)

        # user2 should be able to see the document user1 added
        self.logout()
        self.login('user2')
        response = self.testapp.get('/users/contents', status=200)
        result = response.json
        content_ids = [(i['id'], i['rolesToAccept'], i['state'])
                       for i in result['results']['items']]
        self.assertIn(
            ('{}@draft'.format(page['id']), ['editors'], 'Awaiting acceptance'
             ), content_ids)
        self.assert_cors_headers(response)

        self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']), status=200)

        # user2 rejects the role request
        self.testapp.post_json(
            '/contents/{}@draft/acceptance'.format(page['id']),
            {'license': True,
             'roles': [{'role': 'editors', 'hasAccepted': False}]},
            status=200)

        # user2 should see the document with state "Rejecting roles" on their
        # workspace
        response = self.testapp.get('/users/contents', status=200)
        result = json.loads(response.body.decode('utf-8'))
        content_ids = [(i['id'], i['rolesToAccept'], i['state'])
                       for i in result['results']['items']]
        self.assertIn(
            ('{}@draft'.format(page['id']), [], 'Rejected roles'), content_ids)
        self.assert_cors_headers(response)

        # after user2 deletes the document from the workspace, they won't see
        # it anymore
        self.testapp.delete('/contents/{}@draft/users/me'.format(page['id']))
        response = self.testapp.get('/users/contents', status=200)
        result = response.json
        content_ids = [i['id'] for i in result['results']['items']]
        self.assertNotIn('{}@draft'.format(page['id']), content_ids)
        self.assert_cors_headers(response)

        # user3 should be able to see the document user1 added
        self.logout()
        self.login('user3')
        response = self.testapp.get('/users/contents', status=200)
        result = response.json
        content_ids = [(i['id'], i['rolesToAccept'])
            for i in result['results']['items']]
        self.assertIn(('{}@draft'.format(page['id']),
                       ['authors', 'copyright_holders', 'editors',
                        'publishers']), content_ids)
        self.assert_cors_headers(response)

        self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']), status=200)

        # user3 should not be able to edit the document before accepting their
        # role
        self.testapp.put_json(
            '/contents/{}@draft.json'.format(page['id']), {}, status=403)

        # user3 rejects the editor role
        self.testapp.post_json(
            '/contents/{}@draft/acceptance'.format(page['id']),
            {'license': True,
             'roles': [{'role': 'editors', 'hasAccepted': False}]},
            status=200)

        # user3 should still be able to view the content
        response = self.testapp.get('/users/contents', status=200)
        result = response.json
        content_ids = [(i['id'], i['rolesToAccept'])
            for i in result['results']['items']]
        self.assertIn(('{}@draft'.format(page['id']),
                       ['authors', 'copyright_holders', 'publishers']),
                      content_ids)
        self.assert_cors_headers(response)

        self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']), status=200)

        # user3 accepts their other roles
        self.testapp.post_json(
            '/contents/{}@draft/acceptance'.format(page['id']),
            {'license': True,
             'roles': [{'role': 'authors', 'hasAccepted': True},
                       {'role': 'publishers', 'hasAccepted': True},
                       {'role': 'licensors', 'hasAccepted': True}]},
            status=200)

        # user3 should be able to edit the document after accepting their
        # role
        self.testapp.put_json(
            '/contents/{}@draft.json'.format(page['id']), {}, status=200)

        # user4 should not be able to see the document user1 added
        self.logout()
        self.login('user4')
        response = self.testapp.get('/users/contents', status=200)
        result = response.json
        content_ids = [i['id'] for i in result['results']['items']]
        self.assertNotIn('{}@draft'.format(page['id']), content_ids)
        self.assert_cors_headers(response)

        # user1 adds user2 as an illustrator
        self.logout()
        self.login('user1')
        response = self.testapp.put_json(
            '/contents/{}@draft.json'.format(page['id']),
            {'illustrators': [{'id': 'user2'}]}, status=200)
        page = response.json

        # user2 should see the document in their workspace again
        self.logout()
        self.login('user2')
        response = self.testapp.get('/users/contents', status=200)
        result = response.json
        content_ids = [(i['id'], i['rolesToAccept'], i['state'])
                       for i in result['results']['items']]
        self.assertIn(
            ('{}@draft'.format(page['id']), ['illustrators'],
                'Awaiting acceptance'), content_ids)

        # user1 removes self from all roles
        self.logout()
        self.login('user1')
        self.testapp.put_json(
            '/contents/{}@draft.json'.format(page['id']),
            {'authors': [i for i in page['authors'] if i['id'] != 'user1'],
             'publishers': [i for i in page['publishers']
                            if i['id'] != 'user1'],
             'licensors': [i for i in page['licensors']
                           if i['id'] != 'user1']},
            status=200)

        # user1 should not see the document in their workspace
        response = self.testapp.get('/users/contents')
        result = response.json
        content_ids = [i['id'] for i in result['results']['items']]
        self.assertNotIn('{}@draft'.format(page['id']), content_ids)

    def test_user_contents_ordering(self):
        # user4 adds a document
        self.logout()
        self.login('user4')
        date = datetime.datetime(2014, 3, 13, 15, 21, 15, 677617)
        date = pytz.timezone(os.environ['TZ']).localize(date)
        posting_tzinfo = pytz.timezone('America/Whitehorse')
        posting_date = date.astimezone(posting_tzinfo)
        from ..utils import utf8
        response = self.testapp.post_json('/users/contents', {
            'title': 'document by user4',
            'created': utf8(posting_date.isoformat()),
            'revised': utf8(posting_date.isoformat()),
            }, status=201)
        page = response.json

        # user4 should get back the contents just posted - full content test
        response = self.testapp.get('/users/contents', status=200)
        result = response.json
        from ..models import TZINFO
        # Localize the resulting datetime info.
        from ..utils import utf8
        expected_result_revised_date = date.astimezone(TZINFO)
        self.assertEqual(result, {
            u'query': {
                u'limits': [],
                },
            u'results': {u'items': [
                {u'derivedFrom': None,
                 u'containedIn': [],
                 u'id': u'{}@draft'.format(page['id']),
                 u'mediaType': u'application/vnd.org.cnx.module',
                 u'revised': utf8(expected_result_revised_date.isoformat()),
                 u'state': u'Draft',
                 u'title': u'document by user4',
                 u'version': u'draft',
                 u'rolesToAccept': [],
                 }],
                u'limits': [],
                u'total': 1}
            })

        self.assert_cors_headers(response)

        one_week_ago = datetime.datetime.now(TZINFO) - datetime.timedelta(7)
        two_weeks_ago = datetime.datetime.now(TZINFO) - datetime.timedelta(14)

        mock_datetime = mock.Mock()
        mock_datetime.now = mock.Mock(return_value=one_week_ago)
        with mock.patch('datetime.datetime', mock_datetime):
            response = self.testapp.post_json(
                '/users/contents',
                {'derivedFrom': '91cb5f28-2b8a-4324-9373-dac1d617bc24@1'},
                status=201)
        self.assert_cors_headers(response)

        mock_datetime.now = mock.Mock(return_value=two_weeks_ago)
        with mock.patch('datetime.datetime', mock_datetime):
            response = self.testapp.post_json(
                '/users/contents',
                {'title': 'oldest document by user4'}, status=201)
        self.assert_cors_headers(response)

        response = self.testapp.post_json(
            '/users/contents', {'title': 'new document by user4'}, status=201)
        self.assert_cors_headers(response)

        response = self.testapp.get('/users/contents', status=200)
        result = response.json
        self.assertEqual(result['results']['total'], 4)
        self.assertTrue(result['results']['items'][0]['id'].endswith('@draft'))
        self.assertTrue(result['results']['items'][1]['id'].endswith('@draft'))
        self.assertTrue(result['results']['items'][2]['id'].endswith('@draft'))
        self.assertTrue(result['results']['items'][3]['id'].endswith('@draft'))

        titles = [i['title'] for i in result['results']['items']]
        self.assertEqual(titles, [
            u'new document by user4',
            u'Copy of Indkøb',
            u'oldest document by user4',
            u'document by user4'])

        derived_from = [i['derivedFrom'] for i in result['results']['items']]
        self.assertEqual(derived_from, [
            None, '91cb5f28-2b8a-4324-9373-dac1d617bc24@1', None, None])

        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                         'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                         'http://localhost:8000')
        self.assert_cors_headers(response)

    def test_user_contents_hide_documents_inside_binders(self):
        self.logout()
        self.login('user5')
        one_day_ago = datetime.datetime.now(tz=TZINFO) - datetime.timedelta(1)
        one_week_ago = datetime.datetime.now(tz=TZINFO) - datetime.timedelta(7)

        mock_datetime = mock.Mock()
        mock_datetime.now = mock.Mock(return_value=one_day_ago)

        with mock.patch('datetime.datetime', mock_datetime):
            response = self.testapp.post_json('/users/contents',
                {'title': 'single page document'}, status=201)
        single_page = response.json

        mock_datetime.now = mock.Mock(return_value=one_week_ago)
        with mock.patch('datetime.datetime', mock_datetime):
            response = self.testapp.post_json('/users/contents',
                {'title': 'page in a book'}, status=201)
        page_in_book = response.json

        response = self.testapp.post_json('/users/contents', {
            'mediaType': 'application/vnd.org.cnx.collection',
            'title': 'book',
            'tree': {
                'contents': [
                    {
                        'id': '{}@draft'.format(page_in_book['id']),
                        },
                    ],
                },
            }, status=201)
        book = response.json

        # since page_in_book is in book, it should not show in the workspace
        response = self.testapp.get('/users/contents', status=200)
        workspace = response.json
        self.assertEqual(workspace, {
            u'query': {
                u'limits': [],
                },
            u'results': {
                u'items': [
                    {
                        u'containedIn': [],
                        u'id': u'{}@draft'.format(book['id']),
                        u'title': book['title'],
                        u'derivedFrom': None,
                        u'state': u'Draft',
                        u'version': u'draft',
                        u'revised': book['revised'],
                        u'mediaType': u'application/vnd.org.cnx.collection',
                        u'rolesToAccept': [],
                        },
                    {
                        u'containedIn': [],
                        u'id': u'{}@draft'.format(single_page['id']),
                        u'title': single_page['title'],
                        u'derivedFrom': None,
                        u'state': u'Draft',
                        u'version': u'draft',
                        u'revised': single_page['revised'],
                        u'mediaType': u'application/vnd.org.cnx.module',
                        u'rolesToAccept': [],
                        },
                    ],
                u'total': 2,
                u'limits': [],
                },
            })

        # remove page_in_book from book and add single_page to book
        response = self.testapp.put_json(
            '/contents/{}@draft.json'.format(book['id']), {
                'tree': {
                    'contents': [
                        {
                            'id': '{}@draft'.format(single_page['id']),
                            },
                        ],
                    },
                }, status=200)
        book = response.json

        # add page_in_book to a book by someone else
        self.logout()
        self.login('user6')

        response = self.testapp.post_json('/users/contents', {
            'mediaType': 'application/vnd.org.cnx.collection',
            'title': 'some other book',
            'tree': {
                'contents': [
                    {
                        'id': '{}@draft'.format(page_in_book['id']),
                        },
                    ],
                },
            }, status=201)
        other_book = response.json
        self.logout()
        self.login('user5')

        # workspace should now show page_in_book and book
        response = self.testapp.get('/users/contents', status=200)
        workspace = response.json
        self.assertEqual(workspace, {
            u'query': {
                u'limits': [],
                },
            u'results': {
                u'items': [
                    {
                        u'containedIn': [],
                        u'id': u'{}@draft'.format(book['id']),
                        u'title': book['title'],
                        u'derivedFrom': None,
                        u'state': u'Draft',
                        u'version': u'draft',
                        u'revised': book['revised'],
                        u'mediaType': u'application/vnd.org.cnx.collection',
                        u'rolesToAccept': [],
                        },
                    {
                        u'containedIn': [other_book['id']],
                        u'id': u'{}@draft'.format(page_in_book['id']),
                        u'title': page_in_book['title'],
                        u'derivedFrom': None,
                        u'state': u'Draft',
                        u'version': u'draft',
                        u'revised': page_in_book['revised'],
                        u'mediaType': u'application/vnd.org.cnx.module',
                        u'rolesToAccept': [],
                        },
                    ],
                u'total': 2,
                u'limits': [],
                },
            })

        # retrieve just pages, should now show all pages
        response = self.testapp.get(
            '/users/contents?mediaType=application/vnd.org.cnx.module',
            status=200)
        workspace = response.json
        self.assertEqual(workspace, {
            u'query': {
                u'limits': [],
                },
            u'results': {
                u'items': [
                    {
                        u'containedIn': [book['id']],
                        u'id': u'{}@draft'.format(single_page['id']),
                        u'title': single_page['title'],
                        u'derivedFrom': None,
                        u'state': u'Draft',
                        u'version': u'draft',
                        u'revised': single_page['revised'],
                        u'mediaType': u'application/vnd.org.cnx.module',
                        u'rolesToAccept': [],
                        },
                    {
                        u'containedIn': [other_book['id']],
                        u'id': u'{}@draft'.format(page_in_book['id']),
                        u'title': page_in_book['title'],
                        u'derivedFrom': None,
                        u'state': u'Draft',
                        u'version': u'draft',
                        u'revised': page_in_book['revised'],
                        u'mediaType': u'application/vnd.org.cnx.module',
                        u'rolesToAccept': [],
                        },
                    ],
                u'total': 2,
                u'limits': [],
                },
            })

        # Now filter for not:Draft - should supress all
        response = self.testapp.get('/users/contents?state=not:Draft',
                                    status=200)
        workspace = response.json
        self.assertEqual(workspace, {
            u'query': {
                u'limits': [],
                },
            u'results': {
                u'items': [],
                u'total': 0,
                u'limits': [],
                },
            })


class PublicationTests(BaseFunctionalTestCase):

    def test_publish_401(self):
        self.logout()
        response = self.testapp.post_json('/publish', {}, status=401)
        self.assert_cors_headers(response)

    def test_publish_403(self):
        post_data = {
            'title': 'Page one',
            'content': '<html><body><p>Contents of Page one</p></body></html>',
            'abstract': 'Learn how to etc etc',
            }
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        page = response.json

        post_data = {
                'submitlog': u'Nueva versión!',
                'items': [
                    page['id'],
                    ],
                }
        with mock.patch('cnxauthoring.models.Document.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.post_json(
                '/publish', post_data, status=403)
        self.assertTrue('You do not have permission to publish'
                    in response.body.decode('utf-8'))

        post_data = {
                'title': 'Binder',
                'mediaType': 'application/vnd.org.cnx.collection',
                'tree': {
                    'contents': [],
                    },
                }
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        book = response.json

        post_data = {
                'submitlog': u'Nueva versión!',
                'items': [
                    book['id'],
                    ],
                }
        with mock.patch('cnxauthoring.models.Binder.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.post_json(
                '/publish', post_data, status=403)
        self.assertTrue('You do not have permission to publish'
                    in response.body.decode('utf-8'))

    def test_publish_service_not_available(self):
        post_data = {
            'title': 'Page one',
            'content': '<html><body><p>Contents of Page one</p></body></html>',
            }
        response = self.testapp.post_json(
            '/users/contents', post_data, status=201)
        page = response.json

        post_data = {
                'submitlog': 'Publishing is working!',
                'items': [
                    page['id'],
                    ],
                }
        with mock.patch('requests.post') as patched_post:
            patched_post.return_value = mock.Mock(status_code=404)
            response = self.testapp.post_json(
                    '/publish', post_data, status=400)
            self.assertEqual(patched_post.call_count, 1)
        self.assertTrue('Unable to publish: response status code: 404'
                in response.body.decode('utf-8'))
        self.assert_cors_headers(response)

    def test_publish_response_not_json(self):
        post_data = {
            'title': 'Page one',
            'content': '<html><body><p>Contents of Page one</p></body></html>',
            }
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        page = response.json

        post_data = {
                'submitlog': 'Publishing is working!',
                'items': [
                    page['id'],
                    ],
                }
        with mock.patch('requests.post') as patched_post:
            patched_post.return_value = mock.Mock(
                status_code=200, content=b'not json')
            response = self.testapp.post_json(
                '/publish', post_data, status=400)
            self.assertEqual(patched_post.call_count, 1)
        self.assertTrue('Unable to publish: response body: not json'
                in response.body.decode('utf-8'))
        self.assert_cors_headers(response)

    def test_publish_single_pages(self):
        post_data = {
            'title': 'Page one',
            'content': '<html><body><p>Contents of Page one</p></body></html>',
            'abstract': 'Learn how to etc etc',
            }
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        page_one = response.json
        post_data = {
            'title': u'Página dos',
            'content': (u'<html><body><p>Contents of Página dos</p></body>'
                        u'</html>'),
            'language': 'es',
            }
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        page_two = response.json

        # User makes a publication of the two pages...
        post_data = {
                'submitlog': u'Nueva versión!',
                'items': (page_one['id'], page_two['id'],),
                }
        response = self.testapp.post_json(
            '/publish', post_data, status=200)
        self.assertEqual(response.json[u'state'], u'Done/Success')
        expected_mapping = {
            page_one['id']: '{}@1'.format(page_one['id']),
            page_two['id']: '{}@1'.format(page_two['id']),
            }
        self.assertEqual(response.json[u'mapping'], expected_mapping)
        self.assert_cors_headers(response)

        # Grab the publication id for followup assertions.
        publication_id = response.json['publication']

        for page in (page_one, page_two,):
            url = '/contents/{}@draft.json'.format(page['id'])
            response = self.testapp.get(url)
            self.assertEqual(response.json['state'], 'Done/Success')
            self.assertEqual(response.json['publication'],
                             str(publication_id))

    def test_publish_derived_from_single_page(self):
        # Create the derived page
        post_data = {
                'derivedFrom': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
                }
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        page = response.json

        # Publish the derived page
        post_data = {
                'submitlog': 'Publishing is working!',
                'items': [
                    '{}@draft'.format(page['id']),
                    ],
                }
        response = self.testapp.post_json(
            '/publish', post_data, status=200)
        self.assert_cors_headers(response)

        publication_info = response.json
        publication_id = publication_info['publication']
        self.assertEqual(publication_info['state'], 'Done/Success')
        self.assertEqual(publication_info['mapping'][page['id']],
                         '{}@1'.format(page['id']))

        response = self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']))
        result = response.json
        self.assertEqual(result['state'], 'Done/Success')
        self.assertEqual(result['publication'], unicode(publication_id))

    def test_publish_binder(self):
        response = self.testapp.post_json('/users/contents', {
            'title': 'Page one',
            'content': '<html><body><p>Content of page one</p></body></html>',
            'abstract': 'Learn how to etc etc',
            }, status=201)
        page1 = response.json
        self.assert_cors_headers(response)

        response = self.testapp.post_json('/users/contents', {
            'title': 'Page two',
            'content': '<html><body><p>Content of page two</p></body></html>'
            }, status=201)
        page2 = response.json
        self.assert_cors_headers(response)

        response = self.testapp.post_json('/users/contents', {
                    'title': 'Book',
                    'abstract': 'Book abstract',
                    'language': 'de',
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'tree': {
                        'contents': [
                            {
                                'id': '{}@draft'.format(page1['id']),
                                'title': 'Page one',
                                },
                            {
                                'id': 'subcol',
                                'title': 'New section',
                                'contents': [
                                    {
                                        'id': '{}@draft'.format(page2['id']),
                                        'title': 'Page two',
                                        },
                                    ],
                                },
                            ],
                        },
                    }, status=201)
        self.assert_cors_headers(response)
        binder = response.json

        post_data = {
            'submitlog': 'Publishing a book is working?',
            'items': (binder['id'], page1['id'], page2['id'],),
            }
        response = self.testapp.post_json('/publish', post_data, status=200)
        self.assertEqual(response.json[u'state'], u'Done/Success')
        expected_mapping = {
            binder['id']: '{}@1.1'.format(binder['id']),
            page1['id']: '{}@1'.format(page1['id']),
            page2['id']: '{}@1'.format(page2['id']),
            }
        self.assertEqual(response.json[u'mapping'], expected_mapping)
        self.assert_cors_headers(response)

        # Grab the publication id for followup assertions.
        publication_id = response.json['publication']

        for page in (binder, page1, page2,):
            url = '/contents/{}@draft.json'.format(page['id'])
            response = self.testapp.get(url)
            self.assertEqual(response.json['state'], 'Done/Success')
            self.assertEqual(response.json['publication'],
                             str(publication_id))

    def test_publish_derived_from_binder(self):
        self.logout()

        # Create a derived binder
        self.login('e5a07af6-09b9-4b74-aa7a-b7510bee90b8')
        post_data = {
            'derivedFrom': u'e79ffde3-7fb4-4af3-9ec8-df648b391597@6.1',
            }
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        binder = response.json
        self.assert_cors_headers(response)

        # Publish the derived binder
        post_data = {
            'submitlog': 'Publishing a derived book',
            'items': [
                binder['id'],
                ],
            }
        response = self.testapp.post_json(
            '/publish', post_data, status=200)
        self.assert_cors_headers(response)

        publication_info = response.json
        publication_id = publication_info['publication']
        self.assertEqual(publication_info['state'], 'Done/Success')
        self.assertEqual(publication_info['mapping'][binder['id']],
                         '{}@1.1'.format(binder['id']))

        response = self.testapp.get(
            '/contents/{}@draft.json'.format(binder['id']))
        result = response.json
        self.assertEqual(result['state'], 'Done/Success')
        self.assertEqual(result['publication'], unicode(publication_id))

    def test_publish_revision_single_page(self):
        id = '91cb5f28-2b8a-4324-9373-dac1d617bc24'
        # If the content already exists, because of other tests, remove it.
        from ..storage import storage
        document = storage.get(id=id)
        if document is not None:
            storage.remove(document)
            storage.persist()

        self.logout()
        # Create the revision
        self.login('Rasmus1975')
        post_data = {
            'id': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
            'title': u'Turning DNA through resonance',
            'abstract': u'Theories on turning DNA structures',
            'language': u'en',
            'subjects': [u'Science and Technology'],
            'keywords': [u'DNA', u'resonance'],
            }
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        self.assert_cors_headers(response)
        page = response.json

        # Publish the revision
        post_data = {
                'submitlog': 'Publishing a revision',
                'items': [
                    page['id'],
                    ],
                }
        response = self.testapp.post_json(
            '/publish', post_data, status=200)

        publication_info = response.json
        self.assertEqual(publication_info['state'], 'Done/Success')
        self.assertEqual(publication_info['mapping'][page['id']],
                         '{}@2'.format(page['id']))

    def test_edit_after_publish(self):
        # create a new page
        post_data = {
            'title': 'Page one',
            'content': '<html><body><p>Contents of Page one</p></body></html>',
            'abstract': 'Learn how to etc etc',
            }
        response = self.testapp.post_json(
            '/users/contents', post_data, status=201)
        page_one = response.json

        post_data = {
            'submitlog': u'Nueva versión!',
            'items': [
                page_one['id'],
                ],
            }

        response = self.testapp.post_json(
            '/publish', post_data, expect_errors=True)

        publish = response.json
        self.assertEqual(publish['state'], 'Done/Success')
        self.assertEqual(list(publish['mapping'].values()),
                         ['{}@1'.format(page_one['id'])])

        # authoring should have the document in the db with status
        # "Done/Success"
        response = self.testapp.get('/contents/{}@draft.json'.format(
            page_one['id']), status=200)
        body = response.json
        self.assertEqual(body['state'], 'Done/Success')

        # editing the content again
        post_data = {
            'id': '{}@1'.format(page_one['id']),
            'title': 'Page one v2',
            'content': '<html><body><p>Contents of Page one</p></body></html>',
            'abstract': 'Learn how to etc etc',
            }
        response = self.testapp.post_json(
            '/users/contents', post_data, status=201)
        page_one = response.json
        self.assertEqual(page_one['state'], 'Draft')

        # post with the same id should return the same draft
        post_data = {
            'id': '{}@1'.format(page_one['id']),
            }
        response = self.testapp.post_json(
            '/users/contents', post_data, status=201)
        page_one = response.json
        self.assertEqual(page_one['state'], 'Draft')
        self.assertEqual(page_one['title'], 'Page one v2')

        # publish the next version
        post_data = {
            'submitlog': u'Nueva versión!',
            'items': [
                page_one['id'],
                ],
            }
        response = self.testapp.post_json(
            '/publish', post_data, expect_errors=True)
        publish = response.json
        self.assertEqual(publish['state'], 'Done/Success')
        self.assertEqual(list(publish['mapping'].values()),
                         ['{}@2'.format(page_one['id'])])

    def test_delete_after_publish(self):
        # create a new page
        post_data = {
            'title': 'Page one',
            'content': '<html><body><p>Contents of Page one</p></body></html>',
            'abstract': 'Learn how to etc etc',
            }
        response = self.testapp.post_json(
            '/users/contents', post_data, status=201)
        page_one = response.json

        post_data = {
            'submitlog': u'Nueva versión!',
            'items': [
                page_one['id'],
                ],
            }

        response = self.testapp.post_json(
            '/publish', post_data, expect_errors=True)

        publish = response.json
        self.assertEqual(publish['state'], 'Done/Success')
        self.assertEqual(list(publish['mapping'].values()),
                         ['{}@1'.format(page_one['id'])])

        # authoring should have the document in the db with status
        # "Done/Success"
        response = self.testapp.get('/contents/{}@draft.json'.format(
            page_one['id']), status=200)
        body = response.json
        self.assertEqual(body['state'], 'Done/Success')

        # delete the content from authoring
        response = self.testapp.delete(
            '/contents/{}@1'.format(page_one['id']), post_data, status=200)
        self.testapp.get('/contents/{}@1'.format(page_one['id']), status=404)

    def test_publish_after_error(self):
        # create a new page
        post_data = {
            'title': 'Page one',
            'content': '<html><body><p><img src="a.png" /></p></body></html>',
            'abstract': 'Learn how to etc etc',
            }
        response = self.testapp.post_json(
            '/users/contents', post_data, status=201)
        page_one = response.json

        post_data = {
            'submitlog': u'Nueva versión!',
            'items': [
                page_one['id'],
                ],
            }

        response = self.testapp.post_json(
            '/publish', post_data, expect_errors=True)

        publish = response.json
        self.assertEqual(publish['state'], 'Failed/Error')
        self.assertEqual(publish['messages'][0]['type'], 'InvalidReference')

        # authoring should have the document in the db with status
        # "Failed/Error"
        response = self.testapp.get('/contents/{}@draft.json'.format(
            page_one['id']), status=200)
        body = response.json
        self.assertEqual(body['state'], 'Failed/Error')

        # fix up the invalid reference
        post_data = {
            'id': '{}'.format(page_one['id']),
            'title': 'Page one v2',
            'content': '<html><body><p>Contents of Page one</p></body></html>',
            'abstract': 'Learn how to etc etc',
            }
        response = self.testapp.put_json(
            '/contents/{}@draft.json'.format(page_one['id']), post_data)
        page_one = response.json
        self.assertEqual(page_one['state'], 'Draft')

        # publish again
        post_data = {
            'submitlog': u'Nueva versión!',
            'items': [
                page_one['id'],
                ],
            }
        response = self.testapp.post_json(
            '/publish', post_data, expect_errors=True)
        publish = response.json
        self.assertEqual(publish['state'], 'Done/Success')
        self.assertEqual(list(publish['mapping'].values()),
                         ['{}@1'.format(page_one['id'])])

    def test_publish_w_multiple_users(self):
        # create a new page
        post_data = {
            'title': 'Page one',
            'content': '<html><body><p>Contents of Page one</p></body></html>',
            'abstract': 'Learn how to etc etc',
            }
        response = self.testapp.post_json(
            '/users/contents', post_data, status=201)
        page = response.json

        # add an editor
        post_data = {
            'editors': [{'id': 'user2'}],
            }
        self.testapp.put_json(
            '/contents/{}@draft.json'.format(page['id']), post_data,
            status=200)

        # edit some more
        post_data = {
            'title': 'Page one with an editor',
            }
        self.testapp.put_json(
            '/contents/{}@draft.json'.format(page['id']), post_data,
            status=200)

        post_data = {
            'submitlog': u'Nueva versión!',
            'items': [page['id']],
            }
        response = self.testapp.post_json(
            '/publish', post_data, status=200)
        # publication should be waiting for acceptance
        publish = response.json
        self.assertEqual(publish['state'], 'Waiting for acceptance')
        self.assertEqual(list(publish['mapping'].values()),
                         ['{}@1'.format(page['id'])])

        # login as user2 and accept roles
        self.logout()
        self.login('user2')

        post_data = {
            'license': True,
            'roles': [{'role': 'editors', 'hasAccepted': True}],
            }
        self.testapp.post_json(
            '/contents/{}@draft/acceptance'.format(page['id']),
            post_data, status=200)

        # publish the content again
        self.logout()
        self.login('user1')
        post_data = {
            'submitlog': u'Nueva versión!',
            'items': [page['id']],
            }
        response = self.testapp.post_json(
            '/publish', post_data, status=200)
        # publication should be waiting for acceptance
        publish = response.json
        self.assertEqual(publish['state'], 'Done/Success')
        self.assertEqual(list(publish['mapping'].values()),
                         ['{}@1'.format(page['id'])])

    def test_acceptance(self):
        # create a new page
        post_data = {
            'title': 'My Page',
            }
        created = datetime.datetime.now(TZINFO)
        formatted_created = created.astimezone(TZINFO).isoformat()
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = created
            response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        page = response.json

        # user1 has accepted all their roles
        response = self.testapp.get(
            '/contents/{}@draft/acceptance'.format(page['id']))
        acceptance = response.json
        self.assertEqual(acceptance, {
            u'license': {
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'name': u'Attribution',
                u'abbr': u'by',
                u'version': u'4.0',
                },
            u'url': u'http://localhost/contents/{}%40draft.json'.format(
                page['id']),
            u'id': page['id'],
            u'title': u'My Page',
            u'user': u'user1',
            u'roles': [{u'assignmentDate': formatted_created,
                        u'hasAccepted': True,
                        u'requester': u'user1',
                        u'role': u'authors'},
                       {u'assignmentDate': formatted_created,
                        u'hasAccepted': True,
                        u'requester': u'user1',
                        u'role': u'copyright_holders'},
                       {u'assignmentDate': formatted_created,
                        u'hasAccepted': True,
                        u'requester': u'user1',
                        u'role': u'publishers'}],
            })

        # add user2 to authors and editors, add user1 to editors, add user3 and
        # user4 to translators
        post_data = {
            'authors': page['authors'] + [{'id': 'user2'}],
            'editors': page['editors'] + [{'id': 'user1'}, {'id': 'user2'}],
            'translators': page['translators'] +
                           [{'id': 'user3'}, {'id': 'user4'}],
            }
        now = datetime.datetime.now(TZINFO)
        formatted_now = now.astimezone(TZINFO).isoformat()
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = now
            response = self.testapp.put_json(
                '/contents/{}@draft.json'.format(page['id']), post_data,
                status=200)
        page = response.json

        # user1 should accept the editor role automatically
        response = self.testapp.get(
            '/contents/{}@draft/acceptance'.format(page['id']))
        acceptance = response.json
        self.assertEqual(acceptance, {
            u'license': {
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'name': u'Attribution',
                u'abbr': u'by',
                u'version': u'4.0',
                },
            u'url': u'http://localhost/contents/{}%40draft.json'.format(
                page['id']),
            u'id': page['id'],
            u'title': u'My Page',
            u'user': u'user1',
            u'roles': [{u'assignmentDate': formatted_created,
                        u'hasAccepted': True,
                        u'requester': u'user1',
                        u'role': u'authors'},
                       {u'assignmentDate': formatted_created,
                        u'hasAccepted': True,
                        u'requester': u'user1',
                        u'role': u'copyright_holders'},
                       {u'assignmentDate': formatted_now,
                        u'hasAccepted': True,
                        u'requester': u'user1',
                        u'role': u'editors'},
                       {u'assignmentDate': formatted_created,
                        u'hasAccepted': True,
                        u'requester': u'user1',
                        u'role': u'publishers'}],
            })

        # log in as user2
        self.logout()
        self.login('user2')

        # user2 should have authors and editors in acceptance info
        response = self.testapp.get(
            '/contents/{}@draft/acceptance'.format(page['id']))
        acceptance = response.json
        self.assertEqual(acceptance, {
            u'license': {
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'name': u'Attribution',
                u'abbr': u'by',
                u'version': u'4.0',
                },
            u'url': u'http://localhost/contents/{}%40draft.json'.format(
                page['id']),
            u'id': page['id'],
            u'title': u'My Page',
            u'user': u'user2',
            u'roles': [{u'role': u'authors',
                        u'assignmentDate': formatted_now,
                        u'requester': u'user1',
                        u'hasAccepted': None},
                       {u'role': u'editors',
                        u'assignmentDate': formatted_now,
                        u'requester': u'user1',
                        u'hasAccepted': None}],
            })

        # user2 accepts the roles
        post_data = {
            'license': True,
            'roles': [{'role': 'editors', 'hasAccepted': True},
                      {'role': 'authors', 'hasAccepted': True}],
            }
        self.testapp.post_json(
            '/contents/{}@draft/acceptance'.format(page['id']),
            post_data, status=200)

        # checks the acceptance info again (all roles accepted)
        response = self.testapp.get(
            '/contents/{}@draft/acceptance'.format(page['id']))
        acceptance = response.json
        self.assertEqual(acceptance, {
            u'license': {
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'name': u'Attribution',
                u'abbr': u'by',
                u'version': u'4.0',
                },
            u'url': u'http://localhost/contents/{}%40draft.json'.format(
                page['id']),
            u'id': page['id'],
            u'title': u'My Page',
            u'user': u'user2',
            u'roles': [{u'role': u'authors',
                        u'assignmentDate': formatted_now,
                        u'requester': u'user1',
                        u'hasAccepted': True},
                       {u'role': u'editors',
                        u'assignmentDate': formatted_now,
                        u'requester': u'user1',
                        u'hasAccepted': True}],
            })

        # login as user3
        self.logout()
        self.login('user3')

        # user3 should have translators in the acceptance info
        response = self.testapp.get(
            '/contents/{}@draft/acceptance'.format(page['id']))
        acceptance = response.json
        self.assertEqual(acceptance, {
            u'license': {
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'name': u'Attribution',
                u'abbr': u'by',
                u'version': u'4.0',
                },
            u'url': u'http://localhost/contents/{}%40draft.json'.format(
                page['id']),
            u'id': page['id'],
            u'title': u'My Page',
            u'user': u'user3',
            u'roles': [{u'role': u'translators',
                        u'assignmentDate': formatted_now,
                        u'requester': u'user1',
                        u'hasAccepted': None}],
            })

        # user3 rejects their roles
        post_data = {
            'license': False,
            'roles': [{'role': 'translators', 'hasAccepted': False}],
            }
        response = self.testapp.post_json(
            '/contents/{}@draft/acceptance'.format(page['id']),
            post_data, status=200)

        # should not be able to view or edit the content anymore
        self.testapp.get(
            '/contents/{}@draft/acceptance'.format(page['id']))
        self.testapp.get(
            '/contents/{}@draft.json'.format(page['id']))
        self.testapp.put_json(
            '/contents/{}@draft.json'.format(page['id']), {}, status=403)

        # content should not be in the workspace
        response = self.testapp.get('/users/contents')
        workspace = response.json
        content_ids = [i['id'] for i in workspace['results']['items']]
        self.assertNotIn(page['id'], content_ids)

        # login as user4
        self.logout()
        self.login('user4')

        # user4 should have translators in the acceptance info
        response = self.testapp.get(
            '/contents/{}@draft/acceptance'.format(page['id']))
        acceptance = response.json
        self.assertEqual(acceptance, {
            u'license': {
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'name': u'Attribution',
                u'abbr': u'by',
                u'version': u'4.0',
                },
            u'url': u'http://localhost/contents/{}%40draft.json'.format(
                page['id']),
            u'id': page['id'],
            u'title': u'My Page',
            u'user': u'user4',
            u'roles': [{u'role': u'translators',
                        u'assignmentDate': formatted_now,
                        u'requester': u'user1',
                        u'hasAccepted': None}],
            })

        # user4 accepts their roles without accepting the license
        post_data = {
            'license': False,
            'roles': [{'role': 'translators', 'hasAccepted': True}],
            }
        response = self.testapp.post_json(
            '/contents/{}@draft/acceptance'.format(page['id']),
            post_data, status=200)

        # acceptance info is reset
        response = self.testapp.get(
            '/contents/{}@draft/acceptance'.format(page['id']))
        acceptance = response.json
        self.assertEqual(acceptance, {
            u'license': {
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'name': u'Attribution',
                u'abbr': u'by',
                u'version': u'4.0',
                },
            u'url': u'http://localhost/contents/{}%40draft.json'.format(
                page['id']),
            u'id': page['id'],
            u'title': u'My Page',
            u'user': u'user4',
            u'roles': [{u'role': u'translators',
                        u'assignmentDate': formatted_now,
                        u'requester': u'user1',
                        u'hasAccepted': None}],
            })
