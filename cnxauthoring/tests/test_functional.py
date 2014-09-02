# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import datetime
import json
import io
import os
import sys
import re
import unittest
import uuid
try:
    from unittest import mock
except ImportError:
    import mock
try:
    import urllib2 # python2
except ImportError:
    import urllib.request as urllib2 # renamed in python3

import cnxepub
from pyramid import httpexceptions
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from webtest import Upload
from zope.interface import implementer

from . import test_data
from ..models import DEFAULT_LICENSE, TZINFO


USER_PROFILE = {
        u'username': u'me',
        u'id': 1,
        u'first_name': u'User',
        u'last_name': u'One',
        u'contact_infos': [
            {
                u'type': u'EmailAddress',
                u'verified': True,
                u'id': 1,
                u'value': u'me@example.com',
                },
            ],
        }

SUBMITTER = {
        u'id': u'me',
        u'email': u'me@example.com',
        u'firstname': u'User',
        u'surname': u'One',
        u'fullname': u'User One',
        u'type': u'cnx-id',
        }


class BaseFunctionalTestCase(unittest.TestCase):
    accounts_request_return = ''
    maxDiff = None

    @classmethod
    def setUpClass(self):
        # only run once for all the tests

        # make sure storage is set correctly in cnxauthoring.views by reloading
        # cnxauthoring.views
        if 'cnxauthoring.views' in sys.modules:
            del sys.modules['cnxauthoring.views']

        # make sure test db is empty
        config = ConfigParser.ConfigParser()
        config.read(['testing.ini'])
        test_db = config.get('app:main', 'pickle.filename')
        try:
            os.remove(test_db)
        except OSError:
            # file doesn't exist
            pass

        import pyramid.paster
        app = pyramid.paster.get_app('testing.ini')

        from webtest import TestApp
        self.testapp = TestApp(app)

    @classmethod
    def tearDownClass(self):
        from ..storage import storage
        if hasattr(storage, 'conn'):
            storage.conn.close()

    def setUp(self):
        self.login()
        self.addCleanup(self.logout)

    def login(self, username='me', password='password', login_url='/login',
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

    def mock_archive(self, return_value=None, content_type=None):
        response = mock.Mock()
        response.info = mock.Mock()
        response.info().getheader = mock.Mock(side_effect={
            'Content-Type': content_type}.get)
        # for derived from
        def patched_urlopen(url, *args, **kwargs):
            if return_value:
                response.read = mock.Mock(
                        side_effect=io.BytesIO(return_value).read)
                return response
            filename = test_data(url.rsplit('/', 1)[-1])
            if not os.path.exists(filename):
                raise urllib2.HTTPError(url, 404, 'Not Found', None, None)
            with open(filename, 'rb') as f:
                data = f.read()
                try:
                    data = data.encode('utf-8')
                except:
                    pass
            response.read = mock.Mock(side_effect=io.BytesIO(data).read)
            return response

        urlopen = urllib2.urlopen
        urllib2.urlopen = patched_urlopen
        self.addCleanup(setattr, urllib2, 'urlopen', urlopen)

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
        response = self.testapp.get('/login?redirect=http://example.com/logged_in',
                status=302)
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
        response = self.login(login_url='/login?redirect=http://example.com/logged_in')
        self.assertEqual(response.headers['Location'], 'http://example.com/logged_in')
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
        response = self.testapp.get('/contents/1234abcde@draft.json', status=401)
        self.assert_cors_headers(response)

    def test_get_content_404(self):
        response = self.testapp.get('/contents/1234abcde@draft.json', status=404)
        self.assert_cors_headers(response)

    def test_get_content_403(self):
        response = self.testapp.post_json('/users/contents',
                {'title': 'My New Document'}, status=201)
        content = json.loads(response.body.decode('utf-8'))
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
        content = json.loads(response.body.decode('utf-8'))
        with mock.patch('cnxauthoring.models.Binder.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.get('/contents/{}@draft.json'
                    .format(content['id']), status=403)
        self.assertTrue('You do not have permission to view'
                in response.body.decode('utf-8'))

    def test_get_content_for_document(self):
        response = self.testapp.post_json('/users/contents', {
                    'title': 'My New Document',
                    'created': u'2014-03-13T15:21:15-05:00',
                    'revised': u'2014-03-13T15:21:15-05:00',
                    }, status=201)
        put_result = json.loads(response.body.decode('utf-8'))
        response = self.testapp.get('/contents/{}@draft.json'.format(put_result['id']),
                status=200)
        get_result = json.loads(response.body.decode('utf-8'))
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
            u'authors': [SUBMITTER],
            u'publishers': [SUBMITTER],
            u'abstract': u'',
            u'version': u'draft',
            u'subjects': [],
            u'keywords': [],
            u'state': u'Draft',
            u'publication': None,
            u'licensors': [],
            u'translators': [],
            u'editors': [],
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
        self.assertEqual(json.loads(response.body.decode('utf-8')), {
            u'title': u'Required',
            })
        self.assert_cors_headers(response)

    def test_post_content_empty_binder(self):
        response = self.testapp.post_json('/users/contents', {
                    'mediaType': 'application/vnd.org.cnx.collection',
                    }, status=400)
        self.assertEqual(json.loads(response.body.decode('utf-8')), {
            u'title': u'Required',
            u'tree': u'Required',
            })
        self.assert_cors_headers(response)

    def test_post_content_unknown_media_type(self):
        response = self.testapp.post_json('/users/contents', {
                    'mediaType': 'unknown-media-type',
                    }, status=400)
        self.assertEqual(json.loads(response.body.decode('utf-8')), {
            u'media_type': u'"unknown-media-type" is not one of '
                           u'application/vnd.org.cnx.module, '
                           u'application/vnd.org.cnx.collection',
            u'title': u'Required',
            })
        self.assert_cors_headers(response)

    def test_post_content_minimal(self):
        response = self.testapp.post_json('/users/contents',
                {'title': u'My document タイトル'}, status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['title'], u'My document タイトル')
        self.assertEqual(result['language'], u'en')
        self.assert_cors_headers(response)

        response = self.testapp.get('/contents/{}@draft.json'.format(result['id']),
                status=200)
        self.assert_cors_headers(response)

    def test_post_content_minimal_binder(self):
        response = self.testapp.post_json('/users/contents', {
                    'title': u'My book タイトル',
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'tree': {
                        'contents': [],
                        },
                    }, status=201)
        result = json.loads(response.body.decode('utf-8'))
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
        result = json.loads(response.body.decode('utf-8'))
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
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['title'], u'My document タイトル 1')
        self.assertEqual(result[1]['title'], u'My document タイトル 2')
        self.assert_cors_headers(response)

        response = self.testapp.get('/contents/{}@draft.json'.format(result[0]['id']),
                status=200)
        self.assert_cors_headers(response)
        response = self.testapp.get('/contents/{}@draft.json'.format(result[1]['id']),
                status=200)
        self.assert_cors_headers(response)

    def test_post_content_derived_from_not_found(self):
        post_data = {
                'derivedFrom': u'notfound@1',
            }
        self.mock_archive()

        response = self.testapp.post_json(
                '/users/contents', post_data, status=400)
        self.assertTrue(b'Derive failed' in response.body)
        self.assert_cors_headers(response)

    def test_post_content_derived_from_not_json(self):
        self.mock_archive(return_value=b'invalid json')
        post_data = {
                'derivedFrom': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
            }

        response = self.testapp.post_json('/users/contents',
                post_data, status=400)
        self.assertTrue(b'Derive failed' in response.body)
        self.assert_cors_headers(response)

    def test_post_content_derived_from(self):
        post_data = {
                'derivedFrom': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
            }
        self.mock_archive(content_type='image/jpeg')

        response = self.testapp.post_json('/users/contents',
                post_data, status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.maxDiff = None
        content = result.pop('content')
        self.assertTrue(content.startswith('<html'))
        self.assertTrue(u'Lav en madplan for den kommende uge' in content)
        self.assertFalse('2011-10-05' in result.pop('created'))
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [SUBMITTER],
            u'publishers': [SUBMITTER],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Indkøb',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(post_data['derivedFrom']),
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
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [],
            })
        self.assert_cors_headers(response)

        response = self.testapp.get('/contents/{}@draft.json'.format(result['id']),
                status=200)
        result = json.loads(response.body.decode('utf-8'))
        content = result.pop('content')
        self.assertTrue(u'Lav en madplan for den kommende uge' in content)
        self.assertTrue(content.startswith('<html'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [SUBMITTER],
            u'publishers': [SUBMITTER],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Indkøb',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(post_data['derivedFrom']),
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
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [],
            })
        self.assert_cors_headers(response)

        # Check that resources are saved
        resource_path = re.search('(/resources/[^"]*)"', content).group(1)
        response = self.testapp.get(resource_path, status=200)
        self.assertEqual(response.content_type, 'image/jpeg')
        self.assert_cors_headers(response)

    def test_post_content_derived_from_w_missing_resource(self):
        post_data = {
                'derivedFrom': u'b0db72d9-fac3-4b43-9926-7e6e801663fb@1',
            }
        self.mock_archive()

        response = self.testapp.post_json('/users/contents',
                post_data, status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.maxDiff = None
        content = result.pop('content')
        self.assertTrue(u'Ingredienser (4 personer):' in content)
        self.assertTrue(content.startswith('<html'))
        self.assertFalse('2011-10-12' in result.pop('created'))
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [SUBMITTER],
            u'publishers': [SUBMITTER],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Tilberedning',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(post_data['derivedFrom']),
            u'title': u'Copy of Tilberedning',
            u'abstract': u'',
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'subjects': [u'Arts'],
            u'keywords': [],
            u'state': u'Draft',
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [],
            })
        self.assert_cors_headers(response)

        response = self.testapp.get('/contents/{}@draft.json'.format(result['id']),
                status=200)
        result = json.loads(response.body.decode('utf-8'))
        content = result.pop('content')
        self.assertTrue(u'Ingredienser (4 personer):' in content)
        self.assertTrue(content.startswith('<html'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [SUBMITTER],
            u'publishers': [SUBMITTER],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Tilberedning',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(post_data['derivedFrom']),
            u'title': u'Copy of Tilberedning',
            u'abstract': u'',
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'subjects': [u'Arts'],
            u'keywords': [],
            u'state': u'Draft',
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [],
            })
        self.assert_cors_headers(response)

    def test_post_content_derived_from_binder(self):
        self.mock_archive()
        post_data = {
                'derivedFrom': u'feda4909-5bbd-431e-a017-049aff54416d@1.1',
            }

        response = self.testapp.post_json('/users/contents',
                post_data, status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.maxDiff = None
        self.assertFalse('2011-10-12' in result.pop('created'))
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [SUBMITTER],
            u'publishers': [SUBMITTER],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Madlavning',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(post_data['derivedFrom']),
            u'title': u'Copy of Madlavning',
            u'abstract': u'',
            u'content': u'',
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.collection',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'tree': {
                u'id': u'{}@draft'.format(result['id']),
                u'title': u'Copy of Madlavning',
                u'contents': [
                    {u'id': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
                        u'title': u'Indkøb'},
                    {u'id': u'subcol',
                        u'contents': [
                            {u'id': u'f6b979cb-8904-4265-bf2d-f059cc362217@1',
                                u'title': u'Fødevarer'},
                            {u'id': u'7d089006-5a95-4e24-8e04-8168b5c41aa3@1',
                                u'title': u'Hygiejne'},
                            ],
                        u'title': u'Fødevarer og Hygiejne'},
                    {u'id': u'b0db72d9-fac3-4b43-9926-7e6e801663fb@1',
                        u'title': u'Tilberedning'}
                    ],
                },
            u'subjects': [u'Arts'],
            u'keywords': [u'køkken', u'Madlavning'],
            u'state': u'Draft',
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [],
            })
        self.assert_cors_headers(response)

        response = self.testapp.get(
                '/contents/{}@draft.json'.format(result['id']), status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [SUBMITTER],
            u'publishers': [SUBMITTER],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Madlavning',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(post_data['derivedFrom']),
            u'title': u'Copy of Madlavning',
            u'abstract': u'',
            u'content': u'',
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.collection',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'tree': {
                u'id': u'{}@draft'.format(result['id']),
                u'title': u'Copy of Madlavning',
                u'contents': [
                    {u'id': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
                        u'title': u'Indkøb'},
                    {u'id': u'subcol',
                        u'contents': [
                            {u'id': u'f6b979cb-8904-4265-bf2d-f059cc362217@1',
                                u'title': u'Fødevarer'},
                            {u'id': u'7d089006-5a95-4e24-8e04-8168b5c41aa3@1',
                                u'title': u'Hygiejne'},
                            ],
                        u'title': u'Fødevarer og Hygiejne'},
                    {u'id': u'b0db72d9-fac3-4b43-9926-7e6e801663fb@1',
                        u'title': u'Tilberedning'}
                    ],
                },
            u'subjects': [u'Arts'],
            u'keywords': [u'køkken', u'Madlavning'],
            u'state': u'Draft',
            u'publication': None,
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [],
            })
        self.assert_cors_headers(response)

    def test_post_content_revision_403(self):
        self.mock_archive()
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
        self.mock_archive()
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
        self.mock_archive(content_type='image/jpeg')
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

        response = self.testapp.post_json('/users/contents',
                post_data, status=201)
        result = json.loads(response.body.decode('utf-8'))
        license = result.pop('license')
        self.assertEqual(license['url'], DEFAULT_LICENSE.url)
        created = result.pop('created')
        self.assertTrue(created.startswith('2011-10-05'))
        revised = result.pop('revised')
        self.assertFalse(revised.startswith('2011'))
        content = result.pop('content')
        self.assertTrue(u'Lav en madplan for den kommende uge' in content)

        self.assertEqual(result, {
            u'submitter': {
                u'id': u'Rasmus1975',
                u'firstname': u'Rasmus',
                u'surname': u'Ruby',
                u'fullname': u'Rasmus Ruby',
                u'email': u'rasmus@example.com',
                u'type': u'cnx-id',
                },
            u'authors': [{
                u'website': u'',
                u'surname': u'Ruby',
                u'suffix': u'',
                u'firstname': u'Rasmus',
                u'title': u'',
                u'othername': u'',
                u'email': u'rasmus@example.com',
                u'fullname': u'Rasmus Ruby',
                u'id': u'Rasmus1975',
                u'type': u'cnx-id',
                }],
            u'publishers': [{
                u'website': u'',
                u'surname': u'Ruby',
                u'suffix': u'',
                u'firstname': u'Rasmus',
                u'title': u'',
                u'othername': u'',
                u'email': u'rasmus@example.com',
                u'fullname': u'Rasmus Ruby',
                u'id': u'Rasmus1975',
                u'type': u'cnx-id',
                }],
            u'id': post_data['id'].split('@')[0],
            u'derivedFrom': None,
            u'derivedFromTitle': None,
            u'derivedFromUri': None,
            u'title': u'Turning DNA through resonance',
            u'abstract': u'Theories on turning DNA structures',
            u'language': u'en',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'subjects': [u'Science and Technology'],
            u'keywords': [u'DNA', u'resonance'],
            u'state': u'Draft',
            u'publication': None,
            u'cnx-archive-uri': post_data['id'],
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [{
                u'website': u'',
                u'surname': u'Ruby',
                u'suffix': u'',
                u'firstname': u'Rasmus',
                u'title': u'',
                u'othername': u'',
                u'email': u'rasmus@example.com',
                u'fullname': u'Rasmus Ruby',
                u'id': u'Rasmus1975',
                u'type': u'cnx-id',
                }],
            })
        self.assert_cors_headers(response)

        response = self.testapp.get('/contents/{}@draft.json'.format(result['id']),
                status=200)
        result = json.loads(response.body.decode('utf-8'))
        content = result.pop('content')
        self.assertTrue(u'Lav en madplan for den kommende uge' in content)
        self.assertTrue(content.startswith('<html'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': {
                u'id': u'Rasmus1975',
                u'firstname': u'Rasmus',
                u'surname': u'Ruby',
                u'fullname': u'Rasmus Ruby',
                u'email': u'rasmus@example.com',
                u'type': u'cnx-id',
                },
            u'authors': [{
                u'website': u'',
                u'surname': u'Ruby',
                u'suffix': u'',
                u'firstname': u'Rasmus',
                u'title': u'',
                u'othername': u'',
                u'email': u'rasmus@example.com',
                u'fullname': u'Rasmus Ruby',
                u'id': u'Rasmus1975',
                u'type': u'cnx-id',
                }],
            u'publishers': [{
                u'website': u'',
                u'surname': u'Ruby',
                u'suffix': u'',
                u'firstname': u'Rasmus',
                u'title': u'',
                u'othername': u'',
                u'email': u'rasmus@example.com',
                u'fullname': u'Rasmus Ruby',
                u'id': u'Rasmus1975',
                u'type': u'cnx-id',
                }],
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
            u'publication': None,
            u'cnx-archive-uri': post_data['id'],
            u'containedIn': [],
            u'editors': [],
            u'translators': [],
            u'licensors': [{
                u'website': u'',
                u'surname': u'Ruby',
                u'suffix': u'',
                u'firstname': u'Rasmus',
                u'title': u'',
                u'othername': u'',
                u'email': u'rasmus@example.com',
                u'fullname': u'Rasmus Ruby',
                u'id': u'Rasmus1975',
                u'type': u'cnx-id',
                }],
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

        response = self.testapp.post_json('/users/contents',
                post_data, status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.maxDiff = None
        license = result.pop('license')
        self.assertEqual(license['url'], post_data['license']['url'])
        created = result.pop('created')
        self.assertTrue(created.startswith('2014-03-13T15:21:15.677617'))
        revised = result.pop('revised')
        self.assertTrue(revised.startswith('2014-03-13T15:21:15.677617'))
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [SUBMITTER],
            u'publishers': [SUBMITTER],
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
            u'publication': None,
            u'editors': [SUBMITTER],
            u'translators': [],
            u'licensors': [],
            })
        self.assert_cors_headers(response)

    def test_post_content_binder(self):
        response = self.testapp.post_json('/users/contents',
                {'title': 'Page one'}, status=201)
        page1 = json.loads(response.body.decode('utf-8'))
        self.assert_cors_headers(response)

        response = self.testapp.post_json('/users/contents',
                {'title': 'Page two'}, status=201)
        page2 = json.loads(response.body.decode('utf-8'))
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
        book = json.loads(response.body.decode('utf-8'))
        self.assert_cors_headers(response)

        response = self.testapp.get(
                '/contents/{}@draft.json'.format(book['id']), status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
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
            u'authors': [SUBMITTER],
            u'publishers': [SUBMITTER],
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
            u'publication': None,
            u'editors': [],
            u'translators': [],
            u'licensors': [],
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
        document = json.loads(response.body.decode('utf-8'))

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
        binder = json.loads(response.body.decode('utf-8'))

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
        document = json.loads(response.body.decode('utf-8'))
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
        self.mock_archive()

        response = self.testapp.post_json('/users/contents',
                post_data, status=201)
        page = json.loads(response.body.decode('utf-8'))
        self.assert_cors_headers(response)

        post_data = {
                'content': '<html><body><p>Page content</p></body></html>',
                }
        response = self.testapp.put_json(
                '/contents/{}@draft.json'.format(page['id']),
                post_data, status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['content'], post_data['content'])
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
        binder = json.loads(response.body.decode('utf-8'))
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
        post_data = {
                'derivedFrom': u'feda4909-5bbd-431e-a017-049aff54416d@1.1',
            }
        self.mock_archive()

        response = self.testapp.post_json('/users/contents',
                post_data, status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.assert_cors_headers(response)

        update_data = {
                'title': u'...',
                'tree': {
                    'contents': [{
                        u'id': u'7d089006-5a95-4e24-8e04-8168b5c41aa3@1',
                        u'title': u'Hygiene',
                        }],
                    },
                'licensors': [SUBMITTER],
                }
        response = self.testapp.put_json(
                '/contents/{}@draft.json'.format(result['id']),
                update_data, status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [SUBMITTER],
            u'publishers': [SUBMITTER],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Madlavning',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(post_data['derivedFrom']),
            u'abstract': u'',
            u'containedIn': [],
            u'content': u'',
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.collection',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'title': u'...',
            u'tree': {
                    u'id': u'{}@draft'.format(result['id']),
                    u'title': u'...',
                    u'contents': [{
                        u'id': u'7d089006-5a95-4e24-8e04-8168b5c41aa3@1',
                        u'title': u'Hygiene',
                        }],
                    },
            u'subjects': [u'Arts',],
            u'keywords': [u'køkken', u'Madlavning'],
            u'state': u'Draft',
            u'publication': None,
            u'editors': [],
            u'translators': [],
            u'licensors': [SUBMITTER],
            })
        self.assert_cors_headers(response)

        response = self.testapp.get(
                '/contents/{}@draft.json'.format(result['id']),
                status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': SUBMITTER,
            u'authors': [SUBMITTER],
            u'publishers': [SUBMITTER],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'derivedFromTitle': u'Madlavning',
            u'derivedFromUri': u'http://cnx.org/contents/{}'.format(post_data['derivedFrom']),
            u'abstract': u'',
            u'containedIn': [],
            u'content': u'',
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.collection',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            u'title': u'...',
            u'tree': {
                    u'id': u'{}@draft'.format(result['id']),
                    u'title': u'...',
                    u'contents': [{
                        u'id': u'7d089006-5a95-4e24-8e04-8168b5c41aa3@1',
                        u'title': u'Hygiene',
                        }],
                    },
            u'subjects': [u'Arts'],
            u'keywords': [u'køkken', u'Madlavning'],
            u'state': u'Draft',
            u'publication': None,
            u'editors': [],
            u'translators': [],
            u'licensors': [SUBMITTER],
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
        binder = json.loads(response.body.decode('utf-8'))

        response = self.testapp.post_json('/users/contents',
                {'title': 'Empty page'}, status=201)
        page = json.loads(response.body.decode('utf-8'))

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
                        },
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'content': '',
                    'state': 'Draft',
                    'version': 'draft',
                    'submitter': SUBMITTER,
                    'authors': [SUBMITTER],
                    'publishers': [SUBMITTER],
                    'error': False,
                    }, status=200)

        response = self.testapp.get(
                '/contents/{}@draft.json'.format(binder['id']), status=200)
        result = json.loads(response.body.decode('utf-8'))
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
        response = self.testapp.post_json('/users/contents', {
                    'title': u'My document タイトル',
                    'abstract': u'My document abstract',
                    'language': u'en'}, status=201)
        document = json.loads(response.body.decode('utf-8'))
        self.assert_cors_headers(response)

        update_data = {
            'title': u"Turning DNA through resonance",
            'abstract': u"Theories on turning DNA structures",
            'content': u"Ding dong the switch is flipped.",
            'keywords': ['DNA', 'resonance'],
            'subjects': ['Science and Technology'],
            }

        response = self.testapp.put_json(
                '/contents/{}@draft.json'.format(document['id']),
                update_data, status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['id'], document['id'])
        self.assertEqual(result['title'], update_data['title'])
        self.assertEqual(result['abstract'], update_data['abstract'])
        self.assertEqual(result['language'], document['language'])
        self.assertEqual(result['content'], update_data['content'])
        self.assertEqual(result['keywords'], update_data['keywords'])
        self.assertEqual(result['subjects'], update_data['subjects'])

        response = self.testapp.get('/contents/{}@draft.json'.format(document['id']))
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['id'], document['id'])
        self.assertEqual(result['title'], update_data['title'])
        self.assertEqual(result['abstract'], update_data['abstract'])
        self.assertEqual(result['language'], document['language'])
        self.assertEqual(result['content'], update_data['content'])
        self.assertEqual(result['keywords'], update_data['keywords'])
        self.assertEqual(result['subjects'], update_data['subjects'])
        self.assert_cors_headers(response)

    def test_delete_content_401(self):
        self.logout()
        response = self.testapp.delete('/contents/{}@draft.json'.format(id),
                status=401)
        self.assert_cors_headers(response)

    def test_delete_content_403(self):
        response = self.testapp.post_json('/users/contents',
                {'title': 'My page'}, status=201)
        page = json.loads(response.body.decode('utf-8'))
        self.assert_cors_headers(response)

        self.logout()
        self.login('you')
        response = self.testapp.delete(
                '/contents/{}@draft.json'.format(page['id']), status=403)
        self.assert_cors_headers(response)

    def test_delete_content(self):
        response = self.testapp.post_json('/users/contents',
                {'title': 'My page'}, status=201)
        page = json.loads(response.body.decode('utf-8'))
        self.assert_cors_headers(response)

        # test that it's possible to get the content we just created
        response = self.testapp.get(
                '/contents/{}@draft.json'.format(page['id']), status=200)

        # delete the content
        response = self.testapp.delete(
                '/contents/{}@draft.json'.format(page['id']), status=200)
        self.assert_cors_headers(response)

        response = self.testapp.get(
                '/contents/{}@draft.json'.format(page['id']), status=404)

    def test_search_content_401(self):
        self.logout()
        response = self.testapp.get('/search', status=401)
        self.assert_cors_headers(response)

    def test_search_content_no_q(self):
        response = self.testapp.get('/search', status=200)
        result = json.loads(response.body.decode('utf-8'))
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
        result = json.loads(response.body.decode('utf-8'))
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
        self.login('user1')
        post_data = {'title': u'Document'}
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        self.assert_cors_headers(response)

        response = self.testapp.get('/search?q="Document', status=200)
        result = json.loads(response.body.decode('utf-8'))
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
        result = json.loads(response.body.decode('utf-8'))
        doc_id = result['id']
        self.assert_cors_headers(response)

        post_data = {'title': u'New stuff'}
        response = self.testapp.post_json('/users/contents', post_data, status=201)
        result = json.loads(response.body.decode('utf-8'))
        new_doc_id = result['id']
        self.assert_cors_headers(response)

        # should not be able to get other user's documents
        response = self.testapp.get('/search?q=document', status=200)
        result = json.loads(response.body.decode('utf-8'))
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
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['results']['total'], 1)
        self.assertEqual(result['results']['items'][0]['id'],
                '{}@draft'.format(doc_id))
        self.assert_cors_headers(response)

        # should be able to search multiple terms
        response = self.testapp.get('/search?q=new+resonance', status=200)
        result = json.loads(response.body.decode('utf-8'))
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
        result = json.loads(response.body.decode('utf-8'))
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

    def test_user_search_no_q(self):
        response = self.testapp.get('/users/search')
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, {
            u'num_matching_users': 0,
            u'per_page': 20,
            u'users': [],
            u'order_by': u'username ASC',
            u'page': 0,
            })
        self.assert_cors_headers(response)

    def test_user_search_q_empty(self):
        response = self.testapp.get('/users/search?q=')
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, {
            u'num_matching_users': 0,
            u'per_page': 20,
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
                u'per_page': 20,
                u'page': 0}
        with mock.patch('openstax_accounts.stub.OpenstaxAccounts.search'
                       ) as accounts_search:
            accounts_search.return_value = mock_accounts_search_results
            response = self.testapp.get('/users/search?q=admin')
        result = json.loads(response.body.decode('utf-8'))
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
            u'per_page': 20,
            u'page': 0,
            })
        self.assert_cors_headers(response)

    def test_profile_401(self):
        self.logout()
        response = self.testapp.get('/users/profile', status=401)
        self.assert_cors_headers(response)

    def test_profile(self):
        response = self.testapp.get('/users/profile', status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, SUBMITTER)
        self.assert_cors_headers(response)

    def test_user_contents_401(self):
        self.logout()
        response = self.testapp.get('/users/contents', status=401)
        self.assert_cors_headers(response)

    def test_user_contents(self):
        response = self.testapp.post_json('/users/contents',
                {'title': 'document by default user'}, status=201)

        # a user should not get any contents that doesn't belong to themselves
        self.logout()
        self.login('user4')
        response = self.testapp.get('/users/contents', status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, {
            u'query': {
                u'limits': [],
                },
            u'results': {
                u'items': [],
                u'total': 0,
                u'limits': [],
                },
            })
        self.assert_cors_headers(response)

        response = self.testapp.post_json('/users/contents', {
            'title': 'document by user4',
            'created': u'2014-03-13T15:21:15.677617-05:00',
            'revised': u'2014-03-13T15:21:15.677617-05:00',
            }, status=201)
        page = json.loads(response.body.decode('utf-8'))

        #user should get back the contents just posted - full content test
        response = self.testapp.get('/users/contents', status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, {
            u'query': {
                u'limits': [],
                },
            u'results': {u'items': [{u'derivedFrom': None,
                           u'containedIn': [],
                           u'id': u'{}@draft'.format(page['id']),
                           u'mediaType': u'application/vnd.org.cnx.module',
                           u'revised': u'2014-03-13T15:21:15.677617-05:00',
                           u'state': u'Draft',
                           u'title': u'document by user4',
                           u'version': u'draft'}],
               u'limits': [],
               u'total': 1}
            })

        self.assert_cors_headers(response)


        self.mock_archive()

        one_week_ago = datetime.datetime.now() - datetime.timedelta(7)
        two_weeks_ago = datetime.datetime.now() - datetime.timedelta(14)

        mock_datetime = mock.Mock()
        mock_datetime.now = mock.Mock(return_value=one_week_ago)
        with mock.patch('datetime.datetime', mock_datetime):
            response = self.testapp.post_json('/users/contents',
                    {'derivedFrom': '91cb5f28-2b8a-4324-9373-dac1d617bc24@1'},
                    status=201)
        self.assert_cors_headers(response)

        mock_datetime.now = mock.Mock(return_value=two_weeks_ago)
        with mock.patch('datetime.datetime', mock_datetime):
            response = self.testapp.post_json('/users/contents',
                    {'title': 'oldest document by user4'}, status=201)
        self.assert_cors_headers(response)

        response = self.testapp.post_json('/users/contents',
                {'title': 'new document by user4'}, status=201)
        self.assert_cors_headers(response)

        response = self.testapp.get('/users/contents', status=200)
        result = json.loads(response.body.decode('utf-8'))
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
        self.assertEqual(derived_from, [None,
            '91cb5f28-2b8a-4324-9373-dac1d617bc24@1', None, None])

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

        single_page = json.loads(response.body.decode('utf-8'))

        mock_datetime.now = mock.Mock(return_value=one_week_ago)
        with mock.patch('datetime.datetime', mock_datetime):
            response = self.testapp.post_json('/users/contents',
                {'title': 'page in a book'}, status=201)
        page_in_book = json.loads(response.body.decode('utf-8'))

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
        book = json.loads(response.body.decode('utf-8'))

        # since page_in_book is in book, it should not show in the workspace
        response = self.testapp.get('/users/contents', status=200)
        workspace = json.loads(response.body.decode('utf-8'))
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
                        },
                    ],
                u'total': 2,
                u'limits': [],
                },
            })

        # remove page_in_book from book and add single_page to book
        self.testapp.put_json('/contents/{}@draft.json'.format(book['id']), {
                    'tree': {
                        'contents': [
                            {
                                'id': '{}@draft'.format(single_page['id']),
                                },
                            ],
                        },
                    }, status=200)

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
        other_book = json.loads(response.body.decode('utf-8'))
        self.logout()
        self.login('user5')

        # workspace should now show page_in_book and book
        response = self.testapp.get('/users/contents', status=200)
        workspace = json.loads(response.body.decode('utf-8'))
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
                        },
                    ],
                u'total': 2,
                u'limits': [],
                },
            })

        # retrieve just pages, should now show all pages
        response = self.testapp.get('/users/contents?mediaType=application/vnd.org.cnx.module', status=200)
        workspace = json.loads(response.body.decode('utf-8'))
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
                        },
                    ],
                u'total': 2,
                u'limits': [],
                },
            })

        # Now filter for not:Draft - should supress all
        response = self.testapp.get('/users/contents?state=not:Draft', status=200)
        workspace = json.loads(response.body.decode('utf-8'))
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
    # When USE_MOCK_PUBLISHING_SERVICE is set to False, the publication tests
    # will post directly to the publishing service configured in testing.ini.
    # It can be used to do some manual integration testing between
    # cnx-authoring and cnx-publishing.  The response from cnx-publishing will
    # be printed out as a failure message in the tests.
    #
    # USE_MOCK_PUBLISHING_SERVICE should be set to True when not testing
    # manually
    USE_MOCK_PUBLISHING_SERVICE = True

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
        page = json.loads(response.body.decode('utf-8'))

        post_data = {
                'submitlog': u'Nueva versión!',
                'items': [
                    page['id'],
                    ],
                }
        with mock.patch('cnxauthoring.models.Document.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.post_json('/publish', post_data, status=403)
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
        book = json.loads(response.body.decode('utf-8'))

        post_data = {
                'submitlog': u'Nueva versión!',
                'items': [
                    book['id'],
                    ],
                }
        with mock.patch('cnxauthoring.models.Binder.__acl__') as acl:
            acl.return_value = ()
            response = self.testapp.post_json('/publish', post_data, status=403)
        self.assertTrue('You do not have permission to publish'
                    in response.body.decode('utf-8'))


    def test_publish_service_not_available(self):
        post_data = {
                'title': 'Page one',
                'content': '<html><body><p>Contents of Page one</p></body></html>',
                }
        response = self.testapp.post_json('/users/contents', post_data, status=201)
        page = json.loads(response.body.decode('utf-8'))

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
        page = json.loads(response.body.decode('utf-8'))

        post_data = {
                'submitlog': 'Publishing is working!',
                'items': [
                    page['id'],
                    ],
                }
        with mock.patch('requests.post') as patched_post:
            patched_post.return_value = mock.Mock(status_code=200, content=b'not json')
            response = self.testapp.post_json('/publish', post_data, status=400)
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
        page_one = json.loads(response.body.decode('utf-8'))
        post_data = {
                'title': u'Página dos',
                'content': u'<html><body><p>Contents of Página dos</p></body></html>',
                'language': 'es',
                }
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        page_two = json.loads(response.body.decode('utf-8'))

        post_data = {
                'submitlog': u'Nueva versión!',
                'items': [
                    page_one['id'],
                    page_two['id'],
                    ],
                }
        if not self.USE_MOCK_PUBLISHING_SERVICE:
            response = self.testapp.post_json(
                    '/publish', post_data, expect_errors=True)
            self.fail('\nResposne status: {}\nResponse body: {}\n'.format(
                response.status, response.body))
        mock_output = json.dumps({u'state': u'Processing', u'publication': 143,
            u'mapping': {
                page_one['id']: '{}@1'.format(page_one['id']),
                page_two['id']: '{}@1'.format(page_two['id']),
                },
            }).encode('utf-8')
        with mock.patch('requests.post') as patched_post:
            patched_post.return_value = mock.Mock(status_code=200, content=mock_output)
            response = self.testapp.post_json('/publish', post_data, status=200)
            self.assertEqual(patched_post.call_count, 1)
            args, kwargs = patched_post.call_args
        self.assertEqual(args, ('http://localhost:6543/publications',))
        self.assertEqual(kwargs['headers'], {'x-api-key': 'b07'})

        filename, epub, content_type = kwargs['files']['epub']
        self.assertEqual(filename, 'contents.epub')
        self.assertEqual(content_type, 'application/epub+zip')
        parsed_epub = cnxepub.EPUB.from_file(io.BytesIO(epub))
        package = parsed_epub[0]
        binder = cnxepub.adapt_package(package)
        self.assertEqual(binder.metadata, {'title': 'Publications binder'})
        self.assertEqual(package.metadata['publication_message'],
            u'Nueva versión!')

        documents = list(cnxepub.flatten_to_documents(binder))
        self.assertEqual(documents[0].id, page_one['id'])
        self.assertEqual(documents[0].metadata['title'], u'Page one')
        self.assertEqual(documents[0].metadata['language'], u'en')
        self.assertTrue('Learn how to etc etc' in documents[0].metadata['summary'])

        self.assertEqual(documents[1].id, page_two['id'])
        self.assertEqual(documents[1].metadata['title'], u'Página dos')
        self.assertEqual(documents[1].metadata['language'], u'es')

        self.assertEqual(json.loads(response.body.decode('utf-8')),
                json.loads(mock_output.decode('utf-8')))

        self.assert_cors_headers(response)

        with mock.patch('requests.get') as patched_get:
            patched_get.return_value = mock.Mock(status_code=200, content=mock_output)
            response = self.testapp.get('/contents/{}@draft.json'
                    .format(page_one['id']))
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['state'], 'Processing')
        self.assertEqual(result['publication'], '143')

        with mock.patch('requests.get') as patched_get:
            patched_get.return_value = mock.Mock(status_code=200, content=mock_output)
            response = self.testapp.get('/contents/{}@draft.json'
                    .format(page_two['id']))
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['state'], 'Processing')
        self.assertEqual(result['publication'], '143')

    def test_publish_derived_from_single_page(self):
        post_data = {
                'derivedFrom': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
                }
        self.mock_archive(content_type='image/jpeg')
        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        page = json.loads(response.body.decode('utf-8'))

        post_data = {
                'submitlog': 'Publishing is working!',
                'items': [
                    '{}@draft'.format(page['id']),
                    ],
                }
        if not self.USE_MOCK_PUBLISHING_SERVICE:
            response = self.testapp.post_json(
                    '/publish', post_data, expect_errors=True)
            self.fail('\nResposne status: {}\nResponse body: {}\n'.format(
                response.status, response.body))
        mock_output = json.dumps({u'state': u'Processing', u'publication': 144,
            u'mapping': {page['id']: '{}@1'.format(page['id'])}}).encode('utf-8')
        with mock.patch('requests.post') as patched_post:
            patched_post.return_value = mock.Mock(status_code=200, content=mock_output)
            response = self.testapp.post_json('/publish', post_data, status=200)
            self.assertEqual(patched_post.call_count, 1)
            args, kwargs = patched_post.call_args
        self.assertEqual(args, ('http://localhost:6543/publications',))
        filename, epub, content_type = kwargs['files']['epub']
        self.assertEqual(filename, 'contents.epub')
        self.assertEqual(content_type, 'application/epub+zip')
        parsed_epub = cnxepub.EPUB.from_file(io.BytesIO(epub))
        package = parsed_epub[0]
        binder = cnxepub.adapt_package(package)
        self.assertEqual(binder.metadata, {'title': 'Publications binder'})
        self.assertEqual(package.metadata['publication_message'],
                u'Publishing is working!')
        documents = list(cnxepub.flatten_to_documents(binder))
        self.assertEqual(documents[0].id, page['id'])
        self.assertEqual(documents[0].metadata['title'], u'Copy of Indkøb')
        self.assertEqual(documents[0].metadata['language'], u'da')
        self.assertEqual(documents[0].metadata['derived_from_uri'],
                         'http://cnx.org/contents/91cb5f28-2b8a-4324-9373-dac1d617bc24@1')
        self.assertEqual(documents[0].metadata['derived_from_title'], u'Indkøb')
        self.assertEqual(len(documents[0].resources), 2)
        self.assertEqual(documents[0].references[0].uri,
                         'http://www.rema1000.dk/Madplanen.aspx')
        self.assertEqual(documents[0].references[1].uri,
                         '../resources/0f3da0de61849a47f77543c383d1ac621b25e6e0')
        self.assertEqual(documents[0].references[2].uri,
                         '../resources/0405557b301a1b689df0f02566bec761d7783232')

        self.assertEqual(json.loads(response.body.decode('utf-8')),
                json.loads(mock_output.decode('utf-8')))

        self.assert_cors_headers(response)

        with mock.patch('requests.get') as patched_get:
            patched_get.return_value = mock.Mock(status_code=200,
                    content=mock_output.replace(b'Processing', b'Publishing'))
            response = self.testapp.get('/contents/{}@draft.json'
                    .format(page['id']))
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['state'], 'Publishing')
        self.assertEqual(result['publication'], '144')

    def test_publish_binder(self):
        response = self.testapp.post_json('/users/contents', {
                    'title': 'Page one',
                    'content': '<html><body><p>Content of page one</p></body></html>',
                    'abstract': 'Learn how to etc etc',
                    }, status=201)
        page1 = json.loads(response.body.decode('utf-8'))
        self.assert_cors_headers(response)

        response = self.testapp.post_json('/users/contents', {
                    'title': 'Page two',
                    'content': '<html><body><p>Content of page two</p></body></html>'
                    }, status=201)
        page2 = json.loads(response.body.decode('utf-8'))
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
        binder = json.loads(response.body.decode('utf-8'))

        post_data = {
                'submitlog': 'Publishing a book is working?',
                'items': [
                    binder['id'],
                    page1['id'],
                    page2['id'],
                    ],
                }
        if not self.USE_MOCK_PUBLISHING_SERVICE:
            response = self.testapp.post_json(
                    '/publish', post_data, expect_errors=True)
            self.fail('\nResposne status: {}\nResponse body: {}\n'.format(
                response.status, response.body))
        mock_output = json.dumps({
            'state': 'Processing',
            'publication': 145,
            'mapping': {
                binder['id']: '{}@1.1'.format(binder['id']),
                page1['id']: '{}@1'.format(page1['id']),
                page2['id']: '{}@1'.format(page2['id']),
                }
            }).encode('utf-8')
        with mock.patch('requests.post') as patched_post:
            patched_post.return_value = mock.Mock(status_code=200, content=mock_output)
            response = self.testapp.post_json(
                    '/publish', post_data, status=200)
            self.assertEqual(patched_post.call_count, 1)
            args, kwargs = patched_post.call_args

        self.assertEqual(args, ('http://localhost:6543/publications',))
        self.assertEqual(kwargs['headers'], {'x-api-key': 'b07'})
        filename, epub, content_type = kwargs['files']['epub']
        self.assertEqual(filename, 'contents.epub')
        self.assertEqual(content_type, 'application/epub+zip')
        parsed_epub = cnxepub.EPUB.from_file(io.BytesIO(epub))
        package = parsed_epub[0]
        publication_binder = cnxepub.adapt_package(package)
        self.assertEqual(publication_binder.metadata['title'], 'Book')
        self.assertTrue('Book abstract' in publication_binder.metadata['summary'])
        self.assertEqual(publication_binder.metadata['cnx-archive-uri'], binder['id'])
        self.assertEqual(package.metadata['publication_message'],
                u'Publishing a book is working?')

        tree = cnxepub.models.model_to_tree(publication_binder)
        self.assertEqual(tree, {
            'id': binder['id'],
            'title': 'Book',
            'contents': [
                {'id': page1['id'], 'title': 'Page one'},
                {'id': 'subcol', 'title': 'New section', 'contents': [
                    {'id': page2['id'], 'title': 'Page two'},
                    ]},
                ],
            })

        documents = list(cnxepub.flatten_to_documents(publication_binder))
        self.assertEqual(documents[0].id, page1['id'])
        self.assertEqual(documents[0].metadata['title'], u'Page one')
        self.assertEqual(documents[0].metadata['language'], u'en')
        self.assertTrue('Learn how to etc etc' in documents[0].metadata['summary'])

    def test_publish_derived_from_binder(self):
        self.mock_archive()
        post_data = {
                'derivedFrom': u'feda4909-5bbd-431e-a017-049aff54416d@1.1',
            }

        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        binder = json.loads(response.body.decode('utf-8'))
        self.assert_cors_headers(response)

        post_data = {
                'submitlog': 'Publishing a derived book',
                'items': [
                    binder['id'],
                    ],
                }
        if not self.USE_MOCK_PUBLISHING_SERVICE:
            response = self.testapp.post_json(
                    '/publish', post_data, expect_errors=True)
            self.fail('\nResposne status: {}\nResponse body: {}\n'.format(
                response.status, response.body))
        mock_output = json.dumps({
            'state': 'Done/Success',
            'publication': 200,
            'mapping': {
                binder['id']: '{}@1.1'.format(binder['id']),
                },
            }).encode('utf-8')
        with mock.patch('requests.post') as patched_post:
            patched_post.return_value = mock.Mock(status_code=200, content=mock_output)
            response = self.testapp.post_json(
                    '/publish', post_data, status=200)
            self.assertEqual(patched_post.call_count, 1)
            args, kwargs = patched_post.call_args

        self.assertEqual(args, ('http://localhost:6543/publications',))
        self.assertEqual(kwargs['headers'], {'x-api-key': 'b07'})
        filename, epub, content_type = kwargs['files']['epub']
        self.assertEqual(filename, 'contents.epub')
        self.assertEqual(content_type, 'application/epub+zip')

        parsed_epub = cnxepub.EPUB.from_file(io.BytesIO(epub))
        package = parsed_epub[0]
        publication_binder = cnxepub.adapt_package(package)
        self.assertEqual(publication_binder.metadata['title'], 'Copy of Madlavning')
        self.assertEqual(publication_binder.metadata['cnx-archive-uri'], binder['id'])
        self.assertEqual(package.metadata['publication_message'],
                         'Publishing a derived book')
        self.assertEqual(publication_binder.metadata['derived_from_uri'],
                         'http://cnx.org/contents/feda4909-5bbd-431e-a017-049aff54416d@1.1')
        self.assertEqual(publication_binder.metadata['derived_from_title'],
                         'Madlavning')

        tree = cnxepub.models.model_to_tree(publication_binder)
        self.assertEqual(tree, {
            'id': binder['id'],
            'title': 'Copy of Madlavning',
            'contents': [
                {'id': '91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
                 'title': u'Indkøb'},
                {'id': 'subcol',
                 'title': u'Fødevarer og Hygiejne',
                 'contents': [
                     {'id': 'f6b979cb-8904-4265-bf2d-f059cc362217@1',
                      'title': u'Fødevarer'},
                     {'id': '7d089006-5a95-4e24-8e04-8168b5c41aa3@1',
                      'title': u'Hygiejne'},
                     ]},
                {'id': 'b0db72d9-fac3-4b43-9926-7e6e801663fb@1',
                 'title': u'Tilberedning'},
                ],
            })

        models = list(cnxepub.flatten_model(publication_binder))
        self.assertEqual(len(models), 6)
        self.assertEqual(models[0].metadata['title'], u'Copy of Madlavning')
        self.assertEqual(models[1].metadata['title'], u'Indkøb')
        self.assertEqual(models[2].metadata['title'], u'Fødevarer og Hygiejne')
        self.assertEqual(models[3].metadata['title'], u'Fødevarer')

    def test_publish_revision_single_page(self):
        self.mock_archive(content_type='image/jpeg')
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

        response = self.testapp.post_json(
                '/users/contents', post_data, status=201)
        self.assert_cors_headers(response)
        page = json.loads(response.body.decode('utf-8'))

        post_data = {
                'submitlog': 'Publishing a revision',
                'items': [
                    page['id'],
                    ],
                }
        if not self.USE_MOCK_PUBLISHING_SERVICE:
            response = self.testapp.post_json(
                    '/publish', post_data, expect_errors=True)
            self.fail('\nResposne status: {}\nResponse body: {}\n'.format(
                response.status, response.body))
        mock_output = json.dumps({
            'state': 'Done/Success',
            'publication': 201,
            'mapping': {
                page['id']: '{}@2'.format(page['id']),
                },
            }).encode('utf-8')
        with mock.patch('requests.post') as patched_post:
            patched_post.return_value = mock.Mock(status_code=200, content=mock_output)
            response = self.testapp.post_json(
                    '/publish', post_data, status=200)
            self.assertEqual(patched_post.call_count, 1)
            args, kwargs = patched_post.call_args

        self.assertEqual(args, ('http://localhost:6543/publications',))
        self.assertEqual(kwargs['headers'], {'x-api-key': 'b07'})
        filename, epub, content_type = kwargs['files']['epub']
        self.assertEqual(filename, 'contents.epub')
        self.assertEqual(content_type, 'application/epub+zip')

        parsed_epub = cnxepub.EPUB.from_file(io.BytesIO(epub))
        package = parsed_epub[0]
        publication_binder = cnxepub.adapt_package(package)
        self.assertEqual(publication_binder.metadata,
                         {'title': 'Publications binder'})
        self.assertEqual(package.metadata['publication_message'],
                         'Publishing a revision')

        documents = list(cnxepub.flatten_to_documents(publication_binder))
        self.assertEqual(documents[0].id, page['id'])
        self.assertEqual(documents[0].get_uri('cnx-archive'), page['id'])
