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
import unittest
import uuid
try:
    from unittest import mock
except ImportError:
    import mock

from pyramid import httpexceptions
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from webtest import Upload
from zope.interface import implementer

from . import test_data
from ..models import DEFAULT_LICENSE


@implementer(IAuthenticationPolicy)
class MockAuthenticationPolicy(object):

    def authenticated_userid(self, request):
        return self.unauthenticated_userid(request)

    def unauthenticated_userid(self, request):
        return FunctionalTests.profile and FunctionalTests.profile.get('username')

    def effective_principals(self, request):
        groups = [Everyone]
        if self.authenticated_userid(request):
            groups.append(Authenticated)
        return groups

    def remember(self, request, principal, **kw):
        pass

    def forget(self, request):
        FunctionalTests.profile = None


def get_user(request):
    return FunctionalTests.profile


def mock_authentication_policy(config):
    config.add_request_method(get_user, 'user', reify=True)
    settings = config.registry.settings
    config.set_authentication_policy(MockAuthenticationPolicy())


def mock_openstax_accounts(config):
    from openstax_accounts.interfaces import IOpenstaxAccounts
    accounts = mock.MagicMock()
    accounts.request.side_effect = lambda *args, **kwargs: (
        FunctionalTests.accounts_request_return)
    config.registry.registerUtility(accounts, IOpenstaxAccounts)


class FunctionalTests(unittest.TestCase):
    profile = None
    accounts_request_return = ''
    maxDiff = None

    @classmethod
    def setUpClass(self):
        # only run once for all the tests

        # make sure storage is set correctly in cnxauthoring.views by reloading
        # cnxauthoring.views
        if 'cnxauthoring.views' in sys.modules:
            del sys.modules['cnxauthoring.views']

        # Mock all the openstax accounts code
        from openstax_accounts import openstax_accounts
        openstax_accounts.main = mock_openstax_accounts
        from openstax_accounts import authentication_policy
        authentication_policy.main = mock_authentication_policy

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
        FunctionalTests.profile = {u'username': u'me'}

    def test_login(self):
        FunctionalTests.profile = None
        def authenticated_userid(*args):
            raise httpexceptions.HTTPFound(
                    location='http://example.com/login_form')
        with mock.patch.object(MockAuthenticationPolicy, 'authenticated_userid',
                side_effect=authenticated_userid):
            response = self.testapp.get('/login', status=302)
        # user logs in successfully
        FunctionalTests.profile = {'username': 'me'}
        response = self.testapp.get('/callback', status=302)
        self.assertEqual(response.headers['Location'], 'http://localhost/')

    def test_login_redirect_already_logged_in(self):
        response = self.testapp.get('/login?redirect=http://example.com/logged_in',
                status=302)
        self.assertEqual(response.headers['Location'],
                'http://example.com/logged_in')
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_login_redirect_loop(self):
        FunctionalTests.profile = None
        def authenticated_userid(*args):
            raise httpexceptions.HTTPFound(
                    location='http://example.com/login_form')
        with mock.patch.object(MockAuthenticationPolicy, 'authenticated_userid',
                side_effect=authenticated_userid):
            response = self.testapp.get('/login',
                    headers={'REFERER': 'http://localhost/login'},
                    status=302)
        # user logs in successfully
        FunctionalTests.profile = {'username': 'me'}
        response = self.testapp.get('/callback', status=302)
        self.assertEqual(response.headers['Location'], 'http://localhost/')

    def test_login_redirect_referer(self):
        FunctionalTests.profile = None
        def authenticated_userid(*args):
            raise httpexceptions.HTTPFound(
                    location='http://example.com/login_form')
        with mock.patch.object(MockAuthenticationPolicy, 'authenticated_userid',
                side_effect=authenticated_userid):
            response = self.testapp.get('/login',
                    headers={'REFERER': 'http://example.com/'},
                    status=302)
        # user logs in successfully
        FunctionalTests.profile = {'username': 'me'}
        response = self.testapp.get('/callback', status=302)
        self.assertEqual(response.headers['Location'], 'http://example.com/')

    def test_login_redirect(self):
        FunctionalTests.profile = None
        def authenticated_userid(*args):
            raise httpexceptions.HTTPFound(
                    location='http://example.com/login_form')
        with mock.patch.object(MockAuthenticationPolicy, 'authenticated_userid',
                side_effect=authenticated_userid):
            response = self.testapp.get(
                    '/login?redirect=http://example.com/logged_in',
                    status=302)
        # user logs in successfully
        FunctionalTests.profile = {'username': 'me'}
        response = self.testapp.get('/callback', status=302)
        self.assertEqual(response.headers['Location'], 'http://example.com/logged_in')

    def test_logout_redirect_loop(self):
        response = self.testapp.get('/logout',
                headers={'REFERER': 'http://localhost/logout'},
                status=302)
        self.assertEqual(response.headers['Location'], 'http://localhost/')
        self.assertEqual(FunctionalTests.profile, None)

    def test_logout_redirect_referer(self):
        response = self.testapp.get('/logout',
                headers={'REFERER': 'http://example.com/logged_out'},
                status=302)
        self.assertEqual(response.headers['Location'],
                'http://example.com/logged_out')
        self.assertEqual(FunctionalTests.profile, None)

    def test_logout_redirect(self):
        response = self.testapp.get(
                '/logout?redirect=http://example.com/logged_out',
                headers={'REFERER': 'http://example.com/'},
                status=302)
        self.assertEqual(response.headers['Location'],
                'http://example.com/logged_out')
        self.assertEqual(FunctionalTests.profile, None)

    def test_get_content_403(self):
        FunctionalTests.profile = None
        self.testapp.get('/contents/1234abcde@draft.json', status=403)

    def test_get_content_404(self):
        self.testapp.get('/contents/1234abcde@draft.json', status=404)

    def test_get_content_for_document(self):
        response = self.testapp.post('/contents',
                json.dumps({
                    'title': 'My New Document',
                    'created': u'2014-03-13T15:21:15',
                    'revised': u'2014-03-13T15:21:15',
                    }),
                status=201)
        put_result = json.loads(response.body.decode('utf-8'))
        response = self.testapp.get('/contents/{}@draft.json'.format(put_result['id']),
                status=200)
        get_result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(get_result, {
            u'id': get_result['id'],
            u'title': u'My New Document',
            u'content': None,
            u'created': get_result['created'],
            u'derivedFrom': None,
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0',
                },
            u'revised': get_result['revised'],
            u'mediaType': u'application/vnd.org.cnx.module',
            u'language': u'en',
            u'submitter': u'me',
            u'abstract': None,
            u'version': u'draft',
            })
        self.assertEqual(put_result, get_result)
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_post_content_403(self):
        FunctionalTests.profile = None
        self.testapp.post('/contents', status=403)

    def test_post_content_invalid_json(self):
        response = self.testapp.post('/contents', 'invalid json', status=400)
        self.assertTrue('Invalid JSON' in response.body.decode('utf-8'))

    def test_post_content_empty(self):
        response = self.testapp.post('/contents', '{}', status=400)
        self.assertEqual(json.loads(response.body.decode('utf-8')), {
            u'title': u'Required',
            })

    def test_post_content_empty_binder(self):
        response = self.testapp.post('/contents',
                json.dumps({
                    'mediaType': 'application/vnd.org.cnx.collection',
                    }), status=400)
        self.assertEqual(json.loads(response.body.decode('utf-8')), {
            u'title': u'Required',
            u'tree': u'Required',
            })

    def test_post_content_minimal(self):
        response = self.testapp.post('/contents', 
                json.dumps({'title': u'My document タイトル'}),
                status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['title'], u'My document タイトル')
        self.assertEqual(result['language'], u'en')
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

        self.testapp.get('/contents/{}@draft.json'.format(result['id']),
                status=200)

    def test_post_content_minimal_binder(self):
        response = self.testapp.post('/contents',
                json.dumps({
                    'title': u'My book タイトル',
                    'mediaType': 'application/vnd.org.cnx.collection',
                    'tree': {
                        'contents': [],
                        },
                    }), status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['title'], u'My book タイトル')
        self.assertEqual(result['language'], u'en')
        self.assertEqual(result['tree'], {
            u'contents': [],
            u'id': '{}@draft'.format(result['id']),
            u'title': result['title'],
            })

        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

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

    def test_post_content_multiple(self):
        post_data = [
                {'title': u'My document タイトル 1'},
                {'title': u'My document タイトル 2'},
                ]
        response = self.testapp.post('/contents', 
                json.dumps(post_data), status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['title'], u'My document タイトル 1')
        self.assertEqual(result[1]['title'], u'My document タイトル 2')
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

        self.testapp.get('/contents/{}@draft.json'.format(result[0]['id']),
                status=200)
        self.testapp.get('/contents/{}@draft.json'.format(result[1]['id']),
                status=200)

    def test_post_content_derived_from_not_found(self):
        post_data = {
                'derivedFrom': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
            }
        try:
            import urllib2 # python2
        except ImportError:
            import urllib.request as urllib2 # renamed in python3

        def patched_urlopen(*args, **kwargs):
            raise urllib2.HTTPError(args[0], 404, 'Not Found', None, None)

        urlopen = urllib2.urlopen
        urllib2.urlopen = patched_urlopen
        self.addCleanup(setattr, urllib2, 'urlopen', urlopen)

        response = self.testapp.post('/contents',
                json.dumps(post_data),
                status=400)
        self.assertTrue(b'Derive failed' in response.body)

    def test_post_content_derived_from_not_json(self):
        post_data = {
                'derivedFrom': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
            }
        def patched_urlopen(*args, **kwargs):
            return io.BytesIO(b'invalid json')
        try:
            import urllib2 # python2
        except ImportError:
            import urllib.request as urllib2 # renamed in python3
        urlopen = urllib2.urlopen
        urllib2.urlopen = patched_urlopen
        self.addCleanup(setattr, urllib2, 'urlopen', urlopen)

        response = self.testapp.post('/contents',
                json.dumps(post_data),
                status=400)
        self.assertTrue(b'Derive failed' in response.body)

    def test_post_content_derived_from(self):
        post_data = {
                'derivedFrom': u'91cb5f28-2b8a-4324-9373-dac1d617bc24@1',
            }

        def patched_urlopen(*args, **kwargs):
            with open(test_data('{}.json'.format(post_data['derivedFrom']))) as f:
                return io.BytesIO(f.read().encode('utf-8'))
        try:
            import urllib2 # python2
        except ImportError:
            import urllib.request as urllib2 # renamed in python3
        urlopen = urllib2.urlopen
        urllib2.urlopen = patched_urlopen
        self.addCleanup(setattr, urllib2, 'urlopen', urlopen)

        response = self.testapp.post('/contents',
                json.dumps(post_data),
                status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.maxDiff = None
        self.assertTrue(u'Lav en madplan for den kommende uge'
                in result.pop('content'))
        self.assertFalse('2011-10-05' in result.pop('created'))
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': FunctionalTests.profile['username'],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'title': u'Copy of Indkøb',
            u'abstract': None,
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            })
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

        self.testapp.get('/contents/{}@draft.json'.format(result['id']),
                status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertTrue(u'Lav en madplan for den kommende uge'
                in result.pop('content'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': FunctionalTests.profile['username'],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'title': u'Copy of Indkøb',
            u'abstract': None,
            u'language': u'da',
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0'},
            })

    def test_post_content_derived_from_binder(self):
        post_data = {
                'derivedFrom': u'feda4909-5bbd-431e-a017-049aff54416d@1.1',
            }

        def patched_urlopen(*args, **kwargs):
            with open(test_data('{}.json'.format(post_data['derivedFrom']))) as f:
                return io.BytesIO(f.read().encode('utf-8'))
        try:
            import urllib2 # python2
        except ImportError:
            import urllib.request as urllib2 # renamed in python3
        urlopen = urllib2.urlopen
        urllib2.urlopen = patched_urlopen
        self.addCleanup(setattr, urllib2, 'urlopen', urlopen)

        response = self.testapp.post('/contents',
                json.dumps(post_data),
                status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.maxDiff = None
        self.assertFalse('2011-10-12' in result.pop('created'))
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': FunctionalTests.profile['username'],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'title': u'Copy of Madlavning',
            u'abstract': None,
            u'content': None,
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
            })
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

        response = self.testapp.get(
                '/contents/{}@draft.json'.format(result['id']), status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': FunctionalTests.profile['username'],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'title': u'Copy of Madlavning',
            u'abstract': None,
            u'content': None,
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
            })

    def test_post_content(self):
        post_data = {
            'title': u"Turning DNA through resonance",
            'abstract': u"Theories on turning DNA structures",
            'created': u'2014-03-13T15:21:15.677617',
            'revised': u'2014-03-13T15:21:15.677617',
            'license': {'url': DEFAULT_LICENSE.url},
            'language': u'en',
            'content': u"Ding dong the switch is flipped.",
            }

        response = self.testapp.post('/contents',
                json.dumps(post_data),
                status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.maxDiff = None
        license = result.pop('license')
        self.assertEqual(license['url'], post_data['license']['url'])
        created = result.pop('created')
        self.assertTrue(created.startswith('2014-03-13T15:21:15.677617'))
        revised = result.pop('revised')
        self.assertTrue(revised.startswith('2014-03-13T15:21:15.677617'))
        self.assertEqual(result, {
            u'submitter': FunctionalTests.profile['username'],
            u'id': result['id'],
            u'derivedFrom': None,
            u'title': post_data['title'],
            u'abstract': post_data['abstract'],
            u'language': post_data['language'],
            u'content': post_data['content'],
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            })
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_post_content_binder(self):
        response = self.testapp.post('/contents',
                json.dumps({'title': 'Page one'}), status=201)
        page1 = json.loads(response.body.decode('utf-8'))

        response = self.testapp.post('/contents',
                json.dumps({'title': 'Page two'}), status=201)
        page2 = json.loads(response.body.decode('utf-8'))

        response = self.testapp.post('/contents',
                json.dumps({
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
                    }), status=201)
        book = json.loads(response.body.decode('utf-8'))

        response = self.testapp.get(
                '/contents/{}@draft.json'.format(book['id']), status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'id': book['id'],
            u'title': u'Book',
            u'abstract': u'Book abstract',
            u'content': None,
            u'mediaType': u'application/vnd.org.cnx.collection',
            u'derivedFrom': None,
            u'language': u'de',
            u'version': u'draft',
            u'submitter': u'me',
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
            })

    def test_put_content_403(self):
        FunctionalTests.profile = None
        self.testapp.put('/contents/1234abcde@draft.json', status=403)

    def test_put_content_not_found(self):
        self.testapp.put('/contents/1234abcde@draft.json',
                json.dumps({'title': u'Update document title'}),
                status=404)

    def test_put_content_invalid_json(self):
        response = self.testapp.post('/contents', 
                json.dumps({
                    'title': u'My document タイトル',
                    'abstract': u'My document abstract',
                    'language': u'en'}),
                status=201)
        document = json.loads(response.body.decode('utf-8'))

        response = self.testapp.put(
                '/contents/{}@draft.json'.format(document['id']),
                'invalid json', status=400)
        self.assertTrue('Invalid JSON' in response.body.decode('utf-8'))

    def test_put_content_binder(self):
        post_data = {
                'derivedFrom': u'feda4909-5bbd-431e-a017-049aff54416d@1.1',
            }

        def patched_urlopen(*args, **kwargs):
            with open(test_data('{}.json'.format(post_data['derivedFrom']))) as f:
                return io.BytesIO(f.read().encode('utf-8'))
        try:
            import urllib2 # python2
        except ImportError:
            import urllib.request as urllib2 # renamed in python3
        urlopen = urllib2.urlopen
        urllib2.urlopen = patched_urlopen
        self.addCleanup(setattr, urllib2, 'urlopen', urlopen)

        response = self.testapp.post('/contents',
                json.dumps(post_data),
                status=201)
        result = json.loads(response.body.decode('utf-8'))

        update_data = {
                'title': u'...',
                'tree': {
                    'contents': [{
                        u'id': u'7d089006-5a95-4e24-8e04-8168b5c41aa3@1',
                        u'title': u'Hygiene',
                        }],
                    },
                }
        response = self.testapp.put(
                '/contents/{}@draft.json'.format(result['id']),
                json.dumps(update_data), status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': FunctionalTests.profile['username'],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'abstract': None,
            u'content': None,
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
            })

        response = self.testapp.get(
                '/contents/{}@draft.json'.format(result['id']),
                status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertTrue(result.pop('created') is not None)
        self.assertTrue(result.pop('revised') is not None)
        self.assertEqual(result, {
            u'submitter': FunctionalTests.profile['username'],
            u'id': result['id'],
            u'derivedFrom': post_data['derivedFrom'],
            u'abstract': None,
            u'content': None,
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
            })

    def test_put_content(self):
        response = self.testapp.post('/contents', 
                json.dumps({
                    'title': u'My document タイトル',
                    'abstract': u'My document abstract',
                    'language': u'en'}),
                status=201)
        document = json.loads(response.body.decode('utf-8'))

        update_data = {
            'title': u"Turning DNA through resonance",
            'abstract': u"Theories on turning DNA structures",
            'content': u"Ding dong the switch is flipped.",
            }

        response = self.testapp.put('/contents/{}@draft.json'.format(document['id']),
                json.dumps(update_data),
                status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['id'], document['id'])
        self.assertEqual(result['title'], update_data['title'])
        self.assertEqual(result['abstract'], update_data['abstract'])
        self.assertEqual(result['language'], document['language'])
        self.assertEqual(result['content'], update_data['content'])

        response = self.testapp.get('/contents/{}@draft.json'.format(document['id']))
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_search_content_403(self):
        FunctionalTests.profile = None
        self.testapp.get('/search', status=403)

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
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

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
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_search_unbalanced_quotes(self):
        FunctionalTests.profile = {'username': str(uuid.uuid4())}
        post_data = {'title': u'Document'}
        self.testapp.post('/contents', json.dumps(post_data), status=201)

        response = self.testapp.get('/search?q="Document', status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['query']['limits'],
                [{'tag': 'text', 'value': 'Document'}])
        self.assertEqual(result['results']['total'], 1)
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_search_content(self):
        post_data = {'title': u"Document"}
        self.testapp.post('/contents', json.dumps(post_data), status=201)

        FunctionalTests.profile = {'username': 'a_new_user'}
        post_data = {
            'title': u"Turning DNA through resonance",
            'abstract': u"Theories on turning DNA structures",
            'created': u'2014-03-13T15:21:15.677617',
            'revised': u'2014-03-13T15:21:15.677617',
            'license': {'url': DEFAULT_LICENSE.url},
            'language': u'en',
            'contents': u"Ding dong the switch is flipped.",
            }
        response = self.testapp.post('/contents', json.dumps(post_data),
                status=201)
        result = json.loads(response.body.decode('utf-8'))
        doc_id = result['id']

        post_data = {'title': u'New stuff'}
        response = self.testapp.post('/contents', json.dumps(post_data),
                status=201)
        result = json.loads(response.body.decode('utf-8'))
        new_doc_id = result['id']

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

        # should be able to search user's own documents
        response = self.testapp.get('/search?q=DNA', status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['results']['total'], 1)
        self.assertEqual(result['results']['items'][0]['id'],
                '{}@draft'.format(doc_id))

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

        # should be able to search with double quotes
        response = self.testapp.get('/search?q="through resonance"',
                status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['query']['limits'], [
            {'tag': 'text', 'value': 'through resonance'}])
        self.assertEqual(result['results']['total'], 1)
        self.assertEqual(result['results']['items'][0]['id'],
                '{}@draft'.format(doc_id))

        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_get_resource_403(self):
        FunctionalTests.profile = None
        self.testapp.get('/resources/1234abcde', status=403)

    def test_get_resource_404(self):
        self.testapp.get('/resources/1234abcde', status=404)

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

        # any logged in user can retrieve any resource files
        FunctionalTests.profile = {'username': str(uuid.uuid4())}
        response = self.testapp.get(redirect_url, status=200)
        self.assertEqual(response.body, upload_data)
        self.assertEqual(response.content_type, 'image/png')
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_post_resource_403(self):
        FunctionalTests.profile = None
        self.testapp.post('/resources',
                {'file': Upload('a.txt', b'hello\n', 'text/plain')},
                status=403)

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

    def test_user_search_no_q(self):
        response = self.testapp.get('/users/search')
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, [])
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_user_search_q_empty(self):
        response = self.testapp.get('/users/search?q=')
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, [])
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_user_search(self):
        FunctionalTests.accounts_request_return = {
                'per_page': 20,
                'users': [
                    {'username': 'admin', 'id': 1, 'contact_infos': []}
                    ],
                'order_by': 'username ASC',
                'num_matching_users': 1,
                'page': 0,
                }
        response = self.testapp.get('/users/search?q=admin')
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, FunctionalTests.accounts_request_return)
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_profile_403(self):
        FunctionalTests.profile = None
        self.testapp.get('/users/profile', status=403)

    def test_profile(self):
        FunctionalTests.profile = {'username': 'first_last'}
        response = self.testapp.get('/users/profile', status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, FunctionalTests.profile)
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')

    def test_user_contents_403(self):
        FunctionalTests.profile = None
        self.testapp.get('/contents', status=403)

    def test_user_contents(self):
        self.testapp.post('/contents',
                json.dumps({'title': 'document by default user'}), status=201)

        # a user should not get any contents that doesn't belong to themselves
        uid = str(uuid.uuid4())
        FunctionalTests.profile = {'username': uid}
        response = self.testapp.get('/contents', status=200)
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

        self.testapp.post('/contents',
                json.dumps({'title': 'document by {}'.format(uid)}),
                status=201)

        self.testapp.post('/contents',
                json.dumps({'title': 'another document by {}'.format(uid)}),
                status=201)

        response = self.testapp.get('/contents', status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['results']['total'], 2)
        self.assertTrue(result['results']['items'][0]['id'].endswith('@draft'))
        self.assertTrue(result['results']['items'][1]['id'].endswith('@draft'))
        titles = [i['title'] for i in result['results']['items']]
        self.assertEqual(sorted(titles), [
            'another document by {}'.format(uid),
            'document by {}'.format(uid)])
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'],
                'true')
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],
                'localhost')
