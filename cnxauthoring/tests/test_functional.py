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
        pass


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
                    'modified': u'2014-03-13T15:21:15',
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
            u'derived_from': None,
            u'license': {
                u'abbr': u'by',
                u'name': u'Attribution',
                u'url': u'http://creativecommons.org/licenses/by/4.0/',
                u'version': u'4.0',
                },
            u'modified': get_result['modified'],
            u'mediaType': u'application/vnd.org.cnx.module',
            u'language': u'en',
            u'submitter': u'me',
            u'abstract': None,
            u'version': u'draft',
            })
        self.assertEqual(put_result, get_result)

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

    def test_post_content_minimal(self):
        response = self.testapp.post('/contents', 
                json.dumps({'title': u'My document タイトル'}),
                status=201)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['title'], u'My document タイトル')

    def test_post_content(self):
        post_data = {
            'title': u"Turning DNA through resonance",
            'abstract': u"Theories on turning DNA structures",
            'created': u'2014-03-13T15:21:15.677617',
            'modified': u'2014-03-13T15:21:15.677617',
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
        self.assertTrue(created.startswith('2014-03-13 15:21:15.677617'))
        modified = result.pop('modified')
        self.assertTrue(modified.startswith('2014-03-13 15:21:15.677617'))
        self.assertEqual(result, {
            u'submitter': FunctionalTests.profile['username'],
            u'id': result['id'],
            u'derived_from': None,
            u'title': post_data['title'],
            u'abstract': post_data['abstract'],
            u'language': post_data['language'],
            u'content': post_data['content'],
            u'mediaType': u'application/vnd.org.cnx.module',
            u'version': u'draft',
            })

    def test_put_content_403(self):
        FunctionalTests.profile = None
        self.testapp.put('/contents/1234abcde', status=403)

    def test_put_content_not_found(self):
        self.testapp.put('/contents/1234abcde',
                json.dumps({'title': u'Update document title'}),
                status=404)

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

        response = self.testapp.put('/contents/{}'.format(document['id']),
                json.dumps(update_data),
                status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['id'], document['id'])
        self.assertEqual(result['title'], update_data['title'])
        self.assertEqual(result['abstract'], update_data['abstract'])
        self.assertEqual(result['language'], document['language'])
        self.assertEqual(result['content'], update_data['content'])

        response = self.testapp.get('/contents/{}@draft.json'.format(document['id']))

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

    def test_search_unbalanced_quotes(self):
        FunctionalTests.profile = {'username': str(uuid.uuid4())}
        post_data = {'title': u'Document'}
        self.testapp.post('/contents', json.dumps(post_data), status=201)

        response = self.testapp.get('/search?q="Document', status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['query']['limits'],
                [{'tag': 'text', 'value': 'Document'}])
        self.assertEqual(result['results']['total'], 1)

    def test_search_content(self):
        post_data = {'title': u"Document"}
        self.testapp.post('/contents', json.dumps(post_data), status=201)

        FunctionalTests.profile = {'username': 'a_new_user'}
        post_data = {
            'title': u"Turning DNA through resonance",
            'abstract': u"Theories on turning DNA structures",
            'created': u'2014-03-13T15:21:15.677617',
            'modified': u'2014-03-13T15:21:15.677617',
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
        self.assertEqual(result['results']['items'][0]['id'], doc_id)

        # should be able to search multiple terms
        response = self.testapp.get('/search?q=new+resonance', status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['query']['limits'], [
            {'tag': 'text', 'value': 'new'},
            {'tag': 'text', 'value': 'resonance'}])
        self.assertEqual(result['results']['total'], 2)
        self.assertEqual(sorted([i['id'] for i in result['results']['items']]),
                sorted([doc_id, new_doc_id]))

        # should be able to search with double quotes
        response = self.testapp.get('/search?q="through resonance"',
                status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result['query']['limits'], [
            {'tag': 'text', 'value': 'through resonance'}])
        self.assertEqual(result['results']['total'], 1)
        self.assertEqual(result['results']['items'][0]['id'], doc_id)

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

    def test_post_resource_403(self):
        FunctionalTests.profile = None
        self.testapp.post('/resources',
                {'file': Upload('a.txt', b'hello\n', 'text/plain')},
                status=403)

    def test_post_resource(self):
        self.testapp.post('/resources',
                {'file': Upload('a.txt', b'hello\n', 'text/plain')},
                status=201)

    def test_user_search_no_q(self):
        response = self.testapp.get('/users/search')
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, [])

    def test_user_search_q_empty(self):
        response = self.testapp.get('/users/search?q=')
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, [])

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

    def test_profile_403(self):
        FunctionalTests.profile = None
        self.testapp.get('/users/profile', status=403)

    def test_profile(self):
        FunctionalTests.profile = {'username': 'first_last'}
        response = self.testapp.get('/users/profile', status=200)
        result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(result, FunctionalTests.profile)

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
        titles = [i['title'] for i in result['results']['items']]
        self.assertEqual(sorted(titles), [
            'another document by {}'.format(uid),
            'document by {}'.format(uid)])
