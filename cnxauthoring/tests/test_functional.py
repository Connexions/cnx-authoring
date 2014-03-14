# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import json
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from zope.interface import implementer

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

    def setUp(self):
        # Mock all the openstax accounts code
        from openstax_accounts import openstax_accounts
        openstax_accounts.main = mock_openstax_accounts
        from openstax_accounts import authentication_policy
        authentication_policy.main = mock_authentication_policy

        import pyramid.paster
        app = pyramid.paster.get_app('testing.ini')
        from webtest import TestApp
        self.testapp = TestApp(app)

        # make sure storage is set correctly in cnxauthoring.views by reloading
        # cnxauthoring.views
        import sys
        del sys.modules['cnxauthoring.views']

        FunctionalTests.profile = {u'username': u'me'}

    def test_get_content_403(self):
        FunctionalTests.profile = None
        self.testapp.get('/contents/1234abcde', status=403)

    def test_get_content_404(self):
        self.testapp.get('/contents/1234abcde', status=404)

    def test_get_content_for_document(self):
        response = self.testapp.post('/contents',
                json.dumps({'title': 'My New Document'}),
                status=201)
        put_result = json.loads(response.body.decode('utf-8'))
        response = self.testapp.get('/contents/{}'.format(put_result['id']),
                status=200)
        get_result = json.loads(response.body.decode('utf-8'))
        self.assertEqual(get_result['title'], 'My New Document')
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
            'summary': u"Theories on turning DNA structures",
            'created': u'2014-03-13T15:21:15.677617',
            'modified': u'2014-03-13T15:21:15.677617',
            'license': {'url': DEFAULT_LICENSE.url},
            'language': u'en-us',
            'contents': u"Ding dong the switch is flipped.",
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
            u'summary': post_data['summary'],
            u'language': post_data['language'],
            u'contents': post_data['contents'],
            })

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
