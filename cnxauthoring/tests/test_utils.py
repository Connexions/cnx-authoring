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
    import urlparse  # python2
except ImportError:
    import urllib.parse as urlparse  # renamed in python3
try:
    from unittest import mock  # python3
except ImportError:
    import mock  # python2

import httpretty
from pyramid import testing

from .. import utils


class UtilsTests(unittest.TestCase):

    def test_change_dict_keys(self):
        data = {
            'id': '1234',
            'deriveFrom': 'uuid@version',
            'nextLevel': {
                'anotherLevel': {
                    'someOtherThing': 'value',
                    },
                },
            'listItem': [
                {'itemTitle': 'itemValue'},
                {'itemTitle2': 'itemValue2'},
                'itemTitle3',
                ],
            }
        utils.change_dict_keys(data, utils.camelcase_to_underscore)
        self.assertEqual(data, {
            'id': '1234',
            'derive_from': 'uuid@version',
            'next_level': {
                'another_level': {
                    'some_other_thing': 'value',
                    },
                },
            'list_item': [
                {'item_title': 'itemValue'},
                {'item_title2': 'itemValue2'},
                'itemTitle3',
                ],
            })

    def test_camelcase_to_underscore(self):
        c2u = utils.camelcase_to_underscore

        self.assertEqual(c2u('id'), 'id')
        self.assertEqual(c2u('deriveFrom'), 'derive_from')
        self.assertEqual(c2u('someOtherThing'), 'some_other_thing')

    def test_underscore_to_camelcase(self):
        u2c = utils.underscore_to_camelcase

        self.assertEqual(u2c('id'), 'id')
        self.assertEqual(u2c('derive_from'), 'deriveFrom')
        self.assertEqual(u2c('some_other_thing'), 'someOtherThing')

    def test_empty_profile_to_dict(self):
        expected = {
            'firstname': '',
            'surname': '',
            'email': '',
            'id': '',
            'fullname': '',
            }

        self.assertEqual(utils.profile_to_user_dict({}), expected)

    def test_full_profile_to_dict(self):
        profile = {
            'first_name': u'Cäroline',
            'last_name': u'Läne',
            'contact_infos': [
                {'type': 'PhoneNumber', 'value': 123456789},
                {'type': 'EmailAddress', 'value': 'something@something.com'}],
            }
        expected = {
            'firstname': u'Cäroline',
            'surname': u'Läne',
            'email': 'something@something.com',
            'id': '',
            'fullname': u'Cäroline Läne',
            }

        self.assertEqual(utils.profile_to_user_dict(profile), expected)

    def test_profile_to_dict_twice(self):
        expected = {
            'firstname': 'Caroline',
            'surname': 'Lane',
            'email': 'something@something.com',
            'id': '',
            'fullname': 'Caroline Lane',
            }

        self.assertEqual(utils.profile_to_user_dict(expected), expected)

    def test_utf8_single_string(self):
        test1 = b'simple test string!'
        test2 = u'idzie wąż wąską dróżką'.encode('utf-8')

        self.assertEqual(utils.utf8(test1).encode('utf-8'), test1)
        self.assertEqual(utils.utf8(test2).encode('utf-8'), test2)

    def test_utf8_list(self):
        test_list = [
            b"email@something.org",
            u"Radioactive (Die Verstoßenen)".encode('utf-8'),
            u"40文字でわかる！".encode('utf-8')]
        utf8_list = utils.utf8(test_list)

        for i in range(len(test_list)):
            self.assertEqual(utf8_list[i].encode('utf-8'), test_list[i])

    def test_utf8_dict(self):
        test_dict = {
            b"First name": b"Caroline",
            u"知っておきたいhiビジネス理論".encode('utf-8'):
            u"40文字でわthereかる-知っ".encode('utf-8')}
        utf8_dict = utils.utf8(test_dict)

        for k, v in utf8_dict.items():
            self.assertEqual(v.encode("utf-8"), test_dict[k.encode('utf-8')])

    def test_structured_query_text(self):
        text1 = 'Some text'
        text2 = '知っておきたいhi thereかる-知っ'
        text3 = '"A phrase"'

        self.assertEqual(utils.structured_query(text1),
                         [('text', 'Some'), ('text', 'text')])
        self.assertEqual(utils.structured_query(text2),
                         [('text', '知っておきたいhi'),
                          ('text', 'thereかる-知っ')])
        self.assertEqual(utils.structured_query(text3),
                         [('text', 'A phrase')])

    def test_structured_query_terms_and_fields(self):
        query = 'author:"John Smith" type:book Radioactive:"(Die Verstoßenen)"'

        self.assertEqual(utils.structured_query(query), [
            ('author', 'John Smith'), ('type', 'book'),
            ('Radioactive', '(Die Verstoßenen)')])

    def test_structured_query_missing_quotes(self):
        test1 = '"Phrase without quotes'

        self.assertEqual(utils.structured_query(test1),
                         [('text', 'Phrase without quotes')])

    def test_create_acl_for(self):
        from ..models import create_content

        document = create_content(title='My Document')
        request = mock.Mock()
        request.registry.settings = {
            'publishing.url': 'http://publishing/',
            'publishing.api_key': 'trusted-publisher',
            }

        with mock.patch('requests.post') as post:
            post.return_value.status_code = 202
            utils.create_acl_for(request, document, ('me', 'you',))
            self.assertEqual(post.call_count, 1)
            (url,), kwargs = post.call_args
            self.assertEqual(url,
                             'http://publishing/contents/{}/permissions'
                             .format(document.id))
            self.assertEqual(json.loads(kwargs['data']),
                             [{'uid': 'me', 'permission': 'publish'},
                              {'uid': 'you', 'permission': 'publish'}])
            self.assertEqual(kwargs['headers'], {
                'x-api-key': 'trusted-publisher',
                'content-type': 'application/json',
                })

    def test_get_acl_for(self):
        from ..models import create_content

        document = create_content(title='My Document')
        request = mock.Mock()
        request.registry.settings = {
            'publishing.url': 'http://publishing/',
            'publishing.api_key': 'trusted-publisher',
            }

        with mock.patch('requests.get') as get:
            get.return_value.status_code = 200
            get.return_value.json.return_value = [{
                'uuid': document.id,
                'uid': 'me',
                'permission': 'publish',
                }]
            utils.get_acl_for(request, document)
            self.assertEqual(get.call_count, 1)
            (url,), kwargs = get.call_args
            self.assertEqual(url,
                             'http://publishing/contents/{}/permissions'
                             .format(document.id))
            self.assertEqual(document.acls,
                             [('me', 'view', 'edit', 'publish')])

    def test_accept_roles(self):
        cstruct = {
            u'submitlog': u'first version',
            u'abstract': None,
            u'revised': None,
            u'derived_from_title': u'Madlavning',
            u'parent_title': None,
            u'keywords': [u'k\xf8kken',
            u'Madlavning'],
            u'subjects': [u'Arts'],
            u'title': u'Copy of Madlavning',
            u'parent_version': u'',
            u'editors': [
                {'fullname': u'User One',
                 'surname': u'One',
                 'email': u'user1@example.com',
                 'firstname': u'User',
                 'id': 'user1'},
                {'fullname': 'User Two',
                 'surname': u'Two',
                 'email': u'user2@example.com',
                 'firstname': u'User',
                 'id': 'user2'},
                ],
            u'id': u'feda4909-5bbd-431e-a017-049aff54416d',
            u'parent_id': None,
            u'version': u'1.1',
            u'legacy_id': u'col11368',
            u'media_type': u'application/vnd.org.cnx.collection',
            u'publishers': [
                {'fullname': u'User One',
                 'surname': u'One',
                 'email': u'user1@example.com',
                 'firstname': u'User',
                 'id': 'user1'}],
            u'parent_authors': [],
            u'stateid': 1,
            u'google_analytics': None,
            u'language': u'da',
            u'maintainers': [],
            u'buy_link': None,
            u'authors': [
                {'fullname': u'User One',
                 'surname': u'One',
                 'email': u'user1@example.com',
                 'firstname': u'User',
                 'id': 'user1'},
                {'fullname': 'User Two',
                 'surname': u'Two',
                 'email': u'user2@example.com',
                 'firstname': u'User',
                 'id': 'user2'},
                ],
            u'legacy_version': u'1.1',
            u'licensors': [
                {'fullname': u'User One',
                 'surname': u'One',
                 'email': u'user1@example.com',
                 'firstname': u'User',
                 'id': 'user1'}],
            u'roles': None,
            u'license': {
                'url': 'http://creativecommons.org/licenses/by/4.0/'
                },
            u'created': None,
            u'tree': {
                u'id': u'feda4909-5bbd-431e-a017-049aff54416d@1.1',
                u'contents': [],
                u'title': u'Madlavning'},
            u'doctype': u'',
            u'illustrators': [],
            u'translators': [],
            u'submitter': {
                'fullname': u'User One',
                'surname': u'One',
                'email': u'user1@example.com',
                'firstname': u'User',
                'id': 'user1'},
            u'derived_from_uri': 'http://cnx.org/contents/'
                'feda4909-5bbd-431e-a017-049aff54416d@1.1',
            }
        utils.accept_roles(cstruct, {
            'fullname': u'User One',
             'surname': u'One',
             'email': u'user1@example.com',
             'firstname': u'User',
             'has_accepted': True,
             'id': 'user1'})
        self.maxDiff = None
        self.assertDictEqual(
            cstruct, {
                u'submitlog': u'first version',
                u'abstract': None,
                u'revised': None,
                u'derived_from_title': u'Madlavning',
                u'parent_title': None,
                u'keywords': [u'k\xf8kken',
                u'Madlavning'],
                u'subjects': [u'Arts'],
                u'title': u'Copy of Madlavning',
                u'parent_version': u'',
                u'editors': [
                    {'fullname': u'User One',
                     'surname': u'One',
                     'email': u'user1@example.com',
                     'firstname': u'User',
                     'has_accepted': True,
                     'id': 'user1'},
                    {'fullname': 'User Two',
                     'surname': u'Two',
                     'email': u'user2@example.com',
                     'firstname': u'User',
                     'id': 'user2'},
                    ],
                u'id': u'feda4909-5bbd-431e-a017-049aff54416d',
                u'parent_id': None,
                u'version': u'1.1',
                u'legacy_id': u'col11368',
                u'media_type': u'application/vnd.org.cnx.collection',
                u'publishers': [
                    {'fullname': u'User One',
                     'surname': u'One',
                     'email': u'user1@example.com',
                     'firstname': u'User',
                     'has_accepted': True,
                     'id': 'user1'}],
                u'parent_authors': [],
                u'stateid': 1,
                u'google_analytics': None,
                u'language': u'da',
                u'maintainers': [],
                u'buy_link': None,
                u'authors': [
                    {'fullname': u'User One',
                     'surname': u'One',
                     'email': u'user1@example.com',
                     'firstname': u'User',
                     'has_accepted': True,
                     'id': 'user1'},
                    {'fullname': 'User Two',
                     'surname': u'Two',
                     'email': u'user2@example.com',
                     'firstname': u'User',
                     'id': 'user2'},
                    ],
                u'legacy_version': u'1.1',
                u'licensors': [
                    {'fullname': u'User One',
                     'surname': u'One',
                     'email': u'user1@example.com',
                     'firstname': u'User',
                     'id': 'user1'}],
                u'roles': None,
                u'license': {
                    'url': 'http://creativecommons.org/licenses/by/4.0/'
                    },
                u'created': None,
                u'tree': {
                    u'id': u'feda4909-5bbd-431e-a017-049aff54416d@1.1',
                    u'contents': [],
                    u'title': u'Madlavning'},
                u'doctype': u'',
                u'illustrators': [],
                u'translators': [],
                u'submitter': {
                    'fullname': u'User One',
                    'surname': u'One',
                    'email': u'user1@example.com',
                    'firstname': u'User',
                    'id': 'user1'},
                u'derived_from_uri': ('http://cnx.org/contents/feda4909-5bbd'
                                      '-431e-a017-049aff54416d@1.1'),
                })

    def test_accept_license(self):
        from ..models import create_content

        document = create_content(
            title='My Document',
            authors=[{'id': 'me'}],
            publishers=[{'id': 'me'}],
            editors=[{'id': 'me'}, {'id': 'you'}],
            translators=[{'id': 'you'}],
            )
        utils.accept_license(document, {'id': 'me'})
        self.assertEqual(document.licensor_acceptance,
                         [{'id': 'me', 'has_accepted': True}])

    def test_declare_roles(self):
        from ..models import create_content

        document = create_content(
            title='My Document',
            authors=[{'id': 'me'}],
            publishers=[{'id': 'me'}],
            editors=[{'id': 'me'}, {'id': 'you'}],
            translators=[{'id': 'you'}],
            )
        settings = {
            'publishing.url': 'http://publishing/',
            'publishing.api_key': 'trusted-publisher',
            }

        with mock.patch('requests.get') as get:
            publishing_records = []
            get.return_value.status_code = 200
            get.json.side_effect = publishing_records
            with mock.patch('requests.post') as post:
                post.return_value.status_code = 202

                with testing.testConfig(settings=settings):
                    utils.declare_roles(document)

                self.assertEqual(post.call_count, 1)

                (url,), kwargs = post.call_args_list[0]
                self.assertEqual(
                    url,
                    'http://publishing/contents/{}/roles'.format(document.id))
                self.assertEqual(
                    sorted(json.loads(kwargs['data']),
                           key=lambda v: (v['uid'], v['role'],)),
                    [{u'uid': u'me', u'role': u'Author',
                      u'has_accepted': None},
                     {u'uid': u'me', u'role': u'Editor',
                      u'has_accepted': None},
                     {u'uid': u'me', u'role': u'Publisher',
                      u'has_accepted': None},
                     {u'uid': u'you', u'role': u'Editor',
                      u'has_accepted': None},
                     {u'uid': u'you', u'role': u'Translator',
                      u'has_accepted': None},
                     ])
                self.assertEqual(kwargs['headers'], {
                    'x-api-key': 'trusted-publisher',
                    'content-type': 'application/json',
                    })

    @httpretty.activate
    def test_declare_roles_w_invalid_role_type(self):
        """Ignore invalid roles"""
        from ..models import create_content

        document = create_content(
            title='My Document',
            authors=[{'id': 'me'}],
            publishers=[{'id': 'me'}],
            editors=[{'id': 'me'}, {'id': 'you'}],
            translators=[{'id': 'you'}],
            )
        publishing_url = 'http://publishing/'
        settings = {
            'publishing.url': publishing_url,
            'publishing.api_key': 'trusted-publisher',
            }

        publishing_records = []
        url = urlparse.urljoin(publishing_url,
                               '/contents/{}/roles'.format(document.id))
        httpretty.register_uri(httpretty.GET, url,
                               body=json.dumps(publishing_records), status=200)
        httpretty.register_uri(httpretty.POST, url, status=202)

        with testing.testConfig(settings=settings):
            utils.declare_roles(document)

        post_request = httpretty.last_request()
        data = post_request.parse_request_body(post_request.body)
        expected = [
            {u'uid': u'me', u'role': u'Author', u'has_accepted': None},
            {u'uid': u'me', u'role': u'Editor', u'has_accepted': None},
            {u'uid': u'me', u'role': u'Publisher', u'has_accepted': None},
            {u'uid': u'you', u'role': u'Editor', u'has_accepted': None},
            {u'uid': u'you', u'role': u'Translator', u'has_accepted': None},
            ]
        self.assertEqual(sorted(data, key=lambda v: (v['uid'], v['role'],)),
                         expected)

    @httpretty.activate
    def test_declare_licensors(self):
        from ..models import create_content, DEFAULT_LICENSE

        document = create_content(
            title='My Document',
            license={'url': DEFAULT_LICENSE.url},
            authors=[{'id': 'me'}],
            publishers=[{'id': 'me'}],
            editors=[{'id': 'me'}, {'id': 'you'}],
            translators=[{'id': 'you'}],
            licensor_acceptance=[{'id': 'me', 'has_accepted': True},
                                 {'id': 'you', 'has_accepted': None}],
            )
        publishing_url = 'http://publishing/'
        settings = {
            'publishing.url': publishing_url,
            'publishing.api_key': 'trusted-publisher',
            }

        publishing_records = {
            'license_url': DEFAULT_LICENSE.url,
            'licensors': [],
            }
        url = urlparse.urljoin(publishing_url,
                               '/contents/{}/licensors'.format(document.id))
        httpretty.register_uri(httpretty.GET, url,
                               body=json.dumps(publishing_records), status=200)
        httpretty.register_uri(httpretty.POST, url, status=202)

        with testing.testConfig(settings=settings):
            utils.declare_licensors(document)

        post_request = httpretty.last_request()
        data = post_request.parse_request_body(post_request.body)
        expected_licensors = [
            {u'uid': u'me', u'has_accepted': True},
            {u'uid': u'you', u'has_accepted': None},
            ]
        self.assertEqual(data['license_url'], DEFAULT_LICENSE.url)
        self.assertEqual(sorted(data['licensors'], key=lambda v: v['uid']),
                         expected_licensors)
