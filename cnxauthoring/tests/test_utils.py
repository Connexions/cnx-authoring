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
    from unittest import mock  # python3
except ImportError:
    import mock  # python2

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

    def test_accept_roles_and_license(self):
        from ..models import create_content, DEFAULT_LICENSE

        document = create_content(
            title='My Document',
            authors=[{'id': 'me'}],
            publishers=[{'id': 'me'}],
            editors=[{'id': 'me'}, {'id': 'you'}],
            translators=[{'id': 'you'}],
            )
        request = mock.Mock()
        request.registry.settings = {
            'publishing.url': 'http://publishing/',
            'publishing.api_key': 'trusted-publisher',
            }

        with mock.patch('requests.post') as post:
            post.return_value.status_code = 202
            utils.accept_roles_and_license(request, document, 'me')
            self.assertEqual(post.call_count, 2)

            (url,), kwargs = post.call_args_list[0]
            self.assertEqual(
                url, 'http://publishing/contents/{}/roles'.format(document.id))
            self.assertEqual(json.loads(kwargs['data']), [
                {u'uid': u'me', u'role': u'Publisher', 'has_accepted': True},
                {u'uid': u'me', u'role': u'Editor', 'has_accepted': True},
                {u'uid': u'me', u'role': u'Author', 'has_accepted': True},
                ])
            self.assertEqual(kwargs['headers'], {
                'x-api-key': 'trusted-publisher',
                'content-type': 'application/json',
                })

            (url,), kwargs = post.call_args_list[1]
            self.assertEqual(url,
                             'http://publishing/contents/{}/licensors'
                             .format(document.id))
            self.assertEqual(json.loads(kwargs['data']), {
                'license_url': DEFAULT_LICENSE.url,
                'licensors': [{'uid': 'me', 'has_accepted': True}],
                })
            self.assertEqual(kwargs['headers'], {
                'x-api-key': 'trusted-publisher',
                'content-type': 'application/json',
                })
