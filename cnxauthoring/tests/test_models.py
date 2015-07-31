# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2015, Rice University
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

import httpretty
from pyramid import testing as pyramid_testing

from . import testing


class ModelUtilitiesTestCase(unittest.TestCase):
    maxDiff = None

    @httpretty.activate
    def test_derive_content(self):
        archive_url = "http://example.com"
        settings = {'archive.url': archive_url}

        from ..models import DEFAULT_LICENSE
        content_id = 'uuid'
        content_title = 'title'
        archived_data = {
            'id': content_id,
            'version': '1',
            'license': DEFAULT_LICENSE.__json__(),
            'title': content_title,
            'authors': [{}, {}, {}],
            'maintainers': [{}, {}, {}],
            'publishers': [{}, {}, {}],
            'licensors': [{}, {}, {}],
            'translators': [{}, {}, {}],
            'editors': [{}, {}, {}],
            'illustrators': [{}, {}, {}],
            'create': 'awhile ago',
            'revised': 'just now',
            }

        url = "{}/contents/{}.json".format(archive_url, content_id)
        faux_response_body = json.dumps(archived_data)
        httpretty.register_uri(httpretty.GET, url,
                               body=faux_response_body, status=200)

        request = pyramid_testing.DummyRequest()
        request.registry = mock.Mock()
        request.registry.settings = settings

        from ..models import derive_content
        document_as_dict = derive_content(request, derived_from=content_id)

        expected = archived_data.copy()
        # FIXME Use cnx-epub.ATTRIBUTED_ROLE_KEYS after the licensor to
        #       copyright_holder fix/mapping is in cnx-archive.
        role_attrs = ('authors', 'licensors', 'editors', 'illustrators',
                      'maintainers', 'publishers', 'translators',)
        for role_attr in  role_attrs:
            expected[role_attr] = []
        expected['title'] = "Copy of {}".format(archived_data['title'])
        expected['created'] = None
        expected['revised'] = None
        expected['derived_from_title'] = archived_data['title']
        # FIXME the hostname is hardcoded and wrong.
        expected['derived_from_uri'] = "http://cnx.org/contents/{}@{}" \
            .format(archived_data['id'], archived_data['version'])
        self.assertEqual(document_as_dict, expected)
