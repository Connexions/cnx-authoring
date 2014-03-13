# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import io
import datetime
import hashlib
import unittest
import uuid
try:
    from unittest import mock
except ImportError:
    import mock

from pyramid import testing


class ViewsTests(unittest.TestCase):

    def setUp(self):
        self.config = testing.setUp()
        from .. import declare_routes
        declare_routes(self.config)
        from .. import storage as storage_pkg
        _storage_instance = self.storage_cls()
        setattr(storage_pkg, 'storage', _storage_instance)
        self.addCleanup(setattr, storage_pkg, 'storage', None)

    tearDown = testing.tearDown

    @property
    def storage_cls(self):
        from ..storage.main import BaseStorage
        return BaseStorage

    def test_get_content_for_document(self):
        # Set up a piece of content.
        id = uuid.uuid4(),
        document_title = "The Floating Dust"
        from ..models import Document
        expected = Document(document_title, id=id)

        # Test the view
        request = testing.DummyRequest()
        request.matchdict = {'id': id}
        with mock.patch.object(self.storage_cls, 'get', return_value=expected):
            from ..views import get_content
            content = get_content(request)
        self.assertEqual(content, expected.to_dict())

    def test_get_content_404(self):
        request = testing.DummyRequest()
        request.matchdict = {'id': '1234abcde'}

        with mock.patch.object(self.storage_cls, 'get', return_value=None):
            from ..views import get_content
            from pyramid.httpexceptions import HTTPNotFound
            self.assertRaises(HTTPNotFound, get_content, request)

    def test_get_resource(self):
        # Set up a resource
        data = b'yada yadda yaadda'
        hasher = hashlib.new('sha1', data)
        mediatype = 'text/plain'
        from ..models import Resource
        expected = Resource(mediatype, data=io.BytesIO(data))

        # Test the view
        request = testing.DummyRequest()
        request.matchdict = {'hash': hasher.hexdigest()}

        with mock.patch.object(self.storage_cls, 'get', return_value=expected):
            from ..views import get_resource
            response = get_resource(request)
        self.assertEqual(b''.join(response.app_iter), data)
        self.assertEqual(response.content_type, mediatype)

    def test_get_resource_404(self):
        request = testing.DummyRequest()
        request.matchdict = {'hash': '2ab3c4d5e6f9eb79'}

        with mock.patch.object(self.storage_cls, 'get', return_value=None):
            from pyramid.httpexceptions import HTTPNotFound
            from ..views import get_resource
            self.assertRaises(HTTPNotFound, get_resource, request)

    def test_post_content_minimal(self):
        title = "Double negative hemispheres"
        self.document = None
        self.addCleanup(delattr, self, 'document')
        def mocked_add(item):
            self.document = item
            self.document.id = uuid.uuid4()
            return self.document
        # Given the minimal amount of information, create a document.
        self.storage_cls.add = mock.Mock(side_effect=mocked_add)
        self.storage_cls.persist = mock.Mock(return_value=None)

        # Minimal document posts require a title.
        from ..views import post_content
        request = testing.DummyRequest()
        request.json_body = {'title': title}
        _unauthenticated_userid = request.__class__.unauthenticated_userid
        self.addCleanup(setattr, request.__class__, 'unauthenticated_userid',
                        _unauthenticated_userid)
        request.__class__.unauthenticated_userid = 'username'
        returned_document = post_content(request)

        self.assertEqual(returned_document, self.document.to_dict())
        self.assertEqual(request.response.status, '201 Created')
        content_url = request.route_url('get-content', id=self.document.id)
        self.assertIn(('Location', content_url,),
                      request.response.headerlist)

    def test_post_content(self):
        from ..models import DEFAULT_LICENSE
        post_data = {
            'id': str(uuid.uuid4()),
            'title': "Turning DNA through resonance",
            'summary': "Theories on turning DNA structures",
            'created': datetime.datetime.now().isoformat(),
            'modified': datetime.datetime.now().isoformat(),
            'license': {'url': DEFAULT_LICENSE.url},
            'language': 'en-us',
            'contents': "Ding dong the switch is flipped.",
            }
        self.document = None
        self.addCleanup(delattr, self, 'document')
        def mocked_add(item):
            self.document = item
            self.document.id = uuid.uuid4()
            return self.document
        self.storage_cls.add = mock.Mock(side_effect=mocked_add)
        self.storage_cls.persist = mock.Mock(return_value=None)

        # Minimal document posts require a title.
        request = testing.DummyRequest()
        request.json_body = post_data.copy()
        _unauthenticated_userid = request.__class__.unauthenticated_userid
        self.addCleanup(setattr, request.__class__, 'unauthenticated_userid',
                        _unauthenticated_userid)
        request.__class__.unauthenticated_userid = 'username'
        from ..views import post_content
        returned_document = post_content(request)

        self.assertEqual(request.response.status, '201 Created')
        content_url = request.route_url('get-content', id=self.document.id)
        self.assertIn(('Location', content_url,),
                      request.response.headerlist)

        self.assertEqual(returned_document, self.document.to_dict())
        self.assertEqual(returned_document['title'], post_data['title'])
        self.assertEqual(returned_document['summary'], post_data['summary'])
        # TODO Test created and modified dates.
        self.assertEqual(returned_document['license']['url'], DEFAULT_LICENSE.url)
        self.assertEqual(returned_document['language'], post_data['language'])
        self.assertEqual(returned_document['contents'], post_data['contents'])

    def test_post_resource(self):
        # Set up a resource
        data = b'yada yadda yaadda'
        mediatype = 'text/plain'
        hash = hashlib.new('sha1', data).hexdigest()
        from ..models import Resource
        expected = Resource(mediatype, data=io.BytesIO(data))

        self.resource = None
        self.addCleanup(delattr, self, 'resource')
        def mocked_add(item):
            self.resource = item
            self.resource.id = uuid.uuid4()
            return self.resource

        self.storage_cls.add = mock.Mock(side_effect=mocked_add)
        self.storage_cls.persist = mock.Mock(return_value=None)

        # Mock cgi.FieldStorage for file upload.
        upload = mock.Mock()
        upload.file = io.BytesIO(data)
        upload.type = mediatype

        # Minimal document posts require a title.
        request = testing.DummyRequest()
        request.POST = {'file': upload}
        from ..views import post_resource
        location = post_resource(request)

        self.assertEqual(request.response.status, '201 Created')
        expected_location = request.route_url('get-resource',
                                              hash=self.resource.hash)
        self.assertIn(('Location', expected_location,),
                      request.response.headerlist)
