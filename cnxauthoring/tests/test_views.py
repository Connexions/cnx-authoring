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
import sys
import unittest
import uuid
try:
    from unittest import mock
except ImportError:
    import mock

from pyramid import testing


unauthenticated_userid = 'pyramid.testing.DummyRequest.unauthenticated_userid'
authenticated_userid = 'pyramid.testing.DummyRequest.authenticated_userid'


@mock.patch(unauthenticated_userid, 'userid')
@mock.patch(authenticated_userid, 'userid')
class ViewsTests(unittest.TestCase):

    def setUp(self):
        if 'cnxauthoring.views' in sys.modules:
            del sys.modules['cnxauthoring.views']
        self.config = testing.setUp()
        from .. import declare_routes
        declare_routes(self.config)
        from .. import storage as storage_pkg
        _storage_instance = self.storage_cls()
        patch = mock.patch.object(_storage_instance, 'persist')
        patch.start()
        self.addCleanup(patch.stop)
        setattr(storage_pkg, 'storage', _storage_instance)
        self.addCleanup(setattr, storage_pkg, 'storage', None)

        testing.DummyRequest.user = {
            u'username': u'me',
            u'id': 1,
            u'contactInfos': [
                {
                    u'type': u'EmailAddress',
                    u'verified': True,
                    u'id': 1,
                    u'value': u'me@example.com',
                    },
                ],
            }
        self.addCleanup(delattr, testing.DummyRequest, 'user')

        for mock_target in (
                'cnxauthoring.utils.declare_acl',
                'cnxauthoring.utils.declare_roles',
                'cnxauthoring.utils.declare_licensors',
                'cnxauthoring.utils.accept_roles',
                ):
            patch = mock.patch(mock_target)
            patch.start()
            self.addCleanup(patch.stop)

    tearDown = testing.tearDown

    @property
    def storage_cls(self):
        from ..storage.main import BaseStorage
        return BaseStorage

    def test_update_content_state_with_parsing(self):
        from ..models import create_content
        from ..utils import TZINFO
        import json
        with open('./cnxauthoring/tests/data/m.json', 'r') as f:
                sample_json = json.load(f)
        # Create some new content
        created = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = created
            document = create_content(title=sample_json['title'])
        self.assertEqual(document.metadata['created'], created)
        self.assertEqual(document.metadata['revised'], created)

        # Update some fields, set state to Failed/Error
        revised = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = revised
            document.update(abstract=sample_json['abstract'],
                            state=sample_json['state'],
                            publication=sample_json['publication'],
                            content=sample_json['content'],
                            )
        self.assertEqual(document.metadata['created'], created)
        self.assertEqual(document.metadata['revised'], revised)
        self.maxDiff = None
        self.assertNotEqual(document.content, sample_json['content'])

        # Update some fields, set state to Failed/Error
        revised = datetime.datetime.now(TZINFO)
        new_content = "<p> HI </p><p> THERE!!! </p>"
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = revised
            document.update(abstract=sample_json['abstract'],
                            state=sample_json['state'],
                            publication=sample_json['publication'],
                            content=new_content,
                            )
        self.assertEqual(document.metadata['created'], created)
        self.assertEqual(document.metadata['revised'], revised)
        self.assertEqual(document.metadata['content'], new_content)
        self.assertEqual(document.content, new_content)

    def test_update_content_state(self):
        from ..models import create_content
        from ..utils import TZINFO

        # Create some new content
        created = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = created
            document = create_content(title='My Document')
        self.assertEqual(document.metadata['created'], created)
        self.assertEqual(document.metadata['revised'], created)

        # Update some fields, set state to Failed/Error
        revised = datetime.datetime.now(TZINFO)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = revised
            document.update(abstract='Abstract of My Document',
                            state='Failed/Error',
                            publication=100)
        self.assertEqual(document.metadata['created'], created)
        self.assertEqual(document.metadata['revised'], revised)

        # Call update_content_state
        from ..views import update_content_state
        request = testing.DummyRequest()
        request.registry.settings['publishing.url'] = 'http://cnx-publishing/'
        mock_response = mock.Mock(status_code=200)
        mock_response.content = b'{"state": "Failed/Error"}'
        with mock.patch('requests.get') as mock_get:
            mock_get.return_value = mock_response
            update_content_state(request, document)
            args, kwargs = mock_get.call_args
            self.assertEqual(args, ('http://cnx-publishing/publications/100',))
        self.assertEqual(document.metadata['created'], created)
        # since the state didn't change, revised should not be updated
        self.assertEqual(document.metadata['revised'], revised)

        # Call update_content_state again with a change in status
        mock_response = mock.Mock(status_code=200)
        mock_response.content = b'{"state": "Done/Success"}'
        state_updated = datetime.datetime.now(TZINFO)
        with mock.patch('requests.get') as mock_get:
            mock_get.return_value = mock_response
            with mock.patch('datetime.datetime') as mock_datetime:
                mock_datetime.now.return_value = state_updated
                with mock.patch.object(self.storage_cls, 'update'):
                    update_content_state(request, document)

            args, kwargs = mock_get.call_args
            self.assertEqual(args, ('http://cnx-publishing/publications/100',))
        self.assertEqual(document.metadata['created'], created)
        # since the state changed, revised should be updated
        self.assertEqual(document.metadata['revised'], state_updated)

    def test_get_content_for_document(self):
        # Set up a piece of content.
        id = str(uuid.uuid4()),
        document_title = "The Floating Dust"
        from ..models import Document
        expected = Document(document_title, id=id)
        expected.acls = {'userid': ('edit', 'view', 'publish')}

        # Test the view
        request = testing.DummyRequest()
        request.matchdict = {'id': id}
        with mock.patch.object(self.storage_cls, 'get', return_value=expected):
            from ..views import get_content
            content = get_content(request)
        self.assertEqual(content, expected)

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
        self.assertEqual(response.body, data)
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
            self.document.acls = {'userid': ('edit', 'publish', 'view')}
            self.document.id = str(uuid.uuid4())
            return self.document
        # Given the minimal amount of information, create a document.
        self.storage_cls.add = mock.Mock(side_effect=mocked_add)
        self.storage_cls.persist = mock.Mock(return_value=None)

        # Minimal document posts require a title.
        from ..views import post_content
        request = testing.DummyRequest()
        request.json_body = {'title': title, 'submitter': request.user}
        returned_document = post_content(request)

        self.assertEqual(returned_document, self.document)
        self.assertEqual(request.response.status, '201 Created')
        content_url = request.route_url('get-content-json', id=self.document.id)
        self.assertIn(('Location', content_url,),
                      request.response.headerlist)

    def test_post_content(self):
        from ..models import DEFAULT_LICENSE
        post_data = {
            'title': "Turning DNA through resonance",
            'abstract': "Theories on turning DNA structures",
            'created': datetime.datetime.now().isoformat(),
            'revised': datetime.datetime.now().isoformat(),
            'license': {'url': DEFAULT_LICENSE.url},
            'language': 'en',
            'content': "Ding dong the switch is flipped.",
            }
        self.document = None
        self.addCleanup(delattr, self, 'document')

        def mocked_add(item):
            self.document = item
            self.document.acls = {'username': ('edit', 'publish', 'view')}
            self.document.id = str(uuid.uuid4())
            return self.document
        self.storage_cls.add = mock.Mock(side_effect=mocked_add)
        self.storage_cls.persist = mock.Mock(return_value=None)

        # Minimal document posts require a title.
        request = testing.DummyRequest()
        request.json_body = post_data.copy()
        request.__class__.unauthenticated_userid = 'username'
        from ..views import post_content
        returned_document = post_content(request)

        self.assertEqual(request.response.status, '201 Created')
        content_url = request.route_url('get-content-json', id=self.document.id)
        self.assertIn(('Location', content_url,),
                      request.response.headerlist)

        self.assertEqual(returned_document, self.document)
        self.assertEqual(returned_document.metadata['title'], post_data['title'])
        self.assertEqual(returned_document.metadata['abstract'], post_data['abstract'])
        # TODO Test created and revised dates.
        self.assertEqual(returned_document.metadata['license'].url, DEFAULT_LICENSE.url)
        self.assertEqual(returned_document.metadata['language'], post_data['language'])
        self.assertEqual(returned_document.content, post_data['content'])

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
        request.registry.settings['authoring.file_upload.limit'] = '50'
        from ..views import post_resource
        location = post_resource(request)

        self.assertEqual(request.response.status, '201 Created')
        expected_location = request.route_path('get-resource',
                                               hash=self.resource.hash)
        self.assertIn(('Location', expected_location,),
                      request.response.headerlist)
