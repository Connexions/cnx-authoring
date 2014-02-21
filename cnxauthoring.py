# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###



def declare_routes(config):
    """Declaration of routing"""
    add_route = config.add_route
    add_route('get-content', '/contents/{id}', request_method='GET')
    add_route('get-resource', '/resources/{hash}', request_method='GET')
    add_route('post-content', '/contents', request_method='POST')



# ############# #
#   Utilities   #
# ############# #









# ########## #
#   Models   #
# ########## #
import time
import datetime
import hashlib

import pytz


# Timezone info initialized from the system timezone.
TZINFO = pytz.timezone(time.tzname[0])

DOCUMENT_MEDIATYPE = "application/vnd.org.cnx.document"
LICENSE_PARAMETER_MARKER = object()
DEFAULT_LANGUAGE = 'en-us'


class License(object):
    """A declaration of authority typically assigned to things."""

    def __init__(self, name, url, abbr=None, version=None):
        self.name = name
        self.url = url
        self.abbr = abbr
        self.version = version


_LICENSE_VALUES = (
  ('Attribution', 'by', '1.0',
   'http://creativecommons.org/licenses/by/1.0'),
  ('Attribution-NoDerivs', 'by-nd', '1.0',
   'http://creativecommons.org/licenses/by-nd/1.0'),
  ('Attribution-NoDerivs-NonCommercial', 'by-nd-nc', '1.0',
   'http://creativecommons.org/licenses/by-nd-nc/1.0'),
  ('Attribution-NonCommercial', 'by-nc', '1.0',
   'http://creativecommons.org/licenses/by-nc/1.0'),
  ('Attribution-ShareAlike', 'by-sa', '1.0',
   'http://creativecommons.org/licenses/by-sa/1.0'),
  ('Attribution', 'by', '2.0',
   'http://creativecommons.org/licenses/by/2.0/'),
  ('Attribution-NoDerivs', 'by-nd', '2.0',
   'http://creativecommons.org/licenses/by-nd/2.0'),
  ('Attribution-NoDerivs-NonCommercial', 'by-nd-nc', '2.0',
   'http://creativecommons.org/licenses/by-nd-nc/2.0'),
  ('Attribution-NonCommercial', 'by-nc', '2.0',
   'http://creativecommons.org/licenses/by-nc/2.0'),
  ('Attribution-ShareAlike', 'by-sa', '2.0',
   'http://creativecommons.org/licenses/by-sa/2.0'),
  ('Attribution', 'by', '3.0',
   'http://creativecommons.org/licenses/by/3.0/'),
  ('Attribution', 'by', '4.0',
   'http://creativecommons.org/licenses/by/4.0/'),
  )
_LICENSE_KEYS = ('name', 'abbr', 'version', 'url',)
LICENSES = [License(**dict(args))
            for args in [zip(_LICENSE_KEYS, v) for v in _LICENSE_VALUES]]
DEFAULT_LICENSE = LICENSES[-1]


class Resource:
    """Any *file* that is referenced within a ``Document``."""

    def __init__(self, mediatype, data):
        self.mediatype = mediatype
        # ``data`` must be a buffer or file-like object.
        self.data = data
        self._hash = hashlib.new('sha1', self.data.read()).hexdigest()
        # FIXME There has got to be a better way to reset position
        #       to zero after read.
        self.data.seek(0)

    @property
    def hash(self):
        return self._hash


class Document:
    """Modular documents that contain written text
    by one or more authors.
    """
    mediatype = DOCUMENT_MEDIATYPE

    def __init__(self, title, id=None,
                 contents=None, summary=None,
                 created=None, modified=None,
                 license=LICENSE_PARAMETER_MARKER,
                 language=None, derived_from=None):
        self.title = title
        self.id = id
        self.contents = contents
        self.summary = summary is None and '' or summary
        now = datetime.datetime.now(tz=TZINFO)
        self.created = created is None and now or created
        self.modified = modified is None and now or modified
        # license is a reserved name that will never be None.
        if license is LICENSE_PARAMETER_MARKER:
            self.license = DEFAULT_LICENSE
        else:
            self.license = license
        self.language = language is None and DEFAULT_LANGUAGE or language
        self.derived_from = derived_from


def create_content(**appstruct):
    """Given a Colander *appstruct*, create a content object."""
    kwargs = appstruct.copy()
    # TODO Lookup via storage.
    if 'license' in appstruct:
        license = [l for l in LICENSES if l.url == appstruct['license']['url']][0]
        kwargs['license'] = license
    return Document(**kwargs)


# ############ #
#   Schemata   #
# ############ #
import colander


@colander.deferred
def deferred_datetime_missing(node, kw):
    dt = datetime.datetime.now(tz=TZINFO)
    return dt


class LicenseSchema(colander.MappingSchema):
    """Schema for ``License``"""

    name = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    url = colander.SchemaNode(
        colander.String(),
        validator=colander.url,
        )
    abbr = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    version = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )

license_schema = LicenseSchema()


class DocumentSchema(colander.MappingSchema):
    """Schema for ``Document``"""

    # id = colander.SchemaNode(
    #     UUID(),
    #     missing=colander.drop,
    #     )
    title = colander.SchemaNode(
        colander.String(),
        )
    summary = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    created = colander.SchemaNode(
        colander.DateTime(default_tzinfo=TZINFO),
        missing=deferred_datetime_missing,
        )
    modified = colander.SchemaNode(
        colander.DateTime(default_tzinfo=TZINFO),
        missing=deferred_datetime_missing,
        )
    license = LicenseSchema(
        missing=colander.drop,
        )
    # language = colander.SchemaNode(
    #     colander.String(),
    #     default=DEFAULT_LANGUAGE,
    #     )
    # derived_from = colander.SchemaNode(
    #     colander.String(),
    #     missing=colander.drop,
    #     validator=colander.url,
    #     )
    contents = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )

document_schema = DocumentSchema()


import unittest


class DocumentSchemaTestCase(unittest.TestCase):

    def test_datetime_fields_missing(self):
        cstruct = {
            'title': 'required title',
            }
        appstruct = document_schema.bind().deserialize(cstruct)
        self.assertTrue(isinstance(appstruct['created'], datetime.datetime))
        self.assertTrue(isinstance(appstruct['created'], datetime.datetime))


    @unittest.skip("not implemented")
    def test_datetime_fields_in_future(self):
        pass

    @unittest.skip("not implemented")
    def test_license_as_url(self):
        # Given the {..., 'license': '<license-url-value>', ...}
        #   prepare it to a LicenseSchema based value.
        pass

    @unittest.skip("not implemented")
    def test_id_dropped_w_new(self):
        # If the schema is bound with ``bind(new=True)``,
        #   then drop the id value if one is given,
        #   this prevents a user from specifying an id,
        #   but allows the id to pass through on update.
        pass


# ################# #
#   Modifications   #
# ################# #
import datetime
import uuid

from pyramid.renderers import JSON


def json_uuid_adapter(obj, request):
    return str(obj)


def json_document_adapter(obj, request):
    return {
        'id': obj.id,
        'title': obj.title,
        'created': obj.created,
        'modified': obj.modified,
        }


def json_datetime_adapter(obj, request):
    return obj.isoformat()


JSON_RENDERERS = [
    (datetime.datetime, json_datetime_adapter,),
    (uuid.UUID, json_uuid_adapter,),
    (Document, json_document_adapter,),
    ]


def includeme(config):
    """Called at application initialization to modify renderers."""
    json_renderer = JSON()
    for type_, adapter in JSON_RENDERERS:
        json_renderer.add_adapter(type_, adapter)


# ########### #
#   Storage   #
# ########### #

class Storage(object):
    """Utility for managing and interfacing with the the storage medium."""


storage = Storage()


# ######### #
#   Views   #
# ######### #
from pyramid.view import view_config
from pyramid import httpexceptions


@view_config(route_name='get-content', request_method='GET', renderer='json')
def get_content(request):
    """Acquisition of content by id"""
    id = request.matchdict['id']
    content = storage.get(id=id)
    if content is None:
        raise httpexceptions.HTTPNotFound()
    return content


@view_config(route_name='get-resource', request_method='GET')
def get_resource(request):
    """Acquisition of a resource item"""
    hash = request.matchdict['hash']
    resource = storage.get(hash=hash, type_=Resource)
    if resource is None:
        raise httpexceptions.HTTPNotFound()
    resp = request.response
    resp.body_file = resource.data
    resp.content_type = resource.mediatype
    return resp


@view_config(route_name='post-content', request_method='POST', renderer='json')
def post_content(request):
    """Create content.
    Returns the content location and a copy of the newly created content.
    """
    cstruct = request.POST
    appstruct = DocumentSchema().bind().deserialize(cstruct)
    content = create_content(**appstruct)

    content = storage.add(content)
    storage.persist()

    resp = request.response
    resp.status = 201
    resp.headers.add(
        'Location',
        request.route_url('get-content', id=content.id))
    return content


@view_config(route_name='post-resource', request_method='POST', renderer='json')
def post_resource(request):
    """Accept a resource file.
    On success, the Location header is set to the resource location.
    The response body contains the resource location.
    """
    file_form_field = request.POST['file']
    mediatype = file_form_field.type
    data = file_form_field.file

    resource = Resource(mediatype, data)
    resource = storage.add(resource)
    storage.persist()

    resp = request.response
    resp.status = 201
    location = request.route_url('get-resource', hash=resource.hash)
    resp.headers.add('Location', location)
    return location


# ######### #
#   Tests   #
# ######### #
import io
import datetime
import hashlib
import json
import unittest
import uuid
from unittest import mock

from pyramid import testing


class ViewsTests(unittest.TestCase):

    def setUp(self):
        self.config = testing.setUp()
        declare_routes(self.config)

    tearDown = testing.tearDown

    def test_get_content_for_document(self):
        # Set up a piece of content.
        id = uuid.uuid4(),
        document_title = "The Floating Dust"
        expected = Document(document_title, id=id)

        # Mock the storage call.
        global storage
        storage.get = mock.MagicMock(return_value=expected)

        # Test the view
        request = testing.DummyRequest()
        request.matchdict = {'id': id}
        content = get_content(request)
        self.assertEqual(content, expected)

    def test_get_content_404(self):
        # Mock the storage call.
        global storage
        storage.get = mock.MagicMock(return_value=None)

        request = testing.DummyRequest()
        request.matchdict = {'id': '1234abcde'}
        from pyramid.httpexceptions import HTTPNotFound
        self.assertRaises(HTTPNotFound, get_content, request)

    def test_get_resource(self):
        # Set up a resource
        data = b'yada yadda yaadda'
        hasher = hashlib.new('sha1', data)
        mediatype = 'text/plain'
        expected = Resource(mediatype, data=io.BytesIO(data))

        # Mock the storage call.
        global storage
        storage.get = mock.MagicMock(return_value=expected)

        # Test the view
        request = testing.DummyRequest()
        request.matchdict = {'hash': hasher.hexdigest()}
        response = get_resource(request)
        self.assertEqual(b''.join(response.app_iter), data)
        self.assertEqual(response.content_type, mediatype)

    def test_get_resource_404(self):
        # Mock the storage call.
        global storage
        storage.get = mock.MagicMock(return_value=None)

        request = testing.DummyRequest()
        request.matchdict = {'hash': '2ab3c4d5e6f9eb79'}
        from pyramid.httpexceptions import HTTPNotFound
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
        global storage
        storage.add = mock.Mock(side_effect=mocked_add)
        storage.persist = mock.MagicMock(return_value=None)

        # Minimal document posts require a title.
        request = testing.DummyRequest()
        request.POST = {'title': title}
        returned_document = post_content(request)

        self.assertEqual(returned_document, self.document)
        self.assertEqual(request.response.status, '201 Created')
        content_url = request.route_url('get-content', id=self.document.id)
        self.assertIn(('Location', content_url,),
                      request.response.headerlist)

    def test_post_content(self):
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

        global storage
        storage.add = mock.Mock(side_effect=mocked_add)
        storage.persist = mock.MagicMock(return_value=None)

        # Minimal document posts require a title.
        request = testing.DummyRequest()
        request.POST = post_data.copy()
        returned_document = post_content(request)

        self.assertEqual(request.response.status, '201 Created')
        content_url = request.route_url('get-content', id=self.document.id)
        self.assertIn(('Location', content_url,),
                      request.response.headerlist)

        self.assertEqual(returned_document, self.document)
        self.assertEqual(returned_document.title, post_data['title'])
        self.assertEqual(returned_document.summary, post_data['summary'])
        # TODO Test created and modified dates.
        self.assertEqual(returned_document.license.url, DEFAULT_LICENSE.url)
        self.assertEqual(returned_document.language, post_data['language'])
        self.assertEqual(returned_document.contents, post_data['contents'])

    def test_post_resource(self):
        # Set up a resource
        data = b'yada yadda yaadda'
        mediatype = 'text/plain'
        hash = hashlib.new('sha1', data).hexdigest()
        expected = Resource(mediatype, data=io.BytesIO(data))

        self.resource = None
        self.addCleanup(delattr, self, 'resource')
        def mocked_add(item):
            self.resource = item
            self.resource.id = uuid.uuid4()
            return self.resource

        global storage
        storage.add = mock.Mock(side_effect=mocked_add)
        storage.persist = mock.MagicMock(return_value=None)

        # Mock cgi.FieldStorage for file upload.
        upload = mock.Mock()
        upload.file = io.BytesIO(data)
        upload.type = mediatype

        # Minimal document posts require a title.
        request = testing.DummyRequest()
        request.POST = {'file': upload}
        location = post_resource(request)

        self.assertEqual(request.response.status, '201 Created')
        expected_location = request.route_url('get-resource',
                                              hash=self.resource.hash)
        self.assertIn(('Location', expected_location,),
                      request.response.headerlist)


class ModelJSONRendering(unittest.TestCase):
    """Ensure the models render to JSON.
    Note that the adaptation to JSON is transparent
    through view configuration of a 'renderer'.
    """

    def setUp(self):
        self.config = testing.setUp()

    tearDown = testing.tearDown

    def render(self, things, adapters=()):
        """Manually call the renderer and pass in the adapters.
        Adapters get passed in because the component registry is scoped
        to the test case.
        """
        from pyramid.renderers import JSON
        renderer = JSON(adapters=adapters)
        return renderer(things)(things, {})

    def test_document_to_json(self):
        id = uuid.uuid4()
        title = "Too late"
        document = Document(title, id=id)

        expected_json = {
            'id': str(id),
            'title': title,
            'created': document.created.isoformat(),
            'modified': document.modified.isoformat(),
            }
        expected_json = json.dumps(expected_json)

       # Call the renderer
        json_document = self.render(document, adapters=JSON_RENDERERS)

        self.assertEqual(json_document, expected_json)
