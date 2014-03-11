# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
from pyramid.view import view_config
from pyramid import httpexceptions

from .models import create_content, Document, Resource
from .schemata import DocumentSchema
from .storage import storage


@view_config(route_name='get-content', request_method='GET', renderer='json')
def get_content(request):
    """Acquisition of content by id"""
    id = request.matchdict['id']
    content = storage.get(id=id)
    if content is None:
        raise httpexceptions.HTTPNotFound()
    return content.to_dict()


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
    cstruct = request.json_body
    appstruct = DocumentSchema().bind().deserialize(cstruct)
    content = create_content(**appstruct)

    content = storage.add(content)
    storage.persist()

    resp = request.response
    resp.status = 201
    resp.headers.add(
        'Location',
        request.route_url('get-content', id=content.id))
    return content.to_dict()


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
