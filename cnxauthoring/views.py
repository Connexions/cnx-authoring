# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import json
try:
    from urllib import urlencode # python 2
except ImportError:
    from urllib.parse import urlencode # renamed in python 3

from pyramid.security import forget
from pyramid.view import view_config
from pyramid import httpexceptions
from openstax_accounts.interfaces import *

from . import Site
from .models import create_content, derive_content, Document, Resource
from .schemata import DocumentSchema
from .storage import storage
from . import utils


@view_config(route_name='login')
def login(request):
    # store where we should redirect to before login
    referer = request.referer or '/'
    redirect_to = request.params.get('redirect', referer)
    if redirect_to == request.route_url('login'):
        redirect_to = '/'
    if request.unauthenticated_userid:
        return httpexceptions.HTTPFound(location=redirect_to)
    request.session.update({'redirect_to': redirect_to})
    request.authenticated_userid # triggers login


@view_config(route_name='callback', context=Site, permission='protected')
def callback(request):
    # callback must be protected so that effective_principals is called
    # callback must redirect
    redirect_to = '/'
    if request.session.get('redirect_to'):
        # redirect_to in session is from login
        redirect_to = request.session.pop('redirect_to')
    raise httpexceptions.HTTPFound(location=redirect_to)


@view_config(route_name='logout')
def logout(request):
    forget(request)
    referer = request.referer or '/'
    redirect_to = request.params.get('redirect', referer)
    if redirect_to == request.route_url('logout'):
        redirect_to = '/'
    raise httpexceptions.HTTPFound(location=redirect_to)


@view_config(route_name='user-search', request_method='GET', renderer='json', context=Site, permission='protected')
def user_search(request):
    """Search for openstax accounts users"""
    q = request.GET.get('q', '')
    if not q:
        return []
    params = urlencode({'q': q})
    accounts = request.registry.getUtility(IOpenstaxAccounts)
    result = accounts.request(
            '/api/users/search.json?{}'.format(params))
    return result


@view_config(route_name='profile', request_method='GET', renderer='json', context=Site, permission='protected')
def profile(request):
    return request.user


@view_config(route_name='user-contents', request_method='GET', renderer='json', context=Site, permission='protected')
def user_contents(request):
    """Contents that belong to the current logged in user"""
    items = []
    for content in storage.get_all(submitter=request.unauthenticated_userid):
        document = content.__json__()
        document['id'] = '@'.join([document['id'], document['version']])
        items.append(document)
    return {
            u'query': {
                u'limits': [],
                },
            u'results': {
                u'items': items,
                u'total': len(items),
                u'limits': [],
                },
            }


@view_config(route_name='get-content-json', request_method='GET', renderer='json', context=Site, permission='protected')
def get_content(request):
    """Acquisition of content by id"""
    id = request.matchdict['id']
    content = storage.get(id=id, submitter=request.unauthenticated_userid)
    if content is None:
        raise httpexceptions.HTTPNotFound()
    return content


@view_config(route_name='get-resource', request_method='GET', context=Site, permission='protected')
def get_resource(request):
    """Acquisition of a resource item"""
    hash = request.matchdict['hash']
    resource = storage.get(hash=hash, type_=Resource)
    if resource is None:
        raise httpexceptions.HTTPNotFound()
    resp = request.response
    if isinstance(resource.data, memoryview):
        resp.body = resource.data.tobytes()
    else:
        resp.body = resource.data
    resp.content_type = resource.mediatype
    return resp


def post_content_single(request, cstruct):
    utils.change_dict_keys(cstruct, utils.camelcase_to_underscore)
    derived_from = cstruct.get('derived_from')
    if derived_from:
        cstruct = derive_content(request, **cstruct)
        if not cstruct:
            raise httpexceptions.HTTPBadRequest(
                    'Derive failed: {}'.format(derived_from))
    cstruct['submitter'] = request.unauthenticated_userid
    try:
        appstruct = DocumentSchema().bind().deserialize(cstruct)
    except Exception as e:
        raise httpexceptions.HTTPBadRequest(body=json.dumps(e.asdict()))
    appstruct['derived_from'] = derived_from
    content = create_content(**appstruct)

    content = storage.add(content)
    storage.persist()

    return content


@view_config(route_name='post-content', request_method='POST', renderer='json', context=Site, permission='protected')
def post_content(request):
    """Create content.
    Returns the content location and a copy of the newly created content.
    """
    try:
        cstruct = request.json_body
    except (TypeError, ValueError):
        raise httpexceptions.HTTPBadRequest('Invalid JSON')

    contents = []
    content = None
    if isinstance(cstruct, list):
        for item in cstruct:
            contents.append(post_content_single(request, item).__json__())
    else:
        content = post_content_single(request, cstruct)

    resp = request.response
    resp.status = 201
    if content:
        resp.headers.add(
            'Location',
            request.route_url('get-content-json', id=content.id))
        return content
    return contents


@view_config(route_name='post-resource', request_method='POST', renderer='json', context=Site, permission='protected')
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


@view_config(route_name='put-content', request_method='PUT', renderer='json', context=Site, permission='protected')
def put_content(request):
    """Modify a stored document"""
    id = request.matchdict['id']
    content = storage.get(id=id, submitter=request.unauthenticated_userid)
    if content is None:
        raise httpexceptions.HTTPNotFound()

    try:
        cstruct = request.json_body
    except (TypeError, ValueError):
        raise httpexceptions.HTTPBadRequest('Invalid JSON')

    cstruct['submitter'] = request.unauthenticated_userid
    for key, value in content.to_dict().items():
        cstruct.setdefault(key, value)

    try:
        appstruct = DocumentSchema().bind().deserialize(cstruct)
    except Exception as e:
        raise httpexceptions.HTTPBadRequest(body=json.dumps(e.asdict()))

    content.update(**appstruct)
    storage.update(content)
    storage.persist()

    resp = request.response
    resp.status = 200
    resp.headers.add(
            'Location',
            request.route_url('get-content-json', id=content.id))
    return content


@view_config(route_name='search-content', request_method='GET', renderer='json', context=Site, permission='protected')
def search_content(request):
    """Search documents by title and contents"""
    empty_response = {
            u'query': {
                u'limits': [],
                },
            u'results': {
                u'items': [],
                u'total': 0,
                u'limits': [],
                },
            }
    q = request.GET.get('q', '').strip()
    if not q:
        return empty_response
    q = utils.structured_query(q)

    result = storage.search(q, submitter=request.unauthenticated_userid)
    items = []
    for content in result:
        document = content.__json__()
        document['id'] = '@'.join([document['id'], document['version']])
        items.append(document)
    return {
            u'query': {
                u'limits': [{'tag': tag, 'value': value} for tag, value in q],
                },
            u'results': {
                u'items': items,
                u'total': len(items),
                u'limits': [],
                },
            }
