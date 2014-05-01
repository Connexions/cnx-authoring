# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import functools
import json
try:
    from urllib import urlencode # python 2
except ImportError:
    from urllib.parse import urlencode # renamed in python 3
try:
    import urlparse # python2
except ImportError:
    import urllib.parse as urlparse # renamed in python3

from pyramid.security import forget
from pyramid.view import view_config
from pyramid import httpexceptions
import requests
from openstax_accounts.interfaces import *

from .models import (create_content, derive_content, Document, Resource,
        BINDER_MEDIATYPE, derive_resources, DocumentNotFoundError)
from .schemata import DocumentSchema, BinderSchema
from .storage import storage
from . import utils


def authenticated_only(function):
    @functools.wraps(function)
    def wrapper(request, *args, **kwargs):
        if not request.authenticated_userid:
            raise httpexceptions.HTTPUnauthorized()
        return function(request, *args, **kwargs)
    return wrapper


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


@view_config(route_name='callback')
@authenticated_only
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


@view_config(route_name='options', request_method='OPTIONS', renderer='string')
def options(request):
    return ''


@view_config(route_name='user-search', request_method='GET', renderer='json')
@authenticated_only
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


@view_config(route_name='profile', request_method='GET', renderer='json')
@authenticated_only
def profile(request):
    return request.user


@view_config(route_name='user-contents', request_method='GET', renderer='json')
@authenticated_only
def user_contents(request):
    """Extract of the contents that belong to the current logged in user"""
    items = []
    for content in storage.get_all(submitter=request.unauthenticated_userid):
        item = content.__json__()
        document = {k: item[k] for k in  
               ['mediaType', 'title', 'id', 'version', 'revised', 'derivedFrom']}
        document['id'] = '@'.join([document['id'], document['version']])
        items.append(document)
    items.sort(key=lambda item: item['revised'], reverse=True)
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


@view_config(route_name='get-content-json', request_method='GET', renderer='json')
@authenticated_only
def get_content(request):
    """Acquisition of content by id"""
    id = request.matchdict['id']
    content = storage.get(id=id, submitter=request.unauthenticated_userid)
    if content is None:
        raise httpexceptions.HTTPNotFound()
    if (content.metadata['state'] not in [None, 'Done/Success'] and
            content.metadata['publication']):
        publishing_url = request.registry.settings['publishing.url']
        if not publishing_url.endswith('/'):
            publishing_url = publishing_url + '/'
        response = requests.get(urlparse.urljoin(
            publishing_url, content.metadata['publication']))
        if response.status_code == 200:
            try:
                result = json.loads(response.content.decode('utf-8'))
                content.update(state=result['state'])
                storage.update(content)
                storage.persist()
            except (TypeError, ValueError):
                pass
    return content


@view_config(route_name='get-resource', request_method='GET')
@authenticated_only
def get_resource(request):
    """Acquisition of a resource item"""
    hash = request.matchdict['hash']
    resource = storage.get(hash=hash, type_=Resource)
    if resource is None:
        raise httpexceptions.HTTPNotFound()
    resp = request.response
    resp.body = resource.data.read()
    resource.data.seek(0)
    resp.content_type = resource.media_type
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
    if cstruct.get('media_type') == BINDER_MEDIATYPE:
        schema = BinderSchema()
    else:
        schema = DocumentSchema()
    try:
        appstruct = schema.bind().deserialize(cstruct)
    except Exception as e:
        raise httpexceptions.HTTPBadRequest(body=json.dumps(e.asdict()))
    appstruct['derived_from'] = derived_from
    content = create_content(**appstruct)
    resources = []
    if content.mediatype != BINDER_MEDIATYPE and derived_from:
        resources = derive_resources(request, content)

    for r in resources:
        try:
            storage.add(r)
        except:
            storage.abort()

    try:
        content = storage.add(content)
    except:
        storage.abort()
    finally:
        storage.persist()

    return content


@view_config(route_name='post-content', request_method='POST', renderer='json')
@authenticated_only
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
    try:
        if isinstance(cstruct, list):
            for item in cstruct:
                contents.append(post_content_single(request, item).__json__())
        else:
            content = post_content_single(request, cstruct)
    except DocumentNotFoundError as e:
        raise httpexceptions.HTTPBadRequest(e.message)

    resp = request.response
    resp.status = 201
    if content is not None:
        resp.headers.add(
            'Location',
            request.route_url('get-content-json', id=content.id))
        return content
    return contents


@view_config(route_name='post-resource', request_method='POST', renderer='string')
@authenticated_only
def post_resource(request):
    """Accept a resource file.
    On success, the Location header is set to the resource location.
    The response body contains the resource location.
    """
    file_form_field = request.POST['file']
    mediatype = file_form_field.type
    data = file_form_field.file

    resource = Resource(mediatype, data)
    try:
        resource = storage.add(resource)
    except:
        storage.abort()
    finally:
        storage.persist()

    resp = request.response
    resp.status = 201
    location = request.route_path('get-resource', hash=resource.hash)
    resp.headers.add('Location', location)
    return location


@view_config(route_name='put-content', request_method='PUT', renderer='json')
@authenticated_only
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

    utils.change_dict_keys(cstruct, utils.camelcase_to_underscore)
    cstruct['submitter'] = request.unauthenticated_userid
    for key, value in utils.utf8(content.to_dict()).items():
        cstruct.setdefault(key, value)

    if cstruct.get('media_type') == BINDER_MEDIATYPE:
        schema = BinderSchema()
    else:
        schema = DocumentSchema()
    try:
        appstruct = schema.bind().deserialize(cstruct)
    except Exception as e:
        raise httpexceptions.HTTPBadRequest(body=json.dumps(e.asdict()))

    try:
        content.update(**appstruct)
    except DocumentNotFoundError as e:
        raise httpexceptions.HTTPBadRequest(e.message)
    storage.update(content)
    storage.persist()

    resp = request.response
    resp.status = 200
    resp.headers.add(
            'Location',
            request.route_url('get-content-json', id=content.id))
    return content


@view_config(route_name='search-content', request_method='GET', renderer='json')
@authenticated_only
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


def post_to_publishing(request, userid, submitlog, content_ids):
    publishing_url = request.registry.settings['publishing.url']
    filename = 'contents.epub'
    contents = []
    for content_id in content_ids:
        content = storage.get(id=content_id, submitter=userid)
        if content is None:
            raise httpexceptions.HTTPBadRequest('Unable to publish: '
                    'content not found {}'.format(content_id))
        contents.append(content)

    upload_data = utils.build_epub(contents, userid, submitlog)
    files = {
        'epub': (filename, upload_data.read(), 'application/epub+zip'),
        }
    api_key = request.registry.settings['publishing.api_key']
    headers = {'x-api-key': api_key}
    return contents, requests.post(publishing_url, files=files, headers=headers)


@view_config(route_name='publish', request_method='POST', renderer='json')
@authenticated_only
def publish(request):
    """Publish documents to archive
    """
    request_body = request.json_body
    contents, response = post_to_publishing(request,
            request.unauthenticated_userid,
            request_body['submitlog'], request_body['items'])
    if response.status_code != 200:
        raise httpexceptions.HTTPBadRequest('Unable to publish: '
                'response status code: {}'.format(response.status_code))
    try:
        result = json.loads(response.content.decode('utf-8'))
        for content in contents:
            content.update(state=result['state'],
                    publication=str(result['publication']))
            storage.update(content)
            storage.persist()
        return result
    except (TypeError, ValueError):
        raise httpexceptions.HTTPBadRequest('Unable to publish: '
                'response body: {}'.format(response.content.decode('utf-8')))
