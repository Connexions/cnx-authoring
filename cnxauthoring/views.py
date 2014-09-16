# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import functools
import io
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

from cnxepub.models import flatten_to_documents
from .models import (create_content, derive_content, revise_content,
        Document, Binder, Resource, BINDER_MEDIATYPE, DOCUMENT_MEDIATYPE,
        DocumentNotFoundError)
from .schemata import DocumentSchema, BinderSchema, UserSchema
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
        return {
                'per_page': 20,
                'users': [],
                'order_by': 'username ASC',
                'num_matching_users': 0,
                'page': 0,
                }
    accounts = request.registry.getUtility(IOpenstaxAccounts)
    result = accounts.search(q)
    result.pop('application_users')
    result['users'] = [utils.profile_to_user_dict(profile)
            for profile in result['users']]
    return result


@view_config(route_name='profile', request_method='GET', renderer='json')
@authenticated_only
def profile(request):
    return UserSchema().bind().deserialize(
            utils.profile_to_user_dict(request.user))

def update_content_state(request, content):
    """Updates content state if it is non-terminal by checking w/ publishing service"""
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
                try:
                    storage.update(content)
                    storage.persist()
                except storage.Error:
                    storage.abort()
            except (TypeError, ValueError):
                # Not critical if there's a json problem here - perhaps log this
                pass

@view_config(route_name='user-contents', request_method='GET', renderer='json')
@authenticated_only
def user_contents(request):
    """Extract of the contents that belong to the current logged in user"""
    items = []
    binder_ids = set()
    # filter kwargs to subset of content metadata fields - avoid DB errors
    kwargs = {k:v for k,v in request.GET.items() if k in ['mediaType','state','containedIn']}
    if kwargs:
        utils.change_dict_keys(kwargs, utils.camelcase_to_underscore)
    # TODO use acls instead of filter by submitter
    contents = storage.get_all(submitter={'id': request.unauthenticated_userid},**kwargs)
    for content in contents:
        update_content_state(request, content)
        if isinstance(content,Binder):
            binder_ids.add(content.id)

        item = content.__json__()
        document = {k: item[k] for k in ['mediaType', 'title', 'id', 'version',
                                         'revised', 'derivedFrom', 'state', 'containedIn']}

        # Don't add version to published items, so they are link to archive instead of authoring (no @draft)
        if document['state'] != 'Done/Success':
            document['id'] = '@'.join([document['id'], document['version']])

        items.append(document)

    # filter out draft docs inside draft binders that this user can see
    items = [i for i in items if not set(i['containedIn']).intersection(binder_ids)]

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
    content = storage.get(id=id)
    if content is None:
        raise httpexceptions.HTTPNotFound()
    if not request.has_permission('view', content):
        raise httpexceptions.HTTPForbidden(
                'You do not have permission to view {}'.format(id))
    update_content_state(request, content)
    return content


@view_config(route_name='get-resource', request_method='GET')
@authenticated_only
def get_resource(request):
    """Acquisition of a resource item"""
    hash = request.matchdict['hash']
    resource = storage.get(hash=hash, type_=Resource)
    if resource is None:
        raise httpexceptions.HTTPNotFound()
    if not request.has_permission('view', resource):
        raise httpexceptions.HTTPForbidden()
    resp = request.response
    with resource.open() as data:
        resp.body = data.read()
    resp.content_type = resource.media_type
    if 'html' in resp.content_type:
        resp.content_type = 'application/octet-stream'
    return resp


def post_content_single(request, cstruct):
    utils.change_dict_keys(cstruct, utils.camelcase_to_underscore)
    derived_from = cstruct.get('derived_from')
    archive_id = cstruct.get('id')
    if derived_from:
        try:
            cstruct = derive_content(request, **cstruct)
        except DocumentNotFoundError:
            raise httpexceptions.HTTPBadRequest(
                    'Derive failed: {}'.format(derived_from))

    if archive_id:
        try:
            cstruct = revise_content(request, **cstruct)
        except DocumentNotFoundError:
            raise httpexceptions.HTTPNotFound()
        can_publish = utils.fetch_archive_content(request, archive_id,
                extras=True)['can_publish']
        if request.unauthenticated_userid not in can_publish:
            raise httpexceptions.HTTPForbidden(
                    'You do not have permission to edit {}'.format(archive_id))

    uids = set([request.unauthenticated_userid])
    cstruct['submitter'] = utils.profile_to_user_dict(request.user)
    cstruct.setdefault('authors', [])
    author_ids = [i['id'] for i in cstruct['authors']]
    uids.update(author_ids)
    if request.unauthenticated_userid not in author_ids:
        cstruct['authors'] += [utils.profile_to_user_dict(request.user)]

    cstruct.setdefault('licensors', [])
    licensor_ids = [i['id'] for i in cstruct['licensors']]
    if request.unauthenticated_userid not in licensor_ids:
        cstruct['licensors'] += [utils.profile_to_user_dict(request.user)]

    cstruct.setdefault('publishers', [])
    publisher_ids = [i['id'] for i in cstruct['publishers']]
    uids.update(publisher_ids)
    # publishers is known as maintainers in legacy
    for maintainer in cstruct.get('maintainers', []):
        if maintainer['id'] not in publisher_ids:
            cstruct['publishers'] += [maintainer]
            publisher_ids.append(maintainer['id'])
            uids.add(maintainer['id'])
    if request.unauthenticated_userid not in publisher_ids:
        cstruct['publishers'] += [utils.profile_to_user_dict(request.user)]

    if cstruct.get('media_type') == BINDER_MEDIATYPE:
        schema = BinderSchema()
    else:
        schema = DocumentSchema()
    try:
        appstruct = schema.bind().deserialize(cstruct)
    except Exception as e:
        raise httpexceptions.HTTPBadRequest(body=json.dumps(e.asdict()))
    appstruct['derived_from'] = derived_from
    if archive_id:
        appstruct['id'] = archive_id.split('@')[0]
        appstruct['cnx_archive_uri'] = archive_id

    content = create_content(**appstruct)

    if not archive_id:
        # new content, need to create acl entry in publishing
        utils.create_acl_for(request, content, uids)
    # accept roles and license
    utils.accept_roles_and_license(
            request, content, request.unauthenticated_userid)

    resources = []
    if content.mediatype != BINDER_MEDIATYPE and (derived_from or archive_id):
        resources = utils.derive_resources(request, content)

    for r in resources:
        try:
            storage.add(r)
            storage.persist()
        except storage.Error:
            storage.abort()

    try:
        content = storage.add(content)
        if content.mediatype == BINDER_MEDIATYPE:
            utils.update_containment(content)
        storage.persist()
    except storage.Error:
        storage.abort()

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
                contents.append(post_content_single(request, item))
                if not request.has_permission('create', contents[-1]):
                    raise httpexceptions.HTTPForbidden()
        else:
            content = post_content_single(request, cstruct)
            if not request.has_permission('create', content):
                raise httpexceptions.HTTPForbidden()
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

    resource = Resource(mediatype, io.BytesIO(data.read()))
    if not request.has_permission('create', resource):
        raise httpexceptions.HTTPForbidden()

    try:
        resource = storage.add(resource)
        storage.persist()
    except storage.Error:
        storage.abort()

    resp = request.response
    resp.status = 201
    location = request.route_path('get-resource', hash=resource.hash)
    resp.headers.add('Location', location)
    return location


@view_config(route_name='delete-content', request_method='DELETE', renderer='json')
@authenticated_only
def delete_content(request):
    """delete a stored document"""
    id = request.matchdict['id']
    content = storage.get(id=id)
    if content is None:
        raise httpexceptions.HTTPNotFound()
    if not request.has_permission('edit', content):
        raise httpexceptions.HTTPForbidden(
                'You do not have permission to delete {}'.format(id))
    if content.metadata['media_type'] == DOCUMENT_MEDIATYPE and content.metadata['contained_in']:
        raise httpexceptions.HTTPForbidden(
                'Content {} is contained in {} and cannot be deleted'.format(id,
                     content.metadata['contained_in']))
    try:
        resource = storage.remove(content)
        if content.metadata['media_type'] == BINDER_MEDIATYPE:
            utils.update_containment(content, deletion = True)
        storage.persist()
    except storage.Error:
        storage.abort()

@view_config(route_name='put-content', request_method='PUT', renderer='json')
@authenticated_only
def put_content(request):
    """Modify a stored document"""
    id = request.matchdict['id']
    content = storage.get(id=id)
    if content is None:
        raise httpexceptions.HTTPNotFound()
    if not request.has_permission('edit', content):
        raise httpexceptions.HTTPForbidden(
                'You do not have permission to edit {}'.format(id))

    try:
        cstruct = request.json_body
    except (TypeError, ValueError):
        raise httpexceptions.HTTPBadRequest('Invalid JSON')

    utils.change_dict_keys(cstruct, utils.camelcase_to_underscore)
    cstruct['submitter'] = utils.profile_to_user_dict(request.user)
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
    try:
        storage.update(content)
        if content.mediatype == BINDER_MEDIATYPE:
            utils.update_containment(content)
        storage.persist()
    except storage.Error:
        storage.abort()

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

    result = storage.search(q, submitter_id=request.unauthenticated_userid)
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
    """all params come from publish post. Content_ids is a json list of lists,
    containing ids of binders and the pages in them to be published.  Each binder
    is a list, starting with the binderid, and following with documentid of each
    draft page to publish. As a degenerate case, it may be a single list of this
    format. In addition to binder lists, the top level list may contain document
    ids - these will be published as a 'looseleaf' set of pages."""

    publishing_url = request.registry.settings['publishing.url']
    filename = 'contents.epub'
    contents = []
    for content_id_item in content_ids:
        if type(content_id_item) == list: # binder list
            content = []
            for content_id in content_id_item:
                if content_id.endswith('@draft'):
                    content_id = content_id[:-len('@draft')]
                content_item = storage.get(id=content_id, submitter=userid)
                if content_item is None:
                    raise httpexceptions.HTTPBadRequest('Unable to publish: '
                            'content not found {}'.format(content_id))
                if not request.has_permission('publish', content):
                    raise httpexceptions.HTTPForbidden(
                        'You do not have permission to publish {}'.format(content_id))
                content.append(content_item)

        else:  #documentid
            content_id = content_id_item
            if content_id.endswith('@draft'):
                content_id = content_id[:-len('@draft')]
            content = storage.get(id=content_id)
            if content is None:
                raise httpexceptions.HTTPBadRequest('Unable to publish: '
                        'content not found {}'.format(content_id))
            if not request.has_permission('publish', content):
                raise httpexceptions.HTTPForbidden(
                    'You do not have permission to publish {}'.format(content_id))

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

