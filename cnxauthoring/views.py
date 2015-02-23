# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import io
import datetime
import functools
import json
import logging
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

from cnxepub.models import ATTRIBUTED_ROLE_KEYS
from .models import (
    BINDER_MEDIATYPE, DOCUMENT_MEDIATYPE,
    ArchiveConnectionError, DocumentNotFoundError,
    create_content, derive_content, revise_content,
    Document, Binder, Resource,
    )
from .schemata import AcceptanceSchema, DocumentSchema, BinderSchema, UserSchema
from .storage import storage
from . import utils


logger = logging.getLogger('cnxauthoring')


def authenticated_only(function):
    @functools.wraps(function)
    def wrapper(request, *args, **kwargs):
        if not request.authenticated_userid:
            raise httpexceptions.HTTPUnauthorized()
        return function(request, *args, **kwargs)
    return wrapper


def storage_management(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            response = function(*args, **kwargs)
            storage.persist()
            return response
        except storage.Error:
            logger.exception('Storage failure')
            try:
                storage.abort()
            except storage.Error:
                logger.exception('Storage failed to abort')
                try:
                    storage.restart()
                except storage.Error:
                    logger.exception('Storage failed to restart')
            finally:
                raise httpexceptions.HTTPServiceUnavailable()
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
    try:
        per_page = int(request.registry.settings.get(
            'openstax_accounts.user_search.per_page', 100))
    except TypeError:
        per_page = 100
    if not q:
        return {
                'users': [],
                'total_count': 0,
                }
    accounts = request.registry.getUtility(IOpenstaxAccounts)
    result = accounts.search(
        q, per_page=per_page, order_by='last_name,first_name')
    result['users'] = [utils.profile_to_user_dict(profile)
            for profile in result.pop('items')]
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
        url = urlparse.urljoin(
            publishing_url,
            'publications/{}'.format(content.metadata['publication']))
        response = requests.get(url)
        if response.status_code == 200:
            try:
                result = json.loads(response.content.decode('utf-8'))
                if content.metadata['state'] != result['state']:
                    content.update(state=result['state'])
                    storage.update(content)
            except (TypeError, ValueError):
                # Not critical if there's a json problem here - perhaps log this
                pass


@view_config(route_name='user-contents', request_method='GET', renderer='json')
@authenticated_only
@storage_management
def user_contents(request):
    """Extract of the contents that belong to the current logged in user"""
    items = []
    binder_ids = set()
    # filter kwargs to subset of content metadata fields - avoid DB errors
    kwargs = {k:v for k,v in request.GET.items() if k in ['mediaType','state','containedIn']}
    if kwargs:
        utils.change_dict_keys(kwargs, utils.camelcase_to_underscore)
    user_id = request.unauthenticated_userid
    contents = storage.get_all(user_id=user_id,
                               permissions=('view',), **kwargs)
    for content in contents:
        update_content_state(request, content)
        if isinstance(content,Binder):
            binder_ids.add(content.id)

        item = content.__json__()
        document = {k: item[k] for k in ['mediaType', 'title', 'id', 'version',
                                         'revised', 'derivedFrom', 'state', 'containedIn']}

        # Don't add version to published items, so they are link to archive
        # instead of authoring (no @draft)
        if document['state'] != 'Done/Success':
            document['id'] = '@'.join([document['id'], document['version']])

        # check if there are roles to accept
        document['rolesToAccept'] = []
        rejected_roles = False
        for role_key in ATTRIBUTED_ROLE_KEYS:
            for role in content.metadata.get(role_key, []):
                if role['id'] == user_id:
                    if role.get('hasAccepted') is None:
                        document['rolesToAccept'].append(role_key)
                    elif role.get('hasAccepted') is False:
                        rejected_roles = True
        if document['rolesToAccept']:
            document['state'] = 'Awaiting acceptance'
        elif rejected_roles:
            document['state'] = 'Rejected roles'

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
@storage_management
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
    content.metadata['permissions'] = sorted(content.acls[request.unauthenticated_userid])
    return content


@view_config(route_name='get-resource', request_method='GET')
@authenticated_only
@storage_management
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
    current_uid = request.unauthenticated_userid
    utils.change_dict_keys(cstruct, utils.camelcase_to_underscore)
    derived_from = cstruct.get('derived_from')
    archive_id = cstruct.get('id')
    if derived_from:
        try:
            cstruct = derive_content(request, **cstruct)
            derived_from = '{}@{}'.format(cstruct['id'],cstruct['version'])
        except (DocumentNotFoundError, ArchiveConnectionError):
            raise httpexceptions.HTTPBadRequest(
                    'Derive failed: {}'.format(derived_from))

    if archive_id:
        # check whether authoring already has a draft that the user can edit
        content = storage.get(id=archive_id.split('@')[0],
                              permissions=('edit',), user_id=current_uid)
        if content:
            if content.metadata['state'] == 'Done/Success':
                storage.remove(content)

            # add view permission for the user
            else:
                if 'view' not in content.acls[current_uid]:
                    content.acls[current_uid] += ('view',)
                    storage.update(content)
                return content

        # get content from archive
        try:
            cstruct = revise_content(request, **cstruct)
        except DocumentNotFoundError:
            raise httpexceptions.HTTPNotFound()
        can_publish = utils.fetch_archive_content(request, archive_id,
                extras=True)['can_publish']
        if request.unauthenticated_userid not in can_publish:
            raise httpexceptions.HTTPForbidden(
                    'You do not have permission to edit {}'.format(archive_id))

    cstruct['submitter'] = utils.profile_to_user_dict(request.user)

    # Add the logged in user to list of authors, licensors and publishers if
    # they are empty
    user = utils.profile_to_user_dict(request.user)
    user.update({
        'requester': request.authenticated_userid,
        'assignment_date': datetime.datetime.now(utils.TZINFO).isoformat(),
        'has_accepted': True,
        })

    cstruct.setdefault('authors', [])
    author_ids = [i['id'] for i in cstruct['authors']]
    if not author_ids:
        cstruct['authors'] = [user]

    cstruct.setdefault('licensors', [])
    licensor_ids = [i['id'] for i in cstruct['licensors']]
    if not licensor_ids:
        cstruct['licensors'] = [user]

    cstruct.setdefault('publishers', [])
    publisher_ids = [i['id'] for i in cstruct['publishers']]
    # publishers is known as maintainers in legacy
    for maintainer in cstruct.get('maintainers', []):
        if maintainer['id'] not in publisher_ids:
            cstruct['publishers'] += [maintainer]
            publisher_ids.append(maintainer['id'])
    if not publisher_ids:
        cstruct['publishers'] = [user]

    utils.accept_roles(cstruct, user)

    if cstruct.get('media_type') == BINDER_MEDIATYPE:
        schema = BinderSchema()
    else:
        schema = DocumentSchema()
    try:
        appstruct = schema.bind().deserialize(cstruct)
    except Exception as e:
        raise httpexceptions.HTTPBadRequest(
            body=json.dumps(e.asdict()),
            headers=[('Content-type', 'application/json',)])
    appstruct['derived_from'] = derived_from
    if archive_id:
        appstruct['id'] = archive_id.split('@')[0]
        appstruct['cnx_archive_uri'] = archive_id

    content = create_content(**appstruct)

    utils.accept_license(content, user)
    utils.declare_roles(content)
    utils.declare_licensors(content)
    utils.declare_acl(content)

    resources = []
    if content.mediatype != BINDER_MEDIATYPE and (derived_from or archive_id):
        resources = utils.derive_resources(request, content)

    try:
        for r in resources:
            storage.add(r)
    except ArchiveConnectionError:
        raise httpexceptions.HTTPBadRequest(
            'Derive failed: {}'.format(derived_from))

    content = storage.add(content)
    if content.mediatype == BINDER_MEDIATYPE:
        utils.update_containment(content)

    return content

@view_config(route_name='post-content', request_method='POST', renderer='json')
@authenticated_only
@storage_management
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
        content.metadata['permissions'] = sorted(content.acls[request.unauthenticated_userid])
        return content
    return contents


@view_config(route_name='post-resource', request_method='POST', renderer='string')
@authenticated_only
@storage_management
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
    size_limit = request.registry.settings['authoring.file_upload.limit']
    with resource.open() as f:
        data = f.read()
    if len(data) > int(size_limit) * 1024 * 1024:
        raise httpexceptions.HTTPBadRequest(
                'File uploaded has exceeded limit {}MB'.format(size_limit))


    resource = storage.add(resource)

    resp = request.response
    resp.status = 201
    location = request.route_path('get-resource', hash=resource.hash)
    resp.headers.add('Location', location)
    return location


def delete_content_single(request, id, user_id=None, raise_error=True):
    content = storage.get(id=id)
    if content is None:
        if raise_error:
            raise httpexceptions.HTTPNotFound()
        return False
    if (user_id is None and not request.has_permission('edit', content)
            or not request.has_permission('view', content)):
        if raise_error:
            raise httpexceptions.HTTPForbidden(
                'You do not have permission to delete {}'.format(id))
        return False
    if not user_id and len(content.acls.keys()) > 1:
        # there are other users who have permission to this document
        if raise_error:
            raise httpexceptions.HTTPForbidden(
                'There are other users on this document {}'.format(id))
        return False
    if (content.metadata['media_type'] == DOCUMENT_MEDIATYPE and
            content.metadata['contained_in']):
        if raise_error:
            raise httpexceptions.HTTPForbidden(
                'Content {} is contained in {} and cannot be deleted'.format(
                    id, content.metadata['contained_in']))
        return False


    if user_id and len(content.acls.keys()) > 1:
        # remove "view" permission
        for uid, permissions in content.acls.items():
            if uid == user_id and 'view' in permissions:
                permissions = list(permissions)
                permissions.remove('view')
                content.acls[uid] = permissions
        utils.declare_acl(content)
        storage.update(content)
    else:
        resource = storage.remove(content)
        if content.metadata['media_type'] == BINDER_MEDIATYPE:
            utils.update_containment(content, deletion=True)
    return True



@view_config(route_name='delete-user-content', request_method='DELETE',
             renderer='json')
@view_config(route_name='delete-content', request_method='DELETE',
             renderer='json')
@view_config(route_name='delete-content-multiple', request_method='PUT',
             renderer='json')
@authenticated_only
@storage_management
def delete_content(request):
    """delete a stored document"""
    if not request.matchdict.get('ident_hash'):
        # delete multiple content
        user_id = request.authenticated_userid
        deleted_ids = []
        try:
            cstruct = request.json_body
        except (TypeError, ValueError):
            raise httpexceptions.HTTPBadRequest('Invalid JSON')
        for ident_hash in cstruct:
            id = ident_hash.split('@')[0]
            succeeded = delete_content_single(
                request, id, user_id=user_id, raise_error=False)
            if succeeded:
                deleted_ids.append(id)
        return deleted_ids
    ident_hash = request.matchdict['ident_hash']
    id = ident_hash.split('@')[0]
    user_id = None
    if request.matchdict.get('user'):
        user_id = request.authenticated_userid
    delete_content_single(request, id, user_id=user_id)

@view_config(route_name='put-content', request_method='PUT', renderer='json')
@authenticated_only
@storage_management
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

    user = utils.profile_to_user_dict(request.user)
    utils.change_dict_keys(cstruct, utils.camelcase_to_underscore)
    cstruct['submitter'] = user
    for key, value in utils.utf8(content.to_dict()).items():
        cstruct.setdefault(key, value)
    utils.accept_roles(cstruct, user)

    if cstruct.get('media_type') == BINDER_MEDIATYPE:
        schema = BinderSchema()
    else:
        schema = DocumentSchema()
    try:
        appstruct = schema.bind().deserialize(cstruct)
    except Exception as e:
        raise httpexceptions.HTTPBadRequest(body=json.dumps(e.asdict()))

    appstruct['state'] = 'Draft'
    try:
        content.update(**appstruct)
    except DocumentNotFoundError as e:
        raise httpexceptions.HTTPBadRequest(e.message)
    utils.accept_license(content, user)
    utils.declare_roles(content)
    utils.declare_licensors(content)
    utils.declare_acl(content)
    storage.update(content)
    if content.mediatype == BINDER_MEDIATYPE:
        utils.update_containment(content)

    resp = request.response
    resp.status = 200
    resp.headers.add(
            'Location',
            request.route_url('get-content-json', id=content.id))
    content.metadata['permissions'] = sorted(content.acls.get(
        request.unauthenticated_userid, []))
    return content


@view_config(route_name='search-content', request_method='GET', renderer='json')
@authenticated_only
@storage_management
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
    ids - these will be published as a 'looseleaf' set of pages.
    """
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

    # Post an epub to publishing.
    upload_data = utils.build_epub(contents, userid, submitlog)
    files = {
        'epub': (filename, upload_data.read(), 'application/epub+zip'),
        }
    api_key = request.registry.settings['publishing.api_key']
    publishing_url = request.registry.settings['publishing.url']
    url = urlparse.urljoin(publishing_url, 'publications')
    headers = {'x-api-key': api_key}
    return contents, requests.post(url, files=files, headers=headers)


@view_config(route_name='publish', request_method='POST', renderer='json')
@authenticated_only
@storage_management
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
                    publication=str(result['publication']),
                    version=result['mapping'][content.id].split('@')[1])
            storage.update(content)
        return result
    except (TypeError, ValueError):
        raise httpexceptions.HTTPBadRequest('Unable to publish: '
                'response body: {}'.format(response.content.decode('utf-8')))


@view_config(route_name='acceptance-info', request_method='GET',
             renderer='json')
@authenticated_only
@storage_management
def get_acceptance_info(request):
    """Retrieve role and license acceptance info
    on the routed content for the authenticated user.
    """
    content_id = request.matchdict['id']
    user_id = request.authenticated_userid
    content = storage.get(id=content_id)

    if content is None:
        raise httpexceptions.HTTPNotFound()
    elif not request.has_permission('view', content):
        raise httpexceptions.HTTPForbidden(
            'You do not have permission to view {}'.format(content_id))

    tobe_accepted_roles = []
    for role_key in ATTRIBUTED_ROLE_KEYS:
        try:
            roles = content.metadata[role_key]
        except KeyError:
            continue
        for role in roles:
            has_accepted = role.get('has_accepted', None)
            if role['id'] == user_id:
                role_info = {
                    'role': role_key,
                    'has_accepted': has_accepted,
                    'requester': role['requester'],
                    'assignment_date': role['assignment_date'],
                    }
                tobe_accepted_roles.append(role_info)

    info = {
        'license': content.metadata['license'],
        'user': user_id,
        'roles': tobe_accepted_roles,
        'title': content.metadata['title'],
        'id': content.id,
        'url': request.route_url('get-content-json', id=content.id),
        }
    utils.change_dict_keys(info, utils.underscore_to_camelcase)

    resp = request.response
    resp.status = 200
    return info


@view_config(route_name='acceptance-info', request_method=('POST', 'PUT'))
@authenticated_only
@storage_management
def post_acceptance_info(request):
    """Post role and license acceptance info
    on the routed content for the authenticated user.

    This should receive JSON in the format::

    {'license': <true|false>,
     'roles': [{'role': <str>, 'hasAccepted': <true|false>}, ...]}

    """
    content_id = request.matchdict['id']
    user_id = request.authenticated_userid
    content = storage.get(id=content_id)

    if content is None:
        raise httpexceptions.HTTPNotFound()
    elif not request.has_permission('view', content):
        raise httpexceptions.HTTPForbidden(
            'You do not have permission to view {}'.format(content_id))

    try:
        cstruct = request.json_body
    except (TypeError, ValueError):
        raise httpexceptions.HTTPBadRequest('Invalid JSON')

    schema = AcceptanceSchema()
    utils.change_dict_keys(cstruct, utils.camelcase_to_underscore)
    try:
        appstruct = schema.bind().deserialize(cstruct)
    except Exception as e:
        raise httpexceptions.HTTPBadRequest(body=json.dumps(e.asdict()))

    # Mark the license acceptance.
    has_accepted_license = appstruct.get('license', False)
    for licensor in content.licensor_acceptance:
        if licensor['id'] == user_id:
            licensor['has_accepted'] = has_accepted_license

    # Find and mark the roles as accepted.
    tobe_updated_roles = set([])
    for role_acceptance in appstruct['roles']:
        role_type = role_acceptance['role']
        # BBB 18-Nov-2014 licensors - deprecated property 'licensors'
        #     needs changed in webview and archive before removing here.
        if role_type == 'copyright_holders':
            # This is necessary for storage.update to work correctly,
            #   see also the BBB in that method.
            role_type = 'licensors'
        # /BBB
        has_accepted = role_acceptance['has_accepted']
        for i, role in enumerate(content.metadata.get(role_type, [])):
            if role['id'] == user_id:
                # If they haven't accepted the license, it won't matter what
                #   role they accept.
                # Return their role acceptances to an unknown state (aka None).
                if not has_accepted_license:
                    if has_accepted is not False:
                        tobe_updated_roles.add((role_type, None, i,))
                    else:
                        tobe_updated_roles.add((role_type, False, i,))
                else:
                    tobe_updated_roles.add((role_type, has_accepted, i,))

    for role_type, has_accepted, index in tobe_updated_roles:
        content.metadata[role_type][index]['has_accepted'] = has_accepted

    utils.declare_roles(content)
    utils.declare_licensors(content)
    utils.declare_acl(content)

    if tobe_updated_roles:
        storage.update(content)

    resp = request.response
    resp.status = 200
    return resp
