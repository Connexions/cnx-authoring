# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import io
import re
import datetime
import json
import logging
try:
    import urllib2 # python2
except ImportError:
    import urllib.request as urllib2 # renamed in python3
try:
    import urlparse # python2
except ImportError:
    import urllib.parse as urlparse # renamed in python3

import cnxepub
from cnxepub.models import Document, DocumentPointer, TranslucentBinder
import requests
import tzlocal
from openstax_accounts.interfaces import IOpenstaxAccounts
from pyramid.threadlocal import get_current_registry, get_current_request
from cnxquerygrammar.query_parser import grammar, DictFormater
from parsimonious.exceptions import IncompleteParseError


# Timezone info initialized from the system timezone.
TZINFO = tzlocal.get_localzone()
logger = logging.getLogger('cnxauthoring')

PUBLISHING_ROLES_MAPPING = {
    'Author': 'authors',
    'Copyright Holder': 'licensors',
    'Editor': 'editors',
    'Illustrator': 'illustrators',
    'Publisher': 'publishers',
    'Translator': 'translators',
    }


def utf8(item):
    if isinstance(item, list):
        return [utf8(i) for i in item]
    if isinstance(item, dict):
        return {utf8(k): utf8(v) for k, v in item.items()}
    try: 
        return item.decode('utf-8')
    except: # bare except since this method is supposed to be safe anywhere
        return item


def change_dict_keys(data, func):
    for k in data.keys():
        _k = func(k)
        if _k != k:
            data[_k] = data.pop(k)
        if isinstance(data[_k], dict):
            change_dict_keys(data[_k], func)
        if isinstance(data[_k], list):
            for i in data[_k]:
                if isinstance(i, dict):
                    change_dict_keys(i, func)


def camelcase_to_underscore(camelcase):
    def replace(match):
        char = match.group(1)
        return '_{}'.format(char.lower())
    return re.sub('([A-Z])', replace, camelcase)

def underscore_to_camelcase(underscore):
    def replace(match):
        char = match.group(1)
        return '{}'.format(char.upper())
    return re.sub('_([a-z])', replace, underscore)

def structured_query(query_string):
    try:
        node_tree = grammar.parse(query_string)
    except IncompleteParseError:
        query_string = fix_quotes(query_string)
        node_tree = grammar.parse(query_string)
    return DictFormater().visit(node_tree)

def fix_quotes(query_string):
    # Attempt to fix unbalanced quotes in query_string

    if query_string.count('"') % 2 == 0:
        # no unbalanced quotes to fix
        return query_string

    fields = [] # contains what's matched by the regexp
    # e.g. fields = ['sort:pubDate', 'author:"first last"']
    def f(match):
        fields.append(match.string[match.start():match.end()])
        return ''

    # terms will be all the search terms that don't have a field
    terms = re.sub(r'[^\s:]*:("[^"]*"|[^\s]*)', f, query_string)
    query_string = '{}" {}'.format(terms.strip(), ' '.join(fields))
    return query_string

def filter_binder_documents(binder, documents):
    """walks through a binder, converting any draft documents that are
        not in the list of documents into documentpointers."""
    docids = [d.id for d in documents]
    for i, model in enumerate(binder):
        if isinstance(model, TranslucentBinder): # section/subcollection
            filter_binder_documents(model, documents)

        elif isinstance(model,Document):
            if model.id not in docids:
                binder.pop(i) # remove it
                # Is it new?
                if model.get_uri('cnx-archive'):
                    #convert to documentpointer
                    dp = DocumentPointer(model.get_uri('cnx-archive'))
                    binder.insert(i,dp)

def build_epub(contents, submitter, submitlog):
    from .models import DEFAULT_LICENSE, Binder

    epub = io.BytesIO()
    documents = []
    binders = []
    for i,content in enumerate(contents,1):
        if type(content) == list: # book + pages in a list
            if isinstance(content[0], Binder): 
                filter_binder_documents(content[0], content[1:])
                content[0].publish_prep()
                binders.append(content[0])
            else:  # belt and suspenders - seems to be an extra level of lists - filter out docs
                for doc in content:
                    if isinstance(doc,Document):
                        doc.publish_prep()
                        documents.append(doc)
        elif isinstance(content, Binder): # Special case: toplevel is book + pages
            content.publish_prep()
            filter_binder_documents(content, contents[i:])
            binders.append(content)
            break # eat the whole list
        elif isinstance(content,Document):
            content.publish_prep()
            documents.append(content)
        

    if documents:
        license_text = ' '.join([DEFAULT_LICENSE.name, DEFAULT_LICENSE.abbr,
            DEFAULT_LICENSE.version])
        binders.append(TranslucentBinder(
                metadata={
                    'title': 'Publications binder',
                    'created': datetime.datetime.now(),
                    'revised': datetime.datetime.now(),
                    'license_text': license_text,
                    'license_url': DEFAULT_LICENSE.url,
                    },
                nodes=documents))
    cnxepub.adapters.make_publication_epub(
            binders, submitter, submitlog, epub)
    epub.seek(0)
    return epub


def fetch_archive_content(request, archive_id, extras=False):
    from .models import ArchiveConnectionError, DocumentNotFoundError

    settings = request.registry.settings
    archive_url = settings['archive.url']
    if extras:
        content_url = urlparse.urljoin(archive_url,
                '/extras/{}'.format(archive_id))
    else:
        content_url = urlparse.urljoin(archive_url,
                '/contents/{}.json'.format(archive_id))
    try:
        response = requests.get(content_url)
    except requests.exceptions.ConnectionError as exc:
        raise ArchiveConnectionError(exc.message)
    if response.status_code >= 400:
        raise DocumentNotFoundError(archive_id)
    try:
        document = response.json()
    except (TypeError, ValueError):
        raise DocumentNotFoundError(archive_id)
    change_dict_keys(document, camelcase_to_underscore)
    return document


def derive_resources(request, document):
    from .models import ArchiveConnectionError, Resource

    settings = request.registry.settings
    archive_url = settings['archive.url']
    path = urlparse.unquote(request.route_path('get-resource', hash='{}'))
    resources = {}
    for r in document.references:
        if r.uri.startswith('/resources'):
            if not resources.get(r.uri):
                url = urlparse.urljoin(archive_url, r.uri)
                try:
                    response = requests.get(url)
                except requests.exceptions.ConnectionError as exc:
                    raise ArchiveConnectionError(exc.message)
                if response.status_code >= 400:
                    continue
                content_type = response.headers['content-type']
                resources[r.uri] = Resource(content_type,
                                            io.BytesIO(response.content))
                yield resources[r.uri]
            r.bind(resources[r.uri], path)
    document.metadata['content'] = document.html


def profile_to_user_dict(profile):
    """Take a profile from openstax accounts and transform it into a local user
    format"""
    # in case it's already in the local user format, no need to transform
    if 'email' in profile:
        return profile
    email = None
    for contact_info in profile.get('contact_infos') or []:
        if contact_info.get('type') == 'EmailAddress':
            email = contact_info.get('value')
    firstname = profile.get('first_name') or ''
    surname = profile.get('last_name') or ''
    return {
            'firstname': firstname,
            'surname': surname,
            'email': email or '',
            'id': profile.get('username') or '',
            'fullname': profile.get('fullname',
                u'{} {}'.format(firstname, surname).strip()),
            }

def update_containment(binder, deletion = False):
    """updates the containment status of all draft documents in this binder"""
    from .storage import storage

    b_id = binder.id
    doc_ids = []
    old_docs = storage.get_all(contained_in = b_id)

    # additions
    if not deletion:
        docs = cnxepub.flatten_to_documents(binder)
        for doc in docs:
            doc_ids.append(doc.id) # gather for subtractions below
            if b_id not in doc.metadata['contained_in']:
                doc.metadata['contained_in'].append(b_id)
                storage.update(doc)
    # subtractions
    for doc in old_docs:
        if doc.id not in doc_ids:
            if b_id in doc.metadata['contained_in']:
                doc.metadata['contained_in'].remove(b_id)
                storage.update(doc)


def get_roles(document, uid):
    field_to_roles = (
            ('publishers', 'Publisher'),
            ('editors', 'Editor'),
            ('translators', 'Translator'),
            ('authors', 'Author'),
            )
    for field, role in field_to_roles:
        users = [u['id'] for u in document.metadata.get(field) or []]
        if uid in users:
            yield role


def notify_role_for_acceptance(user_id, requester, model):
    """Notify the given ``user_id`` on ``model`` that s/he has been
    assigned a role on said model and can now accept the role.
    """
    accounts = get_current_registry().getUtility(IOpenstaxAccounts)
    settings = get_current_registry().settings
    base_url = settings['webview.url']
    link = urlparse.urljoin(base_url, '/users/role-acceptance/{}'
                            .format(model.id))

    subject = 'Requesting action on OpenStax CNX content'
    body = '''\
Hello {name},

{requester} added you to content titled {title}.
Please go to the following link to accept your roles and license:
{link}

Thank you from your friends at OpenStax CNX
'''.format(name=user_id,
           requester=requester,
           title=model.metadata['title'],
           link=link)
    try:
        accounts.send_message(user_id, subject, body)
    except urllib2.HTTPError:
        # Can't send messages via accounts for some reason - should be async!
        logger.warning("Failed sending notification message to {}".format(user_id))
        pass


def accept_roles(cstruct, user):
    """Accept roles for document and user"""
    # accept roles for user
    authenticated_userid = get_current_request().authenticated_userid
    now = datetime.datetime.now(TZINFO).isoformat()
    for field in cnxepub.ATTRIBUTED_ROLE_KEYS + ('licensors',):
        if field in cstruct:
            value = cstruct.get(field, [])
            for role in value:
                if role.get('id') == user['id']:
                    role['has_accepted'] = True
                    if not role.get('requester'):
                        role['requester'] = authenticated_userid
                        role['assignment_date'] = now
            cstruct[field] = value


def accept_license(document, user):
    # accept license for user
    for r in document.licensor_acceptance:
        if r['id'] == user['id']:
            r['has_accepted'] = True
            break
    else:
        user_copy = user.copy()
        user_copy['has_accepted'] = True
        document.licensor_acceptance.append(user_copy)


def declare_acl(model):
    """Declare publication permission on the model and within publishing.
    The model is updated as part of this procedure, but it is not persisted.
    """
    from .models import PublishingError

    # Put together the information necessary to make publishing requests.
    settings = get_current_registry().settings
    publishing_url = settings['publishing.url']
    api_key = settings['publishing.api_key']
    headers = {
            'x-api-key': api_key,
            'content-type': 'application/json',
            }
    url = urlparse.urljoin(publishing_url,
                           '/contents/{}/permissions'.format(model.id))

    # Acquire the current ACL
    #   (which at this time only contains the publish permission)
    upstream_acl_ids = set([])
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        upstream_acl_ids = set([x['uid'] for x in response.json()])
    elif response.status_code >= 400:
        raise PublishingError(response)

    # Push out the current set of publishers.
    payload = []
    for user in model.metadata['publishers']:
        if user.get('has_accepted'):
            payload.append({'uid': user['id'], 'permission': 'publish'})
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    if response.status_code != 202:
        raise PublishingError(response)

    local_acl_ids = set([x['uid'] for x in payload])
    # Remove any roles that are no longer part of the local set.
    removal_payload = [{'permission': 'publish', 'uid': uid}
                       for uid in upstream_acl_ids.difference(local_acl_ids)]
    if removal_payload:
        response = requests.delete(url, headers=headers,
                                   data=json.dumps(removal_payload))
        if response.status_code != 200:
            raise PublishingError(response)

    # Aquire the updated ACL
    response = requests.get(url, headers=headers)
    upstream_acl = response.json()

    # Update the model's ACL attribute.
    previous_acl = model.acls
    model.acls = {}  # Clear the current ACL values.
    roles_acl = {}
    users_pending_acceptance = []
    for role_type_attr_name in cnxepub.ATTRIBUTED_ROLE_KEYS:
        for role in model.metadata.get(role_type_attr_name, []):
            permissions = ['view']
            if role_type_attr_name == 'publishers' \
               and role.get('has_accepted'):
                permissions.extend(['edit', 'publish'])
            elif role.get('has_accepted'):
                permissions.append('edit')
            elif role.get('has_accepted') is None:
                users_pending_acceptance.append(role['id'])
            roles_acl.setdefault(role['id'], set([]))
            roles_acl[role['id']].update(permissions)

    # Note, it's possible for a user to have removed themselves from
    #   the model by deleting their view permission, which eliminates
    #   the model from the workspace. This means the user will have
    #   edit and possibly publish permissions, but not view.

    for uid, permissions in roles_acl.items():
        # Don't re-add the view permission if it has been removed
        if uid in previous_acl \
           and 'view' not in previous_acl[uid] \
           and uid not in users_pending_acceptance:
            try:
                permissions.remove('view')
            except KeyError:
                pass
        model.acls[uid] = tuple(permissions)

    for user_entry in upstream_acl:
        uid = user_entry['uid']
        permissions = set(['view', 'edit', 'publish'])
        # Don't re-add the view permission if it has been removed
        if uid in model.acls and 'view' not in model.acls[uid]:
            permissions.remove('view')
        model.acls[uid] = permissions


def declare_roles(model):
    """Annotate the roles to include role acceptance information.
    The model is updated as part of this procedure, but it is not persisted.
    """
    from .models import PublishingError

    authenticated_userid = get_current_request().authenticated_userid
    settings = get_current_registry().settings
    publishing_url = settings['publishing.url']
    headers = {
        'x-api-key': settings['publishing.api_key'],
        'content-type': 'application/json',
        }
    url = urlparse.urljoin(publishing_url,
                           '/contents/{}/roles'.format(model.id))

    # Send roles to publishing.
    _roles_mapping = {v: k for k, v in PUBLISHING_ROLES_MAPPING.items()}
    role_submission_keys = ('uid', 'role', 'has_accepted',)
    tobe_notified = set([])
    payload = []
    for role_type in PUBLISHING_ROLES_MAPPING.values():
        publishing_role_type = _roles_mapping[role_type]
        _roles = []
        for role in model.metadata[role_type]:
            has_accepted = role.get('has_accepted', None)
            # Assume this is a new record when the requester is missing.
            if role.get('requester', None) is None:
                role['requester'] = authenticated_userid
                now = datetime.datetime.now(TZINFO).isoformat()
                role['assignment_date'] = now
                if has_accepted is None:
                    tobe_notified.add(role['id'])
            reformatted_role = (role['id'], publishing_role_type,
                                has_accepted,)
            reformatted_role = dict(zip(role_submission_keys,
                                        reformatted_role))
            _roles.append(reformatted_role)
        payload.extend(_roles)

    response = requests.post(url, data=json.dumps(payload),
                             headers=headers)
    if response.status_code != 202:
        raise PublishingError(response)

    # Notify any new roles that they need to accept the assigned attribution.
    logger.debug("Sending notification message to {}".format(', '.join(tobe_notified)))
    for user_id in tobe_notified:
        notify_role_for_acceptance(user_id, authenticated_userid, model)


def declare_licensors(model):
    """Declare license acceptance information on the model.
    The model is updated as part of this procedure, but it is not persisted.
    """
    from .models import PublishingError

    settings = get_current_registry().settings
    publishing_url = settings['publishing.url']
    headers = {
        'x-api-key': settings['publishing.api_key'],
        'content-type': 'application/json',
        }
    url = urlparse.urljoin(publishing_url,
                           '/contents/{}/licensors'.format(model.id))

    # Acquire a list of known roles from publishing.
    response = requests.get(url)
    if response.status_code >= 400:
        upstream_license_info = {
            'license_url': None,
            'licensors': [],
            }
    else:
        upstream_license_info = response.json()
    upstream = upstream_license_info.get('licensors', [])

    # Scan the roles for newly added attribution. In the event that
    #   one or more has been added, add them to the licensor_acceptance.
    #   Ignore removals, because they shouldn't affect anything.
    local_roles = []
    for role_type in PUBLISHING_ROLES_MAPPING.values():
        local_roles.extend(model.metadata.get(role_type, []))
    local_role_ids = set([r['id'] for r in local_roles])
    existing_licensor_ids = set([l['id'] for l in model.licensor_acceptance])
    for new_role in local_role_ids.difference(existing_licensor_ids):
        model.licensor_acceptance.append({'id': new_role,
                                          'has_accepted': None})

    # Send licensors to publishing.
    payload = {
        'license_url': model.metadata['license'].url,
        'licensors': [{'uid': x['id'], 'has_accepted': x['has_accepted']}
                      for x in model.licensor_acceptance],
        }
    response = requests.post(url, data=json.dumps(payload),
                             headers=headers)
    if response.status_code != 202:
        raise PublishingError(response)
