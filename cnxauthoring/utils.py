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
from lxml import etree
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

NAMESPACES = (u'<body xmlns="http://www.w3.org/1999/xhtml" '
              'xmlns:bib="http://bibtexml.sf.net/" '
              'xmlns:data="http://www.w3.org/TR/html5/dom.html#custom-data-attribute" '
              'xmlns:epub="http://www.idpf.org/2007/ops" '
              'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
              'xmlns:dc="http://purl.org/dc/elements/1.1/" '
              'xmlns:lrmi="http://lrmi.net/the-specification">'
              '{}'
              '</body>')


def manage_namespace(content):
    try:
        e = etree.fromstring(content)
    except etree.XMLSyntaxError:
        ##################################################
        # trying to catch error by wrapping content in a #
        # namespaced body tag                            #
        ##################################################
        xp = etree.XMLParser(ns_clean=True, recover=True)
        e = etree.fromstring(NAMESPACES.format(content), xp)

    content_string = etree.tostring(e)
    return content_string


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
        license_text = ' '.join([DEFAULT_LICENSE.name, DEFAULT_LICENSE.code,
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
    try:
        # A username or id MUST be supplied.
        id = profile.get('username') and profile['username'] or profile['id']
    except KeyError:
        raise ValueError("A 'username' or 'id' MUST be supplied "
                         "in the profile argument.")

    user_profile = {'id': id}
    profile_attrs = [
        # (<authoring-key>, <accounts-key>,),
        ('firstname', 'first_name',),
        ('surname', 'last_name',),
        # ('fullname', 'full_name',),
        ('suffix', 'suffix',),
        ('title', 'title',),
        ]

    for au_key, acc_key in profile_attrs:
        if au_key in profile:
            user_profile[au_key] = profile[au_key]
        else:
            user_profile[au_key] = profile.get(acc_key, None)

    if 'fullname' in profile:
        user_profile['fullname'] = profile['fullname']
    else:
        fullname = profile.get('full_name', None)
        if not fullname:
            firstname = user_profile['firstname']
            surname = user_profile['surname']
            fullname = u' '.join([n for n in (firstname, surname) if n])
        user_profile['fullname'] = fullname or None

    return user_profile


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
            for i, role in enumerate(value):
                if role.get('id') == user['id']:
                    if role.get('has_accepted', None) is None \
                       and role.get('requester', None) is None:
                        # This is a self assignment
                        role['has_accepted'] = True
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
    for role_type in ('publishers', 'authors',):
        for user in model.metadata.get(role_type, []):
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

    # Sync with the current set of attributed roles.
    response = requests.get(url, headers=headers)
    upstream_role_entities = []
    if response.status_code == 200:
        upstream_role_entities = response.json()
    elif response.status_code >= 400 and response.status_code != 404:
        raise PublishingError(response)

    tobe_removed = []
    for role_entity in upstream_role_entities:
        user_id = role_entity['uid']
        has_accepted = role_entity['has_accepted']
        role_attr = PUBLISHING_ROLES_MAPPING[role_entity['role']]
        found = False
        for role in model.metadata.get(role_attr, []):
            if role['id'] == user_id and 'has_accepted' not in role:
                found = True
                role['has_accepted'] = has_accepted
                break
        # Note, roles are only removed if they are in a false or unknown
        #   acceptance state. Roles that have been accepted are kept,
        #   in case the user is added to the model again.
        has_not_accepted = not has_accepted
        if not found and has_not_accepted:
            tobe_removed.append((user_id, role_entity['role'],))

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
                role['has_accepted'] = has_accepted
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

    # Remove roles
    if tobe_removed:
        deletes_payload = [dict(zip(['uid', 'role'], e))
                           for e in tobe_removed]
        response = requests.delete(url, data=json.dumps(deletes_payload),
                                   headers=headers)
        if response.status_code != 200:
            raise PublishingError(response)

    # Post roles
    response = requests.post(url, data=json.dumps(payload),
                             headers=headers)
    if response.status_code != 202:
        raise PublishingError(response)

    # BBB 10-Dec-2014 licensors - deprecated property 'licensors'
    #     needs changed in webview and archive before removing here.
    model.metadata['copyright_holders'] = model.metadata['licensors']
    # /BBB

    # Notify any new roles that they need to accept the assigned attribution.
    if tobe_notified:
        logger.debug("Sending notification message to '{}', from '{}'".format(', '.join(tobe_notified),authenticated_userid))
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
    upstream_user_ids = [x['uid'] for x in upstream]
    existing_licensor_ids = [l['id'] for l in model.licensor_acceptance]

    # Scan the roles for newly added attribution. In the event that
    #   one or more has been added, add them to the licensor_acceptance.
    #   Ignore removals, because they shouldn't affect anything.
    local_roles = []
    for role_type in PUBLISHING_ROLES_MAPPING.values():
        local_roles.extend(model.metadata.get(role_type, []))
    # Note, this list is already unique. We only use the set methods.
    local_role_ids = set([r['id'] for r in local_roles])
    for uid in local_role_ids.difference(existing_licensor_ids):
        has_accepted = None
        if uid in upstream_user_ids:
            # In the event that the role exists upstream,
            # use their previous acceptance value.
            idx = upstream_user_ids.index(uid)
            has_accepted = upstream[idx]['has_accepted']
        model.licensor_acceptance.append({'id': uid,
                                          'has_accepted': has_accepted})

    # Remove licensors that are no longer part of the document
    #   and have rejected or have not accepted the license.
    _removal_list = set(upstream_user_ids).difference(local_role_ids)
    tobe_removed = []
    for user_id in _removal_list:
        if user_id in upstream_user_ids \
           and not upstream[upstream_user_ids.index(user_id)]['has_accepted']:
            tobe_removed.append(user_id)
        if user_id in existing_licensor_ids:
            idx = existing_licensor_ids.index(user_id)
            del model.licensor_acceptance[idx]
    if tobe_removed:
        deletes_payload = {'licensors': [{'uid': e} for e in tobe_removed]}
        response = requests.delete(url, data=json.dumps(deletes_payload),
                                   headers=headers)
        if response.status_code != 200:
            raise PublishingError(response)

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


VALIDATION_ROLES_PENDING = 'roles_pending'
VALIDATION_ROLES_REJECTED = 'roles_rejected'
VALIDATION_NO_CONTENT = 'no_content'
VALIDATION_BLOCKERS = (
    VALIDATION_ROLES_PENDING,
    VALIDATION_ROLES_REJECTED,
    VALIDATION_NO_CONTENT,
    )


def _validate_accepted_roles_and_license(model):
    """Have all the roles accepted both the attributed role(s) and license?"""
    accepted_roles = set([])
    users = set([])
    for role_type in cnxepub.ATTRIBUTED_ROLE_KEYS:
        for role in model.metadata[role_type]:
            accepted_roles.add(role.get('has_accepted'))
            users.add(role['id'])
    index_map = {r['id']: i for i, r in enumerate(model.licensor_acceptance)}
    accepted_licensors = set([])
    for user_id in users:
        entry = model.licensor_acceptance[index_map[user_id]]
        accepted_licensors.add(entry.get('has_accepted'))

    validation_errors = []
    if None in accepted_roles or None in accepted_licensors:
        validation_errors.append(VALIDATION_ROLES_PENDING)
    if False in accepted_roles or False in accepted_licensors:
        validation_errors.append(VALIDATION_ROLES_REJECTED)
    return validation_errors


def _validate_required_data(model):
    """Does the model have the required data?"""
    validation_errors = []
    if isinstance(model, cnxepub.Document):
        # Check for content...
        contains_content = False
        # Wrap the content so that we can parse it.
        content = u"<html><body>{}</body></html>".format(model.content)
        tree = etree.parse(io.StringIO(content))
        for element_text in tree.xpath('/html/body//text()'):
            if element_text != '':
                contains_content = True
                break
        if not contains_content:
            validation_errors.append(VALIDATION_NO_CONTENT)
    elif isinstance(model, cnxepub.Binder):
        # Does the binder have documents
        documents_generator = cnxepub.flatten_to_documents(
            model, include_pointers=True)
        contains_docs = len([x for x in documents_generator]) >= 1

        if not contains_docs:
            validation_errors.append(VALIDATION_NO_CONTENT)
    else:
        raise ValueError('{} is not a Document or a Binder'.format(model))
    return validation_errors


def validate_for_publish(model):
    """Validate a model (``Document`` or ``Binder``) is publish ready.
    Returns blockers (list) or None.
    """
    blockers = []
    blockers.extend(_validate_required_data(model))
    blockers.extend(_validate_accepted_roles_and_license(model))
    return blockers and blockers or None
