# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import datetime
import io
import uuid
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

import cnxepub.models as cnxepub
import requests
from pyramid.events import subscriber, ApplicationCreated
from pyramid.security import Allow, Authenticated

from . import utils
# BBB 12-Nov-2014 Moved TZINFO to utils
from .utils import TZINFO


DOCUMENT_MEDIATYPE = "application/vnd.org.cnx.module"
BINDER_MEDIATYPE = "application/vnd.org.cnx.collection"
MEDIATYPES = { 'document' : DOCUMENT_MEDIATYPE,
               'binder' : BINDER_MEDIATYPE }

LICENSE_PARAMETER_MARKER = object()
DEFAULT_LANGUAGE = 'en'

# Initialized via the setup_licenses function.
LICENSES = []
DEFAULT_LICENSE = None


class DocumentNotFoundError(Exception):

    def __init__(self, document_id):
        self.message = 'Document Not Found: {}'.format(document_id)

    def __str__(self):
        return self.message


class ArchiveConnectionError(Exception):

    def __init__(self, message=None):
        self.message = message

    def __str__(self):
        return self.message


class PublishingError(Exception):

    def __init__(self, response):
        self.message = 'Publishing Error: {} {}'.format(
                response.status_code, response.content)

    def __str__(self):
        return self.message


@subscriber(ApplicationCreated)
def initialize_licenses(event):
    """Initializes a fixed set of license objects
    based on the authoritative list stored in archive.
    """
    global DEFAULT_LICENSE
    global LICENSES
    settings = event.app.registry.settings
    archive_url = settings['archive.url']

    try:
        default_license_url = settings['default-license-url']
    except KeyError:
        raise RuntimeError("Default license is not configured. "
                           "Please set the 'default-license-url' in "
                           "the application configuration.")

    # Contact archive for an authoritative list of licenses.
    url = urlparse.urljoin(archive_url, '/extras')
    response = requests.get(url)
    licenses = response.json()['licenses']

    LICENSES = []
    for license in licenses:
        kwargs = {k:v for k, v in license.items()
                  if k in ('name', 'url', 'code', 'version',)}
        LICENSES.append(License(**kwargs))

    # Assign the default license.
    DEFAULT_LICENSE = [l for l in LICENSES if l.url == default_license_url][0]


class License(object):
    """A declaration of authority typically assigned to things."""

    def __init__(self, name, url, code=None, version=None):
        self.name = name
        self.url = url
        self.code = code
        self.version = version

    @classmethod
    def from_url(cls, url):
        """This assumes an initialized application and set of
        initialized License objects.
        """
        try:
            return [l for l in LICENSES if l.url == url][0]
        except IndexError:
            raise ValueError("Invalid url '{}' used to initialize class."
                             .format(url))

    def __json__(self, request=None):
        obj_as_dict = {
            'name': self.name,
            'url': self.url,
            'code': self.code,
            'version': self.version,
            }
        return obj_as_dict


class Resource(cnxepub.Resource):
    """Any *file* that is referenced within a ``Document``."""

    def __init__(self, mediatype, data, filename=None):
        # ``data`` must be a buffer or file-like object.
        cnxepub.Resource.__init__(self, 'resource_id', data,
                mediatype, filename)
        self.id = self.hash

    def __acl__(self):
        return (
                (Allow, Authenticated, ('view', 'create',)),
                )


class BaseContent(object):
    """A base class for common code in Document and Binder
    """

    def __acl__(self):
        acls = [(Allow, Authenticated, ('create',))]
        roles_acl = {}
        # Amend the acl from the model's local ACL record.
        for user_id, permissions in self.acls.items():
            roles_acl.setdefault(user_id, set([]))
            roles_acl[user_id].update(permissions)
        acls.extend([(Allow, user_id, tuple(permissions),)
                     for user_id, permissions in roles_acl.items()])
        return acls

    def update(self, **kwargs):
        if 'created' in kwargs:
            del kwargs['created']
        for key, value in kwargs.items():
            if key in self.metadata:
                self.metadata[key] = value
                # BBB 18-Nov-2014 licensors - deprecated property 'licensors'
                #     needs changed in webview and archive before removing here.
                if key == 'licensors':
                    self.metadata['copyright_holders'] = value
                elif key == 'copyright_holders':
                    self.metadata['licensors'] = value
                # /BBB
        # FIXME if license is in kwargs, ensure the user changing it
        #       has permission to do so.
        if 'license' in kwargs:
            license_url = kwargs['license']['url']
            self.metadata['license'] = License.from_url(license_url)
        self.metadata['revised'] = datetime.datetime.now(TZINFO)

    def to_dict(self):
        return to_dict(self.metadata)

    def __json__(self, request=None):
        result = self.to_dict()
        result['is_publishable'] = self.is_publishable
        result['publishBlockers'] = self.publication_blockers
        utils.change_dict_keys(result, utils.underscore_to_camelcase)
        if request and hasattr(self,'acls'):
           result['permissions'] = sorted(self.acls.get(
               request.unauthenticated_userid, []))
        return result

    @property
    def publication_blockers(self):
        return utils.validate_for_publish(self)

    @property
    def is_publishable(self):
        """Flag to say whether this content is publishable."""
        return not bool(self.publication_blockers)


class Document(cnxepub.Document, BaseContent):
    """Modular documents that contain written text
    by one or more authors.
    """
    mediatype = DOCUMENT_MEDIATYPE

    def __init__(self, title, acls=None,
                 licensor_acceptance=None, **kwargs):
        metadata = build_metadata(title, **kwargs)
        metadata['media_type'] = self.mediatype
        id = str(metadata['id'])
        content = metadata['content']
        cnxepub.Document.__init__(self, id, content, metadata)
        self.acls = acls and acls or {}
        la = licensor_acceptance
        self.licensor_acceptance = la and la or []

    def update(self, **kwargs):
        super(Document, self).update(**kwargs)
        self.metadata['content'] = utils.manage_namespace(
            self.metadata['content'])
        self.content = self.metadata['content']

    def publish_prep(self):
        license = self.metadata['license']
        self.metadata['license_url'] = license.url
        self.metadata['license_text'] = ' '.join([license.name, license.code, license.version])
        self.metadata['summary'] = self.metadata['abstract']
        self.set_uri('cnx-archive', self.id)
        if self.metadata['print_style'] == 'default':
            self.metadata['print_style'] = None
        self.add_resources()

    def add_resources(self):
        from .storage import storage
        resources = {}
        for ref in self.references:
            if ref.uri.startswith('/resources/'):
                resource = resources.get(ref.uri)
                if not resource:
                    hash = ref.uri[len('/resources/'):]
                    resource = storage.get(type_=Resource, hash=hash)
                    self.resources.append(resource)


def build_tree(tree):
    from .storage import storage
    def get_nodes(tree, nodes, title_overrides):
        for i in tree['contents']:
            if 'contents' in i:
                contents_nodes = []
                contents_title_overrides = []
                get_nodes(i, contents_nodes, contents_title_overrides)
                if i['id'] == 'subcol':
                    nodes.append(cnxepub.TranslucentBinder(
                        metadata={'title': i.get('title')},
                        nodes=contents_nodes,
                        title_overrides=contents_title_overrides))
                    title_overrides.append(i.get('title'))
                else:
                    nodes.append(cnxepub.Binder(i['id'],
                        metadata={'title': i.get('title')},
                        nodes=contents_nodes,
                        title_overrides=contents_title_overrides))
                    title_overrides.append(i.get('title'))
                continue
            if i['id'].endswith('@draft'):
                document = storage.get(id=i['id'][:-len('@draft')])
                if not document:
                    raise DocumentNotFoundError(i['id'])
                nodes.append(document)
                title_overrides.append(i.get('title'))
            else:
                nodes.append(cnxepub.DocumentPointer(i['id'], {
                    'title': i.get('title'),
                    # TODO should be a uri/path like /contents
                    'cnx-archive-uri': '{}'.format(i['id']),
                    # TODO not hardcode this url
                    'url': 'http://cnx.org/contents/{}'.format(i['id']),
                    }))
                title_overrides.append(i.get('title'))
    nodes = []
    title_overrides = []
    get_nodes(tree, nodes, title_overrides)
    return nodes, title_overrides


def build_metadata(
        title, id=None, content=None, abstract=None, created=None,
        revised=None, version=None, subjects=None, keywords=None,
        license=LICENSE_PARAMETER_MARKER, language=None, derived_from=None,
        derived_from_uri=None, derived_from_title=None,
        submitter=None, state=None, publication=None, cnx_archive_uri=None,
        authors=None, publishers=None, contained_in=None,
        licensors=None, copyright_holders=None,
        editors=None, translators=None, illustrators=None, print_style=None):
    metadata = {}
    metadata['title'] = title
    metadata['version'] = version is None and 'draft' or version
    metadata['id'] = id or uuid.uuid4()
    metadata['content'] = content and content or ''
    metadata['abstract'] = abstract and abstract or ''
    now = datetime.datetime.now(tz=TZINFO)
    metadata['created'] = created is None and now or created
    metadata['revised'] = revised is None and now or revised
    # license is a reserved name that will never be None.
    if license is LICENSE_PARAMETER_MARKER:
        metadata['license'] = DEFAULT_LICENSE
    else:
        metadata['license'] = license
    metadata['language'] = language is None and DEFAULT_LANGUAGE or language
    metadata['derived_from'] = derived_from
    metadata['derived_from_uri'] = derived_from_uri
    metadata['derived_from_title'] = derived_from_title
    metadata['submitter'] = submitter
    if type(subjects) in (list, tuple):
        metadata['subjects'] =subjects
    else:
        metadata['subjects'] = subjects and [subjects] or []
    if type(keywords) in (list, tuple):
        metadata['keywords'] =keywords
    else:
        metadata['keywords'] = keywords and [keywords] or []
    metadata['publication'] = publication
    metadata['state'] = state or 'Draft'
    metadata['contained_in'] = contained_in or []
    if cnx_archive_uri:
        metadata['cnx-archive-uri'] = cnx_archive_uri
    metadata['authors'] = authors or []
    metadata['publishers'] = publishers or []
    # BBB 18-Nov-2014 deprecated property 'licensors' needs changed
    #     in webview and archive before removing here.
    if licensors is not None:
        copyright_holders = licensors or []
    else:
        copyright_holders = copyright_holders or []
    metadata['licensors'] = metadata['copyright_holders'] = copyright_holders
    # /BBB
    metadata['editors'] = editors or []
    metadata['translators'] = translators or []
    metadata['illustrators'] = illustrators or []
    metadata['print_style'] = print_style
    return metadata


def to_dict(metadata):
    result = metadata.copy()
    result['id'] = str(result['id'])
    created = result['created']
    revised = result['revised']
    result['created'] = created.astimezone(TZINFO).isoformat()
    result['revised'] = revised.astimezone(TZINFO).isoformat()
    result['license'] = result['license'].__dict__.copy()
    return result


def model_to_tree(model, title=None,
                  lucent_id=cnxepub.TRANSLUCENT_BINDER_ID):
    """Given an model, build the tree::

        tree := {'id': <id>|'subcol', 'title': <title>,
                 'is_publishable': <True|False|None>,  # optional
                 'contents': [<tree>, ...]}

    """
    if type(model) is cnxepub.TranslucentBinder:
        id = lucent_id
    else:
        id = model.ident_hash
    title = title is not None and title or model.metadata.get('title')
    tree = {'id': id, 'title': title}
    if id.endswith('draft'):
        tree['is_publishable'] = model.is_publishable
        tree['publish_blockers'] = model.publication_blockers
    if hasattr(model, '__iter__'):
        contents = tree['contents'] = []
        for node in model:
            item = model_to_tree(node, model.get_title_for_node(node),
                                 lucent_id=lucent_id)
            contents.append(item)
    return tree


class Binder(cnxepub.Binder, BaseContent):
    """A collection of documents
    """
    mediatype = BINDER_MEDIATYPE

    def __init__(self, title, tree, acls=None,
                 licensor_acceptance=None, **kwargs):
        metadata = build_metadata(title, **kwargs)
        metadata['media_type'] = self.mediatype
        id = str(metadata['id'])
        nodes, title_overrides = build_tree(tree)
        cnxepub.Binder.__init__(self, id, nodes=nodes,
                metadata=metadata, title_overrides=title_overrides)
        self.acls = acls and acls or {}
        la = licensor_acceptance
        self.licensor_acceptance = la and la or []

    def update(self, **kwargs):
        if 'tree' in kwargs:
            nodes, title_overrides = build_tree(kwargs.pop('tree'))
            self._nodes = nodes
            self._title_overrides = title_overrides
        super(Binder, self).update(**kwargs)

    def publish_prep(self):
        license = self.metadata['license']
        self.metadata['license_url'] = license.url
        self.metadata['license_text'] = ' '.join([license.name, license.code, license.version])
        self.metadata['summary'] = self.metadata['abstract']
        if self.metadata['print_style'] == 'default':
            self.metadata['print_style'] = None

        self.set_uri('cnx-archive', self.id)
        documents = []
        for document in cnxepub.flatten_to_documents(self):
            if document.id not in documents:
                documents.append(document.id)
                document.publish_prep()

    def to_dict(self):
        result = to_dict(self.metadata)
        result['tree'] = model_to_tree(self)
        return result

    @property
    def are_contained_publishable(self):
        """Flag to say whether any contained models are publishable.
        """
        has_publishable_docs = False
        for doc in cnxepub.flatten_to_documents(self):
            has_publishable_docs = has_publishable_docs or doc.is_publishable
        return has_publishable_docs

    def __json__(self, request=None):
        data = super(Binder, self).__json__(request)
        data['are_contained_publishable'] = self.are_contained_publishable
        utils.change_dict_keys(data, utils.underscore_to_camelcase)
        return data


def create_content(**appstruct):
    """Given a Colander *appstruct*, create a content object."""
    kwargs = appstruct.copy()
    # TODO Lookup via storage.
    license = appstruct.get('license')
    if license is not None:
        if not isinstance(license, License):
            license = License.from_url(license['url'])
        kwargs['license'] = license
    media_type = 'media_type' in kwargs and kwargs.pop('media_type')
    if media_type == BINDER_MEDIATYPE:
        return Binder(**kwargs)
    document = Document(**kwargs)
    return document


def revise_content(request, **kwargs):
    archive_id = kwargs['id']
    document = utils.fetch_archive_content(request, archive_id)
    # all the roles have been accepted
    for role_type in cnxepub.ATTRIBUTED_ROLE_KEYS + ('licensors',):
        for role in document.get(role_type, []):
            role['has_accepted'] = True
    document.update(kwargs)
    document['revised'] = None
    document['maintainers'] = document['publishers']
    return document


def derive_content(request, **kwargs):
    derived_from = kwargs['derived_from']
    document = utils.fetch_archive_content(request, derived_from)
    document['derived_from_title'] = document['title']
    # FIXME This is a hardcoded value and the hostname is wrong.
    #       It should point to archive.cnx.org.
    document['derived_from_uri'] = 'http://cnx.org/contents/{}@{}'.format(document['id'],document['version'])
    document['title'] = u'Copy of {}'.format(document['title'])
    document['created'] = None
    document['revised'] = None
    document['authors'] = []
    document['maintainers'] = []
    document['publishers'] = []
    document['licensors'] = []
    document['translators'] = []
    document['editors'] = []
    document['illustrators'] = []
    return document
