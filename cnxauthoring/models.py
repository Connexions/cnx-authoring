# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import datetime
import io
import hashlib
import uuid

import tzlocal
import cnxepub.models as cnxepub
from pyramid.security import Allow, Authenticated

from . import utils


# Timezone info initialized from the system timezone.
TZINFO = tzlocal.get_localzone()

DOCUMENT_MEDIATYPE = "application/vnd.org.cnx.module"
BINDER_MEDIATYPE = "application/vnd.org.cnx.collection"
MEDIATYPES = { 'document' : DOCUMENT_MEDIATYPE,
               'binder' : BINDER_MEDIATYPE }

LICENSE_PARAMETER_MARKER = object()
DEFAULT_LANGUAGE = 'en'


class DocumentNotFoundError(Exception):
    def __init__(self, document_id):
        self.message = 'Document Not Found: {}'.format(document_id)


class License:
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


class Resource(cnxepub.Resource):
    """Any *file* that is referenced within a ``Document``."""

    def __init__(self, mediatype, data, filename=None):
        # ``data`` must be a buffer or file-like object.
        try:
            self.data = data.read()
        except AttributeError:
            self.data = data[:]
        _hash = hashlib.new('sha1', self.data).hexdigest()
        cnxepub.Resource.__init__(self, _hash, io.BytesIO(self.data),
                mediatype, filename)
        self._hash = _hash

    def __acl__(self):
        return (
                (Allow, Authenticated, ('view', 'create',)),
                )


class BaseContent:
    """A base class for common code in Document and Binder
    """

    def __acl__(self):
        acls = [(Allow, Authenticated, ('create',))]
        acls.append((Allow, self.metadata['submitter']['id'],
            ('view', 'edit', 'publish')))
        for user_permissions in self.acls:
            userid = user_permissions[0]
            permissions = user_permissions[1:]
            acls.append((Allow, userid, tuple(permissions)))
        return acls

    def to_dict(self):
        return to_dict(self.metadata)

    def __json__(self, request=None):
        result = self.to_dict()
        utils.change_dict_keys(result, utils.underscore_to_camelcase)
        return result



class Document(cnxepub.Document, BaseContent):
    """Modular documents that contain written text
    by one or more authors.
    """
    mediatype = DOCUMENT_MEDIATYPE

    def __init__(self, title, acls=None, **kwargs):
        metadata = build_metadata(title, **kwargs)
        metadata['media_type'] = self.mediatype
        id = str(metadata['id'])
        content = metadata['content']
        utils.fix_user_fields(metadata)
        cnxepub.Document.__init__(self, id, content, metadata)
        if acls is None:
            self.acls = []
        else:
            self.acls = acls

    def update(self, **kwargs):
        if 'license' in kwargs:
            del kwargs['license']
        for key, value in kwargs.items():
            if key in self.metadata:
                self.metadata[key] = value
        self.content = self.metadata['content']
        utils.fix_user_fields(self.metadata)

    def publish_prep(self):
        license = self.metadata['license']
        self.metadata['license_url'] = license.url
        self.metadata['license_text'] = ' '.join([license.name, license.abbr, license.version])
        self.metadata['summary'] = self.metadata['abstract']
        self.set_uri('cnx-archive', self.id)
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


def build_metadata(title, id=None, content=None, abstract=None, created=None,
        revised=None, subjects=None, keywords=None,
        license=LICENSE_PARAMETER_MARKER, language=None, derived_from=None,
        derived_from_uri=None, derived_from_title=None,
        submitter=None, state=None, publication=None, cnx_archive_uri=None):
    metadata = {}
    metadata['title'] = title
    metadata['version'] = 'draft'
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
    if cnx_archive_uri:
        metadata['cnx-archive-uri'] = cnx_archive_uri
    return metadata


def to_dict(metadata):
    result = metadata.copy()
    result['id'] = str(result['id'])
    result['created'] = result['created'].isoformat()
    result['revised'] = result['revised'].isoformat()
    result['license'] = result['license'].__dict__.copy()
    return result


class Binder(cnxepub.Binder, BaseContent):
    """A collection of documents
    """
    mediatype = BINDER_MEDIATYPE

    def __init__(self, title, tree, acls=None, **kwargs):
        metadata = build_metadata(title, **kwargs)
        metadata['media_type'] = self.mediatype
        id = str(metadata['id'])
        nodes, title_overrides = build_tree(tree)
        utils.fix_user_fields(metadata)
        cnxepub.Binder.__init__(self, id, nodes=nodes,
                metadata=metadata, title_overrides=title_overrides)
        if acls is None:
            self.acls = []
        else:
            self.acls = acls

    def update(self, **kwargs):
        if 'license' in kwargs:
            del kwargs['license']
        if 'tree' in kwargs:
            nodes, title_overrides = build_tree(kwargs.pop('tree'))
            self._nodes = nodes
            self._title_overrides = title_overrides
        for key, value in kwargs.items():
            if key in self.metadata:
                self.metadata[key] = value
        utils.fix_user_fields(self.metadata)

    def publish_prep(self):
        license = self.metadata['license']
        self.metadata['license_url'] = license.url
        self.metadata['license_text'] = ' '.join([license.name, license.abbr, license.version])
        self.metadata['summary'] = self.metadata['abstract']
        self.set_uri('cnx-archive', self.id)
        documents = []
        for document in cnxepub.flatten_to_documents(self):
            if document.id not in documents:
                documents.append(document.id)
                document.publish_prep()

    def to_dict(self):
        result = to_dict(self.metadata)
        result['tree'] = cnxepub.model_to_tree(self)
        return result


def create_content(**appstruct):
    """Given a Colander *appstruct*, create a content object."""
    kwargs = appstruct.copy()
    # TODO Lookup via storage.
    if 'license' in appstruct:
        license = [l for l in LICENSES
                   if l.url == appstruct['license']['url']][0]
        kwargs['license'] = license
    media_type = 'media_type' in kwargs and kwargs.pop('media_type')
    if media_type == BINDER_MEDIATYPE:
        return Binder(**kwargs)
    document = Document(**kwargs)
    return document


def revise_content(request, **kwargs):
    archive_id = kwargs['id']
    document = utils.fetch_archive_content(request, archive_id)
    document.update(kwargs)
    document['revised'] = None
    document['license'] = {'url': DEFAULT_LICENSE.url}
    return document


def derive_content(request, **kwargs):
    derived_from = kwargs['derived_from']
    document = utils.fetch_archive_content(request, derived_from)
    document['derived_from_title'] = document['title']
    # TODO not hardcode this url
    document['derived_from_uri'] = 'http://cnx.org/contents/{}'.format(derived_from)
    document['title'] = u'Copy of {}'.format(document['title'])
    document['created'] = None
    document['revised'] = None
    document['license'] = {'url': DEFAULT_LICENSE.url}
    return document
