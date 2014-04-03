# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import datetime
import io
import json
import hashlib
import uuid
try:
    import urllib2 # python2
except ImportError:
    import urllib.request as urllib2 # renamed in python3
try:
    import urlparse # python2
except ImportError:
    import urllib.parse as urlparse # renamed in python3

import tzlocal
import cnxepub.models as cnxepub

from . import utils


# Timezone info initialized from the system timezone.
TZINFO = tzlocal.get_localzone()

DOCUMENT_MEDIATYPE = "application/vnd.org.cnx.module"
BINDER_MEDIATYPE = "application/vnd.org.cnx.collection"
MEDIATYPES = { 'document' : DOCUMENT_MEDIATYPE,
               'binder' : BINDER_MEDIATYPE }

LICENSE_PARAMETER_MARKER = object()
DEFAULT_LANGUAGE = 'en'


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


class Document:
    """Modular documents that contain written text
    by one or more authors.
    """
    mediatype = DOCUMENT_MEDIATYPE

    def __init__(self, title, **kwargs):
        metadata = build_metadata(title, **kwargs)
        metadata['media_type'] = self.mediatype
        self.id = str(metadata['id'])
        self.content = metadata['content']
        self.metadata = metadata

    def update(self, **kwargs):
        if 'license' in kwargs:
            del kwargs['license']
        for key, value in kwargs.items():
            if key in self.metadata:
                self.metadata[key] = value
        self.content = self.metadata['content']

    def to_dict(self):
        return to_dict(self.metadata)

    def __json__(self, request=None):
        result = self.to_dict()
        utils.change_dict_keys(result, utils.underscore_to_camelcase)
        return result


def build_metadata(title, id=None, content=None, abstract=None, created=None, revised=None, subjects=None, keywords=None, license=LICENSE_PARAMETER_MARKER, language=None, derived_from=None, submitter=None):
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
    metadata['submitter'] = submitter
    if type(subjects) in (list, tuple):
        metadata['subjects'] =subjects
    else:
        metadata['subjects'] = subjects and [subjects] or []
    if type(keywords) in (list, tuple):
        metadata['keywords'] =keywords
    else:
        metadata['keywords'] = keywords and [keywords] or []
    return metadata


def to_dict(metadata):
    result = metadata.copy()
    result['id'] = str(result['id'])
    result['created'] = result['created'].isoformat()
    result['revised'] = result['revised'].isoformat()
    result['license'] = result['license'].__dict__.copy()
    return result


class Binder(Document):
    """A collection of documents
    """
    mediatype = BINDER_MEDIATYPE

    def __init__(self, title, tree, **kwargs):
        metadata = build_metadata(title, **kwargs)
        metadata['media_type'] = self.mediatype
        self.id = str(metadata['id'])
        self.metadata = metadata
        self.build_tree(tree)

    def build_tree(self, tree):
        def get_nodes(tree, nodes):
            for i in tree['contents']:
                if 'contents' in i:
                    contents_nodes = []
                    get_nodes(i, contents_nodes)
                    if i['id'] == 'subcol':
                        nodes.append(cnxepub.TranslucentBinder(
                            metadata={'title': i['title']},
                            nodes=contents_nodes))
                    else:
                        nodes.append(cnxepub.Binder(i['id'],
                            metadata={'title': i['title']},
                            nodes=contents_nodes))
                else:
                    nodes.append(cnxepub.DocumentPointer(i['id'],
                        {'title': i['title']}))
        nodes = []
        get_nodes(tree, nodes)
        self._binder = cnxepub.Binder(self.id,
                metadata=self.metadata.copy(), nodes=nodes)

    def update(self, **kwargs):
        Document.update(self, **kwargs)
        if 'tree' in kwargs:
            self.build_tree(kwargs['tree'])

    def to_dict(self):
        result = to_dict(self.metadata)
        result['tree'] = cnxepub.model_to_tree(self._binder)
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


def derive_content(request, **kwargs):
    derived_from = kwargs['derived_from']
    settings = request.registry.settings
    archive_url = settings['archive.url']
    content_url = urlparse.urljoin(archive_url,
            '/contents/{}.json'.format(derived_from))
    try:
        response = urllib2.urlopen(content_url).read()
    except urllib2.HTTPError:
        return
    try:
        document = json.loads(response.decode('utf-8'))
    except (TypeError, ValueError):
        return
    utils.change_dict_keys(document, utils.camelcase_to_underscore)
    document['title'] = u'Copy of {}'.format(document['title'])
    document['created'] = None
    document['revised'] = None
    document['license'] = {'url': DEFAULT_LICENSE.url}
    return document


def derive_resources(request, document):
    epubdoc = EPUBDocument(document, None)
    settings = request.registry.settings
    archive_url = settings['archive.url']
    for r in epubdoc.references():
        if r.uri.startswith('/resources'):
            try:
                response = urllib2.urlopen(urlparse.urljoin(archive_url, r.uri))
                content_type = response.info().getheader('Content-Type')
                resource = Resource(content_type, response)
                r.uri = request.route_path('get-resource', hash=resource.hash)
                yield resource
            except urllib2.HTTPError:
                pass
    document.metadata['content'] = epubdoc.content()
    document.content = document.metadata['content']


class EPUBDocument(object):
    def __init__(self, document, submitlog):
        self.document = document
        self.submitlog = submitlog
        self.epubdoc = cnxepub.Document(
                str(self.document.id),
                self.document.content,
                metadata=self.metadata())

    def __call__(self):
        return self.epubdoc

    def metadata(self):
        m = self.document.to_dict()
        m['publisher'] = m.pop('submitter')
        m['publication_message'] = self.submitlog
        m.pop('content')
        license = m.pop('license')
        m['license_url'] = license['url']
        m['license_text'] = ' '.join([license['name'], license['abbr'], license['version']])
        return m

    def references(self):
        return self.epubdoc.references

    def content(self):
        return self.epubdoc.html
