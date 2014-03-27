# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import datetime
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


class Resource:
    """Any *file* that is referenced within a ``Document``."""

    def __init__(self, mediatype, data):
        self.mediatype = mediatype
        # ``data`` must be a buffer or file-like object.
        try:
            self.data = data.read()
        except AttributeError:
            self.data = data[:]
        self._hash = hashlib.new('sha1', self.data).hexdigest()

    @property
    def hash(self):
        return self._hash


class Document:
    """Modular documents that contain written text
    by one or more authors.
    """
    mediatype = DOCUMENT_MEDIATYPE

    def __init__(self, title, id=None,
                 content=None, abstract=None,
                 created=None, revised=None,
                 license=LICENSE_PARAMETER_MARKER,
                 language=None, derived_from=None, submitter=None):
        self.title = title
        self.version = 'draft'
        self.id = id or uuid.uuid4()
        self.content = content
        self.abstract = abstract is None and '' or abstract
        now = datetime.datetime.now(tz=TZINFO)
        self.created = created is None and now or created
        self.revised = revised is None and now or revised
        # license is a reserved name that will never be None.
        if license is LICENSE_PARAMETER_MARKER:
            self.license = DEFAULT_LICENSE
        else:
            self.license = license
        self.language = language is None and DEFAULT_LANGUAGE or language
        self.derived_from = derived_from
        self.submitter = submitter

    def update(self, **kwargs):
        if 'license' in kwargs:
            del kwargs['license']
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def to_dict(self):
        c = self.__dict__.copy()
        c['id'] = str(c['id'])
        c['created'] = c['created'].isoformat()
        c['revised'] = c['revised'].isoformat()
        c['license'] = c['license'].__dict__.copy()
        c['media_type'] = self.mediatype
        return c

    def __json__(self, request=None):
        result = self.to_dict()
        utils.change_dict_keys(result, utils.underscore_to_camelcase)
        return result


class Binder(Document):
    """A collection of documents
    """
    mediatype = BINDER_MEDIATYPE

    def __init__(self, title, tree, **kwargs):
        Document.__init__(self, title, **kwargs)
        self.id = str(self.id)
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
                    nodes.append(DocumentPointer(i['id'], i['title']))
        nodes = []
        get_nodes(tree, nodes)
        self._binder = cnxepub.Binder('{}@draft'.format(self.id),
                metadata={'title': self.title},
                nodes=nodes)

    def update(self, **kwargs):
        Document.update(self, **kwargs)
        if 'tree' in kwargs:
            self.build_tree(kwargs['tree'])

    def to_dict(self):
        result = Document.to_dict(self)
        for k in list(result.keys()):
            if k.startswith('_'):
                result.pop(k)
        result['tree'] = cnxepub.model_to_tree(self._binder)
        return result


class DocumentPointer:
    def __init__(self, ident_hash, title):
        self.ident_hash = ident_hash
        self.title = title
        self.metadata = {'title': title}


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
    return Document(**kwargs)


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
