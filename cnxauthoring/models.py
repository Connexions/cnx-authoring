# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import time
import datetime
import hashlib
import uuid

import pytz


# Timezone info initialized from the system timezone.
TZINFO = pytz.timezone(time.tzname[0])

DOCUMENT_MEDIATYPE = "application/vnd.org.cnx.document"
LICENSE_PARAMETER_MARKER = object()
DEFAULT_LANGUAGE = 'en-us'


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
        self.data = data
        self._hash = hashlib.new('sha1', self.data.read()).hexdigest()
        # FIXME There has got to be a better way to reset position
        #       to zero after read.
        self.data.seek(0)

    @property
    def hash(self):
        return self._hash


class Document:
    """Modular documents that contain written text
    by one or more authors.
    """
    mediatype = DOCUMENT_MEDIATYPE

    def __init__(self, title, id=None,
                 contents=None, summary=None,
                 created=None, modified=None,
                 license=LICENSE_PARAMETER_MARKER,
                 language=None, derived_from=None, submitter=None):
        self.title = title
        self.id = id or uuid.uuid4()
        self.contents = contents
        self.summary = summary is None and '' or summary
        now = datetime.datetime.now(tz=TZINFO)
        self.created = created is None and now or created
        self.modified = modified is None and now or modified
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
        c['created'] = str(c['created'])
        c['modified'] = str(c['modified'])
        c['license'] = c['license'].__dict__
        return c


def create_content(**appstruct):
    """Given a Colander *appstruct*, create a content object."""
    kwargs = appstruct.copy()
    # TODO Lookup via storage.
    if 'license' in appstruct:
        license = [l for l in LICENSES
                   if l.url == appstruct['license']['url']][0]
        kwargs['license'] = license
    return Document(**kwargs)
