# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import datetime

import colander

from .models import (TZINFO, DEFAULT_LANGUAGE, DOCUMENT_MEDIATYPE,
        BINDER_MEDIATYPE)


@colander.deferred
def deferred_datetime_missing(node, kw):
    dt = datetime.datetime.now(tz=TZINFO)
    return dt


class LicenseSchema(colander.MappingSchema):
    """Schema for ``License``"""

    name = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    url = colander.SchemaNode(
        colander.String(),
        validator=colander.url,
        )
    abbr = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    version = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )

license_schema = LicenseSchema()


class DocumentSchema(colander.MappingSchema):
    """Schema for ``Document``"""

    # id = colander.SchemaNode(
    #     UUID(),
    #     missing=colander.drop,
    #     )
    title = colander.SchemaNode(
        colander.String(),
        )
    abstract = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    created = colander.SchemaNode(
        colander.DateTime(default_tzinfo=TZINFO),
        missing=deferred_datetime_missing,
        )
    modified = colander.SchemaNode(
        colander.DateTime(default_tzinfo=TZINFO),
        missing=deferred_datetime_missing,
        )
    license = LicenseSchema(
        missing=colander.drop,
        )
    language = colander.SchemaNode(
        colander.String(),
        default=DEFAULT_LANGUAGE,
        missing=colander.drop,
        )
    derived_from = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    content = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    submitter = colander.SchemaNode(
        colander.String(),
        )
    media_type = colander.SchemaNode(
        colander.String(),
        default=DOCUMENT_MEDIATYPE,
        missing=colander.drop,
        validator=colander.OneOf([DOCUMENT_MEDIATYPE, BINDER_MEDIATYPE]),
        )

document_schema = DocumentSchema()


class Tree(colander.MappingSchema):
    id = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    contents = colander.SchemaNode(
        colander.List(),
        )

class BinderSchema(DocumentSchema):
    tree = Tree()
