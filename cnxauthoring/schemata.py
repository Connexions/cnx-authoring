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


class UserSchema(colander.MappingSchema):
    id = colander.SchemaNode(
            colander.String(),
            )
    email = colander.SchemaNode(
            colander.String(),
            missing='',
            )
    firstname = colander.SchemaNode(
            colander.String(),
            missing='',
            )
    surname = colander.SchemaNode(
            colander.String(),
            missing='',
            )
    type = colander.SchemaNode(
            colander.String(),
            missing='cnx-id',
            validator=colander.OneOf(['cnx-id']),
            )
    fullname = colander.SchemaNode(
            colander.String(),
            missing='',
            )

    def schema_type(self, **kw):
        return colander.Mapping(unknown='preserve')


class RoleSchema(UserSchema):
    has_accepted = colander.SchemaNode(
        colander.Boolean(),
        missing=colander.drop,
        )


class RoleSequence(colander.SequenceSchema):
    role = RoleSchema()


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
    revised = colander.SchemaNode(
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
    derived_from_title = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    derived_from_uri = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    content = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )

    submitter = UserSchema()
    authors = RoleSequence(validator=colander.Length(min=1))
    publishers = RoleSequence(validator=colander.Length(min=1)) # maintainers
    licensors = RoleSequence(validator=colander.Length(min=1)) # copyright holders
    translators = RoleSequence(missing=colander.drop)
    editors = RoleSequence(missing=colander.drop)
    illustrators = RoleSequence(missing=colander.drop)

    media_type = colander.SchemaNode(
        colander.String(),
        default=DOCUMENT_MEDIATYPE,
        missing=colander.drop,
        validator=colander.OneOf([DOCUMENT_MEDIATYPE, BINDER_MEDIATYPE]),
        )
    subjects = colander.SchemaNode(
        colander.List(),
        missing=colander.drop,
        )
    keywords = colander.SchemaNode(
        colander.List(),
        missing=colander.drop,
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


class RoleAcceptanceSchema(colander.MappingSchema):
    role = colander.SchemaNode(
        colander.String(),
        )
    has_accepted = colander.SchemaNode(
        colander.Boolean(),
        missing=colander.drop,
        )


class RoleAcceptanceSequence(colander.SequenceSchema):
    role = RoleAcceptanceSchema()


class AcceptanceSchema(colander.MappingSchema):
    license = colander.SchemaNode(
        colander.Boolean(),
        )
    roles = RoleAcceptanceSequence()
