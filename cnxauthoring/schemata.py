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


class Trinary(colander.SchemaType):
    """A type representing a trivalued logic object with - 3 states.
    That is true, false and unknown. These are represented in Python
    as True, False and None.
    """

    def __init__(self, false_choices=('false', '0',),
                 true_choices=('true', '1',),
                 unknown_choices=('none', '',),
                 true_val=True, false_val=False, unknown_val=None):
        self.true_val = true_val
        self.false_val = false_val
        self.unknown_val = unknown_val
        self.false_choices = false_choices
        self.true_choices = true_choices
        self.unknown_choices = unknown_choices

    def serialize(self, node, appstruct):
        if appstruct is colander.null:
            return colander.null

        if appstruct is None:
            return self.unknown_val
        else:
            return appstruct and self.true_val or self.false_val

    def deserialize(self, node, cstruct):
        _ = colander._
        if cstruct is colander.null:
            return colander.null
        elif cstruct is None:
            return None

        try:
            result = str(cstruct)
        except:
            raise colander.Invalid(
                node,
                _('${val} is not a string', mapping={'val':cstruct})
                )
        result = result.lower()

        if result in self.unknown_choices:
            state = None
        elif result in self.false_choices:
            state = False
        elif result in self.true_choices:
            state = True
        else:
            raise colander.Invalid(
                node,
                _('"${val}" is neither in (${false_choices}) '
                  'nor in (${true_choices})',
                  mapping={'val':cstruct,
                           'false_choices': self.false_reprs,
                           'true_choices': self.true_reprs })
                )
        return state


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
    type = colander.SchemaNode(
            colander.String(),
            missing='cnx-id',
            validator=colander.OneOf(['cnx-id']),
            )
    firstname = colander.SchemaNode(
            colander.String(),
            missing=None,
            )
    surname = colander.SchemaNode(
            colander.String(),
            missing=None,
            )
    fullname = colander.SchemaNode(
            colander.String(),
            missing=None,
            )
    suffix = colander.SchemaNode(
            colander.String(),
            missing=colander.drop,
            )
    title = colander.SchemaNode(
            colander.String(),
            missing=colander.drop,
            )

    def schema_type(self, **kw):
        return colander.Mapping(unknown='preserve')


class RoleSchema(UserSchema):
    has_accepted = colander.SchemaNode(
        Trinary(),
        missing=colander.drop,
        )
    requester = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    assignment_date = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        )
    notify_sent = colander.SchemaNode(
        colander.String(),
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
    print_style = colander.SchemaNode(
        colander.String(),
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
