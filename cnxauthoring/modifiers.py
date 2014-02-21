# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import datetime
import uuid

from pyramid.renderers import JSON

from .models import Document


def json_uuid_adapter(obj, request):
    return str(obj)


def json_document_adapter(obj, request):
    return {
        'id': obj.id,
        'title': obj.title,
        'created': obj.created,
        'modified': obj.modified,
        }


def json_datetime_adapter(obj, request):
    return obj.isoformat()


JSON_RENDERERS = [
    (datetime.datetime, json_datetime_adapter,),
    (uuid.UUID, json_uuid_adapter,),
    (Document, json_document_adapter,),
    ]


def includeme(config):
    """Called at application initialization to modify renderers."""
    json_renderer = JSON()
    for type_, adapter in JSON_RENDERERS:
        json_renderer.add_adapter(type_, adapter)
