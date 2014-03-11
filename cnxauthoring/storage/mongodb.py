# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
from pymongo import MongoClient

from .main import BaseStorage, Persistability
from ..models import Document, Resource


class MongoDBStorage(BaseStorage):
    """Utility for managing and interface with a MongoDB database."""

    def __init__(self, connection_uri, database_name):
        self._connection_uri = connection_uri
        self._database_name = database_name
        self._client = MongoClient(self._connection_uri)

    @property
    def db(self):
        return self._client[self._database_name]

    def get(self, **kwargs):
        return  self.db.find_one(**kwargs)

    def add(self, item_or_items):
        was_single_given = False
        if not isinstance(item_or_items, (list, tuple, set,)):
            was_single_given = True
            item_or_items = [item_or_items]
        results = []
        for item in item_or_items:
            results.append(self._insert(item))
        if was_single_given:
            return results[0]
        return results

    def remove(self, item_or_items):
        if not isinstance(item_or_items, (list, tuple, set,)):
            item_or_items = [item_or_items]
        for item in item_or_items:
            self._delete(item)

    def persist(self):
        # NOOP
        pass

    def _get_collection_for_type(self, type_):
        """Retrieve the collection for the given type."""
        return getattr(self.db, type_.__name__.lower())

    def _insert(self, item):
        persistent_item = Persistability(item)
        collection = self._get_collection_for_type(type(item))
        if persistent_item.is_new or persistent_item.has_changed:
            _id = collection.update(to_mongo_document(item))
            persistent_item.ident = _id
            mongo_document = collection.find_one({'_id': _id})
            for key, value in mongo_document.items():
                if key.startswith('_'):
                    continue
                setattr(item, key, value)
        return item

    def _delete(self, item):
        raise NotImplementedError()


class MongoDocument:
    """Adapter for objects to mongo documents."""

    def __init__(self, obj):
        self.obj = obj

    def __call__(self):
        """Returns a dictionary as a transferable mongo document."""
        if isinstance(self.obj, Document):
            results = self.render_document()
        elif isinstance(self.obj, Resource):
            results = self.render_resource()
        else:
            raise TypeError("Unknown type for {}".format(self.obj))
        return results

    def render_document(self):
        # FIXME
        return {'title': self.obj.title}

    def render_resource(self):
        raise NotImplementedError()


def to_mongo_document(item):
    """Transform the item to a mongo document."""
    adapter = MongoDocument(item)
    return adapter()
