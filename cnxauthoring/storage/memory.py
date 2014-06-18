# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###

from .main import BaseStorage
from ..models import Document, Resource, Binder

class MemoryStorage(BaseStorage):
    """Utility for managing and interfacing with the the storage medium."""

    def __init__(self):
        self.storage = {str(Document): [], str(Resource): []}
        # share the same list between Documents and Binders
        self.storage[str(Binder)] = self.storage[str(Document)]

    def get(self, type_=Document, **kwargs):
        """Retrieve ``Document`` objects from storage."""
        for obj in self.get_all(type_=type_, **kwargs):
            return obj

    def get_all(self, type_=Document, **kwargs):
        """Retreive ``Document`` objects from storage."""
        collection = self.storage[str(type_)]
        for item in collection:
            for k, v in kwargs.items():
                if hasattr(item, 'metadata'):
                    value = item.metadata.get(k)
                else:
                    value = getattr(item, k, None)

                if isinstance(v, dict) and isinstance(value, dict):
                    if any([value.get(inner_k) != v[inner_k] for inner_k in v]):
                        break
                else:
                    if str(value) != str(v):
                        break
            else:
                # item found
                if hasattr(item, '_xml'):
                    item.content = item.metadata['content']
                yield item

    def add(self, item_or_items):
        """Adds any item or set of items to storage."""
        if isinstance(item_or_items, list):
            raise NotImplementedError()
        item = item_or_items
        if hasattr(item, '_xml'):
            item._xml = None
        collection = self.storage[str(item.__class__)]
        collection.append(item)
        return item

    def update(self, item_or_items):
        """Updates any item or set of items in storage."""
        item = self.remove(item_or_items)
        self.add(item)
        return item

    def remove(self, item_or_items):
        """Removes any item or set of items from storage."""
        if isinstance(item_or_items, list):
            raise NotImplementedError()
        item = item_or_items
        item.id = str(item.id)
        collection = self.storage[str(item.__class__)]
        for i, member in enumerate(collection):
            if item.id == member.id:
                index = i
                break
        collection.pop(index)
        return item

    def persist(self):
        """Persist/commit the changes."""
        pass

    def abort(self):
        """Persist/commit the changes."""
        pass
    

    def search(self, limits, type_=Document, submitter_id=None):
        """Retrieve any ``Document`` objects from storage that matches the
        search terms."""
        if type_ != Document:
            raise NotImplementedError()
        collection = self.storage[str(type_)]

        search_terms = []
        for limit_type, term in limits:
            if limit_type != 'text':
                raise NotImplementedError()
            search_terms.append(term.lower())

        for item in collection:
            title = item.metadata['title'] or ''
            title = title.lower()
            for term in search_terms:
                if term in title:
                    if submitter_id is None or item.metadata.get('submitter')['id'] == submitter_id:
                        yield item
                        break
