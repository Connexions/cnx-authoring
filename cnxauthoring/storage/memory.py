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
                if str(getattr(item, k)) != str(v):
                    break
            else:
                yield item

    def add(self, item_or_items):
        """Adds any item or set of items to storage."""
        if isinstance(item_or_items, list):
            raise NotImplementedError()
        item = item_or_items
        collection = self.storage[str(item.__class__)]
        collection.append(item)
        return item

    def remove(self, item_or_items):
        """Removes any item or set of items from storage."""
        raise NotImplementedError()

    def update(self, item_or_items):
        """Updates any item or set of items in storage."""
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
        self.add(item)
        return item

    def persist(self):
        """Persist/commit the changes."""
        pass

    def search(self, limits, type_=Document, submitter=None):
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
            title = item.title and item.title.lower() or u''
            for term in search_terms:
                if term in title:
                    if submitter is None or item.submitter == submitter:
                        yield item
