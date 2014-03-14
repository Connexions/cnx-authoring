# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###

from .main import BaseStorage
from ..models import Document, Resource

class MemoryStorage(BaseStorage):
    """Utility for managing and interfacing with the the storage medium."""

    def __init__(self):
        self.storage = {str(Document): [], str(Resource): []}

    def get(self, type_=Document, **kwargs):
        """Retreive ``Document`` objects from storage."""
        collection = self.storage[str(type_)]
        for item in collection:
            for k, v in kwargs.items():
                if getattr(item, k) != v:
                    break
            else:
                return item

    def add(self, item_or_items):
        """Adds any item or set of items to storage."""
        if isinstance(item_or_items, list):
            raise NotImplementedError()
        item = item_or_items
        item.id = str(item.id)
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
