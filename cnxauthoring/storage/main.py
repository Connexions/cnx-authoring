# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
class BaseStorage:
    """Utility for managing and interfacing with the the storage medium."""

    def get(self, **kwargs):
        """Retreive ``Document`` objects from storage."""
        raise NotImplementedError()

    def add(self, item_or_items):
        """Adds any item or set of items to storage."""
        raise NotImplementedError()

    def remove(self, item_or_items):
        """Removes any item or set of items from storage."""
        raise NotImplementedError()

    def update(self, item_or_items):
        """Updates any item or set of items in storage."""
        raise NotImplementedError()

    def persist(self):
        """Persist/commit the changes."""
        raise NotImplementedError()

    def abort(self):
        """Clear any persistent error state"""
        raise NotImplementedError()

    def search(self, **kwargs):
        """Retrieve any ``Document`` objects from storage that matches the
        search terms."""
        raise NotImplementedError()
