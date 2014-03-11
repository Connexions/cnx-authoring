# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
__all__ = (
    'BaseStorage', 'Model', 'Persistent',
    'NOT_PERSISTED', 'OK', 'NEW', 'CHANGED', 'DELETED',
    'PERSISTENT_STATES', 'Persistability',
    )


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

    def partial_update(self, mapping, ident_mapping, type_):
        """Updates a record with the ``mapping`` values,
        against the ``ident_mapping``, which is a mapping of identifiers
        (e.g. ``dict(id='123')``) and ``type_`` to let the storage place
        the update in the correct place.
        """
        raise NotImplementedError()

    def persist(self):
        """Persist/commit the changes."""
        raise NotImplementedError()


NOT_PERSISTED = None
OK = 'ok'
NEW = 'new'
CHANGED = 'changed'
DELETED = 'deleted'
PERSISTENT_STATES = (
    NOT_PERSISTED,
    OK,
    NEW,
    CHANGED,
    DELETED,
    )


class Persistent:
    """Persistent state"""

    def __init__(self, state=NOT_PERSISTED, ident=None):
        self.state = state
        # Internal storage identifier.
        self.ident = ident


class Model:
    """Persistant model base."""

    def __init__(self, *args, **kwargs):
        self._persistent = Persistent()

class Persistability:
    """Adapts model to aid in persitent state lookup."""

    def __init__(self, model):
        self.model = model

    @property
    def persistent(self):
        return self.model._persistent

    @property
    def ident(self):
        return self.persistent.ident
    @ident.setter
    def ident(self, v):
        self.persistent.ident = v


    @property
    def is_new(self):
        return self.persistent.state in (NOT_PERSISTED, NEW,)
