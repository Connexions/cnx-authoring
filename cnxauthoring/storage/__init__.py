# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###

storage = None
storages = {'memory':('memory','MemoryStorage'),
            'pickle':('pickle_storage','PickleStorage'),
            'postgresql':('postgresql','PostgresqlStorage'),
            }
default_storage = 'memory'
