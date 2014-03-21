# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import pickle
import sys
import os

from .memory import MemoryStorage

class PickleStorage(MemoryStorage):

    def __init__(self, storage_filename):
        MemoryStorage.__init__(self)
        self.filename = storage_filename
        try:
            with open(self.filename, 'rb') as f:
                self.storage.update(pickle.load(f))
        except (IOError, EOFError):
            # file doesn't exist or is empty
            pass

    def persist(self):
        fdir = os.path.dirname(self.filename) or '.'
        gerkin, gname = tempfile.mkstemp(dir=fdir)
        pickle.dump(self.storage, gerkin)
        gerkin.close()
        os.rename(gname,self.filename)
