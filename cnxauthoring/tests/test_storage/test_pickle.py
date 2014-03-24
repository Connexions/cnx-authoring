# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###

import unittest
import os

from ...models import Document

class PickleStorageTests(unittest.TestCase):
    def setUp(self):
        from ...storage.pickle_storage import PickleStorage
        self.storage = PickleStorage(filename='gerkin', empty=True)

    def tearDown(self):
        if os.path.exists(self.storage.filename):
            os.remove(self.storage.filename)

    def test_add_document(self):
        d = Document('Document Title: One', id='document-one',
                     content='<p>Document One content etc</p>',
                     abstract='Summary of Document One',
                     language='en-us')
        self.storage.add(d)
        self.storage.persist()

        d2 = Document('Document Two', id='document-two',
                      content='<p>Document Two content etc</p>',
                      abstract='Summary of Document Two',
                      language='en-us')
        self.storage.add(d2)
        self.storage.persist()

        result = self.storage.get(id='document-one')
        self.assertEqual(result, d)

        result = self.storage.get(id='document-two')
        self.assertEqual(result, d2)

    def test_get_document(self):
        result = self.storage.get(id='document-one')
        self.assertEqual(result, None)

        d = Document('Document Title: One', id='document-one',
                     content='<p>Document One content etc</p>',
                     abstract='Summary of Document One',
                     language='en-us')
        self.storage.add(d)

        # get by id
        result = self.storage.get(id='document-one')
        self.assertEqual(result, d)

        result = self.storage.get(id='document')
        self.assertEqual(result, None)

        # get by title
        result = self.storage.get(title='Document Title: One')
        self.assertEqual(result, d)

        result = self.storage.get(title='Document')
        self.assertEqual(result, None)

        # get by content
        result = self.storage.get(content='<p>Document One content etc</p>')
        self.assertEqual(result, d)

        result = self.storage.get(content='<p></p>')
        self.assertEqual(result, None)

        # get by abstract
        result = self.storage.get(abstract='Summary of Document One')
        self.assertEqual(result, d)

        result = self.storage.get(abstract='Summary')
        self.assertEqual(result, None)

        # get by language
        result = self.storage.get(language='en-us')
        self.assertEqual(result, d)

        result = self.storage.get(language='en')
        self.assertEqual(result, None)

        # get by multiple fields
        result = self.storage.get(language='en-us', abstract='Summary of Document One')
        self.assertEqual(result, d)

        result = self.storage.get(language='en', abstract='Summary of Document One')
        self.assertEqual(result, None)
