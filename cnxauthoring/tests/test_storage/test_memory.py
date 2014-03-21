# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###

import unittest

from ...models import Document

class MemoryStorageTests(unittest.TestCase):
    def setUp(self):
        from ...storage.memory import MemoryStorage
        self.storage = MemoryStorage()

    def test_add_document(self):
        d = Document('Document Title: One', id='document-one',
                     content='<p>Document One contents etc</p>',
                     summary='Summary of Document One',
                     language='en-us')
        self.storage.add(d)

        d2 = Document('Document Two', id='document-two',
                      content='<p>Document Two contents etc</p>',
                      summary='Summary of Document Two',
                      language='en-us')
        self.storage.add(d2)

        result = self.storage.get(id='document-one')
        self.assertEqual(result, d)

        result = self.storage.get(id='document-two')
        self.assertEqual(result, d2)

    def test_get_document(self):
        result = self.storage.get(id='document-one')
        self.assertEqual(result, None)

        d = Document('Document Title: One', id='document-one',
                     content='<p>Document One content etc</p>',
                     summary='Summary of Document One',
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

        # get by summary
        result = self.storage.get(summary='Summary of Document One')
        self.assertEqual(result, d)

        result = self.storage.get(summary='Summary')
        self.assertEqual(result, None)

        # get by language
        result = self.storage.get(language='en-us')
        self.assertEqual(result, d)

        result = self.storage.get(language='en')
        self.assertEqual(result, None)

        # get by multiple fields
        result = self.storage.get(language='en-us', summary='Summary of Document One')
        self.assertEqual(result, d)

        result = self.storage.get(language='en', summary='Summary of Document One')
        self.assertEqual(result, None)
