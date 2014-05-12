# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###

import unittest
import uuid

from .. import test_data
from ...models import Document, Resource, Binder

class MemoryStorageTests(unittest.TestCase):
    def setUp(self):
        from ...storage.memory import MemoryStorage
        self.storage = MemoryStorage()

    def test_add_document(self):
        d1_id = uuid.uuid4()
        d = Document('Document Title: One', id=d1_id,
                     content='<p>Document One contents etc</p>',
                     abstract='Summary of Document One',
                     submitter='me',
                     language='en')
        self.storage.add(d)
        self.storage.persist()

        result = self.storage.get(id=d1_id)
        self.assertEqual(result.to_dict(), d.to_dict())

        d2_id = uuid.uuid4()
        d2 = Document('Document Two', id=d2_id,
                      content='<p>Document Two contents etc</p>',
                      abstract='Summary of Document Two',
                      submitter='me',
                      language='en')
        self.storage.add(d2)
        self.storage.persist()

        result = self.storage.get(id=d1_id)
        self.assertEqual(result.to_dict(), d.to_dict())

        result = self.storage.get(id=d2_id)
        self.assertEqual(result.to_dict(), d2.to_dict())

    def test_add_and_get_binder(self):
        d1_id = uuid.uuid4()
        d = Document('Document Title: One', id=d1_id, submitter='me')
        self.storage.add(d)
        self.storage.persist()

        b1_id = uuid.uuid4()
        b = Binder('Book Title', {
            'contents': [
                {'id': str(d1_id)},
                ]},
            id=b1_id, submitter='me')
        self.storage.add(b)
        self.storage.persist()

        result = self.storage.get(id=b1_id)
        self.assertEqual(result.to_dict(), b.to_dict())

    def test_add_and_get_resource(self):
        with open(test_data('1x1.png'), 'rb') as f:
            data = f.read()
        r = Resource('image/png', data)
        self.storage.add(r)
        self.storage.persist()

        result = self.storage.get(type_=Resource, hash=r.hash)
        self.assertEqual(result.hash, r.hash)
        self.assertEqual(result.data.read(), data)

    def test_get_document(self):
        d1_id = uuid.uuid4()
        result = self.storage.get(id=d1_id)
        self.assertEqual(result, None)

        d = Document('Document Title: One', id=d1_id,
                     content='<p>Document One content etc</p>',
                     abstract='Summary of Document One',
                     submitter='me',
                     language='en')
        self.storage.add(d)
        self.storage.persist()

        # get by id
        result = self.storage.get(id=d1_id)
        self.assertEqual(result.to_dict(), d.to_dict())

        result = self.storage.get(id=uuid.uuid4())
        self.assertEqual(result, None)

        # get by title
        result = self.storage.get(title='Document Title: One')
        self.assertEqual(result.to_dict(), d.to_dict())

        result = self.storage.get(title='Document')
        self.assertEqual(result, None)

        # get by content
        result = self.storage.get(content='<p>Document One content etc</p>')
        self.assertEqual(result.to_dict(), d.to_dict())

        result = self.storage.get(content='<p></p>')
        self.assertEqual(result, None)

        # get by abstract
        result = self.storage.get(abstract='Summary of Document One')
        self.assertEqual(result.to_dict(), d.to_dict())

        result = self.storage.get(abstract='Summary')
        self.assertEqual(result, None)

        # get by language
        result = self.storage.get(language='en')
        self.assertEqual(result.to_dict(), d.to_dict())

        result = self.storage.get(language='de')
        self.assertEqual(result, None)

        # get by multiple fields
        result = self.storage.get(language='en', abstract='Summary of Document One')
        self.assertEqual(result.to_dict(), d.to_dict())

        result = self.storage.get(language='de', abstract='Summary of Document One')
        self.assertEqual(result, None)

    def test_update_document(self):
        d1_id = uuid.uuid4()
        d = Document('Document Title: One', id=d1_id, submitter='me')
        self.storage.add(d)
        self.storage.persist()

        d = self.storage.get(id=d1_id)
        self.assertEqual(d.metadata['title'], 'Document Title: One')
        d.update(title='Document Title: Changed')
        self.storage.update(d)

        d = self.storage.get(id=d1_id)
        self.assertEqual(d.metadata['title'], 'Document Title: Changed')

    def test_update_binder(self):
        d1_id = uuid.uuid4()
        d = Document('Document Title: One', id=d1_id, submitter='me')
        self.storage.add(d)
        self.storage.persist()

        b1_id = uuid.uuid4()
        b = Binder('Book Title', {
            'contents': []},
            id=b1_id, submitter='me')
        self.storage.add(b)
        self.storage.persist()

        b = self.storage.get(id=b1_id)
        self.assertEqual(b.to_dict()['tree']['contents'], [])
        self.assertEqual(b.metadata['title'], 'Book Title')

        b.update(tree={
            'contents': [{'id': str(d1_id)}],
            })
        self.storage.update(b)

        b = self.storage.get(id=b1_id)
        self.assertEqual(b.to_dict()['tree']['contents'], [
            {'id': str(d1_id), 'title': None}])
        self.assertEqual(b.metadata['title'], 'Book Title')
