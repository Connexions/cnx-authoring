# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import io
import unittest
import uuid

from .. import test_data
from ...models import Document, Resource, Binder

SUBMITTER = {
        u'id': u'me',
        u'email': u'me@example.com',
        u'firstname': u'User',
        u'surname': u'One',
        }

USER2 = {
        u'id': u'you',
        u'email': u'you@example.com',
        u'firstname': u'User',
        u'surname': u'Two',
        }

class MemoryStorageTests(unittest.TestCase):
    def setUp(self):
        from ...storage.memory import MemoryStorage
        self.storage = MemoryStorage()

    def test_add_document(self):
        d1_id = uuid.uuid4()
        d = Document('Document Title: One', id=d1_id,
                     content='<p>Document One contents etc</p>',
                     abstract='Summary of Document One',
                     submitter=SUBMITTER,
                     authors=[SUBMITTER],
                     publishers=[SUBMITTER, USER2],
                     editors=[USER2],
                     language='en')
        self.storage.add(d)
        self.storage.persist()

        result = self.storage.get(id=d1_id)
        self.assertEqual(result.to_dict(), d.to_dict())

        d2_id = uuid.uuid4()
        d2 = Document('Document Two', id=d2_id,
                      content='<p>Document Two contents etc</p>',
                      abstract='Summary of Document Two',
                      submitter=SUBMITTER,
                      licensors=[SUBMITTER],
                      translators=[USER2],
                      language='en')
        self.storage.add(d2)
        self.storage.persist()

        result = self.storage.get(id=d1_id)
        self.assertEqual(result.to_dict(), d.to_dict())

        result = self.storage.get(id=d2_id)
        self.assertEqual(result.to_dict(), d2.to_dict())

    def test_add_get_and_remove_binder(self):
        d1_id = uuid.uuid4()
        d = Document('Document Title: One', id=d1_id, submitter=SUBMITTER)
        self.storage.add(d)
        self.storage.persist()

        b1_id = uuid.uuid4()
        b = Binder('Book Title', {
            'contents': [
                {'id': str(d1_id)},
                ]},
            id=b1_id, submitter=SUBMITTER)
        self.storage.add(b)
        self.storage.persist()

        result = self.storage.get(id=b1_id)
        self.assertEqual(result.to_dict(), b.to_dict())

        self.storage.remove(b)
        result = self.storage.get(id=b1_id)
        self.assertEqual(result, None)

    def test_add_get_and_remove_resource(self):
        with open(test_data('1x1.png'), 'rb') as f:
            data = f.read()
        r = Resource('image/png', io.BytesIO(data))
        self.storage.add(r)
        self.storage.persist()

        result = self.storage.get(type_=Resource, hash=r.hash)
        self.assertEqual(result.hash, r.hash)
        with result.open() as f:
            self.assertEqual(f.read(), data)

        self.storage.remove(r)
        result = self.storage.get(type_=Resource, hash=r.hash)
        self.assertEqual(result, None)

    def test_get_and_remove_document(self):
        d1_id = uuid.uuid4()
        result = self.storage.get(id=d1_id)
        self.assertEqual(result, None)

        d = Document('Document Title: One', id=d1_id,
                     content='<p>Document One content etc</p>',
                     abstract='Summary of Document One',
                     submitter=SUBMITTER,
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

        # get by submitter username
        result = self.storage.get(submitter={'id': 'me'})
        self.assertEqual(result.to_dict(), d.to_dict())

        result = self.storage.get(submitter={'id': 'you'})
        self.assertEqual(result, None)

        # remove it
        self.storage.remove(d)
        result = self.storage.get(id=d1_id)
        self.assertEqual(result, None)


    def test_update_document(self):
        d1_id = uuid.uuid4()
        d = Document('Document Title: One', id=d1_id, submitter=SUBMITTER)
        self.storage.add(d)
        self.storage.persist()

        d = self.storage.get(id=d1_id)
        self.assertEqual(d.metadata['title'], 'Document Title: One')
        d.update(title='Document Title: Changed',
                 authors=[SUBMITTER, USER2],
                 licensors=[SUBMITTER],
                 editors=[USER2],
                 translators=[],
                )
        self.storage.update(d)

        d = self.storage.get(id=d1_id)
        self.assertEqual(d.metadata['title'], 'Document Title: Changed')

    def test_update_binder(self):
        d1_id = uuid.uuid4()
        d = Document('Document Title: One', id=d1_id, submitter=SUBMITTER)
        self.storage.add(d)
        self.storage.persist()

        b1_id = uuid.uuid4()
        b = Binder('Book Title', {
            'contents': []},
            id=b1_id, submitter=SUBMITTER)
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

    def test_search_single_doc(self):
        d1_id = uuid.uuid4()
        d1 = Document('Document Title: One (Unique Phrase)', id=d1_id, submitter=SUBMITTER)
        self.storage.add(d1)
        self.storage.persist()

        # One term one result
        i = 0
        search_gen = self.storage.search([('text', 'document title: one')])
        for doc in search_gen:
            self.assertEqual(doc.to_dict(), d1.to_dict())
            i += 1
        self.assertEqual(i, 1)

        # One term no results
        search_gen = self.storage.search([('text', 'Purple')])
        for doc in search_gen:
            self.assertTrue(False)

        # Multiple terms one result
        search_gen = self.storage.search([('text', 'One'), ('text', 'Unique'), ('text', 'Phrase'), ('text', 'Purple')])
        i = 0
        for doc in search_gen:
            self.assertEqual(doc.to_dict(), d1.to_dict())
            i += 1
        self.assertEqual(i, 1)

    def test_search_multiple_docs(self):
        d1_id = uuid.uuid4()
        d1 = Document(u'DoCuMeNt Title: One 文字でわかる！', id=d1_id, submitter=SUBMITTER)
        self.storage.add(d1)
        self.storage.persist()

        # Search for first Document added
        i = 0
        search_gen = self.storage.search([('text', 'Document')])
        for doc in search_gen:
            self.assertEqual(doc.to_dict(), d1.to_dict())
            i += 1
        self.assertEqual(i, 1)

        # Add another Document
        d2_id = uuid.uuid4()
        d2 = Document(u'文字でわかる！', id=d2_id, submitter=SUBMITTER)
        self.storage.add(d2)
        self.storage.persist()

        # Search again after adding
        i = 0
        expected = [d1.to_dict(), d2.to_dict()]
        search_gen = self.storage.search([('text', u'文字でわかる！')])
        for doc in search_gen:
           self.assertTrue(doc.to_dict() in expected)
           expected.remove(doc.to_dict())
           i += 1
        self.assertEqual(i, 2)

    def test_search_multiple_submitters(self):
        submitter2 = {
            u'id': u'you',
            u'email': u'you@example.com',
            u'firstname': u'User',
            u'surname': u'Two',
        }
        d1_id = uuid.uuid4()
        d1 = Document('Document Title: One', id=d1_id, submitter=SUBMITTER)
        self.storage.add(d1)
        self.storage.persist()
        d2_id = uuid.uuid4()
        d2 = Document('Document Title: Two', id=d2_id, submitter=submitter2)
        self.storage.add(d2)
        self.storage.persist()

        # Specify the submitter
        i = 0
        search_gen = self.storage.search([('text', 'Document')], submitter_id=SUBMITTER['id'])
        for doc in search_gen:
            self.assertEqual(doc.to_dict(), d1.to_dict())
            i += 1
        self.assertEqual(i, 1)

        # Do not specify the submitter
        i = 0
        expected = [d1.to_dict(), d2.to_dict()]
        search_gen = self.storage.search([('text', 'Document Title')])
        for doc in search_gen:
           self.assertTrue(doc.to_dict() in expected)
           expected.remove(doc.to_dict())
           i += 1
        self.assertEqual(i, 2)
