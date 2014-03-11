# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import unittest

from pymongo import MongoClient


CONNECTION_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "test-authoring-storage"


class StorageTests(unittest.TestCase):


    def setUp(self):
        # Remove all documents and resources from the database.
        for collection in ('document', 'resource',):
            self.mongodb[collection].remove()

    @property
    def mongodb(self):
        if not hasattr(self, '_mongo_client'):
            self._mongo_client = MongoClient(CONNECTION_URI)
        return self._mongo_client[DATABASE_NAME]

    def test_document_addition(self):
        from ...storage.mongodb import MongoDBStorage
        store = MongoDBStorage(CONNECTION_URI, DATABASE_NAME)

        # Create the document.
        from ...models import Document
        document_title = "test document"
        created_document = Document(document_title)

        document = store.add(created_document)

        store.persist()

        self.assertTrue(document.id)

        # Manually check for the instance in the mongo.

        mongodb = MongoClient(CONNECTION_URI)
        database = mongodb[DATABASE_NAME]
        result = database.document.find_one(id=document.id)
        self.assertEqual(result['title'], document_title)
        self.assertEqual(result['_id'], document._persistent.ident)

    def test_document_updated(self):
        from ...storage.mongodb import MongoDBStorage
        store = MongoDBStorage(CONNECTION_URI, DATABASE_NAME)

        # Create the document.
        from ...models import Document
        document_title = "test document"
        created_document = Document(document_title)

        document = store.add(created_document)

        store.persist()

        self.assertTrue(document.id)

        # Manually check for the instance in the mongo.

        mongodb = MongoClient(CONNECTION_URI)
        database = mongodb[DATABASE_NAME]
        result = database.document.find_one(id=document.id)
        self.assertEqual(result['title'], document_title)
        self.assertEqual(result['_id'], document._persistent.ident)
