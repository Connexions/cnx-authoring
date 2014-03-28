# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###

import unittest
import os
from uuid import uuid4
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

from ...models import Document
from ...storage.database import CONNECTION_SETTINGS_KEY, initdb

class PostgresqlStorageTests(unittest.TestCase):
    def setUp(self):
        from ...storage.postgresql import PostgresqlStorage
        config = ConfigParser.ConfigParser()
        config.read(['testing.ini'])
        test_db = config.get('app:main', CONNECTION_SETTINGS_KEY)
        initdb({CONNECTION_SETTINGS_KEY:test_db},clear=True)
        self.storage = PostgresqlStorage(db_connection_string=test_db)

    def tearDown(self):
        cursor = self.storage.conn.cursor()
        cursor.execute('delete from document')
        cursor.execute('delete from resource')
        cursor.close()
        self.storage.persist()
        self.storage.conn.close()

    def test_add_document(self):
        d1_id = uuid4()
        d1 = Document('Document Title: One', id=d1_id,
                      content='<p>Document One content etc</p>',
                      abstract='Summary of Document One',
                      submitter = 'me',
                      language='en-us')
        self.storage.add(d1)
        self.storage.persist()

        d2_id = uuid4()
        d2 = Document('Document Two', id=d2_id,
                      content='<p>Document Two content etc</p>',
                      abstract='Summary of Document Two',
                      submitter = 'me',
                      language='en-us')
        self.storage.add(d2)
        self.storage.persist()

        result = self.storage.get(id=d1_id)
        self.assertEqual(result.to_dict(), d1.to_dict())

        result = self.storage.get(id=d2_id)
        self.assertEqual(result.to_dict(), d2.to_dict())

    def test_get_document(self):
        d3_id = uuid4()
        result = self.storage.get(id=d3_id)
        self.assertEqual(result, None)

        d3 = Document('Document Title: Three', id=d3_id,
                     content='<p>Document Three content etc</p>',
                     abstract='Summary of Document Three',
                     submitter = 'me',
                     language='en-us')
        self.storage.add(d3)

        # get by id
        result = self.storage.get(id=d3_id)
        self.assertEqual(result.to_dict(), d3.to_dict())

        result = self.storage.get(id=uuid4())
        self.assertEqual(result, None)

        # get by title
        result = self.storage.get(title='Document Title: Three')
        self.assertEqual(result.to_dict(), d3.to_dict())

        result = self.storage.get(title='Document')
        self.assertEqual(result, None)

        # get by content
        result = self.storage.get(content='<p>Document Three content etc</p>')
        self.assertEqual(result.to_dict(), d3.to_dict())

        result = self.storage.get(content='<p></p>')
        self.assertEqual(result, None)

        # get by abstract
        result = self.storage.get(abstract='Summary of Document Three')
        self.assertEqual(result.to_dict(), d3.to_dict())

        result = self.storage.get(abstract='Summary')
        self.assertEqual(result, None)

        # get by language
        result = self.storage.get(language='en-us')
        self.assertEqual(result.to_dict(), d3.to_dict())

        result = self.storage.get(language='en')
        self.assertEqual(result, None)

        # get by multiple fields
        result = self.storage.get(language='en-us', abstract='Summary of Document Three')
        self.assertEqual(result.to_dict(), d3.to_dict())

        result = self.storage.get(language='en', abstract='Summary of Document Three')
        self.assertEqual(result, None)
