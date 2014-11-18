# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

from . import test_memory
from ...storage.database import CONNECTION_SETTINGS_KEY, initdb

class PostgresqlStorageTests(test_memory.MemoryStorageTests):
    def setUp(self):
        from ...storage.postgresql import PostgresqlStorage
        config = ConfigParser.ConfigParser()
        config.read(['testing.ini'])
        test_db = config.get('app:main', CONNECTION_SETTINGS_KEY)
        initdb({CONNECTION_SETTINGS_KEY: test_db}, clear=True)
        self.storage = PostgresqlStorage(db_connection_string=test_db)

    def tearDown(self):
        cursor = self.storage.conn.cursor()
        cursor.execute('delete from document_acl')
        cursor.execute('delete from document_licensor_acceptance')
        cursor.execute('delete from document')
        cursor.execute('delete from resource')
        cursor.close()
        self.storage.persist()
        self.storage.conn.close()
