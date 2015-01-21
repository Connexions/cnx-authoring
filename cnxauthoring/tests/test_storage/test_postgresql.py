# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
from . import test_memory
from ..testing import integration_test_settings

import uuid
from .. import test_data
from ...models import Document, Resource, Binder
from .test_memory import SUBMITTER

class PostgresqlStorageTests(test_memory.MemoryStorageTests):

    def setUp(self):
        from ...storage.database import CONNECTION_SETTINGS_KEY, initdb
        from ...storage.postgresql import PostgresqlStorage
        settings = integration_test_settings()
        test_db = settings[CONNECTION_SETTINGS_KEY]
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

    def test_add_get_and_remove_binder(self):
        d1_id = uuid.uuid4()
        d = Document('Document Title: One', id=d1_id, submitter=SUBMITTER)
        d.acls = {'user2': ('view',)}
        self.storage.add(d)
        self.storage.persist()

        result = self.storage.get(id=d1_id)
        self.assertEqual(result.to_dict(), d.to_dict())
        self.assertEqual({k: tuple(sorted(v)) for k, v in result.acls.items()},
                         {'user2': ('view',)})

        b1_id = uuid.uuid4()
        b = Binder('Book Title', {
            'contents': [
                {'id': str(d1_id)},
                ]},
            id=b1_id, submitter=SUBMITTER)
        b.acls = {'user1': ('view', 'edit', 'publish') }
        self.storage.add(b)
        self.storage.persist()

        result = self.storage.get(id=b1_id)
        self.assertEqual(result.to_dict(), b.to_dict())
        self.assertEqual({k: tuple(sorted(v)) for k, v in result.acls.items()},
                         {'user1': ('edit', 'publish', 'view')})

        #FIXME update_containment should become a hidden side effect inside storage
        d.metadata['contained_in'] = [str(b1_id)]
        self.storage.update(d)

        result = self.storage.get(id=d1_id)
        self.assertEqual(result.to_dict(), d.to_dict())
        self.assertEqual({k: tuple(sorted(v)) for k, v in result.acls.items()},
                         {'user2': ('view',),'user1': ('edit', 'publish', 'view')})

        self.storage.remove(b)
        result = self.storage.get(id=b1_id)
        self.assertEqual(result, None)

        #FIXME update_containment should become a hidden side effect inside storage
        d.metadata['contained_in'] = []
        self.storage.update(d)
        result = self.storage.get(id=d1_id)
        self.assertEqual(result.to_dict(), d.to_dict())
        self.assertEqual({k: tuple(sorted(v)) for k, v in result.acls.items()},
                         {'user2': ('view',)})

