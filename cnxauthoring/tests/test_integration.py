# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import json
import unittest

from webtest import TestApp
from pyramid import testing

SETTINGS = {
    'storage': 'mongodb',
    'mongodb.connection_uri': "mongodb://localhost:27017/",
    'mongodb.database_name': "test-authoring",
    }


class WebTest(unittest.TestCase):

    def test_get_content(self):
        """Get the contents of a document."""
        # Create the test application.
        from .. import main
        app = main({}, SETTINGS)
        test_app = TestApp(app)

        # Make a document and persist it in storage.
        from ..models import Document
        document = Document("Test Document One")
        from ..storage import storage
        document = storage.add(document)
        storage.persist()

        pass
